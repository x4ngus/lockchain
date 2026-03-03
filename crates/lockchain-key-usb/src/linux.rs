//! USB watcher that copies key material from removable media into place.

use crate::mounts::find_mount_point;
use anyhow::{bail, Context, Result};
use clap::Parser;
use hex::encode as hex_encode;
use lockchain_core::{
    config::{looks_like_mapping_name, LockchainConfig, DEFAULT_CONFIG_PATH},
    keyfile::{read_key_file, write_raw_key_file},
    logging, ProviderKind,
};
use log::{debug, error, info, warn};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use udev::{Device, Enumerator, MonitorBuilder};

const STAGING_ROOT: &str = "/run/lockchain/media";
const CRYPTSETUP_KEYS_DIR: &str = "/run/cryptsetup-keys.d";

/// Command-line options for the USB watcher service.
#[derive(Parser, Debug)]
#[command(
    name = "lockchain-key-usb",
    version,
    about = "USB key watcher for LockChain deployments."
)]
struct Args {
    /// Path to the LockChain configuration file.
    #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

/// Top-level entry: wrap run() and map errors to logs + exit codes.
pub(crate) fn main() {
    if let Err(err) = run() {
        error!("{err:?}");
        std::process::exit(1);
    }
}

/// Load configuration, prime the daemon, and start monitoring udev events.
fn run() -> Result<()> {
    logging::init("info");

    let args = Args::parse();
    let config = Arc::new(
        LockchainConfig::load_or_bootstrap(&args.config)
            .with_context(|| format!("failed to load config {}", args.config.display()))?,
    );

    if config.path != args.config {
        warn!(
            "configuration missing at {}; using bootstrap at {}",
            args.config.display(),
            config.path.display()
        );
    }

    info!(
        "USB key watcher started (config: {}, dest path: {})",
        config.path.display(),
        config.key_hex_path().display()
    );

    let daemon = UsbKeyDaemon::new(config);
    // Clear any stale staging data left behind after a crash/restart; scan_existing will repopulate.
    daemon.clear_destination();
    daemon.clear_cryptsetup_keys();
    daemon.scan_existing()?;
    daemon.event_loop()
}

/// Tracks the currently mounted USB device so we can clean up on removal.
#[derive(Debug)]
struct ActiveDevice {
    devpath: String,
    devnode: PathBuf,
}

/// Handles device discovery, checksum verification, and file synchronisation.
struct UsbKeyDaemon {
    config: Arc<LockchainConfig>,
    active: Mutex<Option<ActiveDevice>>,
}

impl UsbKeyDaemon {
    /// Construct a daemon with shared configuration.
    fn new(config: Arc<LockchainConfig>) -> Self {
        Self {
            config,
            active: Mutex::new(None),
        }
    }

    /// Look for already-mounted USB devices that match policy.
    fn scan_existing(&self) -> Result<()> {
        let mut enumerator = Enumerator::new()?;
        enumerator.match_subsystem("block")?;
        enumerator.match_property("DEVTYPE", "partition")?;
        enumerator.match_property("ID_BUS", "usb")?;

        for device in enumerator.scan_devices()? {
            self.try_import(&device)?;
        }
        Ok(())
    }

    /// Block on udev events and react to arrivals and removals.
    fn event_loop(&self) -> Result<()> {
        let mut monitor = MonitorBuilder::new()?.match_subsystem("block")?.listen()?;

        loop {
            if let Some(event) = monitor.next() {
                let device = event.device();
                if let Err(err) = self.process_device(&device) {
                    warn!(
                        "handling event for {} failed: {err:?}",
                        device_syspath(&device)
                    );
                }
            } else {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    /// Dispatch the udev event to either import or cleanup handlers.
    fn process_device(&self, device: &Device) -> Result<()> {
        let action = device.action().and_then(os_str_to_str).unwrap_or("change");
        match action {
            "add" | "change" | "bind" => self.try_import(device),
            "remove" | "unbind" => {
                self.handle_removal(device);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Validate the device, verify content, and copy key material into place.
    fn try_import(&self, device: &Device) -> Result<()> {
        if !self.device_matches(device) {
            return Ok(());
        }

        let devpath = device.devpath().to_string_lossy().to_string();
        {
            let active = self.active.lock().unwrap();
            if matches!(active.as_ref(), Some(current) if current.devpath == devpath) {
                debug!("device {} already active, skipping import", devpath);
                return Ok(());
            }
        }

        let devnode = device
            .devnode()
            .ok_or_else(|| anyhow::anyhow!("device {} missing devnode", devpath))?
            .to_path_buf();

        let mount_session = match self.ensure_mount(&devnode)? {
            Some(session) => session,
            None => {
                debug!(
                    "device {} not mounted within timeout; deferring import",
                    devnode.display()
                );
                return Ok(());
            }
        };
        let source_path = mount_session
            .mountpoint()
            .join(&self.config.usb.device_key_path);

        if !source_path.exists() {
            info!(
                "key material not yet present at {}; waiting for provisioning",
                source_path.display()
            );
            // If the key is absent, stay quiet and retry on the next scan.
            return Ok(());
        }

        let (key, converted) = match read_key_file(&source_path) {
            Ok(result) => result,
            Err(err) => {
                // Ignore empty staging files to avoid repeated mount churn during boot.
                if let lockchain_core::error::LockchainError::InvalidHexKey { reason, .. } = &err {
                    if reason.contains("file is empty") {
                        debug!(
                            "key at {} is empty; waiting for provisioning to populate",
                            source_path.display()
                        );
                        return Ok(());
                    }
                }
                warn!("failed to decode key at {}: {err}", source_path.display());
                self.clear_destination();
                self.clear_cryptsetup_keys();
                return Ok(());
            }
        };

        if let Some(expected) = &self.config.usb.expected_sha256 {
            if expected.trim().is_empty() {
                debug!(
                    "expected_sha256 not set; skipping checksum verification for {}",
                    source_path.display()
                );
            } else {
                let checksum = hex_encode(Sha256::digest(&key));
                if !expected.eq_ignore_ascii_case(&checksum) {
                    // If the destination key already matches expected, keep it and ignore this token copy.
                    if let Ok((existing, _)) = read_key_file(&self.config.key_hex_path()) {
                        let dest_sum = hex_encode(Sha256::digest(&existing));
                        if expected.eq_ignore_ascii_case(&dest_sum) {
                            warn!(
                                "Checksum mismatch for {}; retaining existing destination key that matches expected digest.",
                                source_path.display()
                            );
                            return Ok(());
                        }
                    }
                    warn!(
                        "Checksum mismatch for {}; expected {}, got {}. Skipping import.",
                        source_path.display(),
                        expected,
                        checksum
                    );
                    return Ok(());
                }
            }
        }

        if converted {
            info!(
                "normalised legacy hex key from {} before writing destination",
                source_path.display()
            );
        }

        let dest = self.config.key_hex_path();
        if dest.starts_with(STAGING_ROOT) {
            info!(
                "validated key material on token at {}; no host copy required",
                source_path.display()
            );
        } else {
            write_raw_key_file(&dest, &key).map_err(|err| anyhow::anyhow!(err))?;
            info!(
                "copied key material from {} to {}",
                source_path.display(),
                dest.display()
            );
        }

        if let Err(err) = self.stage_cryptsetup_keys(&key) {
            warn!("failed to stage cryptsetup key files: {err:?}");
        }

        drop(mount_session);

        let mut guard = self.active.lock().unwrap();
        *guard = Some(ActiveDevice { devpath, devnode });

        Ok(())
    }

    /// Tear down state when the matching USB device disappears.
    fn handle_removal(&self, device: &Device) {
        let mut guard = self.active.lock().unwrap();
        if guard.is_none() {
            return;
        }

        let matches = {
            let active = guard.as_ref().unwrap();
            let devpath = device.devpath().to_string_lossy();
            let devnode = device.devnode().map(|p| p.to_path_buf());

            if devpath == active.devpath {
                true
            } else if let Some(node) = devnode {
                node == active.devnode
            } else {
                false
            }
        };

        if matches {
            info!(
                "device {} removed; clearing destination key",
                device_syspath(device)
            );
            self.clear_destination();
            self.clear_cryptsetup_keys();
            *guard = None;
        }
    }

    /// Remove the destination key to avoid stale material lingering.
    fn clear_destination(&self) {
        let dest = self.config.key_hex_path();
        // If the configured destination is on the token itself, never delete it on removal.
        if dest.starts_with(STAGING_ROOT) {
            debug!(
                "destination {} resides on token; skipping deletion to preserve key material",
                dest.display()
            );
            return;
        }
        match fs::remove_file(&dest) {
            Ok(_) => info!("removed destination key {}", dest.display()),
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => warn!("failed to remove destination key {}: {err}", dest.display()),
        }
    }

    fn stage_cryptsetup_keys(&self, key: &[u8]) -> Result<()> {
        let provider = self
            .config
            .resolve_provider_kind()
            .unwrap_or(self.config.provider.r#type);
        if provider != ProviderKind::Luks {
            return Ok(());
        }

        if key.len() != 32 {
            bail!("key material must be 32 bytes (got {})", key.len());
        }

        let mappings: Vec<&str> = self
            .config
            .policy
            .targets
            .iter()
            .map(|entry| entry.trim())
            .filter(|entry| looks_like_mapping_name(entry))
            .collect();

        if mappings.is_empty() {
            debug!("no crypt mappings configured; skipping /run/cryptsetup-keys.d staging");
            return Ok(());
        }

        let dir = Path::new(CRYPTSETUP_KEYS_DIR);
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));

        let pid = std::process::id();
        for mapping in mappings {
            let tmp = dir.join(format!(".{mapping}.key.{pid}.new"));
            let dest = dir.join(format!("{mapping}.key"));

            let mut handle = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .with_context(|| format!("open {}", tmp.display()))?;
            handle
                .write_all(key)
                .with_context(|| format!("write {}", tmp.display()))?;
            let _ = handle.sync_all();

            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o400));
            fs::rename(&tmp, &dest)
                .with_context(|| format!("rename {} -> {}", tmp.display(), dest.display()))?;
            let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(0o400));
        }

        Ok(())
    }

    fn clear_cryptsetup_keys(&self) {
        let provider = self
            .config
            .resolve_provider_kind()
            .unwrap_or(self.config.provider.r#type);
        if provider != ProviderKind::Luks {
            return;
        }

        let mappings: Vec<&str> = self
            .config
            .policy
            .targets
            .iter()
            .map(|entry| entry.trim())
            .filter(|entry| looks_like_mapping_name(entry))
            .collect();

        if mappings.is_empty() {
            return;
        }

        let dir = Path::new(CRYPTSETUP_KEYS_DIR);
        for mapping in mappings {
            let dest = dir.join(format!("{mapping}.key"));
            match fs::remove_file(&dest) {
                Ok(_) => debug!("removed staged cryptsetup key {}", dest.display()),
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => warn!("failed to remove staged key {}: {err}", dest.display()),
            }
        }
    }

    /// Poll `/proc/mounts` and attempt to mount the device on the fly when needed.
    fn ensure_mount(&self, devnode: &Path) -> Result<Option<MountSession>> {
        let timeout = Duration::from_secs(self.config.usb.mount_timeout_secs.max(5));
        let deadline = Instant::now() + timeout;

        loop {
            if !devnode.exists() {
                return Ok(None);
            }

            if let Some(existing) = find_mount_point(devnode)? {
                return Ok(Some(MountSession::new(existing, false)));
            }

            match self.mount_device(devnode) {
                Ok(session) => return Ok(Some(session)),
                Err(err) => {
                    if let Some(existing) = find_mount_point(devnode)? {
                        return Ok(Some(MountSession::new(existing, false)));
                    }
                    debug!("mount attempt for {} failed: {err:?}", devnode.display())
                }
            }

            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(250));
        }
    }

    fn mount_device(&self, devnode: &Path) -> Result<MountSession> {
        if !devnode.exists() {
            bail!("device {} not found", devnode.display());
        }
        fs::create_dir_all(STAGING_ROOT)?;
        let leaf = self
            .config
            .usb
            .device_label
            .as_deref()
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(|label| label.to_string())
            .or_else(|| {
                devnode
                    .file_name()
                    .and_then(|os| os.to_str())
                    .map(|value| value.to_string())
            })
            .unwrap_or_else(|| "lockchain".to_string());
        let mountpoint = Path::new(STAGING_ROOT).join(&leaf);
        fs::create_dir_all(&mountpoint)?;

        let status = Command::new("mount")
            .arg("-o")
            .arg("ro,nosuid,nodev,noexec")
            .arg(devnode)
            .arg(&mountpoint)
            .status()
            .with_context(|| format!("mount {} {}", devnode.display(), mountpoint.display()))?;

        if !status.success() {
            bail!(
                "mount command exited with status {:?}",
                status.code().unwrap_or(-1)
            );
        }

        info!(
            "mounted {} at {} (read-only staging)",
            devnode.display(),
            mountpoint.display()
        );

        Ok(MountSession::new(mountpoint, true))
    }

    /// Check whether the udev device aligns with our configured label/UUID.
    fn device_matches(&self, device: &Device) -> bool {
        if device.property_value("DEVTYPE").and_then(os_str_to_str) != Some("partition") {
            return false;
        }

        if device.property_value("ID_BUS").and_then(os_str_to_str) != Some("usb") {
            return false;
        }

        if let Some(expected) = &self.config.usb.device_label {
            let label = device.property_value("ID_FS_LABEL").and_then(os_str_to_str);
            if label.map(|value| value != expected).unwrap_or(true) {
                return false;
            }
        }

        if let Some(expected) = &self.config.usb.device_uuid {
            let uuid = device.property_value("ID_FS_UUID").and_then(os_str_to_str);
            // lgtm[rust/cleartext-logging] - device UUID comparison; not logged, not a secret
            if uuid.map(|value| value != expected).unwrap_or(true) {
                return false;
            }
        }

        true
    }
}

/// Represents a temporary mount that should be torn down when dropped.
struct MountSession {
    mountpoint: PathBuf,
    owns_mount: bool,
}

impl MountSession {
    fn new(mountpoint: PathBuf, owns_mount: bool) -> Self {
        Self {
            mountpoint,
            owns_mount,
        }
    }

    fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for MountSession {
    fn drop(&mut self) {
        if !self.owns_mount {
            return;
        }
        if let Err(err) = Command::new("umount").arg(&self.mountpoint).status() {
            warn!("failed to unmount {}: {err}", self.mountpoint.display());
            return;
        }
        if let Err(err) = fs::remove_dir(&self.mountpoint) {
            if err.kind() != ErrorKind::NotFound {
                debug!(
                    "unable to remove staging directory {}: {err}",
                    self.mountpoint.display()
                );
            }
        }
    }
}

/// Provide a human-readable path for logging udev devices.
fn device_syspath(device: &Device) -> String {
    device.syspath().to_string_lossy().into_owned()
}

/// Convenience helper for zero-copy OsStr → &str conversions.
fn os_str_to_str(value: &OsStr) -> Option<&str> {
    value.to_str()
}
