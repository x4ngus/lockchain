//! Tuning and diagnostic workflows that keep LockChain deployments healthy.

use super::{event, repair_environment, WorkflowEvent, WorkflowLevel, WorkflowReport};
use crate::config::LockchainConfig;
use crate::error::{LockchainError, LockchainResult};
use crate::keyfile::{read_key_file, write_raw_key_file};
use crate::provider::{DatasetKeyDescriptor, KeyState, ZfsProvider};
use crate::service::LockchainService;
use crate::workflow::privilege::run_external;
use crate::workflow::provisioning::{repair_boot_assets, set_keylocation_property};
use sha2::{Digest, Sha256};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

const DEFAULT_SERVICES: &[&str] = &[
    "lockchain-key-usb.service",
    "lockchain.service",
    "run-lockchain.mount",
];
const STAGING_ROOT: &str = "/run/lockchain/media";
const MOUNT_BINARIES: &[&str] = &["/bin/mount", "/usr/bin/mount"];
const UMOUNT_BINARIES: &[&str] = &["/bin/umount", "/usr/bin/umount"];

const INITRAMFS_TOOLS: &[&str] = &["dracut", "update-initramfs", "lsinitrd", "lsinitramfs"];

/// Aggregates the raw results from the tuning pass before we build a report.
#[derive(Default)]
struct TuneOutcome {
    events: Vec<WorkflowEvent>,
    warnings: usize,
    errors: usize,
    key_valid: bool,
    checksum_match: bool,
    updated_config: Option<LockchainConfig>,
}

/// Run non-destructive checks and attempt to repair common issues automatically.
pub fn tune<P>(config: &LockchainConfig, provider: P) -> LockchainResult<WorkflowReport>
where
    P: ZfsProvider<Error = LockchainError> + Clone,
{
    let outcome = run_tune(config, provider.clone())?;
    let TuneOutcome {
        events: heal_events,
        key_valid,
        checksum_match,
        updated_config,
        ..
    } = outcome;
    let mut events = Vec::new();
    let mut remedies = Vec::new();

    if config.path.exists() {
        events.push(event(
            WorkflowLevel::Info,
            format!("Configuration present at {}", config.path.display()),
        ));
    } else {
        events.push(event(
            WorkflowLevel::Warn,
            format!(
                "Configuration file {} not found; bootstrap copy will be regenerated.",
                config.path.display()
            ),
        ));
    }

    events.push(event(
        WorkflowLevel::Info,
        "Tuning baseline diagnostics follow.",
    ));
    events.extend(heal_events);

    if !key_valid {
        remedies.push("Re-import USB key material or re-run the provisioning directive.".into());
    }
    if !checksum_match {
        remedies.push("Update usb.expected_sha256 to match on-disk key material.".into());
    }

    events.push(event(
        WorkflowLevel::Info,
        "Evaluating systemd units required for boot flow.",
    ));
    for unit in DEFAULT_SERVICES {
        if let Some(remedy) = audit_systemd_unit(unit, &mut events) {
            remedies.push(remedy);
        }
    }

    events.push(event(
        WorkflowLevel::Info,
        "Verifying initramfs tooling presence.",
    ));
    remedies.extend(audit_initramfs_tooling(&mut events));

    events.push(event(
        WorkflowLevel::Info,
        "Reapplying system integration policies.",
    ));
    let repair_cfg = updated_config.as_ref().unwrap_or(config);
    match repair_environment(repair_cfg) {
        Ok(report) => events.extend(report.events),
        Err(err) => {
            events.push(event(
                WorkflowLevel::Warn,
                format!("System integration repair failed: {err}"),
            ));
            remedies.push("Run lockchain repair with elevated privileges.".into());
        }
    }

    if !remedies.is_empty() {
        events.push(event(
            WorkflowLevel::Warn,
            format!("Remediation actions suggested: {}", remedies.join(" | ")),
        ));
    }

    let (warnings, errors) = count_levels(&events);
    let summary_level = if errors > 0 {
        WorkflowLevel::Error
    } else if warnings > 0 {
        WorkflowLevel::Warn
    } else {
        WorkflowLevel::Success
    };
    events.push(event(
        summary_level,
        format!("Tuning summary :: warnings={} errors={}", warnings, errors),
    ));

    Ok(WorkflowReport {
        title: "Tuning diagnostics".into(),
        events,
        recovery_key: None,
    })
}

/// Backwards-compatible alias for the consolidated diagnostics workflow.
pub fn doctor<P>(config: &LockchainConfig, provider: P) -> LockchainResult<WorkflowReport>
where
    P: ZfsProvider<Error = LockchainError> + Clone,
{
    tune(config, provider)
}

/// Core implementation shared by doctor/tuning flows so we only probe the system once.
fn run_tune<P>(config: &LockchainConfig, provider: P) -> LockchainResult<TuneOutcome>
where
    P: ZfsProvider<Error = LockchainError> + Clone,
{
    let mut outcome = TuneOutcome::default();
    let mut cfg = config.clone();
    let mut config_dirty = false;
    let key_path = cfg.key_hex_path();
    let key_parent = key_path.parent().map(PathBuf::from);
    let key_on_token = key_path.starts_with(STAGING_ROOT);
    let parent_mounted = key_parent
        .as_ref()
        .map(|p| is_mountpoint(p))
        .unwrap_or(false);
    let datasets: Vec<String> = cfg
        .policy
        .targets
        .iter()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();

    if datasets.is_empty() {
        outcome.events.push(event(
            WorkflowLevel::Error,
            "policy.targets is empty; configure at least one encryption root before running tune/doctor.",
        ));
        return Ok(outcome);
    }

    // If the key path lives under the token mount and is missing or the mount isn't active,
    // try to hydrate before failing. This prevents stale host-side copies from passing when
    // the token is actually absent.
    let requires_hydration = key_on_token && (!key_path.exists() || !parent_mounted);
    let hydrate_result = if requires_hydration {
        hydrate_from_usb(config, &key_path, &mut outcome.events)
    } else {
        HydrateResult::Skipped
    };

    let metadata = match &hydrate_result {
        HydrateResult::Restored(meta) => Some(meta.clone()),
        HydrateResult::MountFailed(_) | HydrateResult::Missing | HydrateResult::Skipped => {
            fs::metadata(&key_path).ok()
        }
    };

    if let Some(meta) = metadata.as_ref() {
        let mode = meta.permissions().mode() & 0o777;
        outcome.events.push(event(
            WorkflowLevel::Info,
            format!(
                "Key file located at {} (mode {:o})",
                key_path.display(),
                mode
            ),
        ));
        if mode != 0o400 {
            match fs::set_permissions(&key_path, fs::Permissions::from_mode(0o400)) {
                Ok(_) => outcome.events.push(event(
                    WorkflowLevel::Warn,
                    format!(
                        "Key file permissions were {:o}; tightened to 0400 for compliance.",
                        mode
                    ),
                )),
                Err(err) => outcome.events.push(event(
                    WorkflowLevel::Error,
                    format!(
                        "Key file permissions {:o}; failed to set 0400 ({err}).",
                        mode
                    ),
                )),
            }
        }
    } else {
        let message = match hydrate_result {
            HydrateResult::MountFailed(reason) => format!(
                "Unable to mount token to read key {} ({reason}). Run lockchain tune as root or ensure pkexec is available.",
                key_path.display()
            ),
            _ => format!(
                "Key file {} missing or unreadable. Insert the LockChain token and rerun lockchain tune before rebooting.",
                key_path.display()
            ),
        };
        outcome.events.push(event(WorkflowLevel::Error, message));
    }

    if metadata.is_some() {
        match read_key_file(&key_path) {
            Ok((key, converted)) => {
                if converted {
                    match write_raw_key_file(&key_path, &key[..]) {
                        Ok(_) => outcome.events.push(event(
                            WorkflowLevel::Warn,
                            "Normalised legacy hex key to raw 32-byte format on disk.",
                        )),
                        Err(err) => outcome.events.push(event(
                            WorkflowLevel::Error,
                            format!("Failed to rewrite key as raw bytes ({err})."),
                        )),
                    }
                }

                if key.len() == 32 {
                    outcome.key_valid = true;
                    outcome.events.push(event(
                        WorkflowLevel::Success,
                        "Key material validated as raw 32-byte payload.",
                    ));
                } else {
                    outcome.events.push(event(
                        WorkflowLevel::Error,
                        format!(
                            "Key material must be 32 bytes; detected {} bytes.",
                            key.len()
                        ),
                    ));
                }

                let digest = hex::encode(Sha256::digest(&key[..]));
                if let Some(expected) = &config.usb.expected_sha256 {
                    if expected.eq_ignore_ascii_case(&digest) {
                        outcome.checksum_match = true;
                        outcome.events.push(event(
                            WorkflowLevel::Success,
                            "usb.expected_sha256 matches on-disk key material.",
                        ));
                    } else {
                        cfg.usb.expected_sha256 = Some(digest.clone());
                        config_dirty = true;
                        outcome.events.push(event(
                            WorkflowLevel::Warn,
                            format!(
                                "usb.expected_sha256 mismatch: config={} actual={digest}",
                                expected
                            ),
                        ));
                    }
                } else {
                    cfg.usb.expected_sha256 = Some(digest.clone());
                    config_dirty = true;
                    outcome.events.push(event(
                        WorkflowLevel::Info,
                        format!(
                            "Computed key SHA-256={digest}; usb.expected_sha256 updated for integrity checks."
                        ),
                    ));
                }
            }
            Err(err) => outcome.events.push(event(
                WorkflowLevel::Error,
                format!("Unable to decode key file {} ({err})", key_path.display()),
            )),
        }
    }

    if outcome.key_valid {
        reconcile_keylocations(&provider, &datasets, &key_path, &mut outcome.events);
        if let Err(err) = repair_boot_assets(&cfg, &mut outcome.events) {
            outcome.events.push(event(
                WorkflowLevel::Warn,
                format!(
                    "Boot unlock assets reconciliation failed; headless unlock may be impacted ({err})."
                ),
            ));
        }
    }

    if let Some(label) = &cfg.usb.device_label {
        outcome.events.push(event(
            WorkflowLevel::Info,
            format!("Configured USB label requirement: {label}"),
        ));
    } else {
        outcome.events.push(event(
            WorkflowLevel::Warn,
            "usb.device_label not set; relying on generic mount discovery.",
        ));
    }

    if let Some(uuid) = &cfg.usb.device_uuid {
        outcome.events.push(event(
            WorkflowLevel::Info,
            format!("Configured USB UUID requirement: {uuid}"),
        ));
    } else {
        // Attempt to learn the UUID from the token to harden future boots.
        if let Some(label) = cfg.usb.device_label.as_deref() {
            if let Some(device) = resolve_block_by_label(label) {
                if let Some(uuid) = probe_uuid(&device) {
                    cfg.usb.device_uuid = Some(uuid.clone());
                    config_dirty = true;
                    outcome.events.push(event(
                        WorkflowLevel::Info,
                        format!(
                            "Captured USB UUID {uuid} from {}; updating config for stricter matching.",
                            device.display()
                        ),
                    ));
                }
            }
        }
        if cfg.usb.device_uuid.is_none() {
            outcome.events.push(event(
                WorkflowLevel::Warn,
                "usb.device_uuid not set; ensure label-based matching is resilient.",
            ));
        }
    }

    // Validate token key material if the device can be located.
    validate_token_key(&cfg, &mut outcome.events);

    let service = LockchainService::new(Arc::new(cfg.clone()), provider.clone());
    match service.list_keys() {
        Ok(snapshot) => {
            for DatasetKeyDescriptor {
                dataset,
                encryption_root,
                state,
            } in snapshot
            {
                match state {
                    KeyState::Available => outcome.events.push(event(
                        WorkflowLevel::Success,
                        format!("{dataset} :: {encryption_root} reports available"),
                    )),
                    KeyState::Unavailable => outcome.events.push(event(
                        WorkflowLevel::Warn,
                        format!("{dataset} :: {encryption_root} remains locked"),
                    )),
                    KeyState::Unknown(detail) => outcome.events.push(event(
                        WorkflowLevel::Warn,
                        format!("{dataset} :: status unknown ({detail})"),
                    )),
                }
            }
        }
        Err(err) => outcome.events.push(event(
            WorkflowLevel::Error,
            format!("Unable to enumerate dataset status ({err})"),
        )),
    }

    if cfg.fallback.enabled {
        let salt = cfg.fallback.passphrase_salt.is_some();
        let xor = cfg.fallback.passphrase_xor.is_some();
        if salt && xor {
            outcome.events.push(event(
                WorkflowLevel::Info,
                "Fallback passphrase material present.",
            ));
        } else {
            outcome.events.push(event(
                WorkflowLevel::Warn,
                "Fallback enabled but salt/xor material incomplete.",
            ));
        }
    } else {
        outcome.events.push(event(
            WorkflowLevel::Info,
            "Fallback passphrase disabled by configuration.",
        ));
    }

    if config_dirty {
        match cfg.save() {
            Ok(_) => outcome.events.push(event(
                WorkflowLevel::Info,
                format!("Persisted configuration updates to {}", cfg.path.display()),
            )),
            Err(err) => outcome.events.push(event(
                WorkflowLevel::Warn,
                format!("Failed to persist configuration updates ({err})"),
            )),
        }
        outcome.updated_config = Some(cfg);
    }

    let (warnings, errors) = count_levels(&outcome.events);
    outcome.warnings = warnings;
    outcome.errors = errors;
    Ok(outcome)
}

/// Inspect a systemd unit's state and suggest follow-up when it's unhealthy.
fn audit_systemd_unit(unit: &str, events: &mut Vec<WorkflowEvent>) -> Option<String> {
    let output = Command::new("systemctl")
        .args([
            "show",
            unit,
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "UnitFileState",
        ])
        .output();

    match output {
        Ok(output) => {
            if !output.status.success() {
                let detail = String::from_utf8_lossy(&output.stderr);
                events.push(event(
                    WorkflowLevel::Warn,
                    format!("systemctl show {unit} failed: {detail}"),
                ));
                return Some(format!(
                    "Ensure {unit} is installed and systemd is available."
                ));
            }

            let text = String::from_utf8_lossy(&output.stdout);
            let mut load = "unknown";
            let mut active = "unknown";
            let mut unit_file = "unknown";
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("LoadState=") {
                    load = rest;
                } else if let Some(rest) = line.strip_prefix("ActiveState=") {
                    active = rest;
                } else if let Some(rest) = line.strip_prefix("UnitFileState=") {
                    unit_file = rest;
                }
            }

            let mut remedy = None;

            let installed = load == "loaded";
            let active_ok = active == "active" || active == "activating";
            let enabled_ok = unit_file == "enabled" || unit_file == "static";
            let healthy = installed && active_ok;

            let mut detail = format!(
                "{unit} is {} (LoadState={load} ActiveState={active} UnitFileState={unit_file})",
                if healthy { "up" } else { "down" }
            );

            let mut severity = if healthy {
                WorkflowLevel::Info
            } else {
                WorkflowLevel::Error
            };

            if !installed {
                remedy = Some(format!(
                    "{unit} is not installed or not loaded (LoadState={load}); reinstall or enable the unit."
                ));
            } else if !active_ok {
                remedy = Some(format!(
                    "{unit} is not running (ActiveState={active}); review `systemctl status {unit}`."
                ));
            } else if !enabled_ok {
                severity = WorkflowLevel::Warn;
                detail.push_str(" (disabled)");
                remedy = Some(format!(
                    "{unit} is not enabled (UnitFileState={unit_file}); run `systemctl enable {unit}`."
                ));
            }

            events.push(event(severity, detail));
            remedy
        }
        Err(err) => {
            events.push(event(
                WorkflowLevel::Warn,
                format!("systemctl not available to inspect {unit} ({err})."),
            ));
            Some("Systemd not present; validate service management manually.".into())
        }
    }
}

/// Confirm the expected initramfs utilities are present in PATH.
fn audit_initramfs_tooling(events: &mut Vec<WorkflowEvent>) -> Vec<String> {
    let mut remedies = Vec::new();
    let mut available = false;

    for tool in INITRAMFS_TOOLS {
        if let Some(path) = search_path(tool) {
            available = true;
            events.push(event(
                WorkflowLevel::Info,
                format!("{tool} detected at {}", path.display()),
            ));
        } else {
            events.push(event(
                WorkflowLevel::Warn,
                format!("{tool} not found in PATH."),
            ));
            remedies.push(format!(
                "Install `{tool}` or ensure initramfs refresh tooling is available."
            ));
        }
    }

    if !available {
        remedies.push(
            "Neither dracut nor initramfs-tools were detected; initramfs rebuilds will fail."
                .into(),
        );
    }

    remedies
}

/// Minimal PATH lookup that honours absolute or relative binary hints.
fn search_path(binary: &str) -> Option<PathBuf> {
    if binary.contains('/') {
        let path = Path::new(binary);
        if path.exists() {
            return Some(path.to_path_buf());
        }
        return None;
    }

    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join(binary);
            if candidate.exists() {
                Some(candidate)
            } else {
                None
            }
        })
    })
}

/// Count how many warnings and errors we collected.
fn count_levels(events: &[WorkflowEvent]) -> (usize, usize) {
    let mut warnings = 0;
    let mut errors = 0;
    for event in events {
        match event.level {
            WorkflowLevel::Warn => warnings += 1,
            WorkflowLevel::Error => errors += 1,
            _ => {}
        }
    }
    (warnings, errors)
}

/// Ensure keylocation points at the configured key path for every encryption root we manage.
fn reconcile_keylocations<P: ZfsProvider<Error = LockchainError>>(
    provider: &P,
    datasets: &[String],
    key_path: &Path,
    events: &mut Vec<WorkflowEvent>,
) {
    let mut roots = Vec::new();
    for dataset in datasets {
        if dataset.trim().is_empty() {
            continue;
        }
        match provider.encryption_root(dataset) {
            Ok(root) => {
                if !roots.contains(&root) {
                    roots.push(root);
                }
            }
            Err(err) => events.push(event(
                WorkflowLevel::Warn,
                format!(
                    "Unable to resolve encryption root for {} ({err}); keylocation may drift.",
                    dataset
                ),
            )),
        }
    }

    for root in roots {
        if let Err(err) = set_keylocation_property(&root, key_path, events) {
            events.push(event(
                WorkflowLevel::Warn,
                format!(
                    "Failed to set keylocation=file://{} for {} ({err}).",
                    key_path.display(),
                    root
                ),
            ));
        }
    }
}

/// Lightweight mountpoint check for paths we manage under /run/lockchain/media.
fn is_mountpoint(path: &Path) -> bool {
    let needle = path.to_string_lossy();
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Some(mountpoint) = line.split_whitespace().nth(1) {
                if mountpoint == needle {
                    return true;
                }
            }
        }
    }
    false
}

/// Attempt to mount the USB token and restore the key if the primary path is missing.
enum HydrateResult {
    Restored(fs::Metadata),
    Missing,
    MountFailed(String),
    Skipped,
}

/// Attempt to mount the USB token and restore the key if the primary path is missing.
fn hydrate_from_usb(
    config: &LockchainConfig,
    dest: &Path,
    events: &mut Vec<WorkflowEvent>,
) -> HydrateResult {
    // If the configured label/UUID is missing, surface a single warning and stop.
    // lgtm[rust/cleartext-logging] - presence check only; device identifiers, not secrets
    let no_usb_selector = config
        .usb
        .device_label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_none()
        && config
            .usb
            .device_uuid
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_none();
    if no_usb_selector {
        events.push(event(
            WorkflowLevel::Warn,
            "USB label/UUID not set; tuning cannot stage or validate key.raw on the token.",
        ));
        return HydrateResult::Missing;
    }

    // Prefer any already-mounted staging paths to avoid churn.
    let mut candidates = Vec::new();
    if let Ok(entries) = fs::read_dir(STAGING_ROOT) {
        for entry in entries.flatten() {
            let path = entry.path().join(&config.usb.device_key_path);
            if path.exists() {
                candidates.push(path);
            }
        }
    }

    let selector_label = config
        .usb
        .device_label
        .as_deref()
        .filter(|label| !label.trim().is_empty());
    let selector_uuid = config
        .usb
        .device_uuid
        .as_deref()
        .filter(|uuid| !uuid.trim().is_empty());

    let device = selector_label
        .and_then(resolve_block_by_label)
        .or_else(|| selector_uuid.and_then(resolve_block_by_uuid));

    if device.is_none() && !candidates.is_empty() {
        // Try copying from an existing staging mount.
        for candidate in candidates {
            if dest == candidate {
                if let Ok(meta) = fs::metadata(&candidate) {
                    events.push(event(
                        WorkflowLevel::Info,
                        format!(
                            "Key already present on mounted token at {}; using in-place.",
                            candidate.display()
                        ),
                    ));
                    return HydrateResult::Restored(meta);
                }
            }

            if let Ok((key, converted)) = read_key_file(&candidate) {
                let _ = write_raw_key_file(dest, &key);
                if converted {
                    let _ = write_raw_key_file(&candidate, &key);
                }
                if let Ok(meta) = fs::metadata(dest) {
                    events.push(event(
                        WorkflowLevel::Info,
                        format!(
                            "Key restored to {} from {}",
                            dest.display(),
                            candidate.display()
                        ),
                    ));
                    return HydrateResult::Restored(meta);
                }
            } else {
                events.push(event(
                    WorkflowLevel::Warn,
                    format!(
                        "Key file at {} unreadable; ensure provisioning writes key.raw to the token.",
                        candidate.display()
                    ),
                ));
            }
        }
        return HydrateResult::Missing;
    }

    let device = match device {
        Some(dev) => dev,
        None => return HydrateResult::Missing,
    };

    let mount_root = PathBuf::from("/run/lockchain/media");
    let mount_leaf = config
        .usb
        .device_label
        .as_deref()
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .unwrap_or_else(|| {
            device
                .file_name()
                .and_then(|os| os.to_str())
                .unwrap_or("usb")
        });
    let mountpoint = mount_root.join(mount_leaf);
    let _ = fs::create_dir_all(&mountpoint);

    let already_mounted = is_mountpoint(&mountpoint);
    let mut mounted_here = false;
    if !already_mounted {
        let args = vec![
            OsString::from("-o"),
            OsString::from("ro,nosuid,nodev,noexec"),
            OsString::from(device.to_string_lossy().into_owned()),
            OsString::from(mountpoint.to_string_lossy().into_owned()),
        ];
        let mount_output = match run_external(MOUNT_BINARIES, &args) {
            Ok(out) => out,
            Err(err) => {
                events.push(event(
                    WorkflowLevel::Warn,
                    format!(
                        "Failed to mount token {} at {} ({err}); run lockchain tune as root or ensure pkexec is available.",
                        device.display(),
                        mountpoint.display()
                    ),
                ));
                return HydrateResult::MountFailed(err.to_string());
            }
        };
        if !mount_output.status.success() {
            let detail = String::from_utf8_lossy(&mount_output.stderr)
                .trim()
                .to_string();
            events.push(event(
                WorkflowLevel::Warn,
                format!(
                    "Mounting token {} at {} failed (status {:?}): {}",
                    device.display(),
                    mountpoint.display(),
                    mount_output.status.code(),
                    detail
                ),
            ));
            return HydrateResult::MountFailed(detail);
        }
        mounted_here = true;
    }

    let source = mountpoint.join(&config.usb.device_key_path);
    if !source.exists() {
        events.push(event(
            WorkflowLevel::Warn,
            format!(
                "Key file missing on token at {}; verify label/UUID match and rerun provisioning.",
                source.display()
            ),
        ));
        if mounted_here {
            let _ = run_external(
                UMOUNT_BINARIES,
                &[OsString::from(mountpoint.to_string_lossy().into_owned())],
            );
            let _ = fs::remove_dir_all(&mountpoint);
        }
        return HydrateResult::Missing;
    }

    let same_path = dest == source;

    // If the destination exists, treat it as authoritative and avoid overwriting it with
    // a mountpoint copy that might become inaccessible once unmounted.
    if dest.exists() {
        if let Ok(meta) = fs::metadata(dest) {
            events.push(event(
                WorkflowLevel::Info,
                format!(
                    "Key already present at {}; leaving token-mounted copy intact.",
                    dest.display()
                ),
            ));
            // If the destination lives on the token, keep the mount active so later reads succeed.
            if mounted_here && !same_path {
                let _ = run_external(
                    UMOUNT_BINARIES,
                    &[OsString::from(mountpoint.to_string_lossy().into_owned())],
                );
                let _ = fs::remove_dir_all(&mountpoint);
            }
            return HydrateResult::Restored(meta);
        }
    } else if !same_path {
        // Ensure parent directories exist when we need to copy off the token.
        if let Some(parent) = dest.parent() {
            let _ = fs::create_dir_all(parent);
        }
    }

    let result = match read_key_file(&source) {
        Ok((key, converted)) => {
            if converted {
                let _ = write_raw_key_file(&source, &key);
            }
            if same_path {
                Some(())
            } else {
                write_raw_key_file(dest, &key).ok()
            }
        }
        Err(_) => None,
    };

    // Only tear down the mount when we copied off-token; if dest==source we must leave
    // the token mounted so subsequent reads succeed.
    if mounted_here {
        let _ = run_external(
            UMOUNT_BINARIES,
            &[OsString::from(mountpoint.to_string_lossy().into_owned())],
        );
        let _ = fs::remove_dir_all(&mountpoint);
    }

    if result.is_some() {
        let meta = fs::metadata(dest).ok();
        if let Some(meta) = meta {
            events.push(event(
                WorkflowLevel::Info,
                format!(
                    "Key restored to {} from USB {}",
                    dest.display(),
                    device.display()
                ),
            ));
            return HydrateResult::Restored(meta);
        }
    }
    HydrateResult::Missing
}

fn resolve_block_by_label(label: &str) -> Option<PathBuf> {
    Command::new("blkid")
        .arg("-L")
        .arg(label)
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(PathBuf::from(path));
                }
            }
            None
        })
}

fn resolve_block_by_uuid(uuid: &str) -> Option<PathBuf> {
    Command::new("blkid")
        .arg("-U")
        .arg(uuid)
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(PathBuf::from(path));
                }
            }
            None
        })
}

fn probe_uuid(device: &Path) -> Option<String> {
    Command::new("blkid")
        .arg("-s")
        .arg("UUID")
        .arg("-o")
        .arg("value")
        .arg(device)
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(path);
                }
            }
            None
        })
}

/// Inspect the USB token (if reachable) to ensure key.raw exists and is 32 bytes.
fn validate_token_key(config: &LockchainConfig, events: &mut Vec<WorkflowEvent>) {
    let selector_label = config
        .usb
        .device_label
        .as_deref()
        .filter(|label| !label.trim().is_empty());
    let selector_uuid = config
        .usb
        .device_uuid
        .as_deref()
        .filter(|uuid| !uuid.trim().is_empty());

    if selector_label.is_none() && selector_uuid.is_none() {
        events.push(event(
            WorkflowLevel::Warn,
            "USB label/UUID not configured; token validation skipped.",
        ));
        return;
    }

    let device = selector_uuid
        .and_then(resolve_block_by_uuid)
        .or_else(|| selector_label.and_then(resolve_block_by_label));
    let Some(device) = device else {
        events.push(event(
            WorkflowLevel::Warn,
            "Unable to validate token key: no USB device found via UUID/label.",
        ));
        return;
    };

    let mount_root = PathBuf::from("/run/lockchain/media");
    let mountpoint = mount_root.join(
        config
            .usb
            .device_label
            .as_deref()
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .unwrap_or_else(|| {
                device
                    .file_name()
                    .and_then(|os| os.to_str())
                    .unwrap_or("usb")
            }),
    );
    let _ = fs::create_dir_all(&mountpoint);

    let already_mounted = is_mountpoint(&mountpoint);
    let mut mounted_here = false;
    if !already_mounted {
        let args = vec![
            OsString::from("-o"),
            OsString::from("ro,nosuid,nodev,noexec"),
            OsString::from(device.to_string_lossy().into_owned()),
            OsString::from(mountpoint.to_string_lossy().into_owned()),
        ];
        match run_external(MOUNT_BINARIES, &args) {
            Ok(out) if out.status.success() => mounted_here = true,
            Ok(out) => {
                let code = out.status.code();
                let stderr = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
                let busy = code == Some(32) || stderr.contains("busy");
                let perm = code == Some(1) && stderr.contains("permission");
                if busy || perm {
                    events.push(event(
                        WorkflowLevel::Info,
                        format!(
                            "USB {} appears mounted/busy; skipping validation mount (status {:?}).",
                            device.display(),
                            code
                        ),
                    ));
                } else {
                    events.push(event(
                        WorkflowLevel::Warn,
                        format!(
                            "Unable to mount USB {} for validation; status={:?} stderr={}",
                            device.display(),
                            code,
                            stderr.trim()
                        ),
                    ));
                }
                if !busy {
                    return;
                }
            }
            Err(err) => {
                events.push(event(
                    WorkflowLevel::Warn,
                    format!(
                        "Unable to mount USB {} for validation ({err}); run lockchain tune as root or ensure pkexec is available.",
                        device.display()
                    ),
                ));
                return;
            }
        }
    }

    let source = mountpoint.join(&config.usb.device_key_path);
    match fs::metadata(&source) {
        Ok(meta) => {
            let size = meta.len();
            if size == 32 {
                events.push(event(
                    WorkflowLevel::Success,
                    format!("Token key validated at {} (32 bytes).", source.display()),
                ));
            } else {
                events.push(event(
                    WorkflowLevel::Error,
                    format!(
                        "Token key {} must be 32 bytes; detected {} bytes.",
                        source.display(),
                        size
                    ),
                ));
            }
        }
        Err(err) => events.push(event(
            WorkflowLevel::Error,
            format!(
                "Unable to locate key on token at {} ({err}).",
                source.display()
            ),
        )),
    }

    if mounted_here {
        let _ = run_external(
            UMOUNT_BINARIES,
            &[OsString::from(mountpoint.to_string_lossy().into_owned())],
        );
        let _ = fs::remove_dir(&mountpoint);
    }
}
