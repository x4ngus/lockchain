//! Configuration model and helpers shared by LockChain components.

use crate::error::{LockchainError, LockchainResult};
use directories_next::ProjectDirs;
use lockchain_provider::ProviderKind;
use log::{info, warn};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::NamedTempFile;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/lockchain.toml";
const LEGACY_ZFS_CONFIG_PATH: &str = "/etc/lockchain-zfs.toml";
const LEGACY_LUKS_CONFIG_PATH: &str = "/etc/lockchain-luks.toml";
const KEY_PATH_ENV: &str = "LOCKCHAIN_KEY_PATH";
const BOOTSTRAP_FILE_NAME: &str = "lockchain.toml";
const APP_QUALIFIER: &str = "io";
const APP_ORGANIZATION: &str = "Lockchain";
const APP_NAME: &str = "lockchain";
pub(crate) const KNOWN_ZFS_PATHS: &[&str] = &[
    "/usr/sbin/zfs",
    "/sbin/zfs",
    "/bin/zfs",
    "/usr/local/sbin/zfs",
];
pub(crate) const KNOWN_ZPOOL_PATHS: &[&str] = &[
    "/usr/sbin/zpool",
    "/sbin/zpool",
    "/bin/zpool",
    "/usr/local/sbin/zpool",
];
pub(crate) const KNOWN_CRYPTSETUP_PATHS: &[&str] = &[
    "/usr/sbin/cryptsetup",
    "/usr/bin/cryptsetup",
    "/sbin/cryptsetup",
    "/bin/cryptsetup",
    "/usr/local/sbin/cryptsetup",
];
const UBUNTU_DATASET_PREFIXES: &[&str] = &[
    "rpool/ROOT/ubuntu",
    "rpool/ROOT/default",
    "rpool/USERDATA",
    "rpool/SYSTEMDATA",
    "bpool/BOOT/ubuntu",
];

pub(crate) fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from(APP_QUALIFIER, APP_ORGANIZATION, APP_NAME)
}

/// Lightweight sanity check that a provided crypt mapping name matches common patterns.
pub fn looks_like_mapping_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.starts_with('-') {
        return false;
    }
    trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

fn looks_like_uuid(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }

    let mut hex_chars = 0usize;
    let mut has_dash = false;
    for ch in trimmed.chars() {
        if ch == '-' {
            has_dash = true;
            continue;
        }
        if !ch.is_ascii_hexdigit() {
            return false;
        }
        hex_chars += 1;
    }

    if hex_chars == 0 {
        return false;
    }

    // If there are no separators, expect a canonical 32-character UUID.
    if !has_dash && hex_chars != 32 {
        return false;
    }

    true
}

/// Lightweight sanity check for LUKS targets configured under `policy.targets`.
///
/// Targets can be mapping names (e.g. `vault`) or `crypttab`-style source identifiers (e.g.
/// `UUID=...`, `PARTUUID=...`, or `/dev/disk/by-uuid/...`).
pub fn looks_like_luks_target(target: &str) -> bool {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return false;
    }

    if looks_like_mapping_name(trimmed) {
        return true;
    }

    if trimmed.starts_with('/') {
        return true;
    }

    if looks_like_uuid(trimmed) {
        return true;
    }

    let Some((prefix, value)) = trimmed.split_once('=') else {
        return false;
    };

    let prefix = prefix.trim();
    let value = value.trim();
    if prefix.is_empty() || value.is_empty() {
        return false;
    }

    if !prefix.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        return false;
    }

    if prefix.eq_ignore_ascii_case("uuid") || prefix.eq_ignore_ascii_case("partuuid") {
        return looks_like_uuid(value);
    }

    true
}

fn detect_ubuntu_root_datasets() -> Option<Vec<String>> {
    let binary = detect_binary_path(KNOWN_ZFS_PATHS)
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("zfs"));

    let output = Command::new(&binary)
        .args(["list", "-H", "-o", "name,mountpoint", "-t", "filesystem"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut datasets = parse_default_dataset_candidates(&stdout);

    if datasets.is_empty() {
        for line in stdout.lines() {
            let mut parts = line.split('\t');
            let name = parts.next().unwrap_or("").trim();
            if name.starts_with("rpool/ROOT/ubuntu") {
                datasets.push(name.to_string());
            }
        }
    }

    if datasets.is_empty() {
        None
    } else {
        datasets.sort();
        datasets.dedup();
        Some(datasets)
    }
}

fn parse_default_dataset_candidates(payload: &str) -> Vec<String> {
    let mut datasets: Vec<String> = payload
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let name = parts.next()?.trim();
            let mount = parts.next().unwrap_or("").trim();
            if mount == "/" || mount.eq_ignore_ascii_case("legacy") {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect();

    for line in payload.lines() {
        let mut parts = line.split('\t');
        let name = parts.next().unwrap_or("").trim();
        if UBUNTU_DATASET_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            datasets.push(name.to_string());
        }
    }

    datasets.sort();
    datasets.dedup();
    datasets
}

/// Lightweight sanity check that a provided dataset name matches common ZFS patterns.
pub fn looks_like_dataset_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return false;
    }

    for segment in trimmed.split('/') {
        if segment.is_empty() {
            return false;
        }
        if segment.starts_with('-') {
            return false;
        }
        if !segment
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | '.'))
        {
            return false;
        }
    }

    true
}

fn default_ubuntu_datasets() -> Vec<String> {
    detect_ubuntu_root_datasets().unwrap_or_else(|| vec!["rpool/ROOT".to_string()])
}

pub(crate) fn detect_binary_path(candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .map(Path::new)
        .find(|path| path.exists())
        .map(|path| path.to_string_lossy().into_owned())
}

fn resolve_binary(configured: Option<&str>, candidates: &[&str], name: &str) -> Option<PathBuf> {
    if let Some(path) = configured {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            let candidate = PathBuf::from(trimmed);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    detect_binary_path(candidates)
        .map(PathBuf::from)
        .or_else(|| find_in_path(name))
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    env::split_paths(&paths).find_map(|dir| {
        let candidate = dir.join(binary);
        if candidate.exists() {
            Some(candidate)
        } else {
            None
        }
    })
}

fn render_bootstrap_template(
    datasets: Option<&[String]>,
    usb_label: Option<&str>,
    usb_uuid: Option<&str>,
) -> String {
    let mut selected = datasets
        .map(|list| {
            list.iter()
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(default_ubuntu_datasets);

    if selected.is_empty() {
        selected = default_ubuntu_datasets();
    } else {
        selected.sort();
        selected.dedup();
    }

    let dataset_list = selected
        .iter()
        .map(|d| format!("\"{}\"", d))
        .collect::<Vec<_>>()
        .join(", ");

    let zfs_path =
        detect_binary_path(KNOWN_ZFS_PATHS).unwrap_or_else(|| "/usr/sbin/zfs".to_string());
    let zpool_path =
        detect_binary_path(KNOWN_ZPOOL_PATHS).unwrap_or_else(|| "/usr/sbin/zpool".to_string());
    let device_label = usb_label
        .map(|label| label.trim())
        .filter(|label| !label.is_empty())
        .unwrap_or("REPLACE_WITH_USB_LABEL");
    let device_uuid_line = usb_uuid
        .map(|uuid| uuid.trim())
        .filter(|uuid| !uuid.is_empty())
        .map(|uuid| format!("device_uuid = \"{uuid}\""))
        .unwrap_or_else(|| "# device_uuid = \"0000-0000\"".to_string());

    format!(
        "# Auto-generated Lockchain configuration bootstrap.\n# Customize these values before provisioning production targets.\n\n[provider]\n# zfs | luks\n# (auto is supported, but explicit type is recommended for systemd-managed hosts)\ntype = \"zfs\"\n\n[policy]\n# Managed targets: datasets for ZFS, crypt mappings for LUKS.\ntargets = [{}]\nallow_root = false\n\n[zfs]\nzfs_path = \"{}\"\nzpool_path = \"{}\"\n\n[luks]\n# cryptsetup_path = \"/usr/sbin/cryptsetup\"\n# crypttab_path = \"/etc/crypttab\"\n\n[crypto]\ntimeout_secs = 10\n\n[usb]\n# Point to the raw key path on the managed host.\nkey_hex_path = \"/run/lockchain/key.raw\"\n# Optional host-side backup (disabled by default); uncomment only if policy allows.\n# host_backup_path = \"/etc/lockchain/key.raw\"\n# Match the removable media via LABEL or UUID.\ndevice_label = \"REPLACE_WITH_USB_LABEL\"\n# device_uuid = \"0000-0000\"\ndevice_key_path = \"key.raw\"\n# Capture the checksum after provisioning.\nexpected_sha256 = \"\"\nmount_timeout_secs = 10\n\n[fallback]\nenabled = true\naskpass = true\naskpass_path = \"/usr/bin/systemd-ask-password\"\npassphrase_salt = \"\"\npassphrase_xor = \"\"\npassphrase_iters = 250000\n\n[retry]\nmax_attempts = 3\nbase_delay_ms = 500\nmax_delay_ms = 5000\njitter_ratio = 0.1\n",
        dataset_list,
        zfs_path,
        zpool_path
    )
    .replace("device_label = \"REPLACE_WITH_USB_LABEL\"", &format!("device_label = \"{device_label}\""))
    .replace("# device_uuid = \"0000-0000\"", &device_uuid_line)
}

fn generate_bootstrap_template() -> String {
    render_bootstrap_template(None, None, None)
}

pub fn bootstrap_template() -> String {
    generate_bootstrap_template()
}

pub fn bootstrap_template_with(
    datasets: &[String],
    usb_label: Option<&str>,
    usb_uuid: Option<&str>,
) -> String {
    render_bootstrap_template(Some(datasets), usb_label, usb_uuid)
}

pub fn detect_zfs_binary_path() -> Option<String> {
    detect_binary_path(KNOWN_ZFS_PATHS)
}

pub fn detect_zpool_binary_path() -> Option<String> {
    detect_binary_path(KNOWN_ZPOOL_PATHS)
}

pub fn bootstrap_dataset_candidates() -> Vec<String> {
    default_ubuntu_datasets()
}

pub fn default_usb_label() -> &'static str {
    "REPLACE_WITH_USB_LABEL"
}

pub fn default_key_filename() -> &'static str {
    "key.raw"
}

pub fn default_key_mountpoint() -> &'static str {
    "/run/lockchain"
}

pub fn default_config_path() -> &'static str {
    DEFAULT_CONFIG_PATH
}

pub fn default_binary_hint() -> &'static str {
    "/usr/local/bin"
}

pub fn default_systemd_hint() -> &'static str {
    "/etc/systemd/system"
}

/// Describes which datasets we manage and the paths to supporting tooling.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Policy {
    /// Provider targets: datasets for ZFS, mapping names or crypttab identifiers for LUKS.
    #[serde(default, alias = "datasets", alias = "mappings", alias = "volumes")]
    pub targets: Vec<String>,

    #[serde(default)]
    pub binary_path: Option<String>,

    #[serde(default)]
    pub allow_root: bool,

    // Legacy ZFS keys (supported for migration; hidden from schema).
    #[serde(default, rename = "zfs_path", skip_serializing)]
    #[schemars(skip)]
    pub legacy_zfs_path: Option<String>,

    #[serde(default, rename = "zpool_path", skip_serializing)]
    #[schemars(skip)]
    pub legacy_zpool_path: Option<String>,
}

/// Provider selection configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct ProviderCfg {
    #[serde(default, rename = "type", alias = "kind")]
    pub r#type: ProviderKind,
}

/// ZFS provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct ZfsCfg {
    #[serde(default)]
    pub zfs_path: Option<String>,

    #[serde(default)]
    pub zpool_path: Option<String>,
}

/// LUKS provider configuration (cryptsetup/crypttab integration).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct LuksCfg {
    #[serde(default)]
    pub cryptsetup_path: Option<String>,

    #[serde(default)]
    pub crypttab_path: Option<String>,
}

/// Timeouts and other crypto-related knobs for CLI interactions.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CryptoCfg {
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_timeout_secs() -> u64 {
    10
}

impl Default for CryptoCfg {
    fn default() -> Self {
        Self {
            timeout_secs: default_timeout_secs(),
        }
    }
}

/// USB token expectations, including mount behaviour and checksum checks.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Usb {
    #[serde(default = "default_usb_key_path")]
    pub key_hex_path: String,

    #[serde(default = "default_usb_host_backup_path")]
    pub host_backup_path: Option<String>,

    #[serde(default)]
    pub expected_sha256: Option<String>,

    #[serde(default)]
    pub device_label: Option<String>,

    #[serde(default)]
    pub device_uuid: Option<String>,

    #[serde(default = "default_usb_device_key_path")]
    pub device_key_path: String,

    #[serde(default = "default_usb_mount_timeout_secs")]
    pub mount_timeout_secs: u64,
}

fn default_usb_key_path() -> String {
    "/run/lockchain/key.raw".to_string()
}

fn default_usb_host_backup_path() -> Option<String> {
    None
}

fn default_usb_device_key_path() -> String {
    "key.raw".to_string()
}

fn default_usb_mount_timeout_secs() -> u64 {
    10
}

impl Default for Usb {
    fn default() -> Self {
        Self {
            key_hex_path: default_usb_key_path(),
            host_backup_path: default_usb_host_backup_path(),
            expected_sha256: None,
            device_label: None,
            device_uuid: None,
            device_key_path: default_usb_device_key_path(),
            mount_timeout_secs: default_usb_mount_timeout_secs(),
        }
    }
}

/// Fallback passphrase tuning for emergency unlocks.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Fallback {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub askpass: bool,

    #[serde(default)]
    pub askpass_path: Option<String>,

    #[serde(default)]
    pub passphrase_salt: Option<String>,

    #[serde(default)]
    pub passphrase_xor: Option<String>,

    #[serde(default = "default_passphrase_iters")]
    pub passphrase_iters: u32,
}

fn default_passphrase_iters() -> u32 {
    250_000
}

impl Default for Fallback {
    fn default() -> Self {
        Self {
            enabled: true,
            askpass: true,
            askpass_path: Some("/usr/bin/systemd-ask-password".to_string()),
            passphrase_salt: None,
            passphrase_xor: None,
            passphrase_iters: default_passphrase_iters(),
        }
    }
}

/// Shared retry/backoff strategy used by higher level workflows.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RetryCfg {
    #[serde(default = "default_retry_attempts")]
    pub max_attempts: u32,

    #[serde(default = "default_retry_base_delay")]
    pub base_delay_ms: u64,

    #[serde(default = "default_retry_max_delay")]
    pub max_delay_ms: u64,

    #[serde(default = "default_retry_jitter")]
    pub jitter_ratio: f64,
}

fn default_retry_attempts() -> u32 {
    3
}

fn default_retry_base_delay() -> u64 {
    500
}

fn default_retry_max_delay() -> u64 {
    5_000
}

fn default_retry_jitter() -> f64 {
    0.1
}

impl Default for RetryCfg {
    fn default() -> Self {
        Self {
            max_attempts: default_retry_attempts(),
            base_delay_ms: default_retry_base_delay(),
            max_delay_ms: default_retry_max_delay(),
            jitter_ratio: default_retry_jitter(),
        }
    }
}

/// Top-level configuration snapshot loaded from disk.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LockchainConfig {
    /// Active provider selection (zfs/luks/auto).
    #[serde(default)]
    pub provider: ProviderCfg,

    pub policy: Policy,

    /// ZFS provider configuration.
    #[serde(default)]
    pub zfs: ZfsCfg,

    #[serde(default)]
    pub crypto: CryptoCfg,

    /// LUKS provider configuration.
    #[serde(default)]
    pub luks: LuksCfg,

    #[serde(default)]
    pub usb: Usb,

    #[serde(default)]
    pub fallback: Fallback,

    #[serde(default)]
    pub retry: RetryCfg,

    #[serde(skip)]
    pub path: PathBuf,

    #[serde(skip)]
    pub format: ConfigFormat,
}

/// Tracks whether we parsed TOML or YAML so writes preserve format.
#[derive(Debug, Clone, Copy, Default)]
pub enum ConfigFormat {
    #[default]
    Toml,
    Yaml,
}

impl LockchainConfig {
    /// Return the canonical system-wide configuration path.
    pub fn default_path() -> &'static Path {
        Path::new(DEFAULT_CONFIG_PATH)
    }

    /// Resolve the per-user configuration path used for bootstrapping.
    pub fn user_config_path() -> Option<PathBuf> {
        ProjectDirs::from(APP_QUALIFIER, APP_ORGANIZATION, APP_NAME)
            .map(|dirs| dirs.config_dir().join(BOOTSTRAP_FILE_NAME))
    }

    /// Load configuration from disk, creating a bootstrap copy when missing.
    ///
    /// If the requested path does not exist, LockChain will attempt to
    /// materialize a bootstrap template at that location. When the caller
    /// requests the global default (`/etc/lockchain.toml`) and the
    /// process lacks permission to create it, a per-user configuration is
    /// written to the platform config directory instead.
    pub fn load_or_bootstrap<P: AsRef<Path>>(path: P) -> LockchainResult<Self> {
        let target = path.as_ref();
        if target.exists() {
            return Self::load(target);
        }

        if target == Self::default_path() {
            match discover_legacy_config() {
                Ok(Some(legacy)) => {
                    warn!(
                        "configuration missing at {}; falling back to legacy config at {}",
                        target.display(),
                        legacy.display()
                    );
                    return Self::load(&legacy);
                }
                Ok(None) => {}
                Err(err) => return Err(err),
            }
        }

        match ensure_bootstrap_file(target) {
            Ok(created) => {
                if created {
                    info!("lockchain config bootstrap created at {}", target.display());
                }
                Self::load(target)
            }
            Err(err) => {
                if target != Self::default_path() {
                    return Err(LockchainError::InvalidConfig(format!(
                        "failed to initialise configuration at {}: {err}",
                        target.display()
                    )));
                }

                let user_path = Self::user_config_path().ok_or_else(|| {
                    LockchainError::InvalidConfig(
                        "unable to determine user configuration directory; \
                        create /etc/lockchain.toml manually"
                            .to_string(),
                    )
                })?;

                let created_user = ensure_bootstrap_file(&user_path).map_err(|io_err| {
                    LockchainError::InvalidConfig(format!(
                        "failed to prepare bootstrap configuration at {}: {io_err}",
                        user_path.display()
                    ))
                })?;

                if created_user {
                    info!(
                        "lockchain config bootstrap created at {}",
                        user_path.display()
                    );
                }

                warn!(
                    "configuration missing at {}; using per-user bootstrap at {}",
                    target.display(),
                    user_path.display()
                );

                Self::load(&user_path)
            }
        }
    }

    /// Read a config file from disk, detect format, and validate basics.
    pub fn load<P: AsRef<Path>>(path: P) -> LockchainResult<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)?;
        let is_toml = matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some(ext) if ext.eq_ignore_ascii_case("toml")
        );
        let mut cfg = if is_toml {
            toml::from_str::<Self>(&contents)?
        } else {
            serde_yaml::from_str::<Self>(&contents)?
        };

        cfg.path = path.to_path_buf();
        cfg.format = if is_toml {
            ConfigFormat::Toml
        } else {
            ConfigFormat::Yaml
        };

        cfg.apply_legacy_defaults();

        match cfg.provider.r#type {
            ProviderKind::Zfs => {
                if cfg.policy.targets.is_empty() {
                    return Err(LockchainError::InvalidConfig(
                        "policy.targets must list at least one dataset (provider=zfs)".to_string(),
                    ));
                }
            }
            ProviderKind::Luks => {
                if cfg.policy.targets.is_empty() {
                    return Err(LockchainError::InvalidConfig(
                        "policy.targets must list at least one volume (provider=luks)".to_string(),
                    ));
                }
            }
            ProviderKind::Auto => {
                if cfg.policy.targets.is_empty() {
                    return Err(LockchainError::InvalidConfig(
                        "policy.targets must list at least one target (provider=auto)".to_string(),
                    ));
                }
            }
        }

        Ok(cfg)
    }

    fn apply_legacy_defaults(&mut self) {
        if self.zfs.zfs_path.is_none() {
            self.zfs.zfs_path = self.policy.legacy_zfs_path.clone();
        }
        if self.zfs.zpool_path.is_none() {
            self.zfs.zpool_path = self.policy.legacy_zpool_path.clone();
        }
    }

    /// Returns true when `dataset` is listed under `policy.targets`.
    pub fn contains_dataset(&self, dataset: &str) -> bool {
        self.policy.targets.iter().any(|configured| {
            configured == dataset
                || configured.starts_with(&format!("{dataset}/"))
                || dataset.starts_with(&format!("{configured}/"))
        })
    }

    /// Returns true when `mapping` is listed under `policy.targets`.
    pub fn contains_mapping(&self, mapping: &str) -> bool {
        self.policy
            .targets
            .iter()
            .any(|configured| configured == mapping)
    }

    /// Returns true when `target` is managed by the selected provider kind.
    pub fn contains_target(&self, provider: ProviderKind, target: &str) -> bool {
        match provider {
            ProviderKind::Zfs => self.contains_dataset(target),
            ProviderKind::Luks => self.contains_mapping(target),
            ProviderKind::Auto => false,
        }
    }

    /// Return the configured targets for a provider kind.
    pub fn targets_for(&self, provider: ProviderKind) -> &[String] {
        match provider {
            ProviderKind::Zfs => &self.policy.targets,
            ProviderKind::Luks => &self.policy.targets,
            ProviderKind::Auto => &[],
        }
    }

    /// Resolve the active provider kind to use for workflows.
    ///
    /// When the configuration requests `auto`, LockChain selects a provider by:
    /// - inspecting provider-specific config sections (`[zfs]`, `[luks]`)
    /// - confirming the corresponding host binaries are present (`zfs`/`zpool` or `cryptsetup`)
    pub fn resolve_provider_kind(&self) -> LockchainResult<ProviderKind> {
        match self.provider.r#type {
            ProviderKind::Zfs => Ok(ProviderKind::Zfs),
            ProviderKind::Luks => Ok(ProviderKind::Luks),
            ProviderKind::Auto => self.auto_detect_provider_kind(),
        }
    }

    fn auto_detect_provider_kind(&self) -> LockchainResult<ProviderKind> {
        if self.policy.targets.is_empty() {
            return Err(LockchainError::ProviderSelection(
                "policy.targets is empty; cannot auto-select provider".into(),
            ));
        }

        let zfs_hint = self.zfs.zfs_path.is_some()
            || self.zfs.zpool_path.is_some()
            || self.policy.legacy_zfs_path.is_some()
            || self.policy.legacy_zpool_path.is_some();
        let luks_hint = self.luks.cryptsetup_path.is_some() || self.luks.crypttab_path.is_some();
        let zfs_available = self.zfs_toolchain_available();
        let luks_available = self.luks_toolchain_available();

        match (zfs_hint, luks_hint) {
            (true, false) => match (zfs_available, luks_available) {
                (true, _) => Ok(ProviderKind::Zfs),
                (false, true) => Ok(ProviderKind::Luks),
                (false, false) => Err(LockchainError::ProviderSelection(
                    "provider.type=auto inferred zfs configuration but `zfs`/`zpool` binaries were not found; set [zfs] zfs_path/zpool_path or install ZFS utilities".into(),
                )),
            },
            (false, true) => match (zfs_available, luks_available) {
                (_, true) => Ok(ProviderKind::Luks),
                (true, false) => Ok(ProviderKind::Zfs),
                (false, false) => Err(LockchainError::ProviderSelection(
                    "provider.type=auto inferred luks configuration but `cryptsetup` was not found; set [luks] cryptsetup_path or install cryptsetup".into(),
                )),
            },
            (true, true) => match (zfs_available, luks_available) {
                (true, false) => Ok(ProviderKind::Zfs),
                (false, true) => Ok(ProviderKind::Luks),
                (true, true) => Err(LockchainError::ProviderSelection(
                    "provider.type=auto is ambiguous: both [zfs] and [luks] sections are configured and both ZFS and cryptsetup binaries are present; set provider.type to `zfs` or `luks`".into(),
                )),
                (false, false) => Err(LockchainError::ProviderSelection(
                    "provider.type=auto cannot select a provider: both [zfs] and [luks] sections are configured but neither ZFS nor cryptsetup binaries were found".into(),
                )),
            },
            (false, false) => match (zfs_available, luks_available) {
                (true, false) => Ok(ProviderKind::Zfs),
                (false, true) => Ok(ProviderKind::Luks),
                (true, true) => Err(LockchainError::ProviderSelection(
                    "provider.type=auto is ambiguous: both ZFS and cryptsetup binaries are present; set provider.type to `zfs` or `luks`".into(),
                )),
                (false, false) => Err(LockchainError::ProviderSelection(
                    "provider.type=auto cannot select a provider: neither ZFS nor cryptsetup binaries were found".into(),
                )),
            },
        }
    }

    fn zfs_toolchain_available(&self) -> bool {
        let zfs = resolve_binary(self.zfs.zfs_path.as_deref(), KNOWN_ZFS_PATHS, "zfs");
        let zpool = resolve_binary(self.zfs.zpool_path.as_deref(), KNOWN_ZPOOL_PATHS, "zpool");
        zfs.is_some() && zpool.is_some()
    }

    fn luks_toolchain_available(&self) -> bool {
        resolve_binary(
            self.luks.cryptsetup_path.as_deref(),
            KNOWN_CRYPTSETUP_PATHS,
            "cryptsetup",
        )
        .is_some()
    }

    /// Perform a best-effort validation pass and return human-readable issues.
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();

        let resolved_provider = match self.provider.r#type {
            ProviderKind::Auto => match self.auto_detect_provider_kind() {
                Ok(kind) => Some(kind),
                Err(err) => {
                    issues.push(err.to_string());
                    None
                }
            },
            kind => Some(kind),
        };

        if self.policy.targets.is_empty() {
            match resolved_provider.unwrap_or(self.provider.r#type) {
                ProviderKind::Zfs => issues.push(
                    "policy.targets must contain at least one dataset target (provider=zfs)"
                        .to_string(),
                ),
                ProviderKind::Luks => issues.push(
                    "policy.targets must contain at least one volume target (provider=luks)"
                        .to_string(),
                ),
                ProviderKind::Auto => issues.push(
                    "policy.targets must contain at least one target (provider=auto)".to_string(),
                ),
            }
        }

        if !self.policy.targets.is_empty() {
            let mut seen = std::collections::HashSet::new();
            for target in &self.policy.targets {
                let trimmed = target.trim();
                if trimmed.is_empty() {
                    issues.push("policy.targets contains an empty entry".to_string());
                    continue;
                }

                if !seen.insert(trimmed.to_string()) {
                    issues.push(format!("duplicate target entry detected: {trimmed}"));
                }

                match resolved_provider {
                    Some(ProviderKind::Zfs) => {
                        if !looks_like_dataset_name(trimmed) {
                            issues.push(format!(
                                "policy.targets contains invalid dataset name: {trimmed}"
                            ));
                        }
                    }
                    Some(ProviderKind::Luks) => {
                        if !looks_like_luks_target(trimmed) {
                            issues.push(format!(
                                "policy.targets contains invalid LUKS target: {trimmed}"
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }

        if let Some(expected) = &self.usb.expected_sha256 {
            let trimmed = expected.trim();
            if !trimmed.is_empty() && (trimmed.len() != 64 || hex::decode(trimmed).is_err()) {
                issues.push("usb.expected_sha256 must be a 64-character hex string".to_string());
            }
        }

        if self.fallback.enabled {
            if self
                .fallback
                .passphrase_salt
                .as_deref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
            {
                issues.push(
                    "fallback.enabled is true but fallback.passphrase_salt is missing".to_string(),
                );
            }
            if self
                .fallback
                .passphrase_xor
                .as_deref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
            {
                issues.push(
                    "fallback.enabled is true but fallback.passphrase_xor is missing".to_string(),
                );
            }
            if self.fallback.passphrase_iters < 100_000 {
                issues.push(format!(
                    "fallback.passphrase_iters is {} which is below the minimum of 100000; \
                     the runtime will clamp to 100000 but the config should be corrected",
                    self.fallback.passphrase_iters
                ));
            }
        }

        if self.retry.max_attempts == 0 {
            issues.push("retry.max_attempts must be at least 1".to_string());
        }
        if self.retry.base_delay_ms == 0 {
            issues.push("retry.base_delay_ms must be greater than 0".to_string());
        }
        if self.retry.max_delay_ms < self.retry.base_delay_ms {
            issues.push(
                "retry.max_delay_ms must be greater than or equal to retry.base_delay_ms"
                    .to_string(),
            );
        }
        if !(0.0..=1.0).contains(&self.retry.jitter_ratio) {
            issues.push("retry.jitter_ratio must be between 0.0 and 1.0".to_string());
        }

        issues
    }

    /// Resolve the path where the USB key material should live.
    pub fn key_hex_path(&self) -> PathBuf {
        if let Ok(override_path) = env::var(KEY_PATH_ENV) {
            if !override_path.is_empty() {
                return PathBuf::from(override_path);
            }
        }
        PathBuf::from(&self.usb.key_hex_path)
    }

    /// Resolve the host-side backup path, when configured.
    pub fn host_backup_path(&self) -> Option<PathBuf> {
        self.usb.host_backup_path.as_ref().map(PathBuf::from)
    }

    /// Translate the stored timeout into a `Duration`.
    pub fn zfs_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.crypto.timeout_secs)
    }

    /// Optional override for the `zfs` CLI path.
    pub fn zfs_binary_path(&self) -> Option<PathBuf> {
        self.zfs
            .zfs_path
            .as_ref()
            .or(self.policy.legacy_zfs_path.as_ref())
            .map(PathBuf::from)
    }

    /// Optional override for the `zpool` CLI path.
    pub fn zpool_binary_path(&self) -> Option<PathBuf> {
        self.zfs
            .zpool_path
            .as_ref()
            .or(self.policy.legacy_zpool_path.as_ref())
            .map(PathBuf::from)
    }

    /// Access the shared retry configuration helpers rely on.
    pub fn retry_config(&self) -> &RetryCfg {
        &self.retry
    }

    /// Persist the configuration back to its original on-disk format.
    pub fn save(&self) -> LockchainResult<()> {
        let payload = match self.format {
            ConfigFormat::Toml => toml::to_string_pretty(self)?,
            ConfigFormat::Yaml => serde_yaml::to_string(self)?,
        };
        let dest = resolve_write_path(&self.path).map_err(LockchainError::Io)?;
        let parent = dest
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }

        #[cfg(unix)]
        let metadata = dest.exists().then(|| fs::metadata(&dest)).transpose()?;

        #[cfg(unix)]
        let desired_mode = metadata
            .as_ref()
            .map(|meta| meta.permissions().mode())
            .unwrap_or_else(|| {
                // Config may contain fallback derivation secrets (salt, xor mask);
                // restrict to owner-only even under /etc/.
                0o600
            });

        #[cfg(unix)]
        let desired_owner = metadata.as_ref().map(|meta| (meta.uid(), meta.gid()));

        let mut temp = NamedTempFile::new_in(parent)?;
        temp.as_file_mut().write_all(payload.as_bytes())?;
        temp.as_file_mut().flush()?;

        #[cfg(unix)]
        {
            fs::set_permissions(temp.path(), PermissionsExt::from_mode(desired_mode))?;
            if let Some((uid, gid)) = desired_owner {
                let rc = unsafe { libc::fchown(temp.as_file().as_raw_fd(), uid, gid) };
                if rc != 0 {
                    return Err(LockchainError::Io(io::Error::last_os_error()));
                }
            }
        }

        let _ = temp.as_file().sync_all();
        temp.persist(&dest)
            .map_err(|err| LockchainError::Io(err.error))?;
        let _ = sync_parent_dir(parent);
        Ok(())
    }
}

fn resolve_write_path(path: &Path) -> io::Result<PathBuf> {
    let mut candidate = path.to_path_buf();
    for _ in 0..16 {
        let meta = match fs::symlink_metadata(&candidate) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Err(err) => return Err(err),
        };

        if !meta.file_type().is_symlink() {
            return Ok(candidate);
        }

        let target = fs::read_link(&candidate)?;
        candidate = if target.is_absolute() {
            target
        } else {
            candidate
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .join(target)
        };
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("symlink resolution depth exceeded for {}", path.display()),
    ))
}

fn sync_parent_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir).and_then(|file| file.sync_all())
}

fn ensure_bootstrap_file(path: &Path) -> io::Result<bool> {
    if path.exists() {
        return Ok(false);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    match OpenOptions::new().create_new(true).write(true).open(path) {
        Ok(mut file) => {
            let template = generate_bootstrap_template();
            file.write_all(template.as_bytes())?;
            file.flush()?;
            #[cfg(unix)]
            {
                // Owner-only: config may contain fallback derivation secrets.
                fs::set_permissions(path, PermissionsExt::from_mode(0o600))?;
            }
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err),
    }
}

fn discover_legacy_config() -> LockchainResult<Option<PathBuf>> {
    let legacy_zfs = Path::new(LEGACY_ZFS_CONFIG_PATH);
    let legacy_luks = Path::new(LEGACY_LUKS_CONFIG_PATH);

    match (legacy_zfs.exists(), legacy_luks.exists()) {
        (true, false) => Ok(Some(legacy_zfs.to_path_buf())),
        (false, true) => Ok(Some(legacy_luks.to_path_buf())),
        (false, false) => Ok(None),
        (true, true) => Err(LockchainError::ProviderSelection(format!(
            "multiple legacy configuration files found ({} and {}); set LOCKCHAIN_CONFIG to select one",
            legacy_zfs.display(),
            legacy_luks.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl Into<String>) -> Self {
            let prev = env::var(key).ok();
            env::set_var(key, value.into());
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(prev) = &self.prev {
                env::set_var(self.key, prev);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn key_path_respects_env_override() {
        let config = LockchainConfig {
            provider: ProviderCfg::default(),
            policy: Policy {
                targets: vec!["tank/secure".into()],
                binary_path: None,
                allow_root: false,
                legacy_zfs_path: None,
                legacy_zpool_path: None,
            },
            zfs: ZfsCfg::default(),
            crypto: CryptoCfg { timeout_secs: 1 },
            luks: LuksCfg::default(),
            usb: Usb::default(),
            fallback: Fallback::default(),
            retry: RetryCfg::default(),
            path: PathBuf::new(),
            format: ConfigFormat::Toml,
        };

        let guard = EnvGuard::set(KEY_PATH_ENV, "/tmp/override.key");
        assert_eq!(config.key_hex_path(), PathBuf::from("/tmp/override.key"));
        drop(guard);
        assert_eq!(config.key_hex_path(), PathBuf::from(default_usb_key_path()));
    }

    #[test]
    fn ubuntu_dataset_detection_handles_suffixes() {
        let payload = "\
rpool\t/\n\
rpool/ROOT/ubuntu_js6lvu\t/\n\
rpool/USERDATA/x4ngus\t/home/x4ngus\n\
bpool/BOOT/ubuntu_js6lvu\tlegacy\n\
tank/secure\t/mnt/secure\n";

        let parsed = parse_default_dataset_candidates(payload);
        assert_eq!(
            parsed,
            vec![
                "bpool/BOOT/ubuntu_js6lvu".to_string(),
                "rpool".to_string(),
                "rpool/ROOT/ubuntu_js6lvu".to_string(),
                "rpool/USERDATA/x4ngus".to_string(),
            ]
        );
    }

    #[test]
    fn dataset_name_validator_accepts_ubuntu_patterns() {
        assert!(looks_like_dataset_name("rpool"));
        assert!(looks_like_dataset_name("rpool/ROOT/ubuntu_js6lvu"));
        assert!(looks_like_dataset_name("bpool/BOOT/ubuntu-xyz123"));
        assert!(looks_like_dataset_name("rpool/USERDATA/alice"));

        assert!(!looks_like_dataset_name(""));
        assert!(!looks_like_dataset_name("pool//dataset"));
        assert!(!looks_like_dataset_name("-pool/dataset"));
        assert!(!looks_like_dataset_name("pool/space here"));
        assert!(!looks_like_dataset_name("pool/dataset@shadow"));
    }

    #[test]
    fn luks_target_validator_accepts_mapping_uuid_and_paths() {
        assert!(looks_like_luks_target("vault"));
        assert!(looks_like_luks_target("UUID=1111-2222-3333-4444"));
        assert!(looks_like_luks_target(
            "uuid=11112222333344445555666677778888"
        ));
        assert!(looks_like_luks_target("/dev/nvme0n1p3"));
        assert!(looks_like_luks_target("/dev/disk/by-uuid/1111-2222"));

        assert!(!looks_like_luks_target(""));
        assert!(!looks_like_luks_target("not a target"));
        assert!(!looks_like_luks_target("UUID="));
        assert!(!looks_like_luks_target("PARTUUID=not-a-uuid"));
    }

    #[test]
    fn contains_dataset_allows_ancestors_and_descendants() {
        let mut config = LockchainConfig {
            provider: ProviderCfg::default(),
            policy: Policy {
                targets: vec!["rpool/ROOT/ubuntu_js6lvu".into()],
                binary_path: None,
                allow_root: false,
                legacy_zfs_path: None,
                legacy_zpool_path: None,
            },
            zfs: ZfsCfg::default(),
            crypto: CryptoCfg::default(),
            luks: LuksCfg::default(),
            usb: Usb::default(),
            fallback: Fallback::default(),
            retry: RetryCfg::default(),
            path: PathBuf::new(),
            format: ConfigFormat::Toml,
        };

        assert!(config.contains_dataset("rpool/ROOT/ubuntu_js6lvu"));
        assert!(config.contains_dataset("rpool/ROOT"));
        assert!(config.contains_dataset("rpool/ROOT/ubuntu_js6lvu/var"));
        assert!(!config.contains_dataset("tank/secure"));

        config.policy.targets = vec!["rpool/ROOT".into()];
        assert!(config.contains_dataset("rpool/ROOT/ubuntu_js6lvu"));
    }

    #[test]
    fn provider_auto_selects_zfs_when_only_datasets_configured() {
        let dir = tempdir().unwrap();
        let zfs = dir.path().join("zfs");
        let zpool = dir.path().join("zpool");
        fs::write(&zfs, "").unwrap();
        fs::write(&zpool, "").unwrap();

        let config = LockchainConfig {
            provider: ProviderCfg {
                r#type: ProviderKind::Auto,
            },
            policy: Policy {
                targets: vec!["tank/secure".into()],
                binary_path: None,
                allow_root: false,
                legacy_zfs_path: None,
                legacy_zpool_path: None,
            },
            zfs: ZfsCfg {
                zfs_path: Some(zfs.to_string_lossy().into_owned()),
                zpool_path: Some(zpool.to_string_lossy().into_owned()),
            },
            crypto: CryptoCfg::default(),
            luks: LuksCfg::default(),
            usb: Usb::default(),
            fallback: Fallback::default(),
            retry: RetryCfg::default(),
            path: PathBuf::new(),
            format: ConfigFormat::Toml,
        };

        assert_eq!(config.resolve_provider_kind().unwrap(), ProviderKind::Zfs);
    }

    #[test]
    fn provider_auto_selects_luks_when_only_mappings_configured() {
        let dir = tempdir().unwrap();
        let cryptsetup = dir.path().join("cryptsetup");
        fs::write(&cryptsetup, "").unwrap();

        let config = LockchainConfig {
            provider: ProviderCfg {
                r#type: ProviderKind::Auto,
            },
            policy: Policy {
                targets: vec!["cryptroot".into()],
                binary_path: None,
                allow_root: false,
                legacy_zfs_path: None,
                legacy_zpool_path: None,
            },
            crypto: CryptoCfg::default(),
            zfs: ZfsCfg::default(),
            luks: LuksCfg {
                cryptsetup_path: Some(cryptsetup.to_string_lossy().into_owned()),
                crypttab_path: None,
            },
            usb: Usb::default(),
            fallback: Fallback::default(),
            retry: RetryCfg::default(),
            path: PathBuf::new(),
            format: ConfigFormat::Toml,
        };

        assert_eq!(config.resolve_provider_kind().unwrap(), ProviderKind::Luks);
    }

    #[test]
    fn provider_auto_errors_when_targets_missing() {
        let config = LockchainConfig {
            provider: ProviderCfg {
                r#type: ProviderKind::Auto,
            },
            policy: Policy {
                targets: Vec::new(),
                binary_path: None,
                allow_root: false,
                legacy_zfs_path: None,
                legacy_zpool_path: None,
            },
            crypto: CryptoCfg::default(),
            zfs: ZfsCfg::default(),
            luks: LuksCfg::default(),
            usb: Usb::default(),
            fallback: Fallback::default(),
            retry: RetryCfg::default(),
            path: PathBuf::new(),
            format: ConfigFormat::Toml,
        };

        assert!(matches!(
            config.resolve_provider_kind(),
            Err(LockchainError::ProviderSelection(_))
        ));
    }

    #[test]
    fn provider_auto_errors_when_ambiguous_and_toolchains_present() {
        let dir = tempdir().unwrap();
        let zfs = dir.path().join("zfs");
        let zpool = dir.path().join("zpool");
        let cryptsetup = dir.path().join("cryptsetup");
        fs::write(&zfs, "").unwrap();
        fs::write(&zpool, "").unwrap();
        fs::write(&cryptsetup, "").unwrap();

        let config = LockchainConfig {
            provider: ProviderCfg {
                r#type: ProviderKind::Auto,
            },
            policy: Policy {
                targets: vec!["tank/secure".into()],
                binary_path: None,
                allow_root: false,
                legacy_zfs_path: None,
                legacy_zpool_path: None,
            },
            crypto: CryptoCfg::default(),
            zfs: ZfsCfg {
                zfs_path: Some(zfs.to_string_lossy().into_owned()),
                zpool_path: Some(zpool.to_string_lossy().into_owned()),
            },
            luks: LuksCfg {
                cryptsetup_path: Some(cryptsetup.to_string_lossy().into_owned()),
                crypttab_path: None,
            },
            usb: Usb::default(),
            fallback: Fallback::default(),
            retry: RetryCfg::default(),
            path: PathBuf::new(),
            format: ConfigFormat::Toml,
        };

        assert!(matches!(
            config.resolve_provider_kind(),
            Err(LockchainError::ProviderSelection(_))
        ));
    }
}
