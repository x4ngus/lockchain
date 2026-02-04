//! System-backed `LuksProvider` implementation.
//!
//! Wraps `cryptsetup` and consults `crypttab` for mapping/source resolution.
//! Initrd integration is tracked under ADR-003.

use crate::command::CryptsetupCommand;
use crate::crypttab::{parse_crypttab, CrypttabEntry};
use lockchain_core::config::looks_like_mapping_name;
use lockchain_core::error::{LockchainError, LockchainResult};
use lockchain_core::LockchainConfig;
use lockchain_provider::luks::{LuksMappingDescriptor, LuksProvider, LuksState};
use log::warn;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const DEFAULT_CRYPTTAB_PATH: &str = "/etc/crypttab";
const DEFAULT_CRYPTSETUP_PATHS: &[&str] = &[
    "/usr/sbin/cryptsetup",
    "/usr/bin/cryptsetup",
    "/sbin/cryptsetup",
    "/bin/cryptsetup",
    "/usr/local/sbin/cryptsetup",
];

/// System provider that manages LUKS mappings via the host `cryptsetup` binary.
#[derive(Debug, Clone)]
pub struct SystemLuksProvider {
    cryptsetup: CryptsetupCommand,
    crypttab_path: Option<PathBuf>,
    targets: Vec<String>,
    key_path: PathBuf,
    last_error: Arc<Mutex<Option<String>>>,
}

impl SystemLuksProvider {
    /// Build a provider from configuration, resolving `cryptsetup` and optional `crypttab` paths.
    pub fn from_config(config: &LockchainConfig) -> LockchainResult<Self> {
        let timeout = config.zfs_timeout();
        let cryptsetup = CryptsetupCommand::new(resolve_cryptsetup_path(config)?, timeout);
        let crypttab_path = resolve_crypttab_path(config)?;
        if crypttab_path.is_none() {
            warn!(
                "crypttab not found at {} and no [luks] crypttab_path configured; UUID/device target resolution will be unavailable",
                DEFAULT_CRYPTTAB_PATH
            );
        }

        Ok(Self {
            cryptsetup,
            crypttab_path,
            targets: config.policy.targets.clone(),
            key_path: config.key_hex_path(),
            last_error: Arc::new(Mutex::new(None)),
        })
    }

    /// Return whether `config.key_hex_path()` exists and contains a 32-byte key.
    pub fn key_staged(&self) -> bool {
        match fs::metadata(&self.key_path) {
            Ok(meta) => meta.is_file() && meta.len() == 32,
            Err(_) => false,
        }
    }

    /// Return the last provider error observed during status/unlock routines.
    pub fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn set_last_error(&self, message: impl Into<String>) {
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(message.into());
    }

    fn clear_last_error(&self) {
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn crypttab_entries(&self) -> LockchainResult<Vec<CrypttabEntry>> {
        let Some(path) = &self.crypttab_path else {
            return Ok(Vec::new());
        };

        let contents = fs::read_to_string(path)?;
        parse_crypttab(&contents)
    }

    fn resolve_target<'a>(
        &self,
        target: &str,
        entries: &'a [CrypttabEntry],
    ) -> Result<Option<&'a CrypttabEntry>, String> {
        // Precedence: name -> source -> UUID -> canonical path.
        let mut name_match = None;
        let mut name_count = 0usize;
        let mut source_match = None;
        let mut source_count = 0usize;

        for entry in entries {
            if entry.name == target {
                name_count += 1;
                if name_count == 1 {
                    name_match = Some(entry);
                }
            }
            if entry.source == target {
                source_count += 1;
                if source_count == 1 {
                    source_match = Some(entry);
                }
            }
        }

        if name_count > 1 {
            return Err(format!(
                "target `{target}` matches multiple crypttab mapping names"
            ));
        }
        if let Some(entry) = name_match {
            return Ok(Some(entry));
        }

        if source_count > 1 {
            return Err(format!(
                "target `{target}` matches multiple crypttab source devices"
            ));
        }
        if let Some(entry) = source_match {
            return Ok(Some(entry));
        }

        if let Some(target_uuid) = normalize_uuid(target) {
            let mut uuid_match = None;
            let mut uuid_count = 0usize;
            for entry in entries {
                if normalize_uuid(&entry.source).as_ref() == Some(&target_uuid) {
                    uuid_count += 1;
                    if uuid_count == 1 {
                        uuid_match = Some(entry);
                    }
                }
            }
            if uuid_count > 1 {
                return Err(format!(
                    "target `{target}` matches multiple crypttab UUID entries"
                ));
            }
            if let Some(entry) = uuid_match {
                return Ok(Some(entry));
            }
        }

        if target.starts_with('/') {
            if let Some(target_path) = canonicalize_existing(target) {
                let mut path_match = None;
                let mut path_count = 0usize;
                for entry in entries {
                    if !entry.source.starts_with('/') {
                        continue;
                    }
                    if canonicalize_existing(&entry.source)
                        .map(|p| p == target_path)
                        .unwrap_or(false)
                    {
                        path_count += 1;
                        if path_count == 1 {
                            path_match = Some(entry);
                        }
                    }
                }

                if path_count > 1 {
                    return Err(format!(
                        "target `{target}` matches multiple crypttab device paths"
                    ));
                }

                if let Some(entry) = path_match {
                    return Ok(Some(entry));
                }
            }
        }

        Ok(None)
    }

    fn keyfile_matches_staged_key(&self, key: &[u8]) -> bool {
        match fs::read(&self.key_path) {
            Ok(bytes) => bytes == key,
            Err(_) => false,
        }
    }
}

impl LuksProvider for SystemLuksProvider {
    type Error = LockchainError;

    fn list_mappings(&self) -> LockchainResult<Vec<LuksMappingDescriptor>> {
        let entries = match self.crypttab_entries() {
            Ok(entries) => entries,
            Err(err) => {
                self.set_last_error(err.to_string());
                Vec::new()
            }
        };

        let mut seen = HashSet::new();
        let mut mappings = Vec::new();

        for target in &self.targets {
            let (name, source, state) = match self.resolve_target(target, &entries) {
                Ok(Some(entry)) => (
                    entry.name.clone(),
                    entry.source.clone(),
                    self.cryptsetup.mapping_state(&entry.name)?,
                ),
                Ok(None) => {
                    if looks_like_mapping_name(target) {
                        (
                            target.clone(),
                            target.clone(),
                            self.cryptsetup.mapping_state(target)?,
                        )
                    } else {
                        (
                            target.clone(),
                            target.clone(),
                            LuksState::Unknown(format!(
                                "target `{target}` not found in crypttab and is not a mapping name"
                            )),
                        )
                    }
                }
                Err(reason) => (
                    target.clone(),
                    target.clone(),
                    LuksState::Unknown(reason.clone()),
                ),
            };

            if !seen.insert(name.clone()) {
                continue;
            }

            if let LuksState::Unknown(reason) = &state {
                self.set_last_error(reason.clone());
            }

            mappings.push(LuksMappingDescriptor {
                name,
                source,
                state,
            });
        }

        mappings.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(mappings)
    }

    fn unlock_mapping(&self, name: &str, key: &[u8]) -> LockchainResult<()> {
        if key.len() != 32 {
            let message = format!(
                "LUKS unlock requires a 32-byte key (got {} bytes)",
                key.len()
            );
            self.set_last_error(message.clone());
            return Err(LockchainError::InvalidConfig(message));
        }

        let entries = self.crypttab_entries()?;
        let resolved = self
            .resolve_target(name, &entries)
            .map_err(LockchainError::InvalidConfig)?;

        let (mapping_name, source) = match resolved {
            Some(entry) => (entry.name.as_str(), entry.source.as_str()),
            None => {
                if looks_like_mapping_name(name) {
                    let crypttab_path = self
                        .crypttab_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| DEFAULT_CRYPTTAB_PATH.to_string());
                    let message = format!(
                        "cannot unlock mapping `{name}`: no matching crypttab entry found; add it to {crypttab_path} or set [luks] crypttab_path",
                    );
                    self.set_last_error(message.clone());
                    return Err(LockchainError::InvalidConfig(message));
                }

                let message = format!(
                    "cannot unlock target `{name}`: not found in crypttab; ensure policy.targets uses a crypttab name/UUID/device path and that {} is present",
                    DEFAULT_CRYPTTAB_PATH
                );
                self.set_last_error(message.clone());
                return Err(LockchainError::InvalidConfig(message));
            }
        };

        let source_device = resolve_source_device(source);

        let result = if self.keyfile_matches_staged_key(key) {
            self.cryptsetup.unlock_mapping_with_keyfile(
                &source_device,
                mapping_name,
                &self.key_path,
            )
        } else {
            self.cryptsetup
                .unlock_mapping_with_key_bytes(&source_device, mapping_name, key)
        };

        match result {
            Ok(()) => {
                let state = self.cryptsetup.mapping_state(mapping_name)?;
                if matches!(state, LuksState::Active) {
                    self.clear_last_error();
                    Ok(())
                } else {
                    let message = format!(
                        "cryptsetup reported success unlocking `{mapping_name}` but mapping is still inactive"
                    );
                    self.set_last_error(message.clone());
                    Err(LockchainError::Provider(message))
                }
            }
            Err(err) => {
                self.set_last_error(format!(
                    "unlock failed for `{name}` (mapping `{mapping_name}`, source `{source}`): {err}"
                ));
                Err(err)
            }
        }
    }

    fn enroll_mapping_key(
        &self,
        target: &str,
        existing_passphrase: &[u8],
        keyfile: &Path,
    ) -> LockchainResult<()> {
        let meta = fs::metadata(keyfile).map_err(|err| {
            LockchainError::InvalidConfig(format!(
                "unable to read key material at {}: {err}",
                keyfile.display()
            ))
        })?;
        if !meta.is_file() || meta.len() != 32 {
            return Err(LockchainError::InvalidConfig(format!(
                "key material at {} must be a 32-byte file",
                keyfile.display()
            )));
        }

        let entries = self.crypttab_entries()?;
        let resolved = self
            .resolve_target(target, &entries)
            .map_err(LockchainError::InvalidConfig)?;
        let Some(entry) = resolved else {
            let crypttab_path = self
                .crypttab_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| DEFAULT_CRYPTTAB_PATH.to_string());
            let message = format!(
                "cannot enroll LockChain key for `{target}`: target not found in {crypttab_path}; ensure policy.targets uses a crypttab name/UUID/device path and that crypttab is present"
            );
            self.set_last_error(message.clone());
            return Err(LockchainError::InvalidConfig(message));
        };

        let source_device = resolve_source_device(&entry.source);
        let mapping_name = entry.name.as_str();

        if existing_passphrase.is_empty() {
            return Err(LockchainError::InvalidConfig(
                "existing LUKS passphrase cannot be empty".into(),
            ));
        }

        self.cryptsetup
            .enroll_keyfile(&source_device, existing_passphrase, keyfile)
            .inspect_err(|err| {
                self.set_last_error(err.to_string());
            })?;

        let verify_name = unique_verify_name(mapping_name);
        self.cryptsetup
            .unlock_mapping_with_keyfile(&source_device, &verify_name, keyfile)
            .inspect_err(|err| {
                self.set_last_error(err.to_string());
            })?;
        self.cryptsetup
            .close_mapping(&verify_name)
            .inspect_err(|err| {
                self.set_last_error(err.to_string());
            })?;

        self.clear_last_error();
        Ok(())
    }

    fn mapping_state(&self, name: &str) -> LockchainResult<LuksState> {
        if looks_like_mapping_name(name) {
            let state = self.cryptsetup.mapping_state(name)?;
            if let LuksState::Unknown(reason) = &state {
                self.set_last_error(reason.clone());
            }
            return Ok(state);
        }

        let entries = match self.crypttab_entries() {
            Ok(entries) => entries,
            Err(err) => {
                let message = format!("unable to read crypttab for target `{name}`: {err}");
                self.set_last_error(message.clone());
                return Ok(LuksState::Unknown(message));
            }
        };

        match self.resolve_target(name, &entries) {
            Ok(Some(entry)) => {
                let state = self.cryptsetup.mapping_state(&entry.name)?;
                if let LuksState::Unknown(reason) = &state {
                    self.set_last_error(reason.clone());
                }
                Ok(state)
            }
            Ok(None) => {
                let message = format!("target `{name}` not found in crypttab");
                self.set_last_error(message.clone());
                Ok(LuksState::Unknown(message))
            }
            Err(reason) => {
                self.set_last_error(reason.clone());
                Ok(LuksState::Unknown(reason))
            }
        }
    }
}

fn resolve_cryptsetup_path(config: &LockchainConfig) -> LockchainResult<PathBuf> {
    if let Some(path) = config
        .luks
        .cryptsetup_path
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        let candidate = Path::new(path);
        if !candidate.exists() {
            return Err(LockchainError::InvalidConfig(format!(
                "cryptsetup binary not found at {}",
                candidate.display()
            )));
        }
        return Ok(candidate.to_path_buf());
    }

    for candidate in DEFAULT_CRYPTSETUP_PATHS {
        let p = Path::new(candidate);
        if p.exists() {
            return Ok(p.to_path_buf());
        }
    }

    find_in_path("cryptsetup").ok_or_else(|| {
        LockchainError::InvalidConfig(format!(
            "unable to locate cryptsetup binary; tried {:?} and PATH",
            DEFAULT_CRYPTSETUP_PATHS
        ))
    })
}

fn resolve_crypttab_path(config: &LockchainConfig) -> LockchainResult<Option<PathBuf>> {
    if let Some(path) = config
        .luks
        .crypttab_path
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        let candidate = PathBuf::from(path);
        if !candidate.exists() {
            return Err(LockchainError::InvalidConfig(format!(
                "crypttab file not found at {}",
                candidate.display()
            )));
        }
        return Ok(Some(candidate));
    }

    let candidate = PathBuf::from(DEFAULT_CRYPTTAB_PATH);
    if candidate.exists() {
        Ok(Some(candidate))
    } else {
        Ok(None)
    }
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

fn normalize_uuid(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let candidate = strip_prefix_case_insensitive(trimmed, "UUID=")
        .unwrap_or(trimmed)
        .trim();
    if candidate.is_empty() {
        return None;
    }

    let mut hex_chars = 0usize;
    let mut has_dash = false;
    for ch in candidate.chars() {
        if ch == '-' {
            has_dash = true;
            continue;
        }
        if !ch.is_ascii_hexdigit() {
            return None;
        }
        hex_chars += 1;
    }

    if hex_chars == 0 || (!has_dash && hex_chars != 32) {
        return None;
    }

    let mut normalised = String::with_capacity(hex_chars);
    for ch in candidate.chars() {
        if ch == '-' {
            continue;
        }
        normalised.push(ch.to_ascii_lowercase());
    }
    Some(normalised)
}

fn canonicalize_existing(path: &str) -> Option<PathBuf> {
    let candidate = Path::new(path);
    candidate
        .exists()
        .then(|| fs::canonicalize(candidate).ok())
        .flatten()
}

fn unique_verify_name(base: &str) -> String {
    let sanitized = base
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>();
    let prefix = format!("lockchain-verify-{sanitized}");
    let mapper_root = Path::new("/dev/mapper");

    if !mapper_root.is_dir() {
        return prefix;
    }

    for idx in 0..1000u32 {
        let candidate = if idx == 0 {
            prefix.clone()
        } else {
            format!("{prefix}-{idx}")
        };
        if !mapper_root.join(&candidate).exists() {
            return candidate;
        }
    }

    format!("{prefix}-{}", std::process::id())
}

fn resolve_source_device(source: &str) -> String {
    let trimmed = source.trim();
    if let Some(uuid) = strip_prefix_case_insensitive(trimmed, "UUID=") {
        let uuid = uuid.trim();
        if !uuid.is_empty() {
            let candidate = Path::new("/dev/disk/by-uuid").join(uuid);
            if candidate.exists() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }

    if let Some(label) = strip_prefix_case_insensitive(trimmed, "LABEL=") {
        let label = label.trim();
        if !label.is_empty() {
            let candidate = Path::new("/dev/disk/by-label").join(label);
            if candidate.exists() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }

    trimmed.to_string()
}

fn strip_prefix_case_insensitive<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .and_then(|_| value.get(prefix.len()..))
}
