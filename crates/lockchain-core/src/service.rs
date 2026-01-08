//! High-level unlock service that coordinates config, providers, and key sources.

use crate::config::LockchainConfig;
use crate::error::{LockchainError, LockchainResult};
use crate::keyfile::{read_key_file, write_raw_key_file};
use crate::provider::{KeyProvider, KeyStatusSnapshot};
use log::warn;
use sha2::{Digest, Sha256};
use std::cmp::min;
use std::path::Path;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use zeroize::Zeroizing;

/// Options that tune the unlock workflow.
#[derive(Debug, Default)]
pub struct UnlockOptions {
    pub strict_usb: bool,
    pub fallback_passphrase: Option<Zeroizing<String>>,
    pub key_override: Option<Zeroizing<Vec<u8>>>,
}

// Manual Clone implementation to ensure sensitive data is properly zeroized
impl Clone for UnlockOptions {
    fn clone(&self) -> Self {
        Self {
            strict_usb: self.strict_usb,
            fallback_passphrase: self.fallback_passphrase.as_ref().map(|p| Zeroizing::new(p.to_string())),
            key_override: self.key_override.as_ref().map(|k| Zeroizing::new(k.to_vec())),
        }
    }
}

/// Result of an unlock attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockReport {
    pub dataset: String,
    pub encryption_root: String,
    pub unlocked: Vec<String>,
    pub already_unlocked: bool,
}

/// Current key status for a dataset and its encryption root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetStatus {
    pub dataset: String,
    pub encryption_root: String,
    pub root_locked: bool,
    pub locked_descendants: Vec<String>,
}

/// Coordinates configuration, providers, and key sources to unlock datasets.
pub struct LockchainService<P: KeyProvider<Error = LockchainError>> {
    config: Arc<LockchainConfig>,
    provider: P,
}

impl<P: KeyProvider<Error = LockchainError>> LockchainService<P> {
    /// Build a service with shared configuration and a concrete provider implementation.
    pub fn new(config: Arc<LockchainConfig>, provider: P) -> Self {
        Self { config, provider }
    }

    /// Attempt to unlock `dataset` once, returning a report of what changed.
    pub fn unlock(&self, dataset: &str, options: UnlockOptions) -> LockchainResult<UnlockReport> {
        self.perform_unlock(dataset, options)
    }

    /// Unlock `dataset` with exponential backoff guided by retry policy.
    pub fn unlock_with_retry(
        &self,
        dataset: &str,
        options: UnlockOptions,
    ) -> LockchainResult<UnlockReport> {
        let policy = &self.config.retry;
        let mut attempt: u32 = 0;
        let mut delay_ms = policy.base_delay_ms.max(1);

        loop {
            attempt += 1;
            match self.perform_unlock(dataset, options.clone()) {
                Ok(report) => return Ok(report),
                Err(err) => {
                    if attempt >= policy.max_attempts {
                        return Err(LockchainError::RetryExhausted {
                            attempts: attempt,
                            last_error: err.to_string(),
                        });
                    }

                    let jitter_ms = if policy.jitter_ratio > 0.0 {
                        let pseudo = ((attempt * 37) % 100) as f64 / 100.0 - 0.5;
                        let factor = 1.0 + (policy.jitter_ratio * pseudo);
                        ((delay_ms as f64 * factor).max(1.0)).round() as u64
                    } else {
                        delay_ms
                    };

                    sleep(Duration::from_millis(jitter_ms));
                    delay_ms = min(delay_ms.saturating_mul(2), policy.max_delay_ms.max(1));
                }
            }
        }
    }

    /// Internal helper shared by the eager and retrying unlock paths.
    fn perform_unlock(
        &self,
        dataset: &str,
        options: UnlockOptions,
    ) -> LockchainResult<UnlockReport> {
        if !self.config.contains_target(self.provider.kind(), dataset) {
            return Err(LockchainError::DatasetNotConfigured(dataset.to_string()));
        }

        let root = self.provider.encryption_root(dataset)?;
        let locked_before = self.provider.locked_descendants(&root)?;
        if !locked_before.iter().any(|ds| ds == &root) {
            return Ok(UnlockReport {
                dataset: dataset.to_string(),
                encryption_root: root,
                unlocked: Vec::new(),
                already_unlocked: true,
            });
        }

        let key = self.key_material(dataset, &options)?;
        let unlocked = self.provider.load_key_tree(&root, &key)?;

        let locked_after = self.provider.locked_descendants(&root)?;
        if locked_after.iter().any(|ds| ds == &root) {
            return Err(LockchainError::Provider(format!(
                "encryption root {} still locked after load-key",
                root
            )));
        }

        Ok(UnlockReport {
            dataset: dataset.to_string(),
            encryption_root: root,
            unlocked,
            already_unlocked: false,
        })
    }

    /// Summarise the current keystatus for `dataset` and its encryption root.
    pub fn status(&self, dataset: &str) -> LockchainResult<DatasetStatus> {
        if !self.config.contains_target(self.provider.kind(), dataset) {
            return Err(LockchainError::DatasetNotConfigured(dataset.to_string()));
        }

        let root = self.provider.encryption_root(dataset)?;
        let locked = self.provider.locked_descendants(&root)?;
        let root_locked = locked.iter().any(|ds| ds == &root);
        let locked_descendants: Vec<String> = locked.into_iter().filter(|ds| ds != &root).collect();

        Ok(DatasetStatus {
            dataset: dataset.to_string(),
            encryption_root: root,
            root_locked,
            locked_descendants,
        })
    }

    /// Pull keystatus for every dataset declared in the policy.
    pub fn list_keys(&self) -> LockchainResult<KeyStatusSnapshot> {
        self.provider
            .describe_targets(self.config.targets_for(self.provider.kind()))
    }

    /// Locate or derive key material according to the supplied unlock options.
    fn key_material(
        &self,
        dataset: &str,
        options: &UnlockOptions,
    ) -> LockchainResult<Zeroizing<Vec<u8>>> {
        if let Some(raw) = &options.key_override {
            // Already wrapped in Zeroizing, just clone the protected data
            return Ok(Zeroizing::new(raw.to_vec()));
        }

        let usb_key_path = self.config.key_hex_path();
        match self.load_usb_key(&usb_key_path) {
            Ok(key) => {
                self.verify_checksum(&key)?;
                return Ok(key);
            }
            Err(err) => {
                let io_error = matches!(&err, LockchainError::Io(_));
                let missing = matches!(
                    &err,
                    LockchainError::Io(io_err) if io_err.kind() == std::io::ErrorKind::NotFound
                );

                if !io_error || options.strict_usb || !self.config.fallback.enabled {
                    return Err(if missing {
                        LockchainError::MissingKeySource(dataset.to_string())
                    } else {
                        err
                    });
                }
            }
        }

        let passphrase = options
            .fallback_passphrase
            .as_ref()
            .ok_or_else(|| LockchainError::MissingKeySource(dataset.to_string()))?;

        // Already wrapped in Zeroizing, convert to bytes directly
        let passphrase_bytes = Zeroizing::new(passphrase.as_bytes().to_vec());
        let key = self.derive_fallback_key(&passphrase_bytes)?;
        Ok(key)
    }

    /// Read and normalise key material stored on disk.
    fn load_usb_key(&self, path: &Path) -> LockchainResult<Zeroizing<Vec<u8>>> {
        let (key, converted) = read_key_file(path)?;
        if converted {
            write_raw_key_file(path, &key)?;
        }
        Ok(key)
    }

    /// Make sure the loaded key matches the expected checksum when configured.
    fn verify_checksum(&self, key: &[u8]) -> LockchainResult<()> {
        if let Some(expected) = &self.config.usb.expected_sha256 {
            let expected = expected.trim();
            if expected.is_empty() {
                warn!("usb.expected_sha256 is empty; skipping checksum verification");
                return Ok(());
            }
            if expected.len() != 64 || hex::decode(expected).is_err() {
                return Err(LockchainError::InvalidConfig(
                    "usb.expected_sha256 must be a 64-character hex string".to_string(),
                ));
            }
            let digest = Sha256::digest(key);
            let actual = hex::encode(digest);
            if !expected.eq_ignore_ascii_case(&actual) {
                return Err(LockchainError::InvalidConfig(format!(
                    "usb.expected_sha256 mismatch: expected {}, got {}",
                    expected, actual
                )));
            }
        } else {
            warn!("usb.expected_sha256 not configured; skipping checksum verification");
        }
        Ok(())
    }

    /// Derive the fallback key using the configured PBKDF2 parameters and mask.
    pub fn derive_fallback_key(&self, passphrase: &[u8]) -> LockchainResult<Zeroizing<Vec<u8>>> {
        crate::fallback::derive_fallback_key(&self.config, passphrase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ConfigFormat, CryptoCfg, Fallback, LockchainConfig, Policy, RetryCfg, Usb,
    };
    use crate::provider::{DatasetKeyDescriptor, KeyState, KeyStatusSnapshot, ZfsProvider};
    use std::collections::HashSet;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct MockProvider {
        root: String,
        locked: Mutex<HashSet<String>>,
        observed_keys: Mutex<Vec<Vec<u8>>>,
        failures_before_success: Mutex<u32>,
    }

    impl MockProvider {
        fn new(root: &str, locked: &[&str]) -> Self {
            Self {
                root: root.to_string(),
                locked: Mutex::new(locked.iter().map(|s| s.to_string()).collect()),
                observed_keys: Mutex::new(Vec::new()),
                failures_before_success: Mutex::new(0),
            }
        }

        fn with_failures(root: &str, locked: &[&str], failures: u32) -> Self {
            Self {
                root: root.to_string(),
                locked: Mutex::new(locked.iter().map(|s| s.to_string()).collect()),
                observed_keys: Mutex::new(Vec::new()),
                failures_before_success: Mutex::new(failures),
            }
        }
    }

    impl ZfsProvider for MockProvider {
        type Error = LockchainError;

        fn encryption_root(&self, _dataset: &str) -> LockchainResult<String> {
            Ok(self.root.clone())
        }

        fn locked_descendants(&self, _root: &str) -> LockchainResult<Vec<String>> {
            let mut entries: Vec<String> = self.locked.lock().unwrap().iter().cloned().collect();
            entries.sort();
            Ok(entries)
        }

        fn load_key_tree(&self, _root: &str, key: &[u8]) -> LockchainResult<Vec<String>> {
            let mut failures = self.failures_before_success.lock().unwrap();
            if *failures > 0 {
                *failures -= 1;
                return Err(LockchainError::Provider("simulated failure".into()));
            }
            self.observed_keys.lock().unwrap().push(key.to_vec());
            let mut guard = self.locked.lock().unwrap();
            let mut unlocked: Vec<String> = guard.iter().cloned().collect();
            unlocked.sort();
            guard.clear();
            Ok(unlocked)
        }

        fn describe_datasets(&self, datasets: &[String]) -> LockchainResult<KeyStatusSnapshot> {
            let locked = self.locked.lock().unwrap();
            Ok(datasets
                .iter()
                .map(|ds| DatasetKeyDescriptor {
                    dataset: ds.clone(),
                    encryption_root: self.root.clone(),
                    state: if locked.contains(ds) {
                        KeyState::Unavailable
                    } else {
                        KeyState::Available
                    },
                })
                .collect())
        }
    }

    fn base_config(key_path: &Path) -> LockchainConfig {
        LockchainConfig {
            provider: crate::config::ProviderCfg::default(),
            policy: Policy {
                targets: vec!["tank/secure".to_string()],
                binary_path: None,
                allow_root: false,
                legacy_zfs_path: None,
                legacy_zpool_path: None,
            },
            zfs: crate::config::ZfsCfg::default(),
            crypto: CryptoCfg { timeout_secs: 5 },
            luks: crate::config::LuksCfg::default(),
            usb: Usb {
                key_hex_path: key_path.display().to_string(),
                expected_sha256: None,
                ..Usb::default()
            },
            fallback: Fallback {
                enabled: false,
                askpass: false,
                askpass_path: None,
                passphrase_salt: None,
                passphrase_xor: None,
                passphrase_iters: 1,
            },
            retry: RetryCfg::default(),
            path: key_path.to_path_buf(),
            format: ConfigFormat::Toml,
        }
    }

    #[test]
    fn unlock_uses_usb_key_material() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("key.raw");
        fs::write(
            &key_path,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .unwrap();

        let cfg = Arc::new(base_config(&key_path));
        let provider = MockProvider::new("tank/secure", &["tank/secure"]);
        let service = LockchainService::new(cfg, provider);

        let report = service
            .unlock("tank/secure", UnlockOptions::default())
            .unwrap();

        assert!(!report.already_unlocked);
        assert_eq!(report.unlocked.len(), 1);

        let metadata = fs::metadata(&key_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
        assert_eq!(fs::read(&key_path).unwrap().len(), 32);
    }

    #[test]
    fn unlock_bails_when_dataset_not_in_policy() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("key.raw");
        let cfg = Arc::new(base_config(&key_path));
        let provider = MockProvider::new("tank/secure", &["tank/secure"]);
        let service = LockchainService::new(cfg, provider);

        let err = service
            .unlock("tank/other", UnlockOptions::default())
            .unwrap_err();

        assert!(matches!(err, LockchainError::DatasetNotConfigured(_)));
    }

    #[test]
    fn status_reports_locked_descendants() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("key.raw");
        let cfg = Arc::new(base_config(&key_path));
        let provider = MockProvider::new("tank/secure", &["tank/secure", "tank/secure/home"]);
        let service = LockchainService::new(cfg, provider);

        let status = service.status("tank/secure").unwrap();
        assert!(status.root_locked);
        assert_eq!(
            status.locked_descendants,
            vec!["tank/secure/home".to_string()]
        );
    }

    #[test]
    fn list_keys_uses_provider_snapshot() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("key.raw");
        let cfg = Arc::new(base_config(&key_path));
        let provider = MockProvider::new("tank/secure", &["tank/secure"]);
        let service = LockchainService::new(cfg, provider);

        let snapshot = service.list_keys().unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].dataset, "tank/secure");
    }

    #[test]
    fn unlock_fails_on_checksum_mismatch() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("key.raw");
        fs::write(
            &key_path,
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let mut cfg = base_config(&key_path);
        cfg.usb.expected_sha256 = Some("ffffffff".to_string());
        let cfg = Arc::new(cfg);
        let provider = MockProvider::new("tank/secure", &["tank/secure"]);
        let service = LockchainService::new(cfg, provider);

        let err = service
            .unlock("tank/secure", UnlockOptions::default())
            .unwrap_err();

        assert!(matches!(err, LockchainError::InvalidConfig(_)));
    }

    #[test]
    fn unlock_fails_on_invalid_usb_key_material() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("key.raw");
        fs::write(&key_path, "00").unwrap();

        let cfg = Arc::new(base_config(&key_path));
        let provider = MockProvider::new("tank/secure", &["tank/secure"]);
        let service = LockchainService::new(cfg, provider);

        let err = service
            .unlock("tank/secure", UnlockOptions::default())
            .unwrap_err();

        assert!(matches!(err, LockchainError::InvalidHexKey { .. }));
    }

    #[test]
    fn unlock_with_retry_succeeds_after_transient_failures() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("key.raw");
        fs::write(
            &key_path,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .unwrap();

        let cfg = Arc::new(base_config(&key_path));
        let provider = MockProvider::with_failures("tank/secure", &["tank/secure"], 2);
        let service = LockchainService::new(cfg, provider);

        let report = service
            .unlock_with_retry("tank/secure", UnlockOptions::default())
            .unwrap();
        assert!(!report.already_unlocked);
    }

    #[test]
    fn unlock_with_retry_reports_exhaustion() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("key.raw");
        fs::write(
            &key_path,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .unwrap();

        let mut cfg = base_config(&key_path);
        cfg.retry.max_attempts = 2;
        cfg.retry.base_delay_ms = 1;
        cfg.retry.max_delay_ms = 2;
        let cfg = Arc::new(cfg);

        let provider = MockProvider::with_failures("tank/secure", &["tank/secure"], 5);
        let service = LockchainService::new(cfg, provider);

        let err = service
            .unlock_with_retry("tank/secure", UnlockOptions::default())
            .unwrap_err();

        match err {
            LockchainError::RetryExhausted { attempts, .. } => assert_eq!(attempts, 2),
            other => panic!("unexpected error {other:?}"),
        }
    }
}
