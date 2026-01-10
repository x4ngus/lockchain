use lockchain_core::config::{
    ConfigFormat, CryptoCfg, Fallback, LockchainConfig, LuksCfg, Policy, ProviderCfg, RetryCfg,
    Usb, ZfsCfg,
};
use lockchain_core::error::{LockchainError, LockchainResult};
use lockchain_core::provider::LuksKeyProvider;
use lockchain_core::service::{LockchainService, UnlockOptions};
use lockchain_luks::SystemLuksProvider;
use lockchain_provider::luks::{LuksMappingDescriptor, LuksProvider, LuksState};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

#[test]
fn system_provider_status_reports_mapping_state() -> LockchainResult<()> {
    let tmp = tempdir()?;
    let cryptsetup = write_fake_cryptsetup(tmp.path().join("cryptsetup"), &[("vault", 0)])?;
    let crypttab = tmp.path().join("crypttab");
    fs::write(
        &crypttab,
        "vault UUID=1111-2222-3333-4444 none luks,noauto\n",
    )?;

    let config = sample_luks_config(
        vec!["vault".to_string()],
        cryptsetup,
        Some(crypttab),
        tmp.path().join("key.raw"),
    );
    let provider = SystemLuksProvider::from_config(&config)?;

    assert_eq!(provider.mapping_state("vault")?, LuksState::Active);
    assert!(provider.last_error().is_none());
    Ok(())
}

#[test]
fn mock_provider_harness_unlocks_mapping_via_service() -> LockchainResult<()> {
    let config = Arc::new(sample_luks_config(
        vec!["vault".to_string()],
        PathBuf::from("/bin/true"),
        None,
        PathBuf::from("/dev/null"),
    ));
    let mock = MockLuksProvider::new([("vault", LuksState::Inactive)]);
    let service = LockchainService::new(config.clone(), LuksKeyProvider::new(mock));

    let before = service.status("vault")?;
    assert!(before.root_locked);

    let report = service.unlock(
        "vault",
        UnlockOptions {
            key_override: Some(vec![0xAA; 32].into()),
            ..UnlockOptions::default()
        },
    )?;
    assert!(!report.already_unlocked);

    let after = service.status("vault")?;
    assert!(!after.root_locked);
    Ok(())
}

#[test]
fn system_provider_resolves_uuid_targets_via_crypttab() -> LockchainResult<()> {
    let tmp = tempdir()?;
    let cryptsetup = write_fake_cryptsetup(tmp.path().join("cryptsetup"), &[("vault", 0)])?;
    let crypttab = tmp.path().join("crypttab");
    fs::write(&crypttab, "vault UUID=1111-2222-3333-4444 none luks\n")?;

    let config = sample_luks_config(
        vec!["UUID=1111-2222-3333-4444".to_string()],
        cryptsetup,
        Some(crypttab),
        tmp.path().join("key.raw"),
    );
    let provider = SystemLuksProvider::from_config(&config)?;

    assert_eq!(
        provider.mapping_state("UUID=1111-2222-3333-4444")?,
        LuksState::Active
    );

    let mappings = provider.list_mappings()?;
    assert_eq!(
        mappings,
        vec![LuksMappingDescriptor {
            name: "vault".to_string(),
            source: "UUID=1111-2222-3333-4444".to_string(),
            state: LuksState::Active
        }]
    );
    Ok(())
}

#[test]
fn system_provider_key_staging_status_tracks_key_file() -> LockchainResult<()> {
    let tmp = tempdir()?;
    let cryptsetup = write_fake_cryptsetup(tmp.path().join("cryptsetup"), &[("vault", 4)])?;
    let key_path = tmp.path().join("key.raw");

    let config = sample_luks_config(
        vec!["vault".to_string()],
        cryptsetup,
        None,
        key_path.clone(),
    );
    let provider = SystemLuksProvider::from_config(&config)?;

    assert!(!provider.key_staged());

    fs::write(&key_path, vec![0xAA; 32])?;
    assert!(provider.key_staged());

    fs::write(&key_path, vec![0xAA; 31])?;
    assert!(!provider.key_staged());
    Ok(())
}

#[test]
fn system_provider_unlocks_mapping_via_service() -> LockchainResult<()> {
    let tmp = tempdir()?;
    let key_path = tmp.path().join("key.raw");
    fs::write(&key_path, vec![0xAA; 32])?;

    let state_path = tmp.path().join("state.txt");
    let cryptsetup = write_stateful_cryptsetup(
        tmp.path().join("cryptsetup"),
        &key_path,
        &state_path,
        None,
        None,
    )?;

    let crypttab = tmp.path().join("crypttab");
    fs::write(&crypttab, "vault /dev/fake none luks,noauto\n")?;

    let config = Arc::new(sample_luks_config(
        vec!["vault".to_string()],
        cryptsetup,
        Some(crypttab),
        key_path.clone(),
    ));

    let provider = SystemLuksProvider::from_config(&config)?;
    let service = LockchainService::new(config.clone(), LuksKeyProvider::new(provider.clone()));

    let before = service.status("vault")?;
    assert!(before.root_locked);

    let report = service.unlock_with_retry("vault", UnlockOptions::default())?;
    assert!(!report.already_unlocked);

    let after = service.status("vault")?;
    assert!(!after.root_locked);
    assert!(provider.last_error().is_none());
    Ok(())
}

#[test]
fn system_provider_unlock_failure_is_loud_and_actionable() -> LockchainResult<()> {
    let tmp = tempdir()?;
    let key_path = tmp.path().join("key.raw");
    fs::write(&key_path, vec![0xAA; 32])?;

    let state_path = tmp.path().join("state.txt");
    let cryptsetup = write_stateful_cryptsetup(
        tmp.path().join("cryptsetup"),
        &key_path,
        &state_path,
        None,
        None,
    )?;

    let crypttab = tmp.path().join("crypttab");
    fs::write(&crypttab, "vault /dev/fake none luks,noauto\n")?;

    let config = Arc::new(sample_luks_config(
        vec!["vault".to_string()],
        cryptsetup,
        Some(crypttab),
        key_path.clone(),
    ));

    let provider = SystemLuksProvider::from_config(&config)?;
    let service = LockchainService::new(config.clone(), LuksKeyProvider::new(provider.clone()));

    let err = service
        .unlock(
            "vault",
            UnlockOptions {
                key_override: Some(vec![0xBB; 32].into()),
                ..UnlockOptions::default()
            },
        )
        .expect_err("expected unlock to fail with wrong key");

    match err {
        LockchainError::Provider(message) => {
            assert!(message.contains("rejected") || message.contains("Verify"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    assert!(provider
        .last_error()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("unlock failed"));
    Ok(())
}

#[test]
fn system_provider_unlock_with_retry_recovers_from_transient_failure() -> LockchainResult<()> {
    let tmp = tempdir()?;
    let key_path = tmp.path().join("key.raw");
    fs::write(&key_path, vec![0xAA; 32])?;

    let state_path = tmp.path().join("state.txt");
    let fail_once = tmp.path().join("fail_once");
    fs::write(&fail_once, b"1")?;

    let cryptsetup = write_stateful_cryptsetup(
        tmp.path().join("cryptsetup"),
        &key_path,
        &state_path,
        Some(&fail_once),
        None,
    )?;

    let crypttab = tmp.path().join("crypttab");
    fs::write(&crypttab, "vault /dev/fake none luks,noauto\n")?;

    let mut config = sample_luks_config(
        vec!["vault".to_string()],
        cryptsetup,
        Some(crypttab),
        key_path.clone(),
    );
    config.retry.max_attempts = 2;
    config.retry.base_delay_ms = 1;
    config.retry.max_delay_ms = 5;
    config.retry.jitter_ratio = 0.0;

    let config = Arc::new(config);
    let provider = SystemLuksProvider::from_config(&config)?;
    let service = LockchainService::new(config.clone(), LuksKeyProvider::new(provider));

    let report = service.unlock_with_retry("vault", UnlockOptions::default())?;
    assert!(!report.already_unlocked);
    assert!(!fail_once.exists());
    Ok(())
}

#[test]
fn system_provider_enrolls_new_key_and_unlocks() -> LockchainResult<()> {
    let tmp = tempdir()?;
    let existing_key_path = tmp.path().join("existing.raw");
    fs::write(&existing_key_path, vec![0x11; 32])?;

    let key_bytes = vec![0xAA; 32];
    let new_key_path = tmp.path().join("key.raw");
    fs::write(&new_key_path, &key_bytes)?;

    let state_path = tmp.path().join("state.txt");
    let cryptsetup = write_stateful_cryptsetup(
        tmp.path().join("cryptsetup"),
        &existing_key_path,
        &state_path,
        None,
        Some("letmein"),
    )?;

    let crypttab = tmp.path().join("crypttab");
    fs::write(&crypttab, "vault /dev/fake none luks,noauto\n")?;

    let mut config = sample_luks_config(
        vec!["vault".to_string()],
        cryptsetup,
        Some(crypttab),
        new_key_path.clone(),
    );
    config.usb.expected_sha256 = Some(hex::encode(Sha256::digest(&key_bytes)));

    let provider = SystemLuksProvider::from_config(&config)?;
    provider.enroll_mapping_key("vault", b"letmein", &new_key_path)?;

    let config = Arc::new(config);
    let service = LockchainService::new(config.clone(), LuksKeyProvider::new(provider.clone()));

    let report = service.unlock_with_retry("vault", UnlockOptions::default())?;
    assert!(!report.already_unlocked);

    let status = service.status("vault")?;
    assert!(!status.root_locked);
    assert!(provider.last_error().is_none());
    Ok(())
}

#[test]
fn system_provider_enroll_rejects_wrong_passphrase() -> LockchainResult<()> {
    let tmp = tempdir()?;
    let existing_key_path = tmp.path().join("existing.raw");
    fs::write(&existing_key_path, vec![0x11; 32])?;

    let new_key_path = tmp.path().join("key.raw");
    fs::write(&new_key_path, vec![0xAA; 32])?;

    let state_path = tmp.path().join("state.txt");
    let cryptsetup = write_stateful_cryptsetup(
        tmp.path().join("cryptsetup"),
        &existing_key_path,
        &state_path,
        None,
        Some("letmein"),
    )?;

    let crypttab = tmp.path().join("crypttab");
    fs::write(&crypttab, "vault /dev/fake none luks,noauto\n")?;

    let config = sample_luks_config(
        vec!["vault".to_string()],
        cryptsetup,
        Some(crypttab),
        new_key_path.clone(),
    );
    let provider = SystemLuksProvider::from_config(&config)?;

    let err = provider
        .enroll_mapping_key("vault", b"wrong-pass", &new_key_path)
        .expect_err("expected enrollment to fail with wrong passphrase");

    match err {
        LockchainError::Provider(message) => {
            assert!(message.to_ascii_lowercase().contains("passphrase"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    assert!(provider
        .last_error()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("passphrase"));
    Ok(())
}

#[test]
fn system_provider_unlock_blocks_on_checksum_mismatch() -> LockchainResult<()> {
    let tmp = tempdir()?;
    let key_path = tmp.path().join("key.raw");
    fs::write(&key_path, vec![0xAA; 32])?;

    let state_path = tmp.path().join("state.txt");
    let cryptsetup = write_stateful_cryptsetup(
        tmp.path().join("cryptsetup"),
        &key_path,
        &state_path,
        None,
        None,
    )?;

    let crypttab = tmp.path().join("crypttab");
    fs::write(&crypttab, "vault /dev/fake none luks,noauto\n")?;

    let mut config = sample_luks_config(
        vec!["vault".to_string()],
        cryptsetup,
        Some(crypttab),
        key_path.clone(),
    );
    config.usb.expected_sha256 = Some("ffffffff".to_string());

    let config = Arc::new(config);
    let provider = SystemLuksProvider::from_config(&config)?;
    let service = LockchainService::new(config.clone(), LuksKeyProvider::new(provider.clone()));

    let err = service
        .unlock("vault", UnlockOptions::default())
        .expect_err("expected checksum mismatch to fail unlock");

    assert!(matches!(err, LockchainError::InvalidConfig(_)));
    assert!(service.status("vault")?.root_locked);
    assert!(provider.last_error().is_none());
    Ok(())
}

#[derive(Clone)]
struct MockLuksProvider {
    state: Arc<Mutex<HashMap<String, LuksState>>>,
}

impl MockLuksProvider {
    fn new<const N: usize>(entries: [(&str, LuksState); N]) -> Self {
        let mut state = HashMap::new();
        for (name, mapping_state) in entries {
            state.insert(name.to_string(), mapping_state);
        }
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }
}

impl LuksProvider for MockLuksProvider {
    type Error = LockchainError;

    fn list_mappings(&self) -> LockchainResult<Vec<LuksMappingDescriptor>> {
        let state = self.state.lock().unwrap();
        let mut mappings: Vec<LuksMappingDescriptor> = state
            .iter()
            .map(|(name, mapping_state)| LuksMappingDescriptor {
                name: name.clone(),
                source: "UUID=MOCK".to_string(),
                state: mapping_state.clone(),
            })
            .collect();
        mappings.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(mappings)
    }

    fn unlock_mapping(&self, name: &str, _key: &[u8]) -> LockchainResult<()> {
        let mut state = self.state.lock().unwrap();
        let entry = state.get_mut(name).ok_or_else(|| {
            LockchainError::InvalidConfig(format!("mock mapping not declared: {name}"))
        })?;
        *entry = LuksState::Active;
        Ok(())
    }

    fn enroll_mapping_key(
        &self,
        _target: &str,
        _existing_passphrase: &[u8],
        _keyfile: &Path,
    ) -> LockchainResult<()> {
        Ok(())
    }

    fn mapping_state(&self, name: &str) -> LockchainResult<LuksState> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_else(|| LuksState::Unknown("mock mapping not declared".into())))
    }
}

fn write_fake_cryptsetup(path: PathBuf, statuses: &[(&str, i32)]) -> LockchainResult<PathBuf> {
    let mut script = String::from("#!/bin/sh\n");
    script.push_str("if [ \"$1\" = \"status\" ]; then\n");
    script.push_str("  case \"$2\" in\n");
    for (name, code) in statuses {
        let line = format!("    {name}) echo \"/dev/mapper/{name} status\"; exit {code} ;;\n");
        script.push_str(&line);
    }
    script.push_str("    *) echo \"/dev/mapper/$2 inactive\"; exit 4 ;;\n");
    script.push_str("  esac\n");
    script.push_str("fi\n");
    script.push_str("echo \"unsupported\" 1>&2\n");
    script.push_str("exit 1\n");

    fs::write(&path, script)?;
    let mut perms = fs::metadata(&path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms)?;
    Ok(path)
}

fn write_stateful_cryptsetup(
    path: PathBuf,
    expected_key_path: &Path,
    state_path: &Path,
    fail_once: Option<&Path>,
    enroll_passphrase: Option<&str>,
) -> LockchainResult<PathBuf> {
    let expected_key = expected_key_path.display();
    let state = state_path.display();
    let fail_once = fail_once
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let enroll_passphrase = enroll_passphrase.unwrap_or_default();
    let keyring_dir = format!("{state}.keys");

    let script = format!(
        r#"#!/bin/sh
STATE_PATH="{state}"
EXPECTED_KEY="{expected_key}"
FAIL_ONCE="{fail_once}"
ENROLL_PASSPHRASE="{enroll_passphrase}"
KEYRING_DIR="{keyring_dir}"

cmd="$1"
shift

mkdir -p "$KEYRING_DIR" 2>/dev/null || true
if [ ! -f "$KEYRING_DIR/slot0" ] && [ -f "$EXPECTED_KEY" ]; then
  cp "$EXPECTED_KEY" "$KEYRING_DIR/slot0" 2>/dev/null || true
fi

case "$cmd" in
  status)
    name="$1"
    if [ -f "$STATE_PATH" ] && grep -q "^$name=active$" "$STATE_PATH"; then
      echo "/dev/mapper/$name is active"
      exit 0
    fi
    echo "/dev/mapper/$name is inactive"
    exit 4
    ;;
  open|luksOpen)
    KEYFILE=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --key-file)
          KEYFILE="$2"
          shift 2
          ;;
        --key-file=*)
          KEYFILE="${{1#--key-file=}}"
          shift
          ;;
        --batch-mode)
          shift
          ;;
        --type)
          shift 2
          ;;
        *)
          break
          ;;
      esac
    done

    SOURCE="$1"
    NAME="$2"
    if [ -z "$NAME" ]; then
      echo "missing mapping name" 1>&2
      exit 1
    fi

    if [ -n "$FAIL_ONCE" ] && [ -f "$FAIL_ONCE" ]; then
      rm -f "$FAIL_ONCE"
      echo "Device or resource busy" 1>&2
      exit 5
    fi

    KEY_TO_CHECK=""
    if [ "$KEYFILE" = "-" ]; then
      TMP="$(mktemp)"
      cat > "$TMP"
      KEY_TO_CHECK="$TMP"
    else
      KEY_TO_CHECK="$KEYFILE"
    fi

    MATCH=0
    for SLOT in "$KEYRING_DIR"/slot*; do
      if [ -f "$SLOT" ] && cmp -s "$KEY_TO_CHECK" "$SLOT"; then
        MATCH=1
        break
      fi
    done

    if [ "$KEYFILE" = "-" ]; then
      rm -f "$KEY_TO_CHECK"
    fi

    if [ "$MATCH" -ne 1 ]; then
      echo "No key available with this passphrase." 1>&2
      exit 2
    fi

    if [ -f "$STATE_PATH" ]; then
      grep -v "^$NAME=" "$STATE_PATH" > "$STATE_PATH.tmp" 2>/dev/null || true
      mv "$STATE_PATH.tmp" "$STATE_PATH"
    fi
    echo "$NAME=active" >> "$STATE_PATH"

    echo "unlocked"
    exit 0
    ;;
  close|luksClose)
    NAME="$1"
    if [ -f "$STATE_PATH" ]; then
      grep -v "^$NAME=" "$STATE_PATH" > "$STATE_PATH.tmp" 2>/dev/null || true
      mv "$STATE_PATH.tmp" "$STATE_PATH"
    fi
    exit 0
    ;;
  luksAddKey)
    KEYFILE=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --key-file)
          KEYFILE="$2"
          shift 2
          ;;
        --key-file=*)
          KEYFILE="${{1#--key-file=}}"
          shift
          ;;
        --batch-mode)
          shift
          ;;
        *)
          break
          ;;
      esac
    done

    SOURCE="$1"
    NEW_KEY="$2"
    if [ -z "$SOURCE" ] || [ -z "$NEW_KEY" ]; then
      echo "missing source or keyfile" 1>&2
      exit 1
    fi

    PASSPHRASE="$(cat)"
    PASSPHRASE="$(printf "%s" "$PASSPHRASE" | tr -d '\n')"
    if [ -n "$ENROLL_PASSPHRASE" ] && [ "$PASSPHRASE" != "$ENROLL_PASSPHRASE" ]; then
      echo "No key available with this passphrase." 1>&2
      exit 2
    fi

    IDX=0
    for SLOT in "$KEYRING_DIR"/slot*; do
      if [ -f "$SLOT" ]; then
        IDX=$((IDX+1))
      fi
    done

    cp "$NEW_KEY" "$KEYRING_DIR/slot$IDX" 2>/dev/null || true
    echo "Key slot added"
    exit 0
    ;;
  *)
    echo "unsupported" 1>&2
    exit 1
    ;;
esac
"#
    );

    fs::write(&path, script)?;
    let mut perms = fs::metadata(&path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms)?;
    Ok(path)
}

fn sample_luks_config(
    targets: Vec<String>,
    cryptsetup_path: PathBuf,
    crypttab_path: Option<PathBuf>,
    key_hex_path: PathBuf,
) -> LockchainConfig {
    LockchainConfig {
        provider: ProviderCfg::default(),
        policy: Policy {
            targets,
            binary_path: None,
            allow_root: false,
            legacy_zfs_path: None,
            legacy_zpool_path: None,
        },
        zfs: ZfsCfg::default(),
        crypto: CryptoCfg { timeout_secs: 5 },
        luks: LuksCfg {
            cryptsetup_path: Some(cryptsetup_path.to_string_lossy().into_owned()),
            crypttab_path: crypttab_path.map(|p| p.to_string_lossy().into_owned()),
        },
        usb: Usb {
            key_hex_path: key_hex_path.to_string_lossy().into_owned(),
            ..Usb::default()
        },
        fallback: Fallback::default(),
        retry: RetryCfg::default(),
        path: PathBuf::from("/etc/lockchain.toml"),
        format: ConfigFormat::Toml,
    }
}
