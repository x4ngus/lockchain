//! Fallback key derivation helpers.
//!
//! Expands an operator passphrase into the 32-byte unlock key using the configured PBKDF2 + XOR
//! mask. Used by break-glass recovery when USB key material is unavailable.

use crate::config::LockchainConfig;
use crate::error::{LockchainError, LockchainResult};
use hex::FromHex;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Derive the fallback key for `config` using the supplied `passphrase`.
///
/// # Errors
/// Returns `LockchainError::InvalidConfig` when fallback settings are missing or invalid.
pub fn derive_fallback_key(
    config: &LockchainConfig,
    passphrase: &[u8],
) -> LockchainResult<Zeroizing<Vec<u8>>> {
    let fallback = &config.fallback;
    let salt_hex = fallback
        .passphrase_salt
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| LockchainError::InvalidConfig("fallback.passphrase_salt missing".into()))?;
    let xor_hex = fallback
        .passphrase_xor
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| LockchainError::InvalidConfig("fallback.passphrase_xor missing".into()))?;

    let salt = Vec::from_hex(salt_hex).map_err(|_| {
        LockchainError::InvalidConfig("fallback.passphrase_salt is not valid hex".into())
    })?;
    let cipher = Vec::from_hex(xor_hex).map_err(|_| {
        LockchainError::InvalidConfig("fallback.passphrase_xor is not valid hex".into())
    })?;

    if cipher.len() != 32 {
        return Err(LockchainError::InvalidConfig(format!(
            "fallback.passphrase_xor length must be 32 bytes, got {}",
            cipher.len()
        )));
    }

    // OWASP recommends >= 600_000 for PBKDF2-HMAC-SHA256 (2023). Enforce a
    // hard floor of 100_000 to prevent misconfiguration from gutting the KDF.
    const MIN_PBKDF2_ITERS: u32 = 100_000;
    let iterations = fallback.passphrase_iters.max(MIN_PBKDF2_ITERS);
    let mut derived = Zeroizing::new(vec![0u8; cipher.len()]);
    pbkdf2_hmac::<Sha256>(passphrase, &salt, iterations, &mut derived);

    let raw: Vec<u8> = cipher
        .iter()
        .zip(derived.iter())
        .map(|(cipher_byte, derived_byte)| cipher_byte ^ derived_byte)
        .collect();

    Ok(Zeroizing::new(raw))
}
