// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Encryption utilities for sensitive session data.
//!
//! This module provides AES-256-GCM encryption and decryption for protecting
//! sensitive fields in session storage (PKCE code_verifier, full session
//! payloads). A Master Encryption Key (MEK) is retrieved from the Cloudflare
//! Secrets Store and cached for the lifetime of the worker invocation.
//!
//! # Security Properties
//!
//! AES-256-GCM provides authenticated encryption (AEAD), meaning ciphertext
//! is both confidential and integrity-protected. Each encryption generates a
//! fresh 12-byte IV from the platform CSPRNG (`getrandom` with the "js"
//! feature, backed by `crypto.getRandomValues` in Workers). IV reuse would
//! break GCM's security guarantees, so every call to [`encrypt_with_mek`]
//! draws new randomness. Associated Authenticated Data (AAD) binds each
//! ciphertext to its storage context, preventing cross-field replay.
//!
//! All key material is wrapped in [`Zeroizing`] so it is scrubbed on drop.
//! Decrypted plaintext is likewise returned as `Zeroizing<String>`.
//! The underlying AES-GCM implementation uses constant-time tag comparison.
//!
//! # Wire Format
//!
//! Encrypted output: `IV (12 bytes) || Ciphertext (variable) || Auth Tag (16 bytes)`,
//! base64url-encoded (no padding) for KV storage compatibility.
//!
//! # Key Rotation
//!
//! [`decrypt_code_verifier`] tries the primary MEK first. If decryption
//! fails it falls back to `HOSTED_MEK_PREVIOUS`, allowing zero-downtime
//! rotation. Encryption always uses the primary key.
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::sync::OnceLock;
use worker::Env;
use zeroize::Zeroizing;

/// Process-wide cache for the hosted MEK. Workers are single-threaded, so
/// a `OnceLock` is sufficient. The key is fetched once from the Secrets Store
/// on first use and reused for the remainder of the isolate lifetime.
static HOSTED_MEK_CACHE: OnceLock<Zeroizing<Vec<u8>>> = OnceLock::new();

/// SC-009: Process-wide cache for `HOSTED_MEK_PREVIOUS` (key rotation fallback).
/// Same lifecycle as `HOSTED_MEK_CACHE`. Fetched lazily on first secondary-key
/// decryption attempt and reused for the remainder of the isolate lifetime.
static HOSTED_MEK_PREVIOUS_CACHE: OnceLock<Zeroizing<Vec<u8>>> = OnceLock::new();

/// Returns whether the hosted MEK has been loaded into the process-wide cache.
///
/// Used by the health check subsystem to report MEK readiness. A `false` result
/// is not a failure; it indicates a cold start where the MEK will be fetched on
/// the first request that requires encryption.
pub fn mek_cache_populated() -> bool {
    HOSTED_MEK_CACHE.get().is_some()
}

/// Outcome of the startup hosted-MEK pre-load. Carries the public-safe 6-char
/// fingerprints of each slot so the caller can populate `AppState` without a
/// second Secrets Store read. The fingerprints are derived from the raw
/// base64url secret string (not the decoded key bytes) to keep the value
/// identical to the previous startup behaviour and to the `x-secret-version`
/// header the hosted handlers emit.
pub struct HostedMekPreload {
    /// 6-char fingerprint of `HOSTED_MEK`, or the unset sentinel when absent.
    pub primary_fingerprint: String,
    /// 6-char fingerprint of `HOSTED_MEK_PREVIOUS`, or the unset sentinel.
    pub previous_fingerprint: String,
    /// Whether the primary `HOSTED_MEK` was successfully decoded and cached.
    pub primary_loaded: bool,
}

/// Decode a base64url MEK string into a validated 32-byte key, populating the
/// supplied process-wide cache. Returns the fingerprint of the raw base64
/// string regardless of decode outcome (the fingerprint identifies the slot
/// value; a decode failure means the cache stays empty but the fingerprint
/// still describes what is configured).
///
/// Returns `(fingerprint, cached)` where `cached` is true only when the value
/// decoded to a valid 32-byte key and was offered to the cache.
// `binding` is only read by the wasm32-gated audit logs below.
#[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
fn decode_and_cache(
    raw_b64: &str,
    cache: &OnceLock<Zeroizing<Vec<u8>>>,
    binding: &str,
) -> (String, bool) {
    let fingerprint = crate::security::secret_fingerprint::fingerprint6_str(Some(raw_b64));

    let decoded = match URL_SAFE_NO_PAD.decode(raw_b64.as_bytes()) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "{{\"audit\":true,\"event\":\"hosted_mek_preload\",\"secret\":\"{}\",\"outcome\":\"decode_failure\",\"severity\":\"error\"}}",
                binding
            );
            return (fingerprint, false);
        }
    };

    if decoded.len() != 32 {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "{{\"audit\":true,\"event\":\"hosted_mek_preload\",\"secret\":\"{}\",\"outcome\":\"invalid_length\",\"severity\":\"error\",\"bytes\":{}}}",
            binding,
            decoded.len()
        );
        return (fingerprint, false);
    }

    // OnceLock::set races are benign: concurrent callers all hold a valid value.
    let _ = cache.set(decoded);
    (fingerprint, true)
}

/// M1: Pre-load `HOSTED_MEK` (and `HOSTED_MEK_PREVIOUS`) into the process-wide
/// caches during the worker startup sequence.
///
/// Without this, the hosted MEK is fetched lazily on the first hosted-flow
/// request, so a cold isolate pays the Secrets Store latency on that request
/// and a transient Secrets Store failure surfaces as a first-request error.
/// Pre-loading at startup means hosted handlers read the key from cache and a
/// configuration problem is visible in cold-start logs immediately.
///
/// This is best-effort and never fails startup: a missing `HOSTED_MEK` is
/// logged at warning severity (`primary_loaded == false`) so the hosted
/// handlers still return a fast 503 on first use, but the verifier's
/// non-hosted endpoints (the bulk of traffic) remain available. Both slots are
/// fetched concurrently. Each fetch is bounded-retry on transient failure.
pub async fn preload_hosted_mek(env: &Env) -> HostedMekPreload {
    let unset = crate::security::secret_fingerprint::FINGERPRINT_UNSET.to_string();

    let primary_fut = async {
        let binding = "HOSTED_MEK";
        match env.secret_store(binding) {
            Ok(store) => match crate::utils::retry::get_with_retry(&store, binding).await {
                Ok(Some(s)) if !s.is_empty() => {
                    let raw = Zeroizing::new(s);
                    Some(decode_and_cache(&raw, &HOSTED_MEK_CACHE, binding))
                }
                Ok(_) => None,
                Err(_e) => {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "{{\"audit\":true,\"event\":\"hosted_mek_preload\",\"secret\":\"HOSTED_MEK\",\"outcome\":\"fetch_error\",\"severity\":\"error\"}}"
                    );
                    None
                }
            },
            Err(_e) => None,
        }
    };

    let previous_fut = async {
        let binding = "HOSTED_MEK_PREVIOUS";
        match env.secret_store(binding) {
            Ok(store) => match crate::utils::retry::get_with_retry(&store, binding).await {
                Ok(Some(s)) if !s.is_empty() => {
                    let raw = Zeroizing::new(s);
                    Some(decode_and_cache(&raw, &HOSTED_MEK_PREVIOUS_CACHE, binding))
                }
                _ => None,
            },
            Err(_e) => None,
        }
    };

    let (primary, previous) = futures::join!(primary_fut, previous_fut);

    let (primary_fingerprint, primary_loaded) = primary.unwrap_or((unset.clone(), false));
    let (previous_fingerprint, _previous_loaded) = previous.unwrap_or((unset.clone(), false));

    if primary_loaded {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "{{\"audit\":true,\"event\":\"hosted_mek_preload\",\"secret\":\"HOSTED_MEK\",\"outcome\":\"success\"}}"
        );
    } else {
        // Warn-not-fail: hosted-flow endpoints will return a fast 503 on first
        // use; non-hosted endpoints remain available.
        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "{{\"audit\":true,\"event\":\"hosted_mek_preload\",\"secret\":\"HOSTED_MEK\",\"outcome\":\"unavailable\",\"severity\":\"warning\",\"message\":\"HOSTED_MEK not pre-loaded at startup. Hosted-flow endpoints will return 503 until the secret is provisioned.\"}}"
        );
    }

    HostedMekPreload {
        primary_fingerprint,
        previous_fingerprint,
        primary_loaded,
    }
}

/// Errors returned by encryption and decryption operations in this module.
#[derive(Debug)]
pub enum EncryptionError {
    /// Invalid key format or length
    InvalidKey(String),
    /// Encryption operation failed
    EncryptionFailed(String),
    /// Decryption operation failed
    DecryptionFailed(String),
    /// Failed to retrieve MEK from secrets store
    SecretsStoreFailed(String),
    /// Invalid encrypted data format
    InvalidFormat(String),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionError::InvalidKey(msg) => write!(f, "Invalid encryption key: {}", msg),
            EncryptionError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            EncryptionError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            EncryptionError::SecretsStoreFailed(msg) => write!(f, "Secrets store error: {}", msg),
            EncryptionError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
        }
    }
}

impl std::error::Error for EncryptionError {}

// SECURITY: AAD binds ciphertext to the code_verifier context so that an encrypted
// value from one field cannot be spliced into another. Changing this string
// invalidates all existing encrypted code_verifiers.
const CODE_VERIFIER_AAD: &[u8] = b"provii-verifier:code_verifier:v1";

/// Retrieve the hosted Master Encryption Key from Cloudflare Secrets Store.
///
/// The decoded key is cached in a process-wide `OnceLock` so the Secrets Store
/// is only hit once per worker invocation. Subsequent calls return the cached
/// copy. The key is stored as base64url (no padding) in the `HOSTED_MEK`
/// binding and must decode to exactly 32 bytes.
///
/// # Errors
///
/// Returns [`EncryptionError::SecretsStoreFailed`] if the binding is missing,
/// the secret is absent, or the value is not valid 32-byte base64url.
pub async fn get_mek_from_secrets(env: &Env) -> Result<Zeroizing<Vec<u8>>, EncryptionError> {
    if let Some(mek) = HOSTED_MEK_CACHE.get() {
        return Ok(mek.clone());
    }

    #[cfg(target_arch = "wasm32")]
    worker::console_log!("[PERF] First-time fetch of HOSTED_MEK from Secrets Store");
    let store = env.secret_store("HOSTED_MEK").map_err(|e| {
        EncryptionError::SecretsStoreFailed(format!("HOSTED_MEK binding not configured: {:?}", e))
    })?;

    // H1/M1: Retry the Secrets Store fetch on transient failure so a single
    // dropped read does not surface as a hard error on the first hosted-flow
    // request (or block the startup pre-load).
    let mek_b64 = Zeroizing::new(
        crate::utils::retry::get_with_retry(&store, "HOSTED_MEK")
            .await
            .map_err(|e| {
                EncryptionError::SecretsStoreFailed(format!(
                    "Failed to get HOSTED_MEK from Secrets Store: {:?}",
                    e
                ))
            })?
            .ok_or_else(|| {
                EncryptionError::SecretsStoreFailed(
                    "HOSTED_MEK secret not found in Secrets Store".to_string(),
                )
            })?,
    );

    let mek = Zeroizing::new(URL_SAFE_NO_PAD.decode(mek_b64.as_bytes()).map_err(|e| {
        EncryptionError::SecretsStoreFailed(format!("Invalid MEK encoding: {}", e))
    })?);

    if mek.len() != 32 {
        return Err(EncryptionError::SecretsStoreFailed(format!(
            "MEK must be 32 bytes, got {}",
            mek.len()
        )));
    }

    // OnceLock::set races are benign; concurrent callers all hold a valid value.
    let _ = HOSTED_MEK_CACHE.set(mek.clone());

    Ok(mek)
}

/// Encrypt plaintext using AES-256-GCM with the Master Encryption Key.
///
/// # Arguments
///
/// * `mek` - 32-byte Master Encryption Key
/// * `plaintext` - Data to encrypt (typically PKCE code_verifier)
/// * `aad` - Associated Authenticated Data for context binding
///
/// # Returns
///
/// Base64url-encoded string containing: IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)
///
/// # Security
///
/// - Uses cryptographically random 12-byte IV per encryption
/// - IV is never reused (ensures semantic security)
/// - AAD binds ciphertext to specific context
/// - GCM provides authenticated encryption (confidentiality + integrity)
///
/// # Errors
///
/// Returns [`EncryptionError::InvalidKey`] if `mek` is not exactly 32 bytes,
/// or [`EncryptionError::EncryptionFailed`] if the AES-GCM encrypt call or
/// IV generation fails.
pub fn encrypt_with_mek(
    mek: &[u8],
    plaintext: &str,
    aad: &[u8],
) -> Result<String, EncryptionError> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };

    // SECURITY: Reject anything other than a 256-bit key before touching the cipher.
    if mek.len() != 32 {
        return Err(EncryptionError::InvalidKey(format!(
            "MEK must be 32 bytes, got {}",
            mek.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(mek)
        .map_err(|e| EncryptionError::InvalidKey(format!("Failed to create cipher: {}", e)))?;

    // SECURITY: Fresh 12-byte IV per encryption via platform CSPRNG. GCM security
    // collapses on IV reuse under the same key, so this MUST NOT be deterministic.
    // ADV-VA-02-003: Use getrandom directly instead of rand::thread_rng() which
    // is not guaranteed to be cryptographically secure on all platforms (WASM).
    let mut iv_bytes = [0u8; 12];
    getrandom::getrandom(&mut iv_bytes).map_err(|e| {
        EncryptionError::EncryptionFailed(format!("CSPRNG IV generation failed: {}", e))
    })?;
    let nonce = Nonce::from_slice(&iv_bytes);

    let payload = Payload {
        msg: plaintext.as_bytes(),
        aad,
    };

    let ciphertext = cipher.encrypt(nonce, payload).map_err(|e| {
        EncryptionError::EncryptionFailed(format!("AES-GCM encryption failed: {}", e))
    })?;

    let mut result = iv_bytes.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(URL_SAFE_NO_PAD.encode(&result))
}

/// Decrypt ciphertext using AES-256-GCM with the Master Encryption Key.
///
/// # Arguments
///
/// * `mek` - 32-byte Master Encryption Key
/// * `encrypted_b64` - Base64url-encoded ciphertext (IV || Ciphertext || Tag)
/// * `aad` - Associated Authenticated Data (must match encryption AAD)
///
/// # Returns
///
/// Decrypted plaintext as UTF-8 string, wrapped in `Zeroizing` for automatic zeroization on drop
///
/// # Security
///
/// - Verifies authentication tag before returning plaintext
/// - AAD must match encryption context
/// - Constant-time comparison prevents timing attacks
/// - Returned `Zeroizing<String>` ensures plaintext is zeroized when dropped
///
/// # Errors
///
/// Returns error if:
/// - MEK is not 32 bytes
/// - Base64url decoding fails
/// - Encrypted data is too short (< 28 bytes for IV + tag)
/// - Authentication verification fails
/// - Decryption operation fails
/// - Result is not valid UTF-8
pub fn decrypt_with_mek(
    mek: &[u8],
    encrypted_b64: &str,
    aad: &[u8],
) -> Result<Zeroizing<String>, EncryptionError> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };

    // SECURITY: Reject anything other than a 256-bit key before touching the cipher.
    if mek.len() != 32 {
        return Err(EncryptionError::InvalidKey(format!(
            "MEK must be 32 bytes, got {}",
            mek.len()
        )));
    }

    let encrypted_data = URL_SAFE_NO_PAD
        .decode(encrypted_b64.as_bytes())
        .map_err(|e| {
            EncryptionError::InvalidFormat(format!("Invalid base64url encoding: {}", e))
        })?;

    // SECURITY: Minimum 28 bytes = 12-byte IV + 16-byte GCM auth tag (zero plaintext).
    // Anything shorter is structurally invalid and must be rejected before parsing.
    if encrypted_data.len() < 28 {
        return Err(EncryptionError::InvalidFormat(format!(
            "Encrypted data too short: {} bytes (minimum 28)",
            encrypted_data.len()
        )));
    }

    let (iv_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(iv_bytes);

    let cipher = Aes256Gcm::new_from_slice(mek)
        .map_err(|e| EncryptionError::InvalidKey(format!("Failed to create cipher: {}", e)))?;

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    // SECURITY: Zeroizing wraps both the raw bytes and the final String so
    // decrypted plaintext does not linger in memory after the caller drops it.
    let mut plaintext_bytes = Zeroizing::new(cipher.decrypt(nonce, payload).map_err(|e| {
        EncryptionError::DecryptionFailed(format!("AES-GCM decryption failed: {}", e))
    })?);

    // SECURITY: Move the bytes out of Zeroizing rather than .to_vec() which
    // would create a second un-zeroized copy. std::mem::take replaces the inner
    // Vec with an empty one (which Zeroizing then zeroizes on drop, a no-op).
    let raw_bytes = std::mem::take(&mut *plaintext_bytes);

    String::from_utf8(raw_bytes)
        .map(Zeroizing::new)
        .map_err(|e| {
            // SECURITY: FromUtf8Error owns the bytes that failed UTF-8 validation.
            // Extract and zeroize them before returning the error to prevent
            // decrypted plaintext lingering in the dropped error value.
            let mut leaked_bytes = e.into_bytes();
            zeroize::Zeroize::zeroize(&mut leaked_bytes);
            EncryptionError::DecryptionFailed("Invalid UTF-8 in decrypted data".to_string())
        })
}

/// SC-009: Retrieve the secondary MEK from the process-wide cache or Secrets Store.
///
/// Like [`get_mek_from_secrets`], the decoded key is cached in a `OnceLock` so
/// only the first call per isolate hits the Secrets Store.
///
/// Returns `None` if `HOSTED_MEK_PREVIOUS` is not configured, not found, or
/// fails to decode to a valid 32-byte key.
pub(crate) async fn get_mek_secondary_from_secrets(env: &Env) -> Option<Zeroizing<Vec<u8>>> {
    if let Some(mek) = HOSTED_MEK_PREVIOUS_CACHE.get() {
        return Some(mek.clone());
    }

    let store = env.secret_store("HOSTED_MEK_PREVIOUS").ok()?;
    // H1/M1: Retry the fetch on transient failure (same rationale as the
    // primary key). An absent previous key is normal outside a rotation window.
    let mek_b64 = Zeroizing::new(
        crate::utils::retry::get_with_retry(&store, "HOSTED_MEK_PREVIOUS")
            .await
            .ok()??,
    );
    let mek = Zeroizing::new(URL_SAFE_NO_PAD.decode(mek_b64.as_bytes()).ok()?);

    if mek.len() != 32 {
        return None;
    }

    // OnceLock::set races are benign.
    let _ = HOSTED_MEK_PREVIOUS_CACHE.set(mek.clone());

    Some(mek)
}

/// Decrypt a PKCE code_verifier from storage.
///
/// Retrieves the primary MEK and attempts decryption. On failure, falls back
/// to `HOSTED_MEK_PREVIOUS` for key rotation support.
///
/// # Returns
///
/// Decrypted PKCE code_verifier, wrapped in `Zeroizing` for automatic
/// zeroization on drop.
///
/// # Errors
///
/// Returns [`EncryptionError::SecretsStoreFailed`] if the primary MEK cannot
/// be retrieved, or [`EncryptionError::DecryptionFailed`] if both primary and
/// secondary keys fail to decrypt.
pub async fn decrypt_code_verifier(
    env: &Env,
    encrypted_b64: &str,
) -> Result<Zeroizing<String>, EncryptionError> {
    decrypt_code_verifier_tracked(env, encrypted_b64, None).await
}

/// Variant of [`decrypt_code_verifier`] that records which HOSTED_MEK slot
/// satisfied the decrypt path via `slot_out`. The outparam is left untouched
/// on error and on the no-fallback path; on success it carries
/// [`crate::security::secret_versions::RotationSlot::Current`] when
/// `HOSTED_MEK` satisfied or `Previous` when `HOSTED_MEK_PREVIOUS` satisfied.
pub async fn decrypt_code_verifier_tracked(
    env: &Env,
    encrypted_b64: &str,
    slot_out: Option<&mut Option<crate::security::secret_versions::RotationSlot>>,
) -> Result<Zeroizing<String>, EncryptionError> {
    use crate::security::secret_versions::RotationSlot;
    let mek = get_mek_from_secrets(env).await?;

    match decrypt_with_mek(&mek, encrypted_b64, CODE_VERIFIER_AAD) {
        Ok(plaintext) => {
            if let Some(out) = slot_out {
                *out = Some(RotationSlot::Current);
            }
            Ok(plaintext)
        }
        Err(_primary_error) => {
            // SECURITY: Key rotation fallback. If primary MEK decryption fails, attempt
            // the rotated-out secondary key so sessions encrypted before rotation remain
            // readable. Both keys are Zeroizing-wrapped and discarded after use.
            // SC-009: Secondary MEK is now cached at process level via OnceLock.

            // AL-098: Structured audit for secondary MEK fallback.
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "{{\"audit\":true,\"event\":\"mek_fallback_to_secondary\",\"severity\":\"warning\",\"message\":\"Primary MEK decryption failed, attempting secondary MEK\"}}"
            );

            let secondary_mek = get_mek_secondary_from_secrets(env).await.ok_or_else(|| {
                EncryptionError::DecryptionFailed(
                    "Primary decryption failed and no secondary MEK available".to_string(),
                )
            })?;

            let plaintext = decrypt_with_mek(&secondary_mek, encrypted_b64, CODE_VERIFIER_AAD)
                .map_err(|_| {
                    EncryptionError::DecryptionFailed(
                        "Both primary and secondary MEK decryption failed".to_string(),
                    )
                })?;
            if let Some(out) = slot_out {
                *out = Some(RotationSlot::Previous);
            }
            Ok(plaintext)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32]; // Test MEK
        let plaintext = "test_code_verifier_12345";
        let aad = CODE_VERIFIER_AAD;

        let encrypted = encrypt_with_mek(&mek, plaintext, aad)?;
        assert!(!encrypted.is_empty());
        assert_ne!(encrypted, plaintext); // Should be different

        let decrypted = decrypt_with_mek(&mek, &encrypted, aad)?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_different_iv_per_encryption() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "same_plaintext";
        let aad = CODE_VERIFIER_AAD;

        let encrypted1 = encrypt_with_mek(&mek, plaintext, aad)?;
        let encrypted2 = encrypt_with_mek(&mek, plaintext, aad)?;

        // Different IVs should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);

        // Both should decrypt to same plaintext
        let decrypted1 = decrypt_with_mek(&mek, &encrypted1, aad)?;
        let decrypted2 = decrypt_with_mek(&mek, &encrypted2, aad)?;
        assert_eq!(&*decrypted1, plaintext);
        assert_eq!(&*decrypted2, plaintext);
        Ok(())
    }

    #[test]
    fn test_wrong_key_fails() -> Result<(), Box<dyn std::error::Error>> {
        let mek1 = vec![0x42u8; 32];
        let mek2 = vec![0x43u8; 32];
        let plaintext = "secret_data";
        let aad = CODE_VERIFIER_AAD;

        let encrypted = encrypt_with_mek(&mek1, plaintext, aad)?;
        let result = decrypt_with_mek(&mek2, &encrypted, aad);

        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
        Ok(())
    }

    #[test]
    fn test_wrong_aad_fails() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "secret_data";
        let aad1 = b"context1";
        let aad2 = b"context2";

        let encrypted = encrypt_with_mek(&mek, plaintext, aad1)?;
        let result = decrypt_with_mek(&mek, &encrypted, aad2);

        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
        Ok(())
    }

    #[test]
    fn test_corrupted_ciphertext_fails() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "secret_data";
        let aad = CODE_VERIFIER_AAD;

        let encrypted = encrypt_with_mek(&mek, plaintext, aad)?;

        // Corrupt the encrypted data
        let mut corrupted_bytes = URL_SAFE_NO_PAD.decode(encrypted.as_bytes())?;
        if let Some(byte) = corrupted_bytes.get_mut(12) {
            *byte ^= 0xFF; // Flip bits in ciphertext
        }
        let corrupted = URL_SAFE_NO_PAD.encode(&corrupted_bytes);

        let result = decrypt_with_mek(&mek, &corrupted, aad);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
        Ok(())
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = vec![0x42u8; 16]; // Only 128 bits
        let plaintext = "test";
        let aad = CODE_VERIFIER_AAD;

        let result = encrypt_with_mek(&short_key, plaintext, aad);
        assert!(matches!(result, Err(EncryptionError::InvalidKey(_))));
    }

    #[test]
    fn test_invalid_base64_decryption() {
        let mek = vec![0x42u8; 32];
        let invalid_b64 = "not!!!valid@@@base64";
        let aad = CODE_VERIFIER_AAD;

        let result = decrypt_with_mek(&mek, invalid_b64, aad);
        assert!(matches!(result, Err(EncryptionError::InvalidFormat(_))));
    }

    #[test]
    fn test_too_short_ciphertext() {
        let mek = vec![0x42u8; 32];
        let short_data = URL_SAFE_NO_PAD.encode([0x01u8; 10]); // Less than 28 bytes
        let aad = CODE_VERIFIER_AAD;

        let result = decrypt_with_mek(&mek, &short_data, aad);
        assert!(matches!(result, Err(EncryptionError::InvalidFormat(_))));
    }

    #[test]
    fn test_base64url_encoding() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "test_verifier";
        let aad = CODE_VERIFIER_AAD;

        let encrypted = encrypt_with_mek(&mek, plaintext, aad)?;

        // Should be valid base64url (no +, /, or = characters)
        assert!(!encrypted.contains('+'));
        assert!(!encrypted.contains('/'));
        assert!(!encrypted.contains('='));
        Ok(())
    }

    // ======================================================================
    // Key length validation
    // ======================================================================

    #[test]
    fn test_encrypt_rejects_empty_key() {
        let result = encrypt_with_mek(&[], "plaintext", CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidKey(_))));
    }

    #[test]
    fn test_encrypt_rejects_16_byte_key() {
        let mek = vec![0x42u8; 16];
        let result = encrypt_with_mek(&mek, "plaintext", CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidKey(_))));
    }

    #[test]
    fn test_encrypt_rejects_64_byte_key() {
        let mek = vec![0x42u8; 64];
        let result = encrypt_with_mek(&mek, "plaintext", CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidKey(_))));
    }

    #[test]
    fn test_decrypt_rejects_empty_key() {
        let mek_valid = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek_valid, "test", CODE_VERIFIER_AAD).unwrap();

        let result = decrypt_with_mek(&[], &encrypted, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidKey(_))));
    }

    #[test]
    fn test_decrypt_rejects_16_byte_key() {
        let mek_valid = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek_valid, "test", CODE_VERIFIER_AAD).unwrap();

        let short_key = vec![0x42u8; 16];
        let result = decrypt_with_mek(&short_key, &encrypted, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidKey(_))));
    }

    // ======================================================================
    // Plaintext edge cases
    // ======================================================================

    #[test]
    fn test_encrypt_decrypt_empty_plaintext() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek, "", CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, "");
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_single_char() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek, "a", CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, "a");
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_long_plaintext() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "x".repeat(10_000);
        let encrypted = encrypt_with_mek(&mek, &plaintext, CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, &plaintext);
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_unicode_plaintext() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "Hello, World! Emoji too \u{1F600}";
        let encrypted = encrypt_with_mek(&mek, plaintext, CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    // ======================================================================
    // AAD edge cases
    // ======================================================================

    #[test]
    fn test_encrypt_decrypt_with_empty_aad() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "test_data";
        let encrypted = encrypt_with_mek(&mek, plaintext, b"")?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, b"")?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_with_long_aad() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "test_data";
        let aad = vec![0xAB; 1000];
        let encrypted = encrypt_with_mek(&mek, plaintext, &aad)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, &aad)?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_different_aad_cross_decrypt_fails() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "test_data";

        let encrypted = encrypt_with_mek(&mek, plaintext, b"aad_one")?;
        let result = decrypt_with_mek(&mek, &encrypted, b"aad_two");
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
        Ok(())
    }

    // ======================================================================
    // Corrupted ciphertext edge cases
    // ======================================================================

    #[test]
    fn test_corrupted_iv_fails() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek, "secret", CODE_VERIFIER_AAD)?;

        let mut bytes = URL_SAFE_NO_PAD.decode(encrypted.as_bytes())?;
        // Corrupt the IV (first 12 bytes)
        if let Some(byte) = bytes.get_mut(0) {
            *byte ^= 0xFF;
        }
        let corrupted = URL_SAFE_NO_PAD.encode(&bytes);

        let result = decrypt_with_mek(&mek, &corrupted, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
        Ok(())
    }

    #[test]
    fn test_corrupted_auth_tag_fails() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek, "secret", CODE_VERIFIER_AAD)?;

        let mut bytes = URL_SAFE_NO_PAD.decode(encrypted.as_bytes())?;
        // Corrupt the auth tag (last 16 bytes)
        let last_idx = bytes.len().saturating_sub(1);
        if let Some(byte) = bytes.get_mut(last_idx) {
            *byte ^= 0xFF;
        }
        let corrupted = URL_SAFE_NO_PAD.encode(&bytes);

        let result = decrypt_with_mek(&mek, &corrupted, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
        Ok(())
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let mek = vec![0x42u8; 32];
        // 27 bytes: just under the 28-byte minimum (12 IV + 16 tag)
        let short_data = URL_SAFE_NO_PAD.encode([0u8; 27]);
        let result = decrypt_with_mek(&mek, &short_data, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidFormat(_))));
    }

    #[test]
    fn test_exactly_28_bytes_is_valid_format() {
        let mek = vec![0x42u8; 32];
        // 28 bytes: minimum valid (12 IV + 16 tag, zero plaintext)
        let data = URL_SAFE_NO_PAD.encode([0u8; 28]);
        let result = decrypt_with_mek(&mek, &data, CODE_VERIFIER_AAD);
        // Should fail decryption (random bytes), not format validation
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
    }

    // ======================================================================
    // EncryptionError Display
    // ======================================================================

    #[test]
    fn test_encryption_error_display_invalid_key() {
        let err = EncryptionError::InvalidKey("bad key".to_string());
        assert!(format!("{}", err).contains("bad key"));
    }

    #[test]
    fn test_encryption_error_display_encryption_failed() {
        let err = EncryptionError::EncryptionFailed("cipher error".to_string());
        assert!(format!("{}", err).contains("cipher error"));
    }

    #[test]
    fn test_encryption_error_display_decryption_failed() {
        let err = EncryptionError::DecryptionFailed("tag mismatch".to_string());
        assert!(format!("{}", err).contains("tag mismatch"));
    }

    #[test]
    fn test_encryption_error_display_secrets_store_failed() {
        let err = EncryptionError::SecretsStoreFailed("binding missing".to_string());
        assert!(format!("{}", err).contains("binding missing"));
    }

    #[test]
    fn test_encryption_error_display_invalid_format() {
        let err = EncryptionError::InvalidFormat("too short".to_string());
        assert!(format!("{}", err).contains("too short"));
    }

    #[test]
    fn test_encryption_error_is_error_trait() {
        let err = EncryptionError::InvalidKey("test".to_string());
        let _: &dyn std::error::Error = &err;
    }

    // ======================================================================
    // mek_cache_populated (process-wide state)
    // ======================================================================

    #[test]
    fn test_mek_cache_populated_returns_bool() {
        // The static might or might not be populated depending on test
        // ordering, but the function must return without panicking.
        let _result: bool = mek_cache_populated();
    }

    // ======================================================================
    // CODE_VERIFIER_AAD constant
    // ======================================================================

    #[test]
    fn test_code_verifier_aad_is_set() {
        assert!(CODE_VERIFIER_AAD.starts_with(b"provii-verifier"));
    }

    #[test]
    fn test_code_verifier_aad_has_version_suffix() {
        let aad_str = std::str::from_utf8(CODE_VERIFIER_AAD).unwrap();
        assert!(aad_str.ends_with(":v1"));
    }

    // ======================================================================
    // Key rotation: different keys
    // ======================================================================

    #[test]
    fn test_key_rotation_primary_then_secondary() -> Result<(), Box<dyn std::error::Error>> {
        let primary = vec![0x42u8; 32];
        let secondary = vec![0x43u8; 32];
        let plaintext = "rotating_secret";

        // Encrypt with secondary (old key)
        let encrypted = encrypt_with_mek(&secondary, plaintext, CODE_VERIFIER_AAD)?;

        // Decrypt with primary fails
        let result = decrypt_with_mek(&primary, &encrypted, CODE_VERIFIER_AAD);
        assert!(result.is_err());

        // Decrypt with secondary succeeds
        let decrypted = decrypt_with_mek(&secondary, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    // ======================================================================
    // Wire format verification
    // ======================================================================

    #[test]
    fn test_wire_format_iv_12_bytes_prefix() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0xAA; 32];
        let plaintext = "wire_format_check";
        let encrypted = encrypt_with_mek(&mek, plaintext, CODE_VERIFIER_AAD)?;
        let raw = URL_SAFE_NO_PAD.decode(encrypted.as_bytes())?;

        // Minimum: 12-byte IV + plaintext_len ciphertext + 16-byte tag
        assert_eq!(
            raw.len(),
            12 + plaintext.len() + 16,
            "wire format length mismatch"
        );
        Ok(())
    }

    #[test]
    fn test_wire_format_empty_plaintext_length() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0xBB; 32];
        let encrypted = encrypt_with_mek(&mek, "", CODE_VERIFIER_AAD)?;
        let raw = URL_SAFE_NO_PAD.decode(encrypted.as_bytes())?;

        // Empty plaintext: 12-byte IV + 0 ciphertext + 16-byte tag = 28 bytes
        assert_eq!(raw.len(), 28);
        Ok(())
    }

    #[test]
    fn test_wire_format_iv_differs_between_encryptions() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0xCC; 32];
        let encrypted1 = encrypt_with_mek(&mek, "same", CODE_VERIFIER_AAD)?;
        let encrypted2 = encrypt_with_mek(&mek, "same", CODE_VERIFIER_AAD)?;

        let raw1 = URL_SAFE_NO_PAD.decode(encrypted1.as_bytes())?;
        let raw2 = URL_SAFE_NO_PAD.decode(encrypted2.as_bytes())?;

        // IVs (first 12 bytes) must differ
        assert_ne!(&raw1[..12], &raw2[..12]);
        Ok(())
    }

    // ======================================================================
    // Key length boundary: 31 and 33 bytes
    // ======================================================================

    #[test]
    fn test_encrypt_rejects_31_byte_key() {
        let mek = vec![0x42u8; 31];
        let result = encrypt_with_mek(&mek, "test", CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidKey(_))));
    }

    #[test]
    fn test_encrypt_rejects_33_byte_key() {
        let mek = vec![0x42u8; 33];
        let result = encrypt_with_mek(&mek, "test", CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidKey(_))));
    }

    #[test]
    fn test_decrypt_rejects_31_byte_key() -> Result<(), Box<dyn std::error::Error>> {
        let mek_valid = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek_valid, "test", CODE_VERIFIER_AAD)?;

        let short_key = vec![0x42u8; 31];
        let result = decrypt_with_mek(&short_key, &encrypted, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidKey(_))));
        Ok(())
    }

    #[test]
    fn test_decrypt_rejects_33_byte_key() -> Result<(), Box<dyn std::error::Error>> {
        let mek_valid = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek_valid, "test", CODE_VERIFIER_AAD)?;

        let long_key = vec![0x42u8; 33];
        let result = decrypt_with_mek(&long_key, &encrypted, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidKey(_))));
        Ok(())
    }

    #[test]
    fn test_encrypt_rejects_1_byte_key() {
        let result = encrypt_with_mek(&[0xFF], "test", CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidKey(_))));
    }

    #[test]
    fn test_decrypt_rejects_64_byte_key() -> Result<(), Box<dyn std::error::Error>> {
        let mek_valid = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek_valid, "test", CODE_VERIFIER_AAD)?;

        let long_key = vec![0x42u8; 64];
        let result = decrypt_with_mek(&long_key, &encrypted, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidKey(_))));
        Ok(())
    }

    // ======================================================================
    // Decrypt format edge cases
    // ======================================================================

    #[test]
    fn test_decrypt_empty_string_input() {
        let mek = vec![0x42u8; 32];
        // Empty base64 decodes to 0 bytes, well below the 28-byte minimum
        let result = decrypt_with_mek(&mek, "", CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidFormat(_))));
    }

    #[test]
    fn test_decrypt_12_bytes_too_short() {
        let mek = vec![0x42u8; 32];
        let data = URL_SAFE_NO_PAD.encode([0u8; 12]);
        let result = decrypt_with_mek(&mek, &data, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidFormat(_))));
    }

    #[test]
    fn test_decrypt_0_bytes_too_short() {
        let mek = vec![0x42u8; 32];
        let data = URL_SAFE_NO_PAD.encode([0u8; 0]);
        let result = decrypt_with_mek(&mek, &data, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidFormat(_))));
    }

    #[test]
    fn test_decrypt_1_byte_too_short() {
        let mek = vec![0x42u8; 32];
        let data = URL_SAFE_NO_PAD.encode([0xAB; 1]);
        let result = decrypt_with_mek(&mek, &data, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidFormat(_))));
    }

    #[test]
    fn test_decrypt_exactly_27_bytes_too_short() {
        let mek = vec![0x42u8; 32];
        let data = URL_SAFE_NO_PAD.encode([0u8; 27]);
        let result = decrypt_with_mek(&mek, &data, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidFormat(_))));
    }

    #[test]
    fn test_decrypt_29_bytes_passes_format_check() {
        let mek = vec![0x42u8; 32];
        // 29 bytes: passes format check (>= 28) but fails auth verification
        let data = URL_SAFE_NO_PAD.encode([0u8; 29]);
        let result = decrypt_with_mek(&mek, &data, CODE_VERIFIER_AAD);
        // Should be DecryptionFailed (auth tag mismatch), not InvalidFormat
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
    }

    #[test]
    fn test_decrypt_invalid_base64_characters() {
        let mek = vec![0x42u8; 32];
        let result = decrypt_with_mek(&mek, "====", CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidFormat(_))));
    }

    #[test]
    fn test_decrypt_base64_with_standard_alphabet_rejected() {
        let mek = vec![0x42u8; 32];
        // Standard base64 uses + and /, which are invalid in base64url
        let standard_b64 = "AAAAAAAAAAAAAAAA+/AAAAAAAAAAAAAAAAAA==";
        let result = decrypt_with_mek(&mek, standard_b64, CODE_VERIFIER_AAD);
        // Should fail on base64 decoding or format
        assert!(result.is_err());
    }

    // ======================================================================
    // Ciphertext corruption: middle bytes
    // ======================================================================

    #[test]
    fn test_corrupted_middle_ciphertext_fails() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "some longer plaintext for middle corruption test";
        let encrypted = encrypt_with_mek(&mek, plaintext, CODE_VERIFIER_AAD)?;

        let mut bytes = URL_SAFE_NO_PAD.decode(encrypted.as_bytes())?;
        // Corrupt a byte in the middle of the ciphertext (after IV, before tag)
        let mid = bytes.len() / 2;
        if let Some(byte) = bytes.get_mut(mid) {
            *byte ^= 0xFF;
        }
        let corrupted = URL_SAFE_NO_PAD.encode(&bytes);

        let result = decrypt_with_mek(&mek, &corrupted, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
        Ok(())
    }

    #[test]
    fn test_corrupted_all_iv_bytes_fails() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek, "test", CODE_VERIFIER_AAD)?;

        let mut bytes = URL_SAFE_NO_PAD.decode(encrypted.as_bytes())?;
        // Corrupt all 12 IV bytes
        for b in bytes.iter_mut().take(12) {
            *b ^= 0xFF;
        }
        let corrupted = URL_SAFE_NO_PAD.encode(&bytes);

        let result = decrypt_with_mek(&mek, &corrupted, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
        Ok(())
    }

    #[test]
    fn test_corrupted_all_tag_bytes_fails() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek, "test", CODE_VERIFIER_AAD)?;

        let mut bytes = URL_SAFE_NO_PAD.decode(encrypted.as_bytes())?;
        // Corrupt all 16 tag bytes (last 16 bytes)
        let tag_start = bytes.len().saturating_sub(16);
        for b in bytes.iter_mut().skip(tag_start) {
            *b ^= 0xFF;
        }
        let corrupted = URL_SAFE_NO_PAD.encode(&bytes);

        let result = decrypt_with_mek(&mek, &corrupted, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
        Ok(())
    }

    #[test]
    fn test_appended_bytes_fail_decryption() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek, "test", CODE_VERIFIER_AAD)?;

        let mut bytes = URL_SAFE_NO_PAD.decode(encrypted.as_bytes())?;
        // Append extra bytes after the auth tag
        bytes.extend_from_slice(&[0xDE, 0xAD]);
        let tampered = URL_SAFE_NO_PAD.encode(&bytes);

        let result = decrypt_with_mek(&mek, &tampered, CODE_VERIFIER_AAD);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
        Ok(())
    }

    #[test]
    fn test_truncated_one_byte_from_valid_fails() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek, "test", CODE_VERIFIER_AAD)?;

        let mut bytes = URL_SAFE_NO_PAD.decode(encrypted.as_bytes())?;
        bytes.pop(); // Remove last byte of auth tag
        let truncated = URL_SAFE_NO_PAD.encode(&bytes);

        let result = decrypt_with_mek(&mek, &truncated, CODE_VERIFIER_AAD);
        // Could be DecryptionFailed (auth tag too short) or still pass format check
        assert!(result.is_err());
        Ok(())
    }

    // ======================================================================
    // Plaintext content edge cases
    // ======================================================================

    #[test]
    fn test_encrypt_decrypt_plaintext_with_newlines() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "line1\nline2\r\nline3\n";
        let encrypted = encrypt_with_mek(&mek, plaintext, CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_plaintext_with_null_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "before\0after";
        let encrypted = encrypt_with_mek(&mek, plaintext, CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_plaintext_with_special_chars() -> Result<(), Box<dyn std::error::Error>>
    {
        let mek = vec![0x42u8; 32];
        let plaintext = r#"{"key": "value", "special": "<>&\"'"}"#;
        let encrypted = encrypt_with_mek(&mek, plaintext, CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_plaintext_with_multibyte_utf8() -> Result<(), Box<dyn std::error::Error>>
    {
        let mek = vec![0x42u8; 32];
        // 1-byte, 2-byte, 3-byte, and 4-byte UTF-8 sequences
        let plaintext = "A\u{00E9}\u{4E16}\u{1F600}";
        let encrypted = encrypt_with_mek(&mek, plaintext, CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_realistic_pkce_verifier() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        // PKCE code_verifier: 43-128 chars from unreserved URI chars
        let plaintext = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let encrypted = encrypt_with_mek(&mek, plaintext, CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_max_pkce_verifier_length() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        // PKCE max length is 128 characters
        let plaintext: String = (0..128).map(|i| (b'A' + (i % 26) as u8) as char).collect();
        let encrypted = encrypt_with_mek(&mek, &plaintext, CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, &plaintext);
        Ok(())
    }

    // ======================================================================
    // AAD content edge cases
    // ======================================================================

    #[test]
    fn test_aad_with_null_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "test";
        let aad = b"context\0v2";
        let encrypted = encrypt_with_mek(&mek, plaintext, aad)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, aad)?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_aad_single_byte_difference_fails() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "test";
        let aad1 = b"provii-verifier:code_verifier:v1";
        let aad2 = b"provii-verifier:code_verifier:v2";

        let encrypted = encrypt_with_mek(&mek, plaintext, aad1)?;
        let result = decrypt_with_mek(&mek, &encrypted, aad2);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
        Ok(())
    }

    #[test]
    fn test_empty_aad_vs_nonempty_aad_cross_fails() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "test";

        let encrypted = encrypt_with_mek(&mek, plaintext, b"")?;
        let result = decrypt_with_mek(&mek, &encrypted, b"notempty");
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
        Ok(())
    }

    // ======================================================================
    // Multiple key values
    // ======================================================================

    #[test]
    fn test_all_zeros_key_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x00; 32];
        let plaintext = "zero_key_test";
        let encrypted = encrypt_with_mek(&mek, plaintext, CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_all_ff_key_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0xFF; 32];
        let plaintext = "ff_key_test";
        let encrypted = encrypt_with_mek(&mek, plaintext, CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_sequential_key_bytes_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let mek: Vec<u8> = (0u8..32).collect();
        let plaintext = "sequential_key_test";
        let encrypted = encrypt_with_mek(&mek, plaintext, CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, plaintext);
        Ok(())
    }

    // ======================================================================
    // Cross-key + cross-AAD combined
    // ======================================================================

    #[test]
    fn test_wrong_key_and_wrong_aad_both_fail() -> Result<(), Box<dyn std::error::Error>> {
        let mek1 = vec![0x42u8; 32];
        let mek2 = vec![0x43u8; 32];
        let plaintext = "test";

        let encrypted = encrypt_with_mek(&mek1, plaintext, b"aad_a")?;
        let result = decrypt_with_mek(&mek2, &encrypted, b"aad_b");
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
        Ok(())
    }

    // ======================================================================
    // Multiple independent encryptions with same key
    // ======================================================================

    #[test]
    fn test_multiple_plaintexts_same_key() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintexts = ["alpha", "bravo", "charlie", "delta"];

        let encrypted: Vec<String> = plaintexts
            .iter()
            .map(|pt| encrypt_with_mek(&mek, pt, CODE_VERIFIER_AAD))
            .collect::<Result<Vec<_>, _>>()?;

        // All ciphertexts must be distinct
        for i in 0..encrypted.len() {
            for j in (i + 1)..encrypted.len() {
                assert_ne!(encrypted[i], encrypted[j]);
            }
        }

        // All must roundtrip correctly
        for (i, ct) in encrypted.iter().enumerate() {
            let decrypted = decrypt_with_mek(&mek, ct, CODE_VERIFIER_AAD)?;
            assert_eq!(&*decrypted, plaintexts[i]);
        }
        Ok(())
    }

    // ======================================================================
    // EncryptionError Display: exact prefix verification
    // ======================================================================

    #[test]
    fn test_error_display_invalid_key_prefix() {
        let err = EncryptionError::InvalidKey("msg".to_string());
        let display = format!("{}", err);
        assert!(
            display.starts_with("Invalid encryption key: "),
            "got: {}",
            display
        );
    }

    #[test]
    fn test_error_display_encryption_failed_prefix() {
        let err = EncryptionError::EncryptionFailed("msg".to_string());
        let display = format!("{}", err);
        assert!(
            display.starts_with("Encryption failed: "),
            "got: {}",
            display
        );
    }

    #[test]
    fn test_error_display_decryption_failed_prefix() {
        let err = EncryptionError::DecryptionFailed("msg".to_string());
        let display = format!("{}", err);
        assert!(
            display.starts_with("Decryption failed: "),
            "got: {}",
            display
        );
    }

    #[test]
    fn test_error_display_secrets_store_failed_prefix() {
        let err = EncryptionError::SecretsStoreFailed("msg".to_string());
        let display = format!("{}", err);
        assert!(
            display.starts_with("Secrets store error: "),
            "got: {}",
            display
        );
    }

    #[test]
    fn test_error_display_invalid_format_prefix() {
        let err = EncryptionError::InvalidFormat("msg".to_string());
        let display = format!("{}", err);
        assert!(display.starts_with("Invalid format: "), "got: {}", display);
    }

    // ======================================================================
    // EncryptionError Debug
    // ======================================================================

    #[test]
    fn test_error_debug_contains_variant_name() {
        let err = EncryptionError::InvalidKey("test_debug".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("InvalidKey"), "got: {}", debug);
        assert!(debug.contains("test_debug"), "got: {}", debug);
    }

    #[test]
    fn test_error_debug_encryption_failed() {
        let err = EncryptionError::EncryptionFailed("cipher_err".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("EncryptionFailed"), "got: {}", debug);
    }

    #[test]
    fn test_error_debug_decryption_failed() {
        let err = EncryptionError::DecryptionFailed("tag_mismatch".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("DecryptionFailed"), "got: {}", debug);
    }

    #[test]
    fn test_error_debug_secrets_store_failed() {
        let err = EncryptionError::SecretsStoreFailed("missing".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("SecretsStoreFailed"), "got: {}", debug);
    }

    #[test]
    fn test_error_debug_invalid_format() {
        let err = EncryptionError::InvalidFormat("short".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("InvalidFormat"), "got: {}", debug);
    }

    // ======================================================================
    // Error trait object coercion
    // ======================================================================

    #[test]
    fn test_all_error_variants_implement_error_trait() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(EncryptionError::InvalidKey("a".into())),
            Box::new(EncryptionError::EncryptionFailed("b".into())),
            Box::new(EncryptionError::DecryptionFailed("c".into())),
            Box::new(EncryptionError::SecretsStoreFailed("d".into())),
            Box::new(EncryptionError::InvalidFormat("e".into())),
        ];
        // All five variants must coerce to dyn Error without panicking
        assert_eq!(variants.len(), 5);
    }

    // ======================================================================
    // Error message content from actual failures
    // ======================================================================

    #[test]
    fn test_encrypt_invalid_key_error_includes_actual_length() {
        let mek = vec![0x42u8; 15];
        let result = encrypt_with_mek(&mek, "test", CODE_VERIFIER_AAD);
        match result {
            Err(EncryptionError::InvalidKey(msg)) => {
                assert!(
                    msg.contains("15"),
                    "expected length in message, got: {}",
                    msg
                );
            }
            other => panic!("expected InvalidKey, got: {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    #[test]
    fn test_decrypt_invalid_key_error_includes_actual_length() {
        let data_28 = URL_SAFE_NO_PAD.encode([0u8; 28]);
        let mek = vec![0x42u8; 10];
        let result = decrypt_with_mek(&mek, &data_28, CODE_VERIFIER_AAD);
        match result {
            Err(EncryptionError::InvalidKey(msg)) => {
                assert!(
                    msg.contains("10"),
                    "expected length in message, got: {}",
                    msg
                );
            }
            other => panic!("expected InvalidKey, got: {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    #[test]
    fn test_decrypt_too_short_error_includes_actual_length() {
        let mek = vec![0x42u8; 32];
        let data = URL_SAFE_NO_PAD.encode([0u8; 20]);
        let result = decrypt_with_mek(&mek, &data, CODE_VERIFIER_AAD);
        match result {
            Err(EncryptionError::InvalidFormat(msg)) => {
                assert!(
                    msg.contains("20"),
                    "expected length in message, got: {}",
                    msg
                );
            }
            other => panic!("expected InvalidFormat, got: {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
    }

    // ======================================================================
    // CODE_VERIFIER_AAD constant: exact value
    // ======================================================================

    #[test]
    fn test_code_verifier_aad_exact_value() {
        assert_eq!(CODE_VERIFIER_AAD, b"provii-verifier:code_verifier:v1");
    }

    #[test]
    fn test_code_verifier_aad_is_valid_utf8() -> Result<(), Box<dyn std::error::Error>> {
        let _ = std::str::from_utf8(CODE_VERIFIER_AAD)?;
        Ok(())
    }

    // ======================================================================
    // Roundtrip with CODE_VERIFIER_AAD specifically
    // ======================================================================

    #[test]
    fn test_roundtrip_with_code_verifier_aad_constant() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let verifier = "S256-verifier-abcdef1234567890abcdef1234567890ab";
        let encrypted = encrypt_with_mek(&mek, verifier, CODE_VERIFIER_AAD)?;
        let decrypted = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        assert_eq!(&*decrypted, verifier);
        Ok(())
    }

    // ======================================================================
    // Zeroizing wrapper on decrypt output
    // ======================================================================

    #[test]
    fn test_decrypt_returns_zeroizing_string() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        let plaintext = "sensitive_data";
        let encrypted = encrypt_with_mek(&mek, plaintext, CODE_VERIFIER_AAD)?;
        let decrypted: Zeroizing<String> = decrypt_with_mek(&mek, &encrypted, CODE_VERIFIER_AAD)?;
        // Verify we can deref to &str and it matches
        let s: &str = &decrypted;
        assert_eq!(s, plaintext);
        Ok(())
    }

    // ======================================================================
    // Base64url output: no padding, correct alphabet
    // ======================================================================

    #[test]
    fn test_encrypt_output_valid_base64url_alphabet() -> Result<(), Box<dyn std::error::Error>> {
        let mek = vec![0x42u8; 32];
        // Encrypt several values and validate output charset
        let long_input = "x".repeat(500);
        let inputs = ["short", "a", "", long_input.as_str()];
        for input in &inputs {
            let encrypted = encrypt_with_mek(&mek, input, CODE_VERIFIER_AAD)?;
            for ch in encrypted.chars() {
                assert!(
                    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                    "invalid base64url char '{}' in output for input {:?}",
                    ch,
                    input
                );
            }
        }
        Ok(())
    }

    #[test]
    fn test_encrypt_output_round_trips_through_base64url() -> Result<(), Box<dyn std::error::Error>>
    {
        let mek = vec![0x42u8; 32];
        let encrypted = encrypt_with_mek(&mek, "roundtrip_b64", CODE_VERIFIER_AAD)?;
        // Decode and re-encode must yield identical string
        let raw = URL_SAFE_NO_PAD.decode(encrypted.as_bytes())?;
        let re_encoded = URL_SAFE_NO_PAD.encode(&raw);
        assert_eq!(encrypted, re_encoded);
        Ok(())
    }

    // ── M1: decode_and_cache (hosted MEK pre-load) ──────────────────────────

    #[test]
    fn test_decode_and_cache_valid_key_populates_cache() {
        // A valid 32-byte key encoded as base64url should decode, validate,
        // and populate the supplied cache. The returned fingerprint must match
        // the fingerprint of the RAW base64 string (not the decoded bytes), so
        // the value stays identical to the previous startup behaviour.
        let key = vec![0x42u8; 32];
        let raw_b64 = URL_SAFE_NO_PAD.encode(&key);
        let cache: OnceLock<Zeroizing<Vec<u8>>> = OnceLock::new();

        let (fp, cached) = decode_and_cache(&raw_b64, &cache, "TEST_MEK");

        assert!(cached, "valid 32-byte key should be cached");
        assert_eq!(
            fp,
            crate::security::secret_fingerprint::fingerprint6_str(Some(&raw_b64)),
            "fingerprint must be derived from the raw base64 string"
        );
        assert_eq!(
            cache.get().map(|v| v.as_slice().to_vec()),
            Some(key),
            "cache must hold the decoded 32 bytes"
        );
    }

    #[test]
    fn test_decode_and_cache_wrong_length_does_not_cache() {
        // A correctly-encoded but wrong-length key (16 bytes) must be rejected:
        // the cache stays empty but a fingerprint is still returned.
        let short_key = vec![0x11u8; 16];
        let raw_b64 = URL_SAFE_NO_PAD.encode(&short_key);
        let cache: OnceLock<Zeroizing<Vec<u8>>> = OnceLock::new();

        let (fp, cached) = decode_and_cache(&raw_b64, &cache, "TEST_MEK");

        assert!(!cached, "16-byte key must not be cached");
        assert!(cache.get().is_none(), "cache must remain empty");
        assert_ne!(
            fp,
            crate::security::secret_fingerprint::FINGERPRINT_UNSET,
            "a present-but-invalid value still yields a real fingerprint"
        );
    }

    #[test]
    fn test_decode_and_cache_invalid_base64_does_not_cache() {
        // '!' is not a base64url character; decode fails, cache stays empty.
        let cache: OnceLock<Zeroizing<Vec<u8>>> = OnceLock::new();

        let (_fp, cached) = decode_and_cache("not!valid!b64", &cache, "TEST_MEK");

        assert!(!cached, "undecodable value must not be cached");
        assert!(cache.get().is_none(), "cache must remain empty");
    }

    #[test]
    fn test_decode_and_cache_is_idempotent_on_first_value() {
        // OnceLock::set only takes the first value; a second decode of a
        // different key must not overwrite the cached one. This guards the
        // benign-race comment in the pre-load path.
        let key_a = vec![0x01u8; 32];
        let key_b = vec![0x02u8; 32];
        let raw_a = URL_SAFE_NO_PAD.encode(&key_a);
        let raw_b = URL_SAFE_NO_PAD.encode(&key_b);
        let cache: OnceLock<Zeroizing<Vec<u8>>> = OnceLock::new();

        let (_fp_a, cached_a) = decode_and_cache(&raw_a, &cache, "TEST_MEK");
        let (_fp_b, cached_b) = decode_and_cache(&raw_b, &cache, "TEST_MEK");

        assert!(cached_a);
        // The second call still reports it offered a valid value to the cache,
        // but the cache retains the first key.
        assert!(cached_b);
        assert_eq!(
            cache.get().map(|v| v.as_slice().to_vec()),
            Some(key_a),
            "first value must win (OnceLock semantics)"
        );
    }
}
