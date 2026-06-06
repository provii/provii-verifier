// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Envelope encryption for HMAC secrets using AES-256-GCM.
//!
//! SECURITY POLICY (ASVS V11.7.2): All types containing sensitive cryptographic
//! material implement custom `Debug` traits to prevent accidental logging of
//! secrets in error messages.
//!
//! SECURITY: This module implements envelope encryption to protect HMAC secrets
//! at rest in Cloudflare KV storage. The architecture uses a two-tier key
//! hierarchy. The Master Encryption Key (MEK) lives in Cloudflare Workers
//! Secrets (never in KV). Per-client Data Encryption Keys (DEK) are encrypted
//! with the MEK and stored alongside client records in KV.
//!
//! ## Vulnerability Addressed
//!
//! CWE-311 (Missing Encryption of Sensitive Data), ASVS V8.2.1 (Data
//! Protection at Rest).
//!
//! ## Encryption Parameters
//!
//! | Parameter   | Value                     |
//! |-------------|---------------------------|
//! | Cipher      | AES-256-GCM               |
//! | Key size    | 256 bits (32 bytes)        |
//! | IV/Nonce    | 96 bits (12 bytes)         |
//! | Tag size    | 128 bits (16 bytes)        |
//! | AAD         | Context-binding strings    |
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use provii_verifier::security::envelope_encryption::*;
//!
//! // Get MEK from Secrets Store
//! let store = env.secret_store("VERIFIER_MEK")?;
//! let mek = store.get().await?.ok_or_else(|| anyhow::anyhow!("MEK not found"))?;
//! let mek_bytes = base64url_decode(&mek)?;
//!
//! // Encrypt HMAC secret
//! let plaintext = b"my-hmac-secret";
//! let encrypted = encrypt_hmac_secret(plaintext, &mek_bytes).await?;
//!
//! // Store in KV
//! // client.encrypted_hmac_secret = encrypted.encrypted_secret;
//! // client.dek_encrypted = encrypted.encrypted_dek;
//!
//! // Later: Decrypt HMAC secret
//! let decrypted = decrypt_hmac_secret(&encrypted, &mek_bytes).await?;
//! // Use decrypted secret, then zeroize
//! ```
#![forbid(unsafe_code)]

use crate::error::{ApiError, ApiResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_arch = "wasm32")]
use js_sys::{Array, Object, Reflect, Uint8Array};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use web_sys::CryptoKey;

// Use worker console_log on WASM, no-op macro for native testing
#[cfg(target_arch = "wasm32")]
use worker::console_log;

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_macros)]
macro_rules! console_log {
    ($($t:tt)*) => {{}};
}

/// Encryption version for schema evolution and rollback support.
pub const ENCRYPTION_VERSION_V1: u8 = 1;

/// AAD (Additional Authenticated Data) for HMAC secret encryption.
/// SECURITY: This binds the ciphertext to its context, preventing substitution attacks.
const AAD_HMAC_SECRET: &[u8] = b"provii-hmac-secret-v1";

/// AAD for DEK encryption.
const AAD_DEK: &[u8] = b"provii-dek-v1";

/// AES-256-GCM key size (256 bits = 32 bytes).
const AES_256_KEY_SIZE: usize = 32;

/// GCM recommended IV/nonce size (96 bits = 12 bytes).
const GCM_IV_SIZE: usize = 12;

/// GCM authentication tag size (128 bits = 16 bytes).
const GCM_TAG_SIZE: usize = 16;

/// Encrypted secret container with all necessary cryptographic material.
///
/// SECURITY: This structure is designed for safe storage in KV. All fields are
/// base64url-encoded for safe JSON serialisation. The DEK is encrypted with the MEK,
/// so KV compromise alone cannot decrypt the HMAC secrets.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct EncryptedSecret {
    /// Base64url-encoded encrypted HMAC secret (IV + ciphertext + tag).
    pub encrypted_secret: String,

    /// Base64url-encoded encrypted DEK (IV + ciphertext + tag).
    pub encrypted_dek: String,

    /// Encryption version for schema evolution.
    pub version: u8,
}

// SECURITY POLICY (ASVS V11.7.2): All types containing sensitive cryptographic
// material MUST implement custom Debug trait to prevent accidental logging.
// Use #[cfg(test)] to verify no sensitive data appears in debug output.
impl fmt::Debug for EncryptedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedSecret")
            .field("encrypted_secret", &"[REDACTED]")
            .field("encrypted_dek", &"[REDACTED]")
            .field("version", &self.version)
            .finish()
    }
}

// SECURITY: Zeroize encrypted key material from memory when no longer needed.
impl Zeroize for EncryptedSecret {
    fn zeroize(&mut self) {
        self.encrypted_secret.zeroize();
        self.encrypted_dek.zeroize();
        self.version = 0;
    }
}

// SECURITY: Guarantee zeroisation on drop even if caller forgets to call zeroize().
impl Drop for EncryptedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Generates a cryptographically secure random key.
///
/// SECURITY: Uses Web Crypto API (WASM) or getrandom (native) for CSPRNG.
/// Each generated key is unique and unpredictable.
///
/// # Arguments
/// * `size` - Key size in bytes (typically 32 for AES-256)
///
/// # Returns
/// * `Ok(Vec<u8>)` - Cryptographically secure random bytes
/// * `Err(ApiError)` - If random number generation fails
pub fn generate_random_key(size: usize) -> ApiResult<Zeroizing<Vec<u8>>> {
    #[cfg(target_arch = "wasm32")]
    {
        // Access crypto from global scope (Workers environment, not browser window)
        let global = js_sys::global();
        let crypto_js =
            js_sys::Reflect::get(&global, &JsValue::from_str("crypto")).map_err(|e| {
                ApiError::Internal(anyhow::anyhow!(
                    "Crypto not available in global scope: {:?}",
                    e
                ))
            })?;
        let crypto: web_sys::Crypto = crypto_js.dyn_into().map_err(|e| {
            ApiError::Internal(anyhow::anyhow!(
                "Failed to convert to Crypto object: {:?}",
                e
            ))
        })?;

        let mut buffer = vec![0u8; size];
        crypto
            .get_random_values_with_u8_array(&mut buffer[..])
            .map_err(|e| {
                ApiError::Internal(anyhow::anyhow!("Failed to generate random bytes: {:?}", e))
            })?;

        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[SECURITY] [ENCRYPTION] Generated random key: {} bytes",
            size
        );
        Ok(Zeroizing::new(buffer))
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        use getrandom::getrandom;
        let mut buffer = vec![0u8; size];
        getrandom(&mut buffer).map_err(|e| {
            ApiError::Internal(anyhow::anyhow!("Failed to generate random bytes: {}", e))
        })?;
        Ok(Zeroizing::new(buffer))
    }
}

/// Generates a cryptographically secure random IV/nonce for GCM.
///
/// SECURITY: IV must be unique for each encryption operation with the same key.
/// GCM mode requires 96-bit (12-byte) IVs for optimal security.
///
/// # Returns
/// * `Ok([u8; GCM_IV_SIZE])` - 12-byte random IV
/// * `Err(ApiError)` - If random number generation fails
pub fn generate_random_iv() -> ApiResult<[u8; GCM_IV_SIZE]> {
    let bytes = generate_random_key(GCM_IV_SIZE)?;
    let mut iv = [0u8; GCM_IV_SIZE];
    iv.copy_from_slice(&bytes);
    Ok(iv)
}

/// Encrypts plaintext using AES-256-GCM.
///
/// SECURITY: This is a low-level encryption primitive. Use `encrypt_hmac_secret()`
/// for envelope encryption of HMAC secrets.
///
/// # Arguments
/// * `key` - 32-byte AES-256 key
/// * `iv` - 12-byte GCM nonce (must be unique per encryption)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional Authenticated Data for context binding
///
/// # Returns
/// * `Ok(Vec<u8>)` - Ciphertext + authentication tag
/// * `Err(ApiError)` - If encryption fails
#[cfg(target_arch = "wasm32")]
async fn aes_256_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> ApiResult<Vec<u8>> {
    if key.len() != AES_256_KEY_SIZE {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Invalid key size: expected {}, got {}",
            AES_256_KEY_SIZE,
            key.len()
        )));
    }

    if iv.len() != GCM_IV_SIZE {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Invalid IV size: expected {}, got {}",
            GCM_IV_SIZE,
            iv.len()
        )));
    }

    // Access crypto from global scope (Workers environment, not browser window)
    let global = js_sys::global();
    let crypto_js = js_sys::Reflect::get(&global, &JsValue::from_str("crypto")).map_err(|e| {
        ApiError::Internal(anyhow::anyhow!(
            "Crypto not available in global scope: {:?}",
            e
        ))
    })?;
    let crypto: web_sys::Crypto = crypto_js.dyn_into().map_err(|e| {
        ApiError::Internal(anyhow::anyhow!(
            "Failed to convert to Crypto object: {:?}",
            e
        ))
    })?;
    let subtle = crypto.subtle();

    // Import key
    let key_data = Uint8Array::from(key);
    let algorithm = Object::new();
    Reflect::set(&algorithm, &"name".into(), &"AES-GCM".into()).map_err(|e| {
        ApiError::Internal(anyhow::anyhow!("Failed to set algorithm name: {:?}", e))
    })?;

    let key_usages = Array::new();
    key_usages.push(&"encrypt".into());

    let crypto_key_promise = subtle
        .import_key_with_object("raw", &key_data, &algorithm, false, &key_usages)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to import key: {:?}", e)))?;

    let crypto_key = wasm_bindgen_futures::JsFuture::from(crypto_key_promise)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to import key: {:?}", e)))?;
    let crypto_key: CryptoKey = crypto_key.into();

    // Setup encryption algorithm with IV and AAD
    let encrypt_algorithm = Object::new();
    Reflect::set(&encrypt_algorithm, &"name".into(), &"AES-GCM".into())
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set algorithm: {:?}", e)))?;
    Reflect::set(&encrypt_algorithm, &"iv".into(), &Uint8Array::from(iv))
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set IV: {:?}", e)))?;
    Reflect::set(
        &encrypt_algorithm,
        &"additionalData".into(),
        &Uint8Array::from(aad),
    )
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set AAD: {:?}", e)))?;
    Reflect::set(
        &encrypt_algorithm,
        &"tagLength".into(),
        &JsValue::from(GCM_TAG_SIZE * 8),
    )
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set tag length: {:?}", e)))?;

    // Encrypt
    let plaintext_data = Uint8Array::from(plaintext);
    let encrypt_promise = subtle
        .encrypt_with_object_and_buffer_source(&encrypt_algorithm, &crypto_key, &plaintext_data)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to encrypt: {:?}", e)))?;

    let ciphertext_buffer = wasm_bindgen_futures::JsFuture::from(encrypt_promise)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Encryption failed: {:?}", e)))?;

    let ciphertext_array = Uint8Array::new(&ciphertext_buffer);
    let mut ciphertext = vec![0u8; ciphertext_array.length() as usize];
    ciphertext_array.copy_to(&mut ciphertext);

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[SECURITY] [ENCRYPTION] Encrypted {} bytes → {} bytes (includes tag)",
        plaintext.len(),
        ciphertext.len()
    );

    Ok(ciphertext)
}

/// Decrypts ciphertext using AES-256-GCM.
///
/// SECURITY: This function verifies the authentication tag, ensuring integrity
/// and authenticity of the ciphertext. Tampering will cause decryption to fail.
///
/// # Arguments
/// * `key` - 32-byte AES-256 key
/// * `iv` - 12-byte GCM nonce (same as used during encryption)
/// * `ciphertext` - Encrypted data + authentication tag
/// * `aad` - Additional Authenticated Data (must match encryption AAD)
///
/// # Returns
/// * `Ok(Vec<u8>)` - Decrypted plaintext
/// * `Err(ApiError)` - If decryption fails (wrong key, tampered data, wrong AAD)
#[cfg(target_arch = "wasm32")]
async fn aes_256_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> ApiResult<Vec<u8>> {
    if key.len() != AES_256_KEY_SIZE {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Invalid key size: expected {}, got {}",
            AES_256_KEY_SIZE,
            key.len()
        )));
    }

    if iv.len() != GCM_IV_SIZE {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Invalid IV size: expected {}, got {}",
            GCM_IV_SIZE,
            iv.len()
        )));
    }

    // Access crypto from global scope (Workers environment, not browser window)
    let global = js_sys::global();
    let crypto_js = js_sys::Reflect::get(&global, &JsValue::from_str("crypto")).map_err(|e| {
        ApiError::Internal(anyhow::anyhow!(
            "Crypto not available in global scope: {:?}",
            e
        ))
    })?;
    let crypto: web_sys::Crypto = crypto_js.dyn_into().map_err(|e| {
        ApiError::Internal(anyhow::anyhow!(
            "Failed to convert to Crypto object: {:?}",
            e
        ))
    })?;
    let subtle = crypto.subtle();

    // Import key
    let key_data = Uint8Array::from(key);
    let algorithm = Object::new();
    Reflect::set(&algorithm, &"name".into(), &"AES-GCM".into())
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set algorithm: {:?}", e)))?;

    let key_usages = Array::new();
    key_usages.push(&"decrypt".into());

    let crypto_key_promise = subtle
        .import_key_with_object("raw", &key_data, &algorithm, false, &key_usages)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to import key: {:?}", e)))?;

    let crypto_key = wasm_bindgen_futures::JsFuture::from(crypto_key_promise)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to import key: {:?}", e)))?;
    let crypto_key: CryptoKey = crypto_key.into();

    // Setup decryption algorithm with IV and AAD
    let decrypt_algorithm = Object::new();
    Reflect::set(&decrypt_algorithm, &"name".into(), &"AES-GCM".into())
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set algorithm: {:?}", e)))?;
    Reflect::set(&decrypt_algorithm, &"iv".into(), &Uint8Array::from(iv))
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set IV: {:?}", e)))?;
    Reflect::set(
        &decrypt_algorithm,
        &"additionalData".into(),
        &Uint8Array::from(aad),
    )
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set AAD: {:?}", e)))?;
    Reflect::set(
        &decrypt_algorithm,
        &"tagLength".into(),
        &JsValue::from(GCM_TAG_SIZE * 8),
    )
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set tag length: {:?}", e)))?;

    // Decrypt
    let ciphertext_data = Uint8Array::from(ciphertext);
    let decrypt_promise = subtle
        .decrypt_with_object_and_buffer_source(&decrypt_algorithm, &crypto_key, &ciphertext_data)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to decrypt: {:?}", e)))?;

    let plaintext_buffer = wasm_bindgen_futures::JsFuture::from(decrypt_promise)
        .await
        .map_err(|e| {
            #[cfg(target_arch = "wasm32")]
            console_log!("[SECURITY] [ENCRYPTION] [ERROR] Decryption failed (wrong key, tampered data, or AAD mismatch): {:?}", e);
            ApiError::Internal(anyhow::anyhow!("Decryption failed: authentication tag verification failed"))
        })?;

    let plaintext_array = Uint8Array::new(&plaintext_buffer);
    let mut plaintext = vec![0u8; plaintext_array.length() as usize];
    plaintext_array.copy_to(&mut plaintext);

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[SECURITY] [ENCRYPTION] Decrypted {} bytes → {} bytes",
        ciphertext.len(),
        plaintext.len()
    );

    Ok(plaintext)
}

/// Native implementation of AES-256-GCM encryption for testing.
///
/// SECURITY: This is only used in native tests. WASM uses Web Crypto API.
#[cfg(not(target_arch = "wasm32"))]
async fn aes_256_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> ApiResult<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };

    if key.len() != AES_256_KEY_SIZE {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Invalid key size: expected {}, got {}",
            AES_256_KEY_SIZE,
            key.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(iv);
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Encryption failed: {}", e)))?;

    Ok(ciphertext)
}

/// Native implementation of AES-256-GCM decryption for testing.
///
/// SECURITY: GCM authentication tag is verified during decryption.
/// Tampered ciphertext or mismatched AAD will produce an error.
#[cfg(not(target_arch = "wasm32"))]
async fn aes_256_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> ApiResult<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };

    if key.len() != AES_256_KEY_SIZE {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Invalid key size: expected {}, got {}",
            AES_256_KEY_SIZE,
            key.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(iv);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Decryption failed: {}", e)))?;

    Ok(plaintext)
}

/// Encrypts an HMAC secret using envelope encryption.
///
/// SECURITY: Two-tier key hierarchy. Generates a random DEK (Data
/// Encryption Key), encrypts the HMAC secret with the DEK, then
/// encrypts the DEK with the MEK (Master Encryption Key).
///
/// This design ensures that KV compromise alone cannot decrypt secrets.
/// The attacker would need both KV access AND the MEK from Workers Secrets.
///
/// # Arguments
/// * `plaintext_secret` - Raw HMAC secret bytes
/// * `mek` - 32-byte Master Encryption Key from Workers Secrets
///
/// # Returns
/// * `Ok(EncryptedSecret)` - Encrypted secret ready for KV storage
/// * `Err(ApiError)` - If encryption fails
///
/// # Example
/// ```rust,ignore
/// let store = env.secret_store("VERIFIER_MEK")?;
/// let mek = store.get().await?.ok_or_else(|| anyhow::anyhow!("MEK not found"))?;
/// let mek_bytes = base64url_decode(&mek)?;
/// let encrypted = encrypt_hmac_secret(b"my-secret", &mek_bytes).await?;
/// ```
pub async fn encrypt_hmac_secret(
    plaintext_secret: &[u8],
    mek: &[u8],
) -> ApiResult<EncryptedSecret> {
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[SECURITY] [ENCRYPTION] Starting envelope encryption for HMAC secret ({} bytes)",
        plaintext_secret.len()
    );

    // SECURITY: Step 1 - Generate unique DEK for this client
    let dek = generate_random_key(AES_256_KEY_SIZE)?;
    #[cfg(target_arch = "wasm32")]
    console_log!("[SECURITY] [ENCRYPTION] Generated DEK: {} bytes", dek.len());

    // SECURITY: Step 2 - Encrypt HMAC secret with DEK
    let secret_iv = generate_random_iv()?;
    let secret_ciphertext =
        aes_256_gcm_encrypt(&dek, &secret_iv, plaintext_secret, AAD_HMAC_SECRET).await?;

    // SECURITY: Prepend IV to ciphertext for storage (IV + ciphertext + tag)
    let mut secret_blob =
        Vec::with_capacity(secret_iv.len().saturating_add(secret_ciphertext.len()));
    secret_blob.extend_from_slice(&secret_iv);
    secret_blob.extend_from_slice(&secret_ciphertext);
    let encrypted_secret = URL_SAFE_NO_PAD.encode(&secret_blob);

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[SECURITY] [ENCRYPTION] Encrypted HMAC secret: {} bytes plaintext → {} bytes ciphertext",
        plaintext_secret.len(),
        secret_blob.len()
    );

    // SECURITY: Step 3 - Encrypt DEK with MEK
    let dek_iv = generate_random_iv()?;
    let dek_ciphertext = aes_256_gcm_encrypt(mek, &dek_iv, &dek, AAD_DEK).await?;

    // SECURITY: Prepend IV to ciphertext for storage
    let mut dek_blob = Vec::with_capacity(dek_iv.len().saturating_add(dek_ciphertext.len()));
    dek_blob.extend_from_slice(&dek_iv);
    dek_blob.extend_from_slice(&dek_ciphertext);
    let encrypted_dek = URL_SAFE_NO_PAD.encode(&dek_blob);

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[SECURITY] [ENCRYPTION] Encrypted DEK: {} bytes → {} bytes",
        AES_256_KEY_SIZE,
        dek_blob.len()
    );

    #[cfg(target_arch = "wasm32")]
    console_log!("[SECURITY] [ENCRYPTION] Envelope encryption completed successfully");

    Ok(EncryptedSecret {
        encrypted_secret,
        encrypted_dek,
        version: ENCRYPTION_VERSION_V1,
    })
}

/// Decrypts an HMAC secret using envelope encryption.
///
/// SECURITY: Reverses the encryption process. Decrypts the DEK
/// using the MEK, then decrypts the HMAC secret using the DEK.
///
/// The decrypted secret is returned in a `Zeroizing` wrapper to ensure
/// it is cleared from memory when dropped.
///
/// # Arguments
/// * `encrypted` - Encrypted secret container from KV
/// * `mek` - 32-byte Master Encryption Key from Workers Secrets
///
/// # Returns
/// * `Ok(Zeroizing<Vec<u8>>)` - Decrypted HMAC secret (auto-zeroised on drop)
/// * `Err(ApiError)` - If decryption fails (wrong key, tampered data)
///
/// # Example
/// ```rust,ignore
/// let store = env.secret_store("VERIFIER_MEK")?;
/// let mek = store.get().await?.ok_or_else(|| anyhow::anyhow!("MEK not found"))?;
/// let mek_bytes = base64url_decode(&mek)?;
/// let secret = decrypt_hmac_secret(&encrypted, &mek_bytes).await?;
/// // Use secret, then it's automatically zeroised when dropped
/// ```
pub async fn decrypt_hmac_secret(
    encrypted: &EncryptedSecret,
    mek: &[u8],
) -> ApiResult<Zeroizing<Vec<u8>>> {
    decrypt_hmac_secret_with_fallback(encrypted, mek, None).await
}

/// Decrypts an HMAC secret using envelope encryption with optional fallback MEK.
///
/// SECURITY: During MEK rotation, data may be encrypted with either the current or
/// previous MEK. This function attempts decryption with the primary MEK first, then
/// falls back to `previous_mek` if provided and the primary attempt fails.
///
/// The `version` field on the `EncryptedSecret` is logged to help monitor rotation
/// progress (identifying which key version successfully decrypted the data).
///
/// # Arguments
/// * `encrypted` - Encrypted secret container from KV
/// * `mek` - 32-byte current Master Encryption Key
/// * `previous_mek` - Optional 32-byte previous MEK for rotation fallback
///
/// # Returns
/// * `Ok(Zeroizing<Vec<u8>>)` - Decrypted HMAC secret (auto-zeroised on drop)
/// * `Err(ApiError)` - If decryption fails with both keys
pub async fn decrypt_hmac_secret_with_fallback(
    encrypted: &EncryptedSecret,
    mek: &[u8],
    previous_mek: Option<&[u8]>,
) -> ApiResult<Zeroizing<Vec<u8>>> {
    decrypt_hmac_secret_with_fallback_tracked(encrypted, mek, previous_mek, None).await
}

/// Variant of [`decrypt_hmac_secret_with_fallback`] that records which slot
/// satisfied the decrypt path via `slot_out`. The outparam is left untouched
/// on error and on the no-fallback path; on success it carries
/// [`crate::security::secret_versions::RotationSlot::Current`] when the primary
/// MEK satisfied or `Previous` when the fallback satisfied.
///
/// Callers wire this slot
/// signal into a [`crate::security::secret_versions::SecretVersionLine`] so the
/// per-request log line and the `x-secret-version` response header carry the
/// satisfying-slot fingerprint.
pub async fn decrypt_hmac_secret_with_fallback_tracked(
    encrypted: &EncryptedSecret,
    mek: &[u8],
    previous_mek: Option<&[u8]>,
    slot_out: Option<&mut Option<crate::security::secret_versions::RotationSlot>>,
) -> ApiResult<Zeroizing<Vec<u8>>> {
    use crate::security::secret_versions::RotationSlot;
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[SECURITY] [ENCRYPTION] Starting envelope decryption for HMAC secret (version={})",
        encrypted.version
    );

    // SECURITY: Step 1 - Decode the encrypted DEK blob (shared between primary and fallback)
    let dek_blob = URL_SAFE_NO_PAD
        .decode(&encrypted.encrypted_dek)
        .map_err(|e| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] [ENCRYPTION] [ERROR] Failed to decode encrypted DEK: {}",
                e
            );
            ApiError::Internal(anyhow::anyhow!("Invalid encrypted DEK encoding: {}", e))
        })?;

    if dek_blob.len() < GCM_IV_SIZE + GCM_TAG_SIZE {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Invalid encrypted DEK size: expected at least {}, got {}",
            GCM_IV_SIZE + GCM_TAG_SIZE,
            dek_blob.len()
        )));
    }

    // Length validated above: dek_blob.len() >= GCM_IV_SIZE + GCM_TAG_SIZE.
    let dek_iv = dek_blob
        .get(..GCM_IV_SIZE)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("DEK blob too short for IV")))?;
    let dek_ciphertext = dek_blob
        .get(GCM_IV_SIZE..)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("DEK blob too short for ciphertext")))?;

    // SECURITY: Step 2 - Attempt DEK decryption with primary MEK, fall back to previous MEK
    let (dek, slot_used) = match aes_256_gcm_decrypt(mek, dek_iv, dek_ciphertext, AAD_DEK).await {
        Ok(plaintext) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] [ENCRYPTION] DEK decrypted with current MEK (version={})",
                encrypted.version
            );
            (Zeroizing::new(plaintext), RotationSlot::Current)
        }
        Err(primary_err) => match previous_mek {
            Some(prev) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] [ENCRYPTION] Primary MEK failed, trying previous MEK (version={})",
                    encrypted.version
                );
                let plaintext = aes_256_gcm_decrypt(prev, dek_iv, dek_ciphertext, AAD_DEK)
                    .await
                    .map_err(|_| {
                        // Both keys failed: return the primary error for clearer diagnostics
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            "[SECURITY] [ENCRYPTION] [ERROR] Both current and previous MEK failed for version={}",
                            encrypted.version
                        );
                        primary_err
                    })?;
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] [ENCRYPTION] DEK decrypted with previous MEK (version={}) - rotation in progress",
                    encrypted.version
                );
                (Zeroizing::new(plaintext), RotationSlot::Previous)
            }
            None => {
                return Err(primary_err);
            }
        },
    };
    if let Some(out) = slot_out {
        *out = Some(slot_used);
    }

    #[cfg(target_arch = "wasm32")]
    console_log!("[SECURITY] [ENCRYPTION] Decrypted DEK: {} bytes", dek.len());

    // SECURITY: Step 3 - Decrypt HMAC secret using DEK
    let secret_blob = URL_SAFE_NO_PAD
        .decode(&encrypted.encrypted_secret)
        .map_err(|e| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] [ENCRYPTION] [ERROR] Failed to decode encrypted secret: {}",
                e
            );
            ApiError::Internal(anyhow::anyhow!("Invalid encrypted secret encoding: {}", e))
        })?;

    if secret_blob.len() < GCM_IV_SIZE + GCM_TAG_SIZE {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Invalid encrypted secret size: expected at least {}, got {}",
            GCM_IV_SIZE + GCM_TAG_SIZE,
            secret_blob.len()
        )));
    }

    // Length validated above: secret_blob.len() >= GCM_IV_SIZE + GCM_TAG_SIZE.
    let secret_iv = secret_blob
        .get(..GCM_IV_SIZE)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Secret blob too short for IV")))?;
    let secret_ciphertext = secret_blob.get(GCM_IV_SIZE..).ok_or_else(|| {
        ApiError::Internal(anyhow::anyhow!("Secret blob too short for ciphertext"))
    })?;

    let plaintext_secret =
        aes_256_gcm_decrypt(&dek, secret_iv, secret_ciphertext, AAD_HMAC_SECRET).await?;
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[SECURITY] [ENCRYPTION] Decrypted HMAC secret: {} bytes",
        plaintext_secret.len()
    );

    #[cfg(target_arch = "wasm32")]
    console_log!("[SECURITY] [ENCRYPTION] Envelope decryption completed successfully");

    // SECURITY: Return in Zeroizing container for automatic memory cleanup
    Ok(Zeroizing::new(plaintext_secret))
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::string_slice
)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    KEY GENERATION TESTS                                   */
    /* ========================================================================== */

    #[test]
    fn test_generate_random_key_32_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(32)?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    #[test]
    fn test_generate_random_key_uniqueness() -> Result<(), Box<dyn std::error::Error>> {
        let key1 = generate_random_key(32)?;
        let key2 = generate_random_key(32)?;
        assert_ne!(key1, key2, "Generated keys must be unique");
        Ok(())
    }

    #[test]
    fn test_generate_random_iv() -> Result<(), Box<dyn std::error::Error>> {
        let iv = generate_random_iv()?;
        assert_eq!(iv.len(), GCM_IV_SIZE);
        Ok(())
    }

    #[test]
    fn test_generate_random_iv_uniqueness() -> Result<(), Box<dyn std::error::Error>> {
        let iv1 = generate_random_iv()?;
        let iv2 = generate_random_iv()?;
        assert_ne!(iv1, iv2, "Generated IVs must be unique");
        Ok(())
    }

    /* ========================================================================== */
    /*                    ENCRYPTION/DECRYPTION TESTS                           */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"test-hmac-secret-value";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek).await?;
        let decrypted = decrypt_hmac_secret(&encrypted, &mek).await?;

        assert_eq!(&**decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_encryption_produces_different_ciphertexts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"same-secret";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted1 = encrypt_hmac_secret(plaintext, &mek).await?;
        let encrypted2 = encrypt_hmac_secret(plaintext, &mek).await?;

        // Same plaintext should produce different ciphertexts due to random IVs
        assert_ne!(encrypted1.encrypted_secret, encrypted2.encrypted_secret);
        assert_ne!(encrypted1.encrypted_dek, encrypted2.encrypted_dek);

        // But both should decrypt to the same plaintext
        let decrypted1 = decrypt_hmac_secret(&encrypted1, &mek).await?;
        let decrypted2 = decrypt_hmac_secret(&encrypted2, &mek).await?;
        assert_eq!(&**decrypted1, plaintext);
        assert_eq!(&**decrypted2, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_decryption_with_wrong_mek_fails() -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"secret";
        let mek1 = generate_random_key(AES_256_KEY_SIZE)?;
        let mek2 = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek1).await?;
        let result = decrypt_hmac_secret(&encrypted, &mek2).await;

        assert!(result.is_err(), "Decryption with wrong MEK should fail");
        Ok(())
    }

    #[tokio::test]
    async fn test_decryption_with_tampered_ciphertext_fails(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"secret";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let mut encrypted = encrypt_hmac_secret(plaintext, &mek).await?;

        // Tamper with the encrypted secret
        let mut bytes = URL_SAFE_NO_PAD.decode(&encrypted.encrypted_secret)?;
        if !bytes.is_empty() {
            let len = bytes.len();
            bytes[len - 1] ^= 1; // Flip one bit
        }
        encrypted.encrypted_secret = URL_SAFE_NO_PAD.encode(&bytes);

        let result = decrypt_hmac_secret(&encrypted, &mek).await;
        assert!(result.is_err(), "Decryption of tampered data should fail");
        Ok(())
    }

    #[tokio::test]
    async fn test_encrypted_secret_version() -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"secret";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek).await?;
        assert_eq!(encrypted.version, ENCRYPTION_VERSION_V1);
        Ok(())
    }

    #[tokio::test]
    async fn test_empty_plaintext_encryption() -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek).await?;
        let decrypted = decrypt_hmac_secret(&encrypted, &mek).await?;

        assert_eq!(&**decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_large_plaintext_encryption() -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = vec![0x42u8; 1024]; // 1KB of data
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(&plaintext, &mek).await?;
        let decrypted = decrypt_hmac_secret(&encrypted, &mek).await?;

        assert_eq!(&**decrypted, &plaintext[..]);
        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_base64_encrypted_secret() -> Result<(), Box<dyn std::error::Error>> {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let encrypted = EncryptedSecret {
            encrypted_secret: "invalid!base64!".to_string(),
            encrypted_dek: URL_SAFE_NO_PAD.encode([0u8; 32]),
            version: 1,
        };

        let result = decrypt_hmac_secret(&encrypted, &mek).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_base64_encrypted_dek() -> Result<(), Box<dyn std::error::Error>> {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let encrypted = EncryptedSecret {
            encrypted_secret: URL_SAFE_NO_PAD.encode([0u8; 32]),
            encrypted_dek: "invalid!base64!".to_string(),
            version: 1,
        };

        let result = decrypt_hmac_secret(&encrypted, &mek).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_truncated_encrypted_secret() -> Result<(), Box<dyn std::error::Error>> {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let encrypted = EncryptedSecret {
            encrypted_secret: URL_SAFE_NO_PAD.encode([0u8; 10]), // Too short
            encrypted_dek: URL_SAFE_NO_PAD.encode([0u8; 32]),
            version: 1,
        };

        let result = decrypt_hmac_secret(&encrypted, &mek).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_truncated_encrypted_dek() -> Result<(), Box<dyn std::error::Error>> {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let encrypted = EncryptedSecret {
            encrypted_secret: URL_SAFE_NO_PAD.encode([0u8; 32]),
            encrypted_dek: URL_SAFE_NO_PAD.encode([0u8; 10]), // Too short
            version: 1,
        };

        let result = decrypt_hmac_secret(&encrypted, &mek).await;
        assert!(result.is_err());
        Ok(())
    }

    /* ========================================================================== */
    /*                    ZEROISATION TESTS                                     */
    /* ========================================================================== */

    #[test]
    fn test_encrypted_secret_zeroisation() {
        let mut encrypted = EncryptedSecret {
            encrypted_secret: "test123".to_string(),
            encrypted_dek: "dek456".to_string(),
            version: 1,
        };

        encrypted.zeroize();

        assert_eq!(encrypted.encrypted_secret, "");
        assert_eq!(encrypted.encrypted_dek, "");
        assert_eq!(encrypted.version, 0);
    }

    #[tokio::test]
    async fn test_decrypted_secret_zeroisation_on_drop() -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"sensitive-secret";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek).await?;

        {
            let _decrypted = decrypt_hmac_secret(&encrypted, &mek).await?;
            // _decrypted should be zeroized when it goes out of scope
        }

        // No way to verify zeroisation directly in safe Rust,
        // but Zeroizing guarantees this behaviour
        Ok(())
    }

    /* ========================================================================== */
    /*                    DUAL-KEY FALLBACK TESTS                               */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_decrypt_with_fallback_primary_key() -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"test-secret";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let old_mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek).await?;
        let decrypted = decrypt_hmac_secret_with_fallback(&encrypted, &mek, Some(&old_mek)).await?;

        assert_eq!(&**decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_decrypt_with_fallback_previous_key() -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"test-secret-rotated";
        let old_mek = generate_random_key(AES_256_KEY_SIZE)?;
        let new_mek = generate_random_key(AES_256_KEY_SIZE)?;

        // Encrypt with old MEK (simulating pre-rotation data)
        let encrypted = encrypt_hmac_secret(plaintext, &old_mek).await?;

        // Decrypt with new MEK as primary, old MEK as fallback
        let decrypted =
            decrypt_hmac_secret_with_fallback(&encrypted, &new_mek, Some(&old_mek)).await?;

        assert_eq!(&**decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_decrypt_with_fallback_both_keys_fail() -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"test-secret";
        let original_mek = generate_random_key(AES_256_KEY_SIZE)?;
        let wrong_mek1 = generate_random_key(AES_256_KEY_SIZE)?;
        let wrong_mek2 = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &original_mek).await?;
        let result =
            decrypt_hmac_secret_with_fallback(&encrypted, &wrong_mek1, Some(&wrong_mek2)).await;

        assert!(result.is_err(), "Both wrong keys should fail");
        Ok(())
    }

    #[tokio::test]
    async fn test_decrypt_with_fallback_no_previous_key() -> Result<(), Box<dyn std::error::Error>>
    {
        let plaintext = b"test-secret";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek).await?;

        // Without previous_mek, behaves same as decrypt_hmac_secret
        let decrypted = decrypt_hmac_secret_with_fallback(&encrypted, &mek, None).await?;
        assert_eq!(&**decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_decrypt_with_fallback_no_previous_key_wrong_primary(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"test-secret";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let wrong_mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek).await?;
        let result = decrypt_hmac_secret_with_fallback(&encrypted, &wrong_mek, None).await;

        assert!(
            result.is_err(),
            "Wrong primary key with no fallback should fail"
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                  */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    /* ========================================================================== */
    /*                    CONSTANTS AND CRYPTO PARAMETER TESTS                 */
    /* ========================================================================== */

    #[test]
    fn test_encryption_version_constant() {
        assert_eq!(ENCRYPTION_VERSION_V1, 1);
    }

    #[test]
    fn test_aad_constants_have_content() {
        // AAD constants must contain meaningful context strings.
        assert!(AAD_HMAC_SECRET.starts_with(b"provii-"));
        assert!(AAD_DEK.starts_with(b"provii-"));
    }

    #[test]
    fn test_aad_constants_are_distinct() {
        // SECURITY: Different AAD for different encryption contexts prevents
        // substitution attacks.
        assert_ne!(AAD_HMAC_SECRET, AAD_DEK);
    }

    #[test]
    fn test_aes_256_key_size_is_32() {
        assert_eq!(AES_256_KEY_SIZE, 32);
    }

    #[test]
    fn test_gcm_iv_size_is_12() {
        assert_eq!(GCM_IV_SIZE, 12);
    }

    #[test]
    fn test_gcm_tag_size_is_16() {
        assert_eq!(GCM_TAG_SIZE, 16);
    }

    /* ========================================================================== */
    /*                    ENCRYPTED SECRET STRUCT TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_encrypted_secret_debug_redacts_secret_fields() {
        let secret = EncryptedSecret {
            encrypted_secret: "super-secret-ciphertext".to_string(),
            encrypted_dek: "super-secret-dek".to_string(),
            version: 1,
        };
        let debug_str = format!("{:?}", secret);
        // SECURITY: debug output must NOT contain the actual ciphertext values.
        assert!(!debug_str.contains("super-secret-ciphertext"));
        assert!(!debug_str.contains("super-secret-dek"));
        // But it should show [REDACTED] and the version.
        assert!(debug_str.contains("[REDACTED]"));
        assert!(debug_str.contains("1"));
    }

    #[test]
    fn test_encrypted_secret_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let secret = EncryptedSecret {
            encrypted_secret: "enc_secret_b64".to_string(),
            encrypted_dek: "enc_dek_b64".to_string(),
            version: 1,
        };
        let json = serde_json::to_string(&secret)?;
        let decoded: EncryptedSecret = serde_json::from_str(&json)?;
        assert_eq!(decoded.encrypted_secret, "enc_secret_b64");
        assert_eq!(decoded.encrypted_dek, "enc_dek_b64");
        assert_eq!(decoded.version, 1);
        Ok(())
    }

    #[test]
    fn test_encrypted_secret_partial_eq() {
        let a = EncryptedSecret {
            encrypted_secret: "same".to_string(),
            encrypted_dek: "same_dek".to_string(),
            version: 1,
        };
        let b = EncryptedSecret {
            encrypted_secret: "same".to_string(),
            encrypted_dek: "same_dek".to_string(),
            version: 1,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_encrypted_secret_partial_eq_different_version() {
        let a = EncryptedSecret {
            encrypted_secret: "same".to_string(),
            encrypted_dek: "same_dek".to_string(),
            version: 1,
        };
        let b = EncryptedSecret {
            encrypted_secret: "same".to_string(),
            encrypted_dek: "same_dek".to_string(),
            version: 2,
        };
        assert_ne!(a, b);
    }

    /* ========================================================================== */
    /*                    RANDOM GENERATION EDGE CASE TESTS                     */
    /* ========================================================================== */

    #[test]
    fn test_generate_random_key_zero_size() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(0)?;
        assert_eq!(key.len(), 0);
        Ok(())
    }

    #[test]
    fn test_generate_random_key_one_byte() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(1)?;
        assert_eq!(key.len(), 1);
        Ok(())
    }

    #[test]
    fn test_generate_random_key_64_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(64)?;
        assert_eq!(key.len(), 64);
        Ok(())
    }

    #[test]
    fn test_generate_random_key_not_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        // A CSPRNG key of 32 bytes should have at least one non-zero byte.
        // The probability of all zeros from a proper CSPRNG is 2^-256,
        // so if this fails something is fundamentally broken.
        let key = generate_random_key(32)?;
        assert!(key.iter().any(|&b| b != 0), "CSPRNG produced all-zero key");
        Ok(())
    }

    /* ========================================================================== */
    /*                    AES-256-GCM NATIVE ENCRYPT/DECRYPT TESTS             */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_aes_256_gcm_encrypt_wrong_key_size_rejects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let short_key = vec![0u8; 16]; // 128-bit, not 256-bit
        let iv = [0u8; GCM_IV_SIZE];
        let result = aes_256_gcm_encrypt(&short_key, &iv, b"test", b"aad").await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_decrypt_wrong_key_size_rejects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let short_key = vec![0u8; 16]; // 128-bit, not 256-bit
        let iv = [0u8; GCM_IV_SIZE];
        let result = aes_256_gcm_decrypt(&short_key, &iv, b"ciphertext", b"aad").await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_roundtrip_with_aad() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(AES_256_KEY_SIZE)?;
        let iv = generate_random_iv()?;
        let plaintext = b"hello world";
        let aad = b"context-binding-data";

        let ciphertext = aes_256_gcm_encrypt(&key, &iv, plaintext, aad).await?;
        let decrypted = aes_256_gcm_decrypt(&key, &iv, &ciphertext, aad).await?;
        assert_eq!(&decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_wrong_aad_rejects() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(AES_256_KEY_SIZE)?;
        let iv = generate_random_iv()?;
        let plaintext = b"hello world";

        let ciphertext = aes_256_gcm_encrypt(&key, &iv, plaintext, b"correct-aad").await?;
        let result = aes_256_gcm_decrypt(&key, &iv, &ciphertext, b"wrong-aad").await;
        assert!(result.is_err(), "Mismatched AAD must fail decryption");
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_wrong_iv_rejects() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(AES_256_KEY_SIZE)?;
        let iv1 = generate_random_iv()?;
        let iv2 = generate_random_iv()?;
        let plaintext = b"hello world";
        let aad = b"test-aad";

        let ciphertext = aes_256_gcm_encrypt(&key, &iv1, plaintext, aad).await?;
        let result = aes_256_gcm_decrypt(&key, &iv2, &ciphertext, aad).await;
        assert!(result.is_err(), "Mismatched IV must fail decryption");
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_ciphertext_includes_tag() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(AES_256_KEY_SIZE)?;
        let iv = generate_random_iv()?;
        let plaintext = b"test";
        let aad = b"test-aad";

        let ciphertext = aes_256_gcm_encrypt(&key, &iv, plaintext, aad).await?;
        // Ciphertext = plaintext_len + GCM_TAG_SIZE (16 bytes)
        assert_eq!(ciphertext.len(), plaintext.len() + GCM_TAG_SIZE);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ENVELOPE ENCRYPTION EDGE CASES                        */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_encrypt_hmac_secret_sets_version_v1() -> Result<(), Box<dyn std::error::Error>> {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let encrypted = encrypt_hmac_secret(b"secret", &mek).await?;
        assert_eq!(encrypted.version, ENCRYPTION_VERSION_V1);
        Ok(())
    }

    #[tokio::test]
    async fn test_encrypt_hmac_secret_produces_valid_base64_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let encrypted = encrypt_hmac_secret(b"my-secret", &mek).await?;

        // Both fields must be valid base64url-no-pad.
        let secret_bytes = URL_SAFE_NO_PAD.decode(&encrypted.encrypted_secret);
        assert!(
            secret_bytes.is_ok(),
            "encrypted_secret must be valid base64url"
        );

        let dek_bytes = URL_SAFE_NO_PAD.decode(&encrypted.encrypted_dek);
        assert!(dek_bytes.is_ok(), "encrypted_dek must be valid base64url");
        Ok(())
    }

    #[tokio::test]
    async fn test_encrypted_secret_blob_contains_iv_plus_ciphertext(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let encrypted = encrypt_hmac_secret(b"test-data", &mek).await?;

        let secret_blob = URL_SAFE_NO_PAD.decode(&encrypted.encrypted_secret)?;
        // The blob is: IV (12 bytes) + ciphertext (plaintext_len bytes) + tag (16 bytes)
        let expected_len = GCM_IV_SIZE + 9 + GCM_TAG_SIZE; // 9 = len("test-data")
        assert_eq!(secret_blob.len(), expected_len);

        let dek_blob = URL_SAFE_NO_PAD.decode(&encrypted.encrypted_dek)?;
        // DEK blob: IV (12) + encrypted-DEK (32) + tag (16) = 60
        let expected_dek_len = GCM_IV_SIZE + AES_256_KEY_SIZE + GCM_TAG_SIZE;
        assert_eq!(dek_blob.len(), expected_dek_len);
        Ok(())
    }

    #[tokio::test]
    async fn test_decrypt_with_invalid_dek_blob_too_short() -> Result<(), Box<dyn std::error::Error>>
    {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        // DEK blob must be at least GCM_IV_SIZE + GCM_TAG_SIZE = 28 bytes.
        // A 5-byte blob is too short.
        let encrypted = EncryptedSecret {
            encrypted_secret: URL_SAFE_NO_PAD.encode([0u8; 64]),
            encrypted_dek: URL_SAFE_NO_PAD.encode([0u8; 5]),
            version: 1,
        };

        let result = decrypt_hmac_secret(&encrypted, &mek).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_decrypt_with_invalid_secret_blob_too_short(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        // First encrypt normally to get a valid DEK blob.
        let good = encrypt_hmac_secret(b"test", &mek).await?;

        // Replace only the secret blob with a truncated one.
        let mut bad = good.clone();
        bad.encrypted_secret = URL_SAFE_NO_PAD.encode([0u8; 5]);

        let result = decrypt_hmac_secret(&bad, &mek).await;
        assert!(result.is_err());
        Ok(())
    }

    /* ========================================================================== */
    /*                    DUAL-KEY FALLBACK TRACKED TESTS                       */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_decrypt_with_fallback_tracked_reports_current_slot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::security::secret_versions::RotationSlot;

        let plaintext = b"tracked-current";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let old_mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek).await?;
        let mut slot_out: Option<RotationSlot> = None;
        let decrypted = decrypt_hmac_secret_with_fallback_tracked(
            &encrypted,
            &mek,
            Some(&old_mek),
            Some(&mut slot_out),
        )
        .await?;

        assert_eq!(&**decrypted, plaintext);
        assert_eq!(slot_out, Some(RotationSlot::Current));
        Ok(())
    }

    #[tokio::test]
    async fn test_decrypt_with_fallback_tracked_reports_previous_slot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::security::secret_versions::RotationSlot;

        let plaintext = b"tracked-previous";
        let old_mek = generate_random_key(AES_256_KEY_SIZE)?;
        let new_mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &old_mek).await?;
        let mut slot_out: Option<RotationSlot> = None;
        let decrypted = decrypt_hmac_secret_with_fallback_tracked(
            &encrypted,
            &new_mek,
            Some(&old_mek),
            Some(&mut slot_out),
        )
        .await?;

        assert_eq!(&**decrypted, plaintext);
        assert_eq!(slot_out, Some(RotationSlot::Previous));
        Ok(())
    }

    #[tokio::test]
    async fn test_decrypt_with_fallback_tracked_slot_none_on_no_outparam(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"no-outparam";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek).await?;
        // Pass None for slot_out: the function must still decrypt successfully.
        let decrypted =
            decrypt_hmac_secret_with_fallback_tracked(&encrypted, &mek, None, None).await?;

        assert_eq!(&**decrypted, plaintext);
        Ok(())
    }

    /* ========================================================================== */
    /*                    AES-256-GCM KEY SIZE EDGE CASES                      */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_aes_256_gcm_encrypt_oversized_key_rejects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let big_key = vec![0u8; 64]; // 512-bit, not 256-bit
        let iv = [0u8; GCM_IV_SIZE];
        let result = aes_256_gcm_encrypt(&big_key, &iv, b"test", b"aad").await;
        assert!(result.is_err(), "Oversized key must be rejected");
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_decrypt_oversized_key_rejects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let big_key = vec![0u8; 64];
        let iv = [0u8; GCM_IV_SIZE];
        let result = aes_256_gcm_decrypt(&big_key, &iv, b"ciphertext", b"aad").await;
        assert!(result.is_err(), "Oversized key must be rejected");
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_encrypt_empty_key_rejects() -> Result<(), Box<dyn std::error::Error>>
    {
        let iv = [0u8; GCM_IV_SIZE];
        let result = aes_256_gcm_encrypt(&[], &iv, b"test", b"aad").await;
        assert!(result.is_err(), "Empty key must be rejected");
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_decrypt_empty_key_rejects() -> Result<(), Box<dyn std::error::Error>>
    {
        let iv = [0u8; GCM_IV_SIZE];
        let result = aes_256_gcm_decrypt(&[], &iv, b"ciphertext", b"aad").await;
        assert!(result.is_err(), "Empty key must be rejected");
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_encrypt_one_byte_key_rejects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let iv = [0u8; GCM_IV_SIZE];
        let result = aes_256_gcm_encrypt(&[0xAA], &iv, b"test", b"aad").await;
        assert!(result.is_err(), "1-byte key must be rejected");
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_decrypt_one_byte_key_rejects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let iv = [0u8; GCM_IV_SIZE];
        let result = aes_256_gcm_decrypt(&[0xAA], &iv, b"ciphertext", b"aad").await;
        assert!(result.is_err(), "1-byte key must be rejected");
        Ok(())
    }

    /* ========================================================================== */
    /*                    AES-256-GCM EMPTY PLAINTEXT / AAD TESTS                */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_aes_256_gcm_roundtrip_empty_plaintext() -> Result<(), Box<dyn std::error::Error>>
    {
        let key = generate_random_key(AES_256_KEY_SIZE)?;
        let iv = generate_random_iv()?;
        let plaintext = b"";
        let aad = b"context";

        let ciphertext = aes_256_gcm_encrypt(&key, &iv, plaintext, aad).await?;
        // Empty plaintext still produces a GCM tag
        assert_eq!(ciphertext.len(), GCM_TAG_SIZE);

        let decrypted = aes_256_gcm_decrypt(&key, &iv, &ciphertext, aad).await?;
        assert!(decrypted.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_roundtrip_empty_aad() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(AES_256_KEY_SIZE)?;
        let iv = generate_random_iv()?;
        let plaintext = b"data-with-no-aad";
        let aad = b"";

        let ciphertext = aes_256_gcm_encrypt(&key, &iv, plaintext, aad).await?;
        let decrypted = aes_256_gcm_decrypt(&key, &iv, &ciphertext, aad).await?;
        assert_eq!(&decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_roundtrip_both_empty() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(AES_256_KEY_SIZE)?;
        let iv = generate_random_iv()?;

        let ciphertext = aes_256_gcm_encrypt(&key, &iv, b"", b"").await?;
        let decrypted = aes_256_gcm_decrypt(&key, &iv, &ciphertext, b"").await?;
        assert!(decrypted.is_empty());
        Ok(())
    }

    /* ========================================================================== */
    /*                    AES-256-GCM TAMPER DETECTION TESTS                     */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_aes_256_gcm_decrypt_truncated_ciphertext_fails(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(AES_256_KEY_SIZE)?;
        let iv = generate_random_iv()?;
        let plaintext = b"some-data-here";
        let aad = b"test-aad";

        let ciphertext = aes_256_gcm_encrypt(&key, &iv, plaintext, aad).await?;
        // Truncate so the tag is incomplete
        let truncated = &ciphertext[..ciphertext.len() - 1];
        let result = aes_256_gcm_decrypt(&key, &iv, truncated, aad).await;
        assert!(result.is_err(), "Truncated ciphertext must fail decryption");
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_decrypt_empty_ciphertext_fails(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(AES_256_KEY_SIZE)?;
        let iv = generate_random_iv()?;
        // Empty ciphertext has no tag at all
        let result = aes_256_gcm_decrypt(&key, &iv, b"", b"aad").await;
        assert!(result.is_err(), "Empty ciphertext must fail decryption");
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_decrypt_flipped_bit_in_ciphertext(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(AES_256_KEY_SIZE)?;
        let iv = generate_random_iv()?;
        let plaintext = b"bit-flip-test";
        let aad = b"test-aad";

        let mut ciphertext = aes_256_gcm_encrypt(&key, &iv, plaintext, aad).await?;
        // Flip a bit in the first byte of ciphertext (before the tag)
        ciphertext[0] ^= 0x01;
        let result = aes_256_gcm_decrypt(&key, &iv, &ciphertext, aad).await;
        assert!(
            result.is_err(),
            "Bit-flipped ciphertext must fail decryption"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_decrypt_wrong_key_fails() -> Result<(), Box<dyn std::error::Error>> {
        let key1 = generate_random_key(AES_256_KEY_SIZE)?;
        let key2 = generate_random_key(AES_256_KEY_SIZE)?;
        let iv = generate_random_iv()?;
        let plaintext = b"key-mismatch-test";
        let aad = b"aad";

        let ciphertext = aes_256_gcm_encrypt(&key1, &iv, plaintext, aad).await?;
        let result = aes_256_gcm_decrypt(&key2, &iv, &ciphertext, aad).await;
        assert!(result.is_err(), "Wrong key must fail decryption");
        Ok(())
    }

    /* ========================================================================== */
    /*                    ENVELOPE ENCRYPTION: DEK TAMPERING                     */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_decryption_with_tampered_dek_blob_fails() -> Result<(), Box<dyn std::error::Error>>
    {
        let plaintext = b"tamper-dek-test";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let mut encrypted = encrypt_hmac_secret(plaintext, &mek).await?;

        // Tamper with the encrypted DEK
        let mut dek_bytes = URL_SAFE_NO_PAD.decode(&encrypted.encrypted_dek)?;
        if !dek_bytes.is_empty() {
            let len = dek_bytes.len();
            dek_bytes[len - 1] ^= 1;
        }
        encrypted.encrypted_dek = URL_SAFE_NO_PAD.encode(&dek_bytes);

        let result = decrypt_hmac_secret(&encrypted, &mek).await;
        assert!(result.is_err(), "Tampered DEK blob must fail decryption");
        Ok(())
    }

    #[tokio::test]
    async fn test_decryption_with_swapped_secret_and_dek_fails(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"swap-test";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek).await?;

        // Swap encrypted_secret and encrypted_dek: AAD mismatch should cause failure
        let swapped = EncryptedSecret {
            encrypted_secret: encrypted.encrypted_dek.clone(),
            encrypted_dek: encrypted.encrypted_secret.clone(),
            version: encrypted.version,
        };

        let result = decrypt_hmac_secret(&swapped, &mek).await;
        assert!(
            result.is_err(),
            "Swapped secret/DEK fields must fail due to AAD mismatch"
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    ENVELOPE ENCRYPTION: MEK SIZE VALIDATION               */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_encrypt_hmac_secret_with_short_mek_fails(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let short_mek = vec![0u8; 16];
        let result = encrypt_hmac_secret(b"secret", &short_mek).await;
        assert!(result.is_err(), "16-byte MEK must be rejected");
        Ok(())
    }

    #[tokio::test]
    async fn test_encrypt_hmac_secret_with_oversized_mek_fails(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let big_mek = vec![0u8; 64];
        let result = encrypt_hmac_secret(b"secret", &big_mek).await;
        assert!(result.is_err(), "64-byte MEK must be rejected");
        Ok(())
    }

    #[tokio::test]
    async fn test_encrypt_hmac_secret_with_empty_mek_fails(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = encrypt_hmac_secret(b"secret", &[]).await;
        assert!(result.is_err(), "Empty MEK must be rejected");
        Ok(())
    }

    #[tokio::test]
    async fn test_decrypt_hmac_secret_with_short_mek_fails(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let encrypted = encrypt_hmac_secret(b"secret", &mek).await?;

        let short_mek = vec![0u8; 16];
        let result = decrypt_hmac_secret(&encrypted, &short_mek).await;
        assert!(result.is_err(), "16-byte MEK must be rejected for decrypt");
        Ok(())
    }

    #[tokio::test]
    async fn test_decrypt_hmac_secret_with_oversized_mek_fails(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let encrypted = encrypt_hmac_secret(b"secret", &mek).await?;

        let big_mek = vec![0u8; 64];
        let result = decrypt_hmac_secret(&encrypted, &big_mek).await;
        assert!(result.is_err(), "64-byte MEK must be rejected for decrypt");
        Ok(())
    }

    /* ========================================================================== */
    /*                    ENCRYPTED SECRET STRUCT EDGE CASES                     */
    /* ========================================================================== */

    #[test]
    fn test_encrypted_secret_clone() {
        let original = EncryptedSecret {
            encrypted_secret: "sec_data".to_string(),
            encrypted_dek: "dek_data".to_string(),
            version: 1,
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_encrypted_secret_partial_eq_different_secret() {
        let a = EncryptedSecret {
            encrypted_secret: "aaa".to_string(),
            encrypted_dek: "same_dek".to_string(),
            version: 1,
        };
        let b = EncryptedSecret {
            encrypted_secret: "bbb".to_string(),
            encrypted_dek: "same_dek".to_string(),
            version: 1,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_encrypted_secret_partial_eq_different_dek() {
        let a = EncryptedSecret {
            encrypted_secret: "same_secret".to_string(),
            encrypted_dek: "dek_a".to_string(),
            version: 1,
        };
        let b = EncryptedSecret {
            encrypted_secret: "same_secret".to_string(),
            encrypted_dek: "dek_b".to_string(),
            version: 1,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_encrypted_secret_debug_shows_version() {
        let secret = EncryptedSecret {
            encrypted_secret: "x".to_string(),
            encrypted_dek: "y".to_string(),
            version: 42,
        };
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("42"));
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("\"x\""));
        assert!(!debug_str.contains("\"y\""));
    }

    #[test]
    fn test_encrypted_secret_debug_version_zero() {
        let secret = EncryptedSecret {
            encrypted_secret: "data".to_string(),
            encrypted_dek: "key".to_string(),
            version: 0,
        };
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("0"));
        assert!(!debug_str.contains("data"));
        assert!(!debug_str.contains("key"));
    }

    #[test]
    fn test_encrypted_secret_debug_version_max() {
        let secret = EncryptedSecret {
            encrypted_secret: "s".to_string(),
            encrypted_dek: "d".to_string(),
            version: u8::MAX,
        };
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("255"));
    }

    #[test]
    fn test_encrypted_secret_serde_version_zero() -> Result<(), Box<dyn std::error::Error>> {
        let secret = EncryptedSecret {
            encrypted_secret: "a".to_string(),
            encrypted_dek: "b".to_string(),
            version: 0,
        };
        let json = serde_json::to_string(&secret)?;
        let decoded: EncryptedSecret = serde_json::from_str(&json)?;
        assert_eq!(decoded.version, 0);
        Ok(())
    }

    #[test]
    fn test_encrypted_secret_serde_version_max() -> Result<(), Box<dyn std::error::Error>> {
        let secret = EncryptedSecret {
            encrypted_secret: "a".to_string(),
            encrypted_dek: "b".to_string(),
            version: u8::MAX,
        };
        let json = serde_json::to_string(&secret)?;
        let decoded: EncryptedSecret = serde_json::from_str(&json)?;
        assert_eq!(decoded.version, u8::MAX);
        Ok(())
    }

    #[test]
    fn test_encrypted_secret_serde_preserves_all_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let secret = EncryptedSecret {
            encrypted_secret: "long-secret-string-here".to_string(),
            encrypted_dek: "long-dek-string-here".to_string(),
            version: 7,
        };
        let json = serde_json::to_string(&secret)?;
        let decoded: EncryptedSecret = serde_json::from_str(&json)?;
        assert_eq!(decoded.encrypted_secret, "long-secret-string-here");
        assert_eq!(decoded.encrypted_dek, "long-dek-string-here");
        assert_eq!(decoded.version, 7);
        Ok(())
    }

    #[test]
    fn test_encrypted_secret_deserialise_from_raw_json() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"encrypted_secret":"abc","encrypted_dek":"def","version":2}"#;
        let decoded: EncryptedSecret = serde_json::from_str(json)?;
        assert_eq!(decoded.encrypted_secret, "abc");
        assert_eq!(decoded.encrypted_dek, "def");
        assert_eq!(decoded.version, 2);
        Ok(())
    }

    #[test]
    fn test_encrypted_secret_deserialise_missing_field_fails() {
        let json = r#"{"encrypted_secret":"abc","version":1}"#;
        let result: Result<EncryptedSecret, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "Missing encrypted_dek must fail deserialisation"
        );
    }

    #[test]
    fn test_encrypted_secret_deserialise_wrong_version_type_fails() {
        let json = r#"{"encrypted_secret":"abc","encrypted_dek":"def","version":"not_a_number"}"#;
        let result: Result<EncryptedSecret, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "Non-numeric version must fail deserialisation"
        );
    }

    /* ========================================================================== */
    /*                    ZEROISATION EDGE CASES                                 */
    /* ========================================================================== */

    #[test]
    fn test_encrypted_secret_zeroisation_already_empty() {
        let mut encrypted = EncryptedSecret {
            encrypted_secret: String::new(),
            encrypted_dek: String::new(),
            version: 0,
        };
        encrypted.zeroize();
        assert_eq!(encrypted.encrypted_secret, "");
        assert_eq!(encrypted.encrypted_dek, "");
        assert_eq!(encrypted.version, 0);
    }

    #[test]
    fn test_encrypted_secret_zeroisation_large_data() {
        let mut encrypted = EncryptedSecret {
            encrypted_secret: "x".repeat(10_000),
            encrypted_dek: "y".repeat(10_000),
            version: 255,
        };
        encrypted.zeroize();
        assert_eq!(encrypted.encrypted_secret, "");
        assert_eq!(encrypted.encrypted_dek, "");
        assert_eq!(encrypted.version, 0);
    }

    #[test]
    fn test_encrypted_secret_double_zeroise() {
        let mut encrypted = EncryptedSecret {
            encrypted_secret: "data".to_string(),
            encrypted_dek: "key".to_string(),
            version: 5,
        };
        encrypted.zeroize();
        encrypted.zeroize();
        assert_eq!(encrypted.encrypted_secret, "");
        assert_eq!(encrypted.encrypted_dek, "");
        assert_eq!(encrypted.version, 0);
    }

    /* ========================================================================== */
    /*                    RANDOM GENERATION ADDITIONAL TESTS                     */
    /* ========================================================================== */

    #[test]
    fn test_generate_random_key_256_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(256)?;
        assert_eq!(key.len(), 256);
        Ok(())
    }

    #[test]
    fn test_generate_random_iv_not_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let iv = generate_random_iv()?;
        assert!(
            iv.iter().any(|&b| b != 0),
            "CSPRNG IV should not be all zeros"
        );
        Ok(())
    }

    #[test]
    fn test_generate_random_key_returns_zeroizing() -> Result<(), Box<dyn std::error::Error>> {
        // Verify the returned key is wrapped in Zeroizing
        let key: Zeroizing<Vec<u8>> = generate_random_key(32)?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    /* ========================================================================== */
    /*                    AAD CONSTANT VALUE TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_aad_hmac_secret_content() {
        assert_eq!(AAD_HMAC_SECRET, b"provii-hmac-secret-v1");
    }

    #[test]
    fn test_aad_dek_content() {
        assert_eq!(AAD_DEK, b"provii-dek-v1");
    }

    #[test]
    fn test_aad_constants_are_ascii() {
        assert!(AAD_HMAC_SECRET.iter().all(|&b| b.is_ascii()));
        assert!(AAD_DEK.iter().all(|&b| b.is_ascii()));
    }

    /* ========================================================================== */
    /*                    ENVELOPE BLOB STRUCTURE VALIDATION                     */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_encrypted_secret_blob_iv_prefix_is_unique_per_encrypt(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let enc1 = encrypt_hmac_secret(b"same", &mek).await?;
        let enc2 = encrypt_hmac_secret(b"same", &mek).await?;

        let blob1 = URL_SAFE_NO_PAD.decode(&enc1.encrypted_secret)?;
        let blob2 = URL_SAFE_NO_PAD.decode(&enc2.encrypted_secret)?;

        // First 12 bytes are the IV; they must differ between encryptions
        let iv1 = &blob1[..GCM_IV_SIZE];
        let iv2 = &blob2[..GCM_IV_SIZE];
        assert_ne!(iv1, iv2, "IVs must be unique across encryptions");
        Ok(())
    }

    #[tokio::test]
    async fn test_encrypted_dek_blob_iv_prefix_is_unique_per_encrypt(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let enc1 = encrypt_hmac_secret(b"data", &mek).await?;
        let enc2 = encrypt_hmac_secret(b"data", &mek).await?;

        let blob1 = URL_SAFE_NO_PAD.decode(&enc1.encrypted_dek)?;
        let blob2 = URL_SAFE_NO_PAD.decode(&enc2.encrypted_dek)?;

        let iv1 = &blob1[..GCM_IV_SIZE];
        let iv2 = &blob2[..GCM_IV_SIZE];
        assert_ne!(iv1, iv2, "DEK IVs must be unique across encryptions");
        Ok(())
    }

    #[tokio::test]
    async fn test_encrypted_secret_blob_minimum_size() -> Result<(), Box<dyn std::error::Error>> {
        // Even for empty plaintext, the blob must contain IV + tag
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let encrypted = encrypt_hmac_secret(b"", &mek).await?;

        let secret_blob = URL_SAFE_NO_PAD.decode(&encrypted.encrypted_secret)?;
        assert!(
            secret_blob.len() >= GCM_IV_SIZE + GCM_TAG_SIZE,
            "Secret blob must be at least IV + tag size"
        );

        let dek_blob = URL_SAFE_NO_PAD.decode(&encrypted.encrypted_dek)?;
        assert!(
            dek_blob.len() >= GCM_IV_SIZE + GCM_TAG_SIZE,
            "DEK blob must be at least IV + tag size"
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    FALLBACK TRACKED: ERROR PATHS                          */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_decrypt_with_fallback_tracked_both_fail_slot_untouched(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::security::secret_versions::RotationSlot;

        let plaintext = b"both-fail-tracked";
        let real_mek = generate_random_key(AES_256_KEY_SIZE)?;
        let wrong_mek1 = generate_random_key(AES_256_KEY_SIZE)?;
        let wrong_mek2 = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &real_mek).await?;
        let mut slot_out: Option<RotationSlot> = None;
        let result = decrypt_hmac_secret_with_fallback_tracked(
            &encrypted,
            &wrong_mek1,
            Some(&wrong_mek2),
            Some(&mut slot_out),
        )
        .await;

        assert!(result.is_err(), "Both wrong keys must fail");
        assert_eq!(slot_out, None, "slot_out must remain None on error");
        Ok(())
    }

    #[tokio::test]
    async fn test_decrypt_with_fallback_tracked_no_fallback_wrong_primary_slot_untouched(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::security::secret_versions::RotationSlot;

        let plaintext = b"no-fallback-fail";
        let real_mek = generate_random_key(AES_256_KEY_SIZE)?;
        let wrong_mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &real_mek).await?;
        let mut slot_out: Option<RotationSlot> = None;
        let result = decrypt_hmac_secret_with_fallback_tracked(
            &encrypted,
            &wrong_mek,
            None,
            Some(&mut slot_out),
        )
        .await;

        assert!(result.is_err(), "Wrong primary with no fallback must fail");
        assert_eq!(slot_out, None, "slot_out must remain None on error");
        Ok(())
    }

    #[tokio::test]
    async fn test_decrypt_with_fallback_tracked_current_slot_no_fallback(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::security::secret_versions::RotationSlot;

        let plaintext = b"current-no-fallback";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek).await?;
        let mut slot_out: Option<RotationSlot> = None;
        let decrypted =
            decrypt_hmac_secret_with_fallback_tracked(&encrypted, &mek, None, Some(&mut slot_out))
                .await?;

        assert_eq!(&**decrypted, plaintext);
        assert_eq!(slot_out, Some(RotationSlot::Current));
        Ok(())
    }

    /* ========================================================================== */
    /*                    DECRYPT: INVALID BLOB BOUNDARY CONDITIONS              */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_decrypt_dek_blob_exactly_min_size_fails() -> Result<(), Box<dyn std::error::Error>>
    {
        // A blob of exactly GCM_IV_SIZE + GCM_TAG_SIZE (28 bytes) means zero-length
        // ciphertext. The DEK should be 32 bytes, so the AES-GCM decryption will
        // produce a 0-byte DEK, which then fails when used to decrypt the secret.
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let encrypted = EncryptedSecret {
            encrypted_secret: URL_SAFE_NO_PAD.encode([0u8; 64]),
            encrypted_dek: URL_SAFE_NO_PAD.encode([0u8; GCM_IV_SIZE + GCM_TAG_SIZE]),
            version: 1,
        };

        let result = decrypt_hmac_secret(&encrypted, &mek).await;
        assert!(
            result.is_err(),
            "Minimum-size DEK blob with random bytes should fail GCM auth"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_decrypt_secret_blob_exactly_min_size_fails(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mek = generate_random_key(AES_256_KEY_SIZE)?;
        let good = encrypt_hmac_secret(b"test", &mek).await?;

        // Replace secret blob with minimum-size garbage
        let mut bad = good.clone();
        bad.encrypted_secret = URL_SAFE_NO_PAD.encode([0u8; GCM_IV_SIZE + GCM_TAG_SIZE]);

        let result = decrypt_hmac_secret(&bad, &mek).await;
        assert!(
            result.is_err(),
            "Garbage minimum-size secret blob should fail GCM auth"
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    LARGE PAYLOAD ROUNDTRIP                                */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip_64kb() -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = vec![0xABu8; 65_536]; // 64KB
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(&plaintext, &mek).await?;
        let decrypted = decrypt_hmac_secret(&encrypted, &mek).await?;

        assert_eq!(&**decrypted, &plaintext[..]);
        Ok(())
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip_single_byte() -> Result<(), Box<dyn std::error::Error>>
    {
        let plaintext = b"\x00";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek).await?;
        let decrypted = decrypt_hmac_secret(&encrypted, &mek).await?;

        assert_eq!(&**decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip_all_byte_values(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Plaintext containing every byte value 0x00..0xFF
        let plaintext: Vec<u8> = (0..=255).collect();
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(&plaintext, &mek).await?;
        let decrypted = decrypt_hmac_secret(&encrypted, &mek).await?;

        assert_eq!(&**decrypted, &plaintext[..]);
        Ok(())
    }

    /* ========================================================================== */
    /*                    DECRYPT DELEGATES TO FALLBACK_TRACKED                  */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_decrypt_hmac_secret_delegates_to_fallback_with_none(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Verify decrypt_hmac_secret produces identical results to calling
        // decrypt_hmac_secret_with_fallback with None previous_mek
        let plaintext = b"delegation-test";
        let mek = generate_random_key(AES_256_KEY_SIZE)?;

        let encrypted = encrypt_hmac_secret(plaintext, &mek).await?;

        let result_direct = decrypt_hmac_secret(&encrypted, &mek).await?;
        let result_fallback = decrypt_hmac_secret_with_fallback(&encrypted, &mek, None).await?;

        assert_eq!(&**result_direct, &**result_fallback);
        assert_eq!(&**result_direct, plaintext);
        Ok(())
    }

    /* ========================================================================== */
    /*                    AES-256-GCM: LARGE AAD                                */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_aes_256_gcm_roundtrip_large_aad() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(AES_256_KEY_SIZE)?;
        let iv = generate_random_iv()?;
        let plaintext = b"large-aad-test";
        let aad = vec![0x42u8; 4096]; // 4KB AAD

        let ciphertext = aes_256_gcm_encrypt(&key, &iv, plaintext, &aad).await?;
        let decrypted = aes_256_gcm_decrypt(&key, &iv, &ciphertext, &aad).await?;
        assert_eq!(&decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_large_aad_mismatch_fails() -> Result<(), Box<dyn std::error::Error>> {
        let key = generate_random_key(AES_256_KEY_SIZE)?;
        let iv = generate_random_iv()?;
        let plaintext = b"data";
        let aad1 = vec![0x42u8; 4096];
        let mut aad2 = aad1.clone();
        aad2[0] ^= 1;

        let ciphertext = aes_256_gcm_encrypt(&key, &iv, plaintext, &aad1).await?;
        let result = aes_256_gcm_decrypt(&key, &iv, &ciphertext, &aad2).await;
        assert!(result.is_err(), "Mismatched large AAD must fail");
        Ok(())
    }

    /* ========================================================================== */
    /*                    CROSS-ENCRYPTION ISOLATION                             */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_different_meks_produce_non_interchangeable_secrets(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"isolation-test";
        let mek1 = generate_random_key(AES_256_KEY_SIZE)?;
        let mek2 = generate_random_key(AES_256_KEY_SIZE)?;

        let enc1 = encrypt_hmac_secret(plaintext, &mek1).await?;
        let enc2 = encrypt_hmac_secret(plaintext, &mek2).await?;

        // enc1 decrypts only with mek1
        let dec1 = decrypt_hmac_secret(&enc1, &mek1).await?;
        assert_eq!(&**dec1, plaintext);

        // enc1 fails with mek2
        let fail1 = decrypt_hmac_secret(&enc1, &mek2).await;
        assert!(fail1.is_err());

        // enc2 decrypts only with mek2
        let dec2 = decrypt_hmac_secret(&enc2, &mek2).await?;
        assert_eq!(&**dec2, plaintext);

        // enc2 fails with mek1
        let fail2 = decrypt_hmac_secret(&enc2, &mek1).await;
        assert!(fail2.is_err());
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Encryption/decryption roundtrip always succeeds
        #[test]
        fn prop_encrypt_decrypt_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..256)) {
            tokio_test::block_on(async {
                let mek = generate_random_key(AES_256_KEY_SIZE)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                let encrypted = encrypt_hmac_secret(&plaintext, &mek).await
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                let decrypted = decrypt_hmac_secret(&encrypted, &mek).await
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                prop_assert_eq!(&**decrypted, &plaintext[..]);
                Ok(())
            })?;
        }

        /// Property: Different plaintexts produce different ciphertexts
        #[test]
        fn prop_different_plaintexts_different_ciphertexts(
            plaintext1 in prop::collection::vec(any::<u8>(), 1..64),
            plaintext2 in prop::collection::vec(any::<u8>(), 1..64)
        ) {
            prop_assume!(plaintext1 != plaintext2);

            tokio_test::block_on(async {
                let mek = generate_random_key(AES_256_KEY_SIZE)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                let encrypted1 = encrypt_hmac_secret(&plaintext1, &mek).await
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                let encrypted2 = encrypt_hmac_secret(&plaintext2, &mek).await
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;

                // Different plaintexts must produce different encrypted secrets
                prop_assert_ne!(&encrypted1.encrypted_secret, &encrypted2.encrypted_secret);
                Ok(())
            })?;
        }

        /// Property: Wrong MEK always fails decryption
        #[test]
        fn prop_wrong_mek_fails(plaintext in prop::collection::vec(any::<u8>(), 1..64)) {
            tokio_test::block_on(async {
                let mek1 = generate_random_key(AES_256_KEY_SIZE)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                let mek2 = generate_random_key(AES_256_KEY_SIZE)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                prop_assume!(mek1 != mek2);

                let encrypted = encrypt_hmac_secret(&plaintext, &mek1).await
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                let result = decrypt_hmac_secret(&encrypted, &mek2).await;

                prop_assert!(result.is_err());
                Ok(())
            })?;
        }

        /// Property: Fallback tracked with correct primary always reports Current
        #[test]
        fn prop_fallback_tracked_correct_primary_reports_current(
            plaintext in prop::collection::vec(any::<u8>(), 1..64)
        ) {
            use crate::security::secret_versions::RotationSlot;
            tokio_test::block_on(async {
                let mek = generate_random_key(AES_256_KEY_SIZE)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                let old_mek = generate_random_key(AES_256_KEY_SIZE)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                let encrypted = encrypt_hmac_secret(&plaintext, &mek).await
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                let mut slot: Option<RotationSlot> = None;
                let decrypted = decrypt_hmac_secret_with_fallback_tracked(
                    &encrypted, &mek, Some(&old_mek), Some(&mut slot),
                ).await.map_err(|e| TestCaseError::fail(e.to_string()))?;
                prop_assert_eq!(&**decrypted, &plaintext[..]);
                prop_assert_eq!(slot, Some(RotationSlot::Current));
                Ok(())
            })?;
        }

        /// Property: Encrypted blob always large enough for IV + tag
        #[test]
        fn prop_blob_always_contains_iv_and_tag(
            plaintext in prop::collection::vec(any::<u8>(), 0..128)
        ) {
            tokio_test::block_on(async {
                let mek = generate_random_key(AES_256_KEY_SIZE)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                let encrypted = encrypt_hmac_secret(&plaintext, &mek).await
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;

                let secret_blob = URL_SAFE_NO_PAD.decode(&encrypted.encrypted_secret)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                let dek_blob = URL_SAFE_NO_PAD.decode(&encrypted.encrypted_dek)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;

                prop_assert!(secret_blob.len() >= GCM_IV_SIZE + GCM_TAG_SIZE);
                prop_assert!(dek_blob.len() >= GCM_IV_SIZE + GCM_TAG_SIZE);

                // Secret blob = IV + plaintext_len + tag
                prop_assert_eq!(
                    secret_blob.len(),
                    GCM_IV_SIZE + plaintext.len() + GCM_TAG_SIZE
                );
                // DEK blob = IV + AES_256_KEY_SIZE + tag (DEK is always 32 bytes)
                prop_assert_eq!(
                    dek_blob.len(),
                    GCM_IV_SIZE + AES_256_KEY_SIZE + GCM_TAG_SIZE
                );
                Ok(())
            })?;
        }
    }
}
