// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! MEK re-encryption CLI tool for provii-verifier.
//!
//! When VERIFIER_MEK or HOSTED_MEK is rotated in the Cloudflare Secrets Store,
//! the old key must remain active as `_PREVIOUS` until all encrypted KV data is
//! re-encrypted under the new key. This tool performs that re-encryption.
//!
//! ## What gets re-encrypted
//!
//! | Command              | KV Namespace        | Key Pattern    | Encryption Scheme           |
//! |----------------------|---------------------|----------------|-----------------------------|
//! | `rotate-mek`         | VERIFIER_KV_CONFIG  | `origins/*`    | Envelope (DEK wrapped by MEK) |
//! | `rotate-hosted-mek`  | HOSTED_PUBLIC_KEYS  | `pk_live_*` / `pk_test_*` | Direct AES-256-GCM |
//!
//! Sessions (HOSTED_SESSIONS) are intentionally excluded: they expire within
//! 5 minutes and are not worth re-encrypting.
//!
//! ## Safety invariants
//!
//! 1. All key material is wrapped in `Zeroizing` and scrubbed on drop.
//! 2. Dry-run mode (default) prevents writes unless `--commit` is passed.
//! 3. Each entry is read, decrypted, re-encrypted, and written atomically.
//!    A partial failure leaves the entry readable by the old key (which must
//!    remain active as `_PREVIOUS` until `verify-rotation` reports 100% current).

#![forbid(unsafe_code)]

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Constants (must match provii-verifier source)
// ---------------------------------------------------------------------------

/// AAD for HMAC secret encryption (per-client DEK layer).
const AAD_HMAC_SECRET: &[u8] = b"provii-hmac-secret-v1";

/// AAD for DEK encryption (MEK layer, envelope encryption).
const AAD_DEK: &[u8] = b"provii-dek-v1";

/// AAD for hosted public key data (direct MEK encryption).
const PUBLIC_KEY_DATA_AAD: &[u8] = b"provii-verifier:public_key_data:v1";

const AES_256_KEY_SIZE: usize = 32;
const GCM_IV_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "verifier-key-rotation")]
#[command(about = "MEK re-encryption tool for provii-verifier KV data")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Cloudflare account ID
    #[arg(long, env = "CLOUDFLARE_ACCOUNT_ID")]
    account_id: String,

    /// Cloudflare API token (must have KV read/write permissions)
    #[arg(long, env = "CLOUDFLARE_API_TOKEN")]
    api_token: String,

    /// KV namespace ID for VERIFIER_KV_CONFIG (origins/*)
    #[arg(long, env = "KV_CONFIG_NAMESPACE_ID")]
    kv_config_id: Option<String>,

    /// KV namespace ID for HOSTED_PUBLIC_KEYS
    #[arg(long, env = "KV_PUBLIC_KEYS_NAMESPACE_ID")]
    kv_public_keys_id: Option<String>,

    /// Actually write changes (default is dry-run)
    #[arg(long)]
    commit: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Re-encrypt all client DEKs in VERIFIER_KV_CONFIG with a new VERIFIER_MEK.
    ///
    /// For each `origins/*` entry, every client's `dek_encrypted` field is
    /// decrypted with the old MEK and re-encrypted with the new MEK. The HMAC
    /// secret ciphertext is untouched (it is encrypted under the DEK, not the MEK).
    RotateMek {
        /// Old (current/previous) MEK, base64url-encoded, 32 bytes
        #[arg(long, env = "OLD_MEK")]
        old_mek: String,

        /// New MEK, base64url-encoded, 32 bytes
        #[arg(long, env = "NEW_MEK")]
        new_mek: String,
    },

    /// Re-encrypt all hosted key data in HOSTED_PUBLIC_KEYS with a new HOSTED_MEK.
    ///
    /// Each KV value is a base64url-encoded AES-256-GCM blob. The tool decrypts
    /// with the old MEK, then re-encrypts with the new MEK using a fresh IV.
    RotateHostedMek {
        /// Old (current/previous) HOSTED_MEK, base64url-encoded, 32 bytes
        #[arg(long, env = "OLD_HOSTED_MEK")]
        old_mek: String,

        /// New HOSTED_MEK, base64url-encoded, 32 bytes
        #[arg(long, env = "NEW_HOSTED_MEK")]
        new_mek: String,
    },

    /// Report how many entries decrypt with the current key vs the previous key.
    ///
    /// Run this after rotation to confirm all data has been re-encrypted.
    /// When `previous_key_count` reaches 0, the `_PREVIOUS` binding can be removed.
    VerifyRotation {
        /// Current (new) MEK for VERIFIER_KV_CONFIG, base64url-encoded
        #[arg(long, env = "CURRENT_MEK")]
        current_mek: Option<String>,

        /// Previous (old) MEK for VERIFIER_KV_CONFIG, base64url-encoded
        #[arg(long, env = "PREVIOUS_MEK")]
        previous_mek: Option<String>,

        /// Current (new) HOSTED_MEK, base64url-encoded
        #[arg(long, env = "CURRENT_HOSTED_MEK")]
        current_hosted_mek: Option<String>,

        /// Previous (old) HOSTED_MEK, base64url-encoded
        #[arg(long, env = "PREVIOUS_HOSTED_MEK")]
        previous_hosted_mek: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Serialisation types (subset of provii-verifier types, no worker:: dependency)
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct OriginPolicy {
    #[serde(flatten)]
    other: serde_json::Value,
    #[serde(default)]
    clients: Vec<ClientAuthConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ClientAuthConfig {
    client_id: String,
    encrypted_hmac_secret: String,
    dek_encrypted: String,
    #[serde(default = "default_encryption_version")]
    encryption_version: u8,
    #[serde(flatten)]
    other: serde_json::Value,
}

const fn default_encryption_version() -> u8 {
    1
}

// ---------------------------------------------------------------------------
// Cloudflare KV API helpers
// ---------------------------------------------------------------------------

/// One entry from the KV list-keys response.
#[derive(Deserialize)]
struct KvKeyEntry {
    name: String,
}

/// Cloudflare list-keys response wrapper.
#[derive(Deserialize)]
struct KvListResponse {
    result: Vec<KvKeyEntry>,
    result_info: KvListResultInfo,
}

#[derive(Deserialize)]
struct KvListResultInfo {
    cursor: String,
}

/// List all keys in a KV namespace, handling pagination.
async fn list_all_keys(
    client: &Client,
    account_id: &str,
    api_token: &str,
    namespace_id: &str,
) -> Result<Vec<String>> {
    let mut all_keys = Vec::new();
    let mut cursor = String::new();

    loop {
        let mut url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/keys?limit=1000",
            account_id, namespace_id
        );
        if !cursor.is_empty() {
            url.push_str(&format!("&cursor={}", urlencoding::encode(&cursor)));
        }

        let resp: KvListResponse = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_token))
            .send()
            .await?
            .error_for_status()
            .context("KV list-keys request failed")?
            .json()
            .await
            .context("Failed to parse KV list-keys response")?;

        let count = resp.result.len();
        for entry in resp.result {
            all_keys.push(entry.name);
        }

        if count < 1000 || resp.result_info.cursor.is_empty() {
            break;
        }
        cursor = resp.result_info.cursor;
    }

    Ok(all_keys)
}

/// Read a single KV value as raw text.
async fn kv_get(
    client: &Client,
    account_id: &str,
    api_token: &str,
    namespace_id: &str,
    key: &str,
) -> Result<Option<String>> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/values/{}",
        account_id, namespace_id, urlencoding::encode(key)
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await?;

    if response.status().as_u16() == 404 {
        return Ok(None);
    }

    let value = response
        .error_for_status()
        .context("KV get request failed")?
        .text()
        .await?;
    Ok(Some(value))
}

/// Write a single KV value.
async fn kv_put(
    client: &Client,
    account_id: &str,
    api_token: &str,
    namespace_id: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/values/{}",
        account_id, namespace_id, urlencoding::encode(key)
    );

    client
        .put(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .header("Content-Type", "text/plain")
        .body(value.to_string())
        .send()
        .await?
        .error_for_status()
        .context("KV put request failed")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// AES-256-GCM helpers (native, no WASM)
// ---------------------------------------------------------------------------

/// Decrypt AES-256-GCM. Input: raw bytes (IV || ciphertext || tag).
fn aes_gcm_decrypt(key: &[u8], blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != AES_256_KEY_SIZE {
        bail!("Key must be {} bytes, got {}", AES_256_KEY_SIZE, key.len());
    }
    let min_len = GCM_IV_SIZE + GCM_TAG_SIZE;
    if blob.len() < min_len {
        bail!(
            "Ciphertext blob too short: {} bytes (minimum {})",
            blob.len(),
            min_len
        );
    }

    let iv = &blob[..GCM_IV_SIZE];
    let ciphertext_and_tag = &blob[GCM_IV_SIZE..];

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Failed to initialise AES-256-GCM: {}", e))?;
    let nonce = Nonce::from_slice(iv);
    let payload = Payload {
        msg: ciphertext_and_tag,
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| anyhow::anyhow!("AES-GCM decryption failed (wrong key or tampered data)"))?;

    Ok(Zeroizing::new(plaintext))
}

/// Encrypt AES-256-GCM with a fresh random IV. Returns raw bytes (IV || ciphertext || tag).
fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if key.len() != AES_256_KEY_SIZE {
        bail!("Key must be {} bytes, got {}", AES_256_KEY_SIZE, key.len());
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Failed to initialise AES-256-GCM: {}", e))?;

    let mut iv_bytes = [0u8; GCM_IV_SIZE];
    getrandom::getrandom(&mut iv_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to generate random IV: {}", e))?;
    let nonce = Nonce::from_slice(&iv_bytes);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

    let mut result = Vec::with_capacity(GCM_IV_SIZE + ciphertext.len());
    result.extend_from_slice(&iv_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decode a base64url-encoded MEK and validate it is 32 bytes.
fn decode_mek(mek_b64: &str, label: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(mek_b64.as_bytes())
            .with_context(|| format!("Failed to base64url-decode {}", label))?,
    );
    if bytes.len() != AES_256_KEY_SIZE {
        bail!("{} must be 32 bytes, got {}", label, bytes.len());
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// rotate-mek: re-encrypt client DEKs in VERIFIER_KV_CONFIG
// ---------------------------------------------------------------------------

async fn rotate_mek(cli: &Cli, old_mek_b64: &str, new_mek_b64: &str) -> Result<()> {
    let namespace_id = cli
        .kv_config_id
        .as_deref()
        .context("--kv-config-id is required for rotate-mek")?;

    let mut old_mek = decode_mek(old_mek_b64, "old MEK")?;
    let new_mek = decode_mek(new_mek_b64, "new MEK")?;

    if !cli.commit {
        println!("[DRY RUN] No changes will be written. Pass --commit to apply.");
    }
    println!();

    let http = Client::new();
    let all_keys =
        list_all_keys(&http, &cli.account_id, &cli.api_token, namespace_id).await?;

    let origin_keys: Vec<&str> = all_keys
        .iter()
        .filter(|k| k.starts_with("origins/"))
        .map(|k| k.as_str())
        .collect();

    println!(
        "Found {} total keys, {} origin entries to process.",
        all_keys.len(),
        origin_keys.len()
    );
    println!();

    let mut total_clients: u64 = 0;
    let mut re_encrypted: u64 = 0;
    let mut already_current: u64 = 0;
    let mut errors: u64 = 0;

    for key in &origin_keys {
        let raw = match kv_get(&http, &cli.account_id, &cli.api_token, namespace_id, key).await? {
            Some(v) => v,
            None => {
                println!("  [WARN] Key listed but missing on read: {}", key);
                continue;
            }
        };

        let mut policy: OriginPolicy = serde_json::from_str(&raw)
            .with_context(|| format!("Failed to parse OriginPolicy from key: {}", key))?;

        if policy.clients.is_empty() {
            continue;
        }

        let client_count = policy.clients.len();
        println!("Processing {} ({} clients)...", key, client_count);

        let mut modified = false;

        for client_cfg in &mut policy.clients {
            total_clients += 1;

            // Decode the encrypted DEK blob
            let dek_blob = URL_SAFE_NO_PAD
                .decode(client_cfg.dek_encrypted.as_bytes())
                .with_context(|| {
                    format!(
                        "Invalid base64url in dek_encrypted for client {}",
                        client_cfg.client_id
                    )
                })?;

            // Try decrypting with new MEK first (already rotated?)
            if aes_gcm_decrypt(&new_mek, &dek_blob, AAD_DEK).is_ok() {
                already_current += 1;
                continue;
            }

            // Decrypt DEK with old MEK
            let dek_plaintext = match aes_gcm_decrypt(&old_mek, &dek_blob, AAD_DEK) {
                Ok(pt) => pt,
                Err(e) => {
                    eprintln!(
                        "  [ERROR] Failed to decrypt DEK for client {} in {}: {}",
                        client_cfg.client_id, key, e
                    );
                    errors += 1;
                    continue;
                }
            };

            // Verify the DEK actually decrypts the HMAC secret (integrity check)
            let secret_blob = URL_SAFE_NO_PAD
                .decode(client_cfg.encrypted_hmac_secret.as_bytes())
                .with_context(|| {
                    format!(
                        "Invalid base64url in encrypted_hmac_secret for client {}",
                        client_cfg.client_id
                    )
                })?;

            if let Err(e) = aes_gcm_decrypt(&dek_plaintext, &secret_blob, AAD_HMAC_SECRET) {
                eprintln!(
                    "  [ERROR] DEK decrypted but cannot decrypt HMAC secret for client {} in {}: {}",
                    client_cfg.client_id, key, e
                );
                errors += 1;
                continue;
            }

            // Re-encrypt DEK with new MEK
            let new_dek_blob = aes_gcm_encrypt(&new_mek, &dek_plaintext, AAD_DEK)
                .context("Failed to re-encrypt DEK with new MEK")?;

            client_cfg.dek_encrypted = URL_SAFE_NO_PAD.encode(&new_dek_blob);
            modified = true;
            re_encrypted += 1;

            println!(
                "  Re-encrypted DEK for client: {}",
                client_cfg.client_id
            );
        }

        if modified && cli.commit {
            let updated_json = serde_json::to_string(&policy)
                .context("Failed to serialise updated OriginPolicy")?;
            kv_put(
                &http,
                &cli.account_id,
                &cli.api_token,
                namespace_id,
                key,
                &updated_json,
            )
            .await
            .with_context(|| format!("Failed to write updated policy for {}", key))?;
            println!("  Written to KV: {}", key);
        } else if modified {
            println!("  [DRY RUN] Would write updated policy to KV: {}", key);
        }
    }

    old_mek.zeroize();

    println!();
    println!("=== VERIFIER_MEK Rotation Summary ===");
    println!("  Origin entries scanned:  {}", origin_keys.len());
    println!("  Total clients found:     {}", total_clients);
    println!("  Re-encrypted (this run): {}", re_encrypted);
    println!("  Already on new key:      {}", already_current);
    println!("  Errors:                  {}", errors);
    if !cli.commit && re_encrypted > 0 {
        println!();
        println!("  Run again with --commit to apply changes.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// rotate-hosted-mek: re-encrypt hosted key data in HOSTED_PUBLIC_KEYS
// ---------------------------------------------------------------------------

async fn rotate_hosted_mek(cli: &Cli, old_mek_b64: &str, new_mek_b64: &str) -> Result<()> {
    let namespace_id = cli
        .kv_public_keys_id
        .as_deref()
        .context("--kv-public-keys-id is required for rotate-hosted-mek")?;

    let mut old_mek = decode_mek(old_mek_b64, "old HOSTED_MEK")?;
    let new_mek = decode_mek(new_mek_b64, "new HOSTED_MEK")?;

    if !cli.commit {
        println!("[DRY RUN] No changes will be written. Pass --commit to apply.");
    }
    println!();

    let http = Client::new();
    let all_keys =
        list_all_keys(&http, &cli.account_id, &cli.api_token, namespace_id).await?;

    // Filter to pk_live_* and pk_test_* entries only
    let pk_keys: Vec<&str> = all_keys
        .iter()
        .filter(|k| k.starts_with("pk_live_") || k.starts_with("pk_test_"))
        .map(|k| k.as_str())
        .collect();

    println!(
        "Found {} total keys, {} public key entries to process.",
        all_keys.len(),
        pk_keys.len()
    );
    println!();

    let mut re_encrypted: u64 = 0;
    let mut already_current: u64 = 0;
    let mut errors: u64 = 0;

    for key in &pk_keys {
        let raw = match kv_get(&http, &cli.account_id, &cli.api_token, namespace_id, key).await? {
            Some(v) => v,
            None => {
                println!("  [WARN] Key listed but missing on read: {}", key);
                continue;
            }
        };

        // The value is base64url-encoded encrypted blob
        let encrypted_blob = URL_SAFE_NO_PAD
            .decode(raw.as_bytes())
            .with_context(|| format!("Invalid base64url for key: {}", key))?;

        // Try decrypting with new MEK first
        if aes_gcm_decrypt(&new_mek, &encrypted_blob, PUBLIC_KEY_DATA_AAD).is_ok() {
            already_current += 1;
            println!("  Already on new key: {}", key);
            continue;
        }

        // Decrypt with old MEK
        let plaintext = match aes_gcm_decrypt(&old_mek, &encrypted_blob, PUBLIC_KEY_DATA_AAD) {
            Ok(pt) => pt,
            Err(e) => {
                eprintln!("  [ERROR] Failed to decrypt {}: {}", key, e);
                errors += 1;
                continue;
            }
        };

        // Validate the plaintext is valid JSON (integrity check)
        if serde_json::from_slice::<serde_json::Value>(&plaintext).is_err() {
            eprintln!(
                "  [ERROR] Decrypted data for {} is not valid JSON, skipping.",
                key
            );
            errors += 1;
            continue;
        }

        // Re-encrypt with new MEK and fresh IV
        let new_blob = aes_gcm_encrypt(&new_mek, &plaintext, PUBLIC_KEY_DATA_AAD)
            .context("Failed to re-encrypt with new HOSTED_MEK")?;

        let new_value = URL_SAFE_NO_PAD.encode(&new_blob);

        if cli.commit {
            kv_put(
                &http,
                &cli.account_id,
                &cli.api_token,
                namespace_id,
                key,
                &new_value,
            )
            .await
            .with_context(|| format!("Failed to write re-encrypted data for {}", key))?;
            println!("  Re-encrypted and written: {}", key);
        } else {
            println!("  [DRY RUN] Would re-encrypt: {}", key);
        }

        re_encrypted += 1;
    }

    old_mek.zeroize();

    println!();
    println!("=== HOSTED_MEK Rotation Summary ===");
    println!("  Public key entries scanned: {}", pk_keys.len());
    println!("  Re-encrypted (this run):    {}", re_encrypted);
    println!("  Already on new key:         {}", already_current);
    println!("  Errors:                     {}", errors);
    if !cli.commit && re_encrypted > 0 {
        println!();
        println!("  Run again with --commit to apply changes.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// verify-rotation: audit which key decrypts each entry
// ---------------------------------------------------------------------------

async fn verify_rotation(
    cli: &Cli,
    current_mek_b64: Option<&str>,
    previous_mek_b64: Option<&str>,
    current_hosted_mek_b64: Option<&str>,
    previous_hosted_mek_b64: Option<&str>,
) -> Result<()> {
    let http = Client::new();

    // --- VERIFIER_MEK (envelope DEKs) ---
    if let (Some(cur), Some(prev)) = (current_mek_b64, previous_mek_b64) {
        let namespace_id = cli
            .kv_config_id
            .as_deref()
            .context("--kv-config-id required to verify VERIFIER_MEK rotation")?;

        let current_mek = decode_mek(cur, "current MEK")?;
        let previous_mek = decode_mek(prev, "previous MEK")?;

        let all_keys =
            list_all_keys(&http, &cli.account_id, &cli.api_token, namespace_id).await?;
        let origin_keys: Vec<&str> = all_keys
            .iter()
            .filter(|k| k.starts_with("origins/"))
            .map(|k| k.as_str())
            .collect();

        let mut current_count: u64 = 0;
        let mut previous_count: u64 = 0;
        let mut neither_count: u64 = 0;

        for key in &origin_keys {
            let raw =
                match kv_get(&http, &cli.account_id, &cli.api_token, namespace_id, key).await? {
                    Some(v) => v,
                    None => continue,
                };

            let policy: OriginPolicy = match serde_json::from_str(&raw) {
                Ok(p) => p,
                Err(_) => continue,
            };

            for client_cfg in &policy.clients {
                let dek_blob = match URL_SAFE_NO_PAD.decode(client_cfg.dek_encrypted.as_bytes()) {
                    Ok(b) => b,
                    Err(_) => {
                        neither_count += 1;
                        continue;
                    }
                };

                if aes_gcm_decrypt(&current_mek, &dek_blob, AAD_DEK).is_ok() {
                    current_count += 1;
                } else if aes_gcm_decrypt(&previous_mek, &dek_blob, AAD_DEK).is_ok() {
                    previous_count += 1;
                    println!(
                        "  [PREVIOUS] {} / client {}",
                        key, client_cfg.client_id
                    );
                } else {
                    neither_count += 1;
                    eprintln!(
                        "  [NEITHER] {} / client {} - decrypts with NEITHER key",
                        key, client_cfg.client_id
                    );
                }
            }
        }

        println!();
        println!("=== VERIFIER_MEK Rotation Status ===");
        println!("  Current key:  {}", current_count);
        println!("  Previous key: {}", previous_count);
        println!("  Neither key:  {}", neither_count);
        if previous_count == 0 && neither_count == 0 {
            println!("  RESULT: Rotation complete. VERIFIER_MEK_PREVIOUS can be removed.");
        } else {
            println!("  RESULT: Rotation INCOMPLETE. Do not remove the previous key.");
        }
    }

    // --- HOSTED_MEK (direct encryption) ---
    if let (Some(cur), Some(prev)) = (current_hosted_mek_b64, previous_hosted_mek_b64) {
        let namespace_id = cli
            .kv_public_keys_id
            .as_deref()
            .context("--kv-public-keys-id required to verify HOSTED_MEK rotation")?;

        let current_mek = decode_mek(cur, "current HOSTED_MEK")?;
        let previous_mek = decode_mek(prev, "previous HOSTED_MEK")?;

        let all_keys =
            list_all_keys(&http, &cli.account_id, &cli.api_token, namespace_id).await?;
        let pk_keys: Vec<&str> = all_keys
            .iter()
            .filter(|k| k.starts_with("pk_live_") || k.starts_with("pk_test_"))
            .map(|k| k.as_str())
            .collect();

        let mut current_count: u64 = 0;
        let mut previous_count: u64 = 0;
        let mut neither_count: u64 = 0;

        for key in &pk_keys {
            let raw =
                match kv_get(&http, &cli.account_id, &cli.api_token, namespace_id, key).await? {
                    Some(v) => v,
                    None => continue,
                };

            let blob = match URL_SAFE_NO_PAD.decode(raw.as_bytes()) {
                Ok(b) => b,
                Err(_) => {
                    neither_count += 1;
                    continue;
                }
            };

            if aes_gcm_decrypt(&current_mek, &blob, PUBLIC_KEY_DATA_AAD).is_ok() {
                current_count += 1;
            } else if aes_gcm_decrypt(&previous_mek, &blob, PUBLIC_KEY_DATA_AAD).is_ok() {
                previous_count += 1;
                println!("  [PREVIOUS] {}", key);
            } else {
                neither_count += 1;
                eprintln!("  [NEITHER] {} - decrypts with NEITHER key", key);
            }
        }

        println!();
        println!("=== HOSTED_MEK Rotation Status ===");
        println!("  Current key:  {}", current_count);
        println!("  Previous key: {}", previous_count);
        println!("  Neither key:  {}", neither_count);
        if previous_count == 0 && neither_count == 0 {
            println!("  RESULT: Rotation complete. HOSTED_MEK_PREVIOUS can be removed.");
        } else {
            println!("  RESULT: Rotation INCOMPLETE. Do not remove the previous key.");
        }
    }

    if current_mek_b64.is_none()
        && previous_mek_b64.is_none()
        && current_hosted_mek_b64.is_none()
        && previous_hosted_mek_b64.is_none()
    {
        bail!("No keys provided. Supply --current-mek/--previous-mek and/or --current-hosted-mek/--previous-hosted-mek.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("provii-verifier MEK Re-encryption Tool");
    println!("====================================");

    match &cli.command {
        Commands::RotateMek { old_mek, new_mek } => {
            rotate_mek(&cli, old_mek, new_mek).await?;
        }
        Commands::RotateHostedMek { old_mek, new_mek } => {
            rotate_hosted_mek(&cli, old_mek, new_mek).await?;
        }
        Commands::VerifyRotation {
            current_mek,
            previous_mek,
            current_hosted_mek,
            previous_hosted_mek,
        } => {
            verify_rotation(
                &cli,
                current_mek.as_deref(),
                previous_mek.as_deref(),
                current_hosted_mek.as_deref(),
                previous_hosted_mek.as_deref(),
            )
            .await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"test-secret-data";
        let aad = b"test-aad";

        let encrypted = aes_gcm_encrypt(&key, plaintext, aad).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &encrypted, aad).unwrap();

        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = b"secret";
        let aad = b"ctx";

        let encrypted = aes_gcm_encrypt(&key1, plaintext, aad).unwrap();
        assert!(aes_gcm_decrypt(&key2, &encrypted, aad).is_err());
    }

    #[test]
    fn test_aes_gcm_wrong_aad_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"secret";

        let encrypted = aes_gcm_encrypt(&key, plaintext, b"aad1").unwrap();
        assert!(aes_gcm_decrypt(&key, &encrypted, b"aad2").is_err());
    }

    #[test]
    fn test_aes_gcm_different_iv_per_call() {
        let key = [0x42u8; 32];
        let plaintext = b"same-data";
        let aad = b"ctx";

        let a = aes_gcm_encrypt(&key, plaintext, aad).unwrap();
        let b = aes_gcm_encrypt(&key, plaintext, aad).unwrap();
        assert_ne!(a, b, "Each encryption must use a fresh IV");
    }

    #[test]
    fn test_aes_gcm_invalid_key_length() {
        assert!(aes_gcm_encrypt(&[0u8; 16], b"pt", b"aad").is_err());
        assert!(aes_gcm_decrypt(&[0u8; 16], &[0u8; 28], b"aad").is_err());
    }

    #[test]
    fn test_aes_gcm_short_blob() {
        let key = [0x42u8; 32];
        assert!(aes_gcm_decrypt(&key, &[0u8; 10], b"aad").is_err());
    }

    #[test]
    fn test_decode_mek_valid() {
        let key = [0x42u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(key);
        let decoded = decode_mek(&b64, "test").unwrap();
        assert_eq!(&*decoded, &key);
    }

    #[test]
    fn test_decode_mek_wrong_length() {
        let key = [0x42u8; 16];
        let b64 = URL_SAFE_NO_PAD.encode(key);
        assert!(decode_mek(&b64, "test").is_err());
    }

    #[test]
    fn test_decode_mek_invalid_base64() {
        assert!(decode_mek("not!!!valid", "test").is_err());
    }

    /// Simulate the full DEK re-encryption flow: encrypt DEK with old MEK,
    /// decrypt with old, re-encrypt with new, verify new key decrypts it.
    #[test]
    fn test_dek_re_encryption_flow() {
        let old_mek = [0x01u8; 32];
        let new_mek = [0x02u8; 32];
        let dek_plaintext = [0xABu8; 32];

        // Encrypt DEK with old MEK (simulating existing KV state)
        let dek_blob_old = aes_gcm_encrypt(&old_mek, &dek_plaintext, AAD_DEK).unwrap();

        // Verify old key works
        let recovered = aes_gcm_decrypt(&old_mek, &dek_blob_old, AAD_DEK).unwrap();
        assert_eq!(&*recovered, &dek_plaintext);

        // Verify new key does NOT work on old blob
        assert!(aes_gcm_decrypt(&new_mek, &dek_blob_old, AAD_DEK).is_err());

        // Re-encrypt with new key
        let dek_blob_new = aes_gcm_encrypt(&new_mek, &recovered, AAD_DEK).unwrap();

        // Verify new key works on re-encrypted blob
        let re_recovered = aes_gcm_decrypt(&new_mek, &dek_blob_new, AAD_DEK).unwrap();
        assert_eq!(&*re_recovered, &dek_plaintext);

        // Verify old key does NOT work on re-encrypted blob
        assert!(aes_gcm_decrypt(&old_mek, &dek_blob_new, AAD_DEK).is_err());
    }

    /// Simulate the full hosted key re-encryption flow.
    #[test]
    fn test_hosted_key_re_encryption_flow() {
        let old_mek = [0x11u8; 32];
        let new_mek = [0x22u8; 32];
        let key_data = br#"{"id":"pk_test_abc","secret_key":"sk_test_xyz","allowed_origins":[],"enabled":true,"created_at":0,"updated_at":0}"#;

        // Encrypt with old key
        let blob_old = aes_gcm_encrypt(&old_mek, key_data, PUBLIC_KEY_DATA_AAD).unwrap();

        // Decrypt with old, re-encrypt with new
        let plaintext = aes_gcm_decrypt(&old_mek, &blob_old, PUBLIC_KEY_DATA_AAD).unwrap();
        let blob_new = aes_gcm_encrypt(&new_mek, &plaintext, PUBLIC_KEY_DATA_AAD).unwrap();

        // Verify new key works
        let recovered = aes_gcm_decrypt(&new_mek, &blob_new, PUBLIC_KEY_DATA_AAD).unwrap();
        assert_eq!(&*recovered, key_data.as_slice());

        // Verify old key fails on new blob
        assert!(aes_gcm_decrypt(&old_mek, &blob_new, PUBLIC_KEY_DATA_AAD).is_err());
    }

    #[test]
    fn test_corrupted_ciphertext_detected() {
        let key = [0x42u8; 32];
        let plaintext = b"integrity-check";
        let aad = b"ctx";

        let mut encrypted = aes_gcm_encrypt(&key, plaintext, aad).unwrap();
        // Flip a bit in the ciphertext (past the IV)
        encrypted[GCM_IV_SIZE] ^= 0xFF;
        assert!(aes_gcm_decrypt(&key, &encrypted, aad).is_err());
    }
}
