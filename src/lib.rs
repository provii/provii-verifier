// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Crate root for the Provii verifier API, a Cloudflare Worker that validates
//! Groth16 zero knowledge proofs of age. This module owns cold start detection,
//! VK integrity verification, cached cryptographic state, and the shared
//! [`AppState`] threaded through every request handler.
#![recursion_limit = "512"]
#![forbid(unsafe_code)]
// Style/doc lints opted out project-wide: uninlined_format_args is a formatting
// preference; private_intra_doc_links flags intentional doc cross-references to
// private impl items (they resolve under --document-private-items).
#![allow(clippy::uninlined_format_args)]
#![allow(rustdoc::private_intra_doc_links)]
// Test code legitimately uses unwrap, expect, panic, indexing, assertions on
// constants, and casts that the production deny-level lints would reject.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::assertions_on_constants,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::arithmetic_side_effects,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
    )
)]

pub mod analytics;
pub mod bindings;
pub mod cache;
pub mod clients;
pub mod config;
pub mod durable_objects;
pub mod error;
pub mod hosted;
pub mod rate_limit_kv;
pub mod rate_limiting;
pub mod routes;
pub mod security;
pub mod storage;
pub mod types;
pub mod utils;
pub mod worker_bindings;
pub mod worker_routes;

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use blake2::{Blake2b512, Digest};
use config::Config;
use security::AuditLogger;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use subtle::ConstantTimeEq;
use worker::Env;

// Thread-local storage for the worker `Context`, used to schedule fire-and-forget
// background work via `ctx.wait_until()`. Workers are single-threaded, so a
// `RefCell` is sufficient. The context is set at the start of each request in
// `handle_request` and consumed (taken) by handlers that need background dispatch.
thread_local! {
    static WORKER_CTX: RefCell<Option<worker::Context>> = const { RefCell::new(None) };
}

/// Store the worker `Context` for the current request so route handlers can
/// schedule background work via `wait_until()`.
pub fn set_worker_context(ctx: worker::Context) {
    WORKER_CTX.with(|cell| {
        *cell.borrow_mut() = Some(ctx);
    });
}

/// Take the stored worker `Context`, leaving `None` in its place. Returns
/// `None` if no context has been set or it was already consumed.
pub fn take_worker_context() -> Option<worker::Context> {
    WORKER_CTX.with(|cell| cell.borrow_mut().take())
}

// Cold start detection and performance monitoring.
//
// These static variables track worker instance lifecycle and cold start metrics.
// A "cold start" occurs when Cloudflare spins up a new Worker isolate to handle
// a request. Cold starts are expensive due to:
//   - WASM module parsing and compilation
//   - Crypto library initialisation (bellman, bls12_381)
//   - VK (Verifying Key) deserialisation
//   - Secrets Store fetches (MEK, keys)
//   - KV namespace binding resolution
//
// Monitoring cold starts helps identify:
//   - Traffic patterns that cause frequent cold starts
//   - Impact of bundle size on initialisation time
//   - Whether cron-based keep-alive triggers are effective
//   - Request distribution across warm vs cold instances

/// Whether this worker instance has handled its first request.
///
/// `false` indicates a cold start (first request). `true` indicates warm
/// (subsequent requests).
static WORKER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Timestamp (ms since epoch) when this worker instance was first initialised.
/// Used to calculate worker instance age and identify cold start patterns.
static WORKER_INIT_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

/// Counter for total requests handled by this worker instance.
/// Useful for understanding request distribution across instances.
static WORKER_REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);

/// Returns true if this is the first request to this worker instance (cold start).
/// After the first call, subsequent calls return false.
pub fn is_cold_start() -> bool {
    // Atomically swap false->true. If previous value was false, this is a cold start.
    !WORKER_INITIALIZED.swap(true, Ordering::SeqCst)
}

/// Records the worker initialisation timestamp. Call once during cold start.
pub fn record_worker_init_time() {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let now = utils::perf::now_millis() as u64;
    WORKER_INIT_TIMESTAMP.store(now, Ordering::SeqCst);
}

/// Returns the timestamp when this worker instance was initialised.
pub fn get_worker_init_timestamp() -> u64 {
    WORKER_INIT_TIMESTAMP.load(Ordering::SeqCst)
}

/// Increments and returns the request count for this worker instance.
pub fn increment_request_count() -> u64 {
    WORKER_REQUEST_COUNT
        .fetch_add(1, Ordering::SeqCst)
        .saturating_add(1)
}

use bellman::groth16::VerifyingKey;
use bls12_381::Bls12;
/// Re-exported Durable Object for challenge lifecycle management.
pub use durable_objects::challenge_do::ChallengeDO;
/// Stub for the deprecated ChallengeLock DO class, required by Cloudflare
/// until the delete-class migration runs. See challenge_lock_stub.rs.
pub use durable_objects::challenge_lock_stub::ChallengeLock;
/// Re-exported Durable Object for idempotent operation deduplication.
pub use durable_objects::idempotency_do::IdempotencyDO;
/// Re-exported Durable Object for single-use nonce enforcement.
pub use durable_objects::nonce_do::NonceDO;
// Hosted-mode Durable Objects
pub use hosted::durable_objects::challenge_notify_do::ChallengeNotifyDO;
pub use hosted::durable_objects::hosted_idempotency_do::HostedIdempotencyDO;
pub use hosted::durable_objects::hosted_nonce_do::HostedNonceDO;
use provii_crypto_verifier::init_with_vk_registry;

/// OnceLock avoids mutex poisoning if the init closure panics.
static CRYPTO_INIT_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

/// Cached parsed verifying key, avoiding 8-12ms of deserialisation per verification.
///
/// At 100M verifications/min (1.67M/sec), parsing on every request would require
/// 16,700 additional concurrent workers just for VK deserialisation. The VK is
/// parsed once during `init_crypto_once()` after the integrity check passes and
/// reused for all verifications. Integrity is verified via Blake2b-512 checksum
/// before parsing (see `verify_vk_integrity`).
static PARSED_VK: OnceLock<VerifyingKey<Bls12>> = OnceLock::new();

/// Expected Blake2b-512 checksum for VK integrity verification (ASVS V10, CSA-10).
///
/// Prevents tampering with the embedded verification key binary.
///
/// To update this checksum:
/// 1. Generate new VK using the circuit compiler
/// 2. Run: `python3 scripts/compute_vk_checksum.py assets/age_vk.914153247.bin`
/// 3. Update this constant with the new Blake2b-512 hash
/// 4. Update [`VK_ID`] if the VK version changed
///
/// VK ID: 914153247. Generated: 2026-02-18. Algorithm: Blake2b-512.
const EXPECTED_VK_CHECKSUM_BLAKE2B512: &str =
    "0aed1bda4ad79cd0c166976c5ee3f2bd1f9ca983ba8af5a7c45224003a356eac6acc61209250fd08e4835994147ca2ebc8b5e3fb6abdbbaaf2cccab566bedc0a";

/// Numeric identifier for the embedded verifying key version.
pub(crate) const VK_ID: u32 = 914153247;

/// Verifies the integrity of the embedded verification key using Blake2b-512.
///
/// Protects against tampering with the VK binary (ASVS V10.3.2, CSA-10).
///
/// # Security Properties
///
/// - Cryptographic integrity check using Blake2b-512 (64-byte hash)
/// - Fails fast on mismatch, halting Worker initialisation
/// - Checksum stored as compile-time constant (immutable)
/// - Verification happens once at startup (no performance impact on requests)
///
/// # Errors
///
/// Returns `Err` with detailed mismatch information when the computed checksum
/// does not match the expected checksum, indicating potential tampering or an
/// incorrect VK file.
fn verify_vk_integrity(vk_bytes: &[u8]) -> anyhow::Result<()> {
    // SECURITY: Compute Blake2b-512 checksum of embedded VK
    let mut hasher = Blake2b512::new();
    hasher.update(vk_bytes);
    let computed_checksum = hex::encode(hasher.finalize());

    // SECURITY: Constant-time comparison using subtle::ConstantTimeEq (ADV-VA-025).
    // The expected value is a compile-time constant so timing is not exploitable
    // here, but the pattern must remain safe to copy into other contexts.
    let checksums_match: bool = computed_checksum
        .as_bytes()
        .ct_eq(EXPECTED_VK_CHECKSUM_BLAKE2B512.as_bytes())
        .into();
    if !checksums_match {
        // SECURITY: Log detailed mismatch for forensic analysis
        #[cfg(target_arch = "wasm32")]
        console_log!("[SECURITY][VK] VK INTEGRITY VERIFICATION FAILED!");
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[SECURITY][VK] Expected checksum: {}",
            EXPECTED_VK_CHECKSUM_BLAKE2B512
        );
        #[cfg(target_arch = "wasm32")]
        console_log!("[SECURITY][VK] Computed checksum: {}", computed_checksum);
        #[cfg(target_arch = "wasm32")]
        console_log!("[SECURITY][VK] VK ID: {}", VK_ID);
        #[cfg(target_arch = "wasm32")]
        console_log!("[SECURITY][VK] VK size: {} bytes", vk_bytes.len());
        #[cfg(target_arch = "wasm32")]
        console_log!("[SECURITY][VK] This indicates potential tampering or incorrect VK file!");
        #[cfg(target_arch = "wasm32")]
        console_log!("[SECURITY][VK] Worker initialisation ABORTED for security.");

        return Err(anyhow::anyhow!(
            "VK integrity verification failed: checksum mismatch. Expected: {}, Got: {}. VK may be tampered or incorrect.",
            EXPECTED_VK_CHECKSUM_BLAKE2B512,
            computed_checksum
        ));
    }

    // SECURITY: Log successful verification for audit trail
    #[cfg(target_arch = "wasm32")]
    console_log!("[SECURITY][VK] ✅ VK integrity verified successfully");
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[SECURITY][VK] VK ID: {}, Size: {} bytes, Algorithm: Blake2b-512",
        VK_ID,
        vk_bytes.len()
    );

    Ok(())
}

/// Logs metadata about the embedded verifying key to help diagnose configuration mismatches.
/// Parses the VK to determine expected public input count and validates the shape.
fn log_vk_info() -> anyhow::Result<()> {
    let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");

    // Parse the verifying key to determine how many public inputs it expects.
    use bellman::groth16::VerifyingKey;
    use bls12_381::Bls12;
    use std::io::Cursor;

    let mut rd = Cursor::new(vk_bytes);
    let vk = VerifyingKey::<Bls12>::read(&mut rd)?;
    let expected_inputs = vk.ic.len().saturating_sub(1);

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[Crypto Init] VK 914153247 expects {} public inputs",
        expected_inputs
    );

    if expected_inputs != 8 {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[Crypto Init] WARNING: Expected 8 but VK wants {}!",
            expected_inputs
        );
        #[cfg(target_arch = "wasm32")]
        console_log!("[Crypto Init] This means:");
        if expected_inputs == 0 {
            #[cfg(target_arch = "wasm32")]
            console_log!("  - VK was generated from circuit WITHOUT pack_into_inputs calls");
        } else if expected_inputs > 100 {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "  - VK was generated from circuit with alloc_input on bit vectors (wrong!)"
            );
        } else {
            #[cfg(target_arch = "wasm32")]
            console_log!("  - VK has unexpected shape, regeneration needed");
        }
    } else {
        #[cfg(target_arch = "wasm32")]
        console_log!("[Crypto Init] ✅ VK shape correct: expects 8 public inputs");
    }

    // Log the verifying key size to help diagnose asset mismatches.
    #[cfg(target_arch = "wasm32")]
    console_log!("[Crypto Init] VK binary size: {} bytes", vk_bytes.len());

    Ok(())
}

/// Performs thread-safe initialisation of the Groth16 verifier and caches the outcome.
///
/// Verifies VK integrity via Blake2b-512, parses the VK into the `PARSED_VK`
/// cache, logs VK metadata, then registers the verifying key in the crypto
/// library's VK registry. Safe to call multiple times; only the first
/// invocation performs work. Uses `OnceLock::get_or_init` which is immune to
/// mutex poisoning.
pub fn init_crypto_once() -> anyhow::Result<()> {
    let result = CRYPTO_INIT_RESULT.get_or_init(|| {
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");

        // SECURITY: Verify VK integrity BEFORE initialisation (ASVS V10, CSA-10).
        // This is a fail-fast check that prevents using a tampered VK.
        let result = verify_vk_integrity(vk_bytes)
            .and_then(|_| {
                // Parse the VK once after integrity check passes. Stored in
                // PARSED_VK so get_cached_vk() can return a reference without
                // re-parsing on every verification request.
                use std::io::Cursor;
                let mut rd = Cursor::new(vk_bytes);
                let vk = VerifyingKey::<Bls12>::read(&mut rd)
                    .map_err(|e| anyhow::anyhow!("Failed to parse VK: {}", e))?;
                let _ = PARSED_VK.set(vk);

                // Log verifying-key metadata after integrity check passes.
                if let Err(_e) = log_vk_info() {
                    #[cfg(target_arch = "wasm32")]
                    console_log!("[Crypto Init] Failed to log VK info: {}", _e);
                }

                // Initialise the verifier with a VK registry keyed by vk_id.
                init_with_vk_registry(vec![(VK_ID, vk_bytes.to_vec())])
                    .map_err(|e| anyhow::anyhow!("Crypto init failed: {}", e))
            })
            .map_err(|e| format!("{}", e));

        match &result {
            Ok(()) => {
                #[cfg(target_arch = "wasm32")]
                console_log!("[Crypto Init] Verifier initialised successfully with VK 914153247");
            }
            Err(_e) => {
                #[cfg(target_arch = "wasm32")]
                console_log!("[Crypto Init] Failed to initialise verifier: {}", _e);
            }
        }

        result
    });

    match result {
        Ok(()) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("{}", e)),
    }
}

/// Returns a reference to the pre-parsed verifying key cached at startup.
///
/// Avoids 8-12ms of deserialisation on every verification request.
///
/// # Errors
///
/// Returns `Err` if VK parsing failed during startup initialisation.
///
/// # Example
///
/// ```ignore
/// let vk = get_cached_vk()?;
/// verify_age_snark(&proof, &inputs, vk)?;
/// ```
pub fn get_cached_vk() -> anyhow::Result<&'static VerifyingKey<Bls12>> {
    PARSED_VK.get().ok_or_else(|| {
        anyhow::anyhow!("Cached VK unavailable: init_crypto_once() has not run or failed")
    })
}

/// Shared application state threaded through every request handler.
///
/// Constructed once during cold start and wrapped in `Arc` for cloning into
/// route closures. Contains cached secrets (zeroised on drop), storage
/// backends, and billing clients.
#[derive(Clone)]
pub struct AppState {
    /// Parsed worker configuration (environment, feature flags, limits).
    pub cfg: Arc<Config>,
    /// KV-backed challenge store for active verification sessions.
    pub challenge_store: Arc<dyn storage::traits::ChallengeStore>,
    /// Nonce store for replay prevention.
    pub nonce_store: Arc<dyn storage::traits::NonceStore>,
    /// Origin ban store for blocking abusive relying parties.
    pub ban_store: Arc<dyn storage::traits::BanStore>,
    /// Cached JWKS key set for JWT validation.
    pub jwks_cache: Arc<storage::jwks::JwksCache>,
    /// Structured audit event emitter.
    pub audit_logger: Arc<AuditLogger>,
    /// KV-counter-based rate limiting.
    pub origin_policy_store: Arc<storage::origin_policy::OriginPolicyStore>,
    /// Idempotency store for duplicate operation prevention (ASVS V11, OWASP API4:2023).
    /// INVARIANT: Always `Some` after successful startup (init_app_state_internal
    /// blocks startup when the DO_IDEMPOTENCY binding is unavailable). Kept as
    /// `Option` because handler call sites pattern-match for type safety.
    pub idempotency_store: Option<Arc<storage::idempotency_store::DurableObjectIdempotencyStore>>,
    /// Credit management client for consuming credits and assigning royalties.
    pub credit_management_client: Option<Arc<clients::CreditManagementClient>>,
    /// Pre-loaded MEK (Master Encryption Key), avoiding 50-150ms Secrets Store
    /// latency per request. Cached at worker startup. Zeroised on drop.
    /// INVARIANT: Always `Some` after successful startup (init_app_state_internal
    /// blocks startup when MEK is unavailable). Kept as `Option` for type
    /// compatibility with the existing handler code paths.
    pub mek_cached: Option<Arc<zeroize::Zeroizing<Vec<u8>>>>,
    /// Previous MEK retained during key rotation so data encrypted with the old
    /// key can still be decrypted. Set to `None` when rotation is complete.
    pub previous_mek: Option<Arc<zeroize::Zeroizing<Vec<u8>>>>,
    /// Pre-loaded IP hash salt for GDPR-compliant salted IP hashing. Loaded from
    /// `VERIFIER_IP_HASH_SALT` in Secrets Store at startup. Zeroised on drop.
    pub ip_hash_salt: zeroize::Zeroizing<String>,
    /// env-aware role suffix used in the
    /// `slot` and `secret_version` keys on the status auth log line. Resolves
    /// to `"STATUS_TOKEN_PROD"` in production and `"STATUS_TOKEN_SBX"` in
    /// sandbox so Grafana panel grouping per the structured log schema attributes
    /// sandbox traffic to its own fingerprint slot. Set once at boot from
    /// `cfg.environment`. Static lifetime: only two valid values.
    ///
    /// The dual-slot Argon2id hash and 6-char fingerprint pair are not
    /// stored on `AppState` because pinning them at cold start would leave
    /// rotated tokens valid on warm isolates for the isolate's lifetime.
    /// The verify path resolves both slots through the five-minute TTL
    /// [`crate::security::status_token_cache`] so a rotated token in
    /// Secrets Store becomes effective without a redeploy.
    pub status_token_role: &'static str,
    /// 6-char fingerprint of the cached `VERIFIER_MEK`. The
    /// sentinel `"000000"` indicates the slot is unset. Computed once at
    /// startup before the MEK bytes are wrapped in `Zeroizing`. See
    /// Computed once at startup before the MEK bytes are wrapped.
    pub mek_fingerprint: String,
    /// 6-char fingerprint of `VERIFIER_MEK_PREVIOUS`. Set to
    /// `"000000"` outside a rotation window.
    pub mek_fingerprint_previous: String,
    /// 6-char fingerprint of `HOSTED_MEK`. The hosted MEK is
    /// loaded lazily by `hosted::encryption` on first use, so this is computed
    /// at startup if available; otherwise carries the unset sentinel until
    /// the first hosted-flow request populates the cache.
    pub hosted_mek_fingerprint: String,
    /// 6-char fingerprint of `HOSTED_MEK_PREVIOUS` (the
    /// hosted MEK previous rotation slot).
    pub hosted_mek_fingerprint_previous: String,
    /// 6-char fingerprint of `SESSION_TOKEN_SECRET`.
    pub session_token_fingerprint: String,
    /// 6-char fingerprint of `SESSION_TOKEN_SECRET_PREVIOUS`.
    pub session_token_fingerprint_previous: String,
    /// 6-char fingerprint of `VERIFIER_IP_HASH_SALT`. v1.0.0
    /// ships single-hash mode for the salt; the framework
    /// exercises only slot rotation, not the dual-hash analytics window.
    pub ip_hash_salt_fingerprint: String,
    /// env-aware role suffix used in `secret_version` keys.
    /// Set once at boot from `cfg.environment`. Resolves to e.g. `MEK_PROD`
    /// vs `MEK_SBX`. Static lifetime: only two valid values per role.
    pub mek_role: &'static str,
    /// env-aware role suffix for hosted MEK.
    pub hosted_mek_role: &'static str,
    /// env-aware role suffix for the per-client HMAC class.
    pub verifier_hmac_role: &'static str,
    /// env-aware role suffix for SESSION_TOKEN_SECRET.
    pub session_token_role_label: &'static str,
    /// env-aware role suffix for IP_HASH_SALT.
    pub ip_hash_salt_role: &'static str,
    /// M-27: Pre-loaded `SANDBOX_API_KEY` cached at startup to avoid per-request
    /// Secrets Store reads on `/v1/register-test-origin`. Zeroised on drop.
    pub sandbox_api_key_cached: Option<zeroize::Zeroizing<String>>,
    /// LT-001: Pre-loaded `LOADTEST_API_KEY` cached at startup, accepted
    /// additively alongside `sandbox_api_key_cached` on `/v1/register-test-origin`
    /// so the load-test harness has a dedicated key. Zeroised on drop.
    pub loadtest_api_key_cached: Option<zeroize::Zeroizing<String>>,
    /// SC-001 / M-049: Pre-loaded `SESSION_TOKEN_SECRET` for HMAC-based session
    /// token signing. Cached at startup to eliminate 7 per-request Secrets Store
    /// reads (session/check, csrf-token, ws, challenge, redeem). Zeroised on drop.
    pub session_token_secret: Option<Arc<zeroize::Zeroizing<String>>>,
    /// SC-001 / M-049: Pre-loaded `SESSION_TOKEN_SECRET_PREVIOUS` for key rotation
    /// fallback during session token verification. Zeroised on drop.
    pub session_token_secret_previous: Option<Arc<zeroize::Zeroizing<String>>>,
    /// SECURITY: Pre-computed Argon2id hash with production parameters (m=65536,t=3,p=4)
    /// used as a decoy when the client_id lookup misses. Verifying against this dummy
    /// hash ensures the reject path takes the same time as the real verification path,
    /// closing the timing oracle that would otherwise reveal whether a client_id exists
    /// (H-13, CWE-208).
    pub dummy_argon2_hash: String,
    /// Raw Cloudflare Worker environment bindings.
    pub env: Env,
    /// Optional Analytics Engine dataset for request telemetry.
    pub analytics: Option<worker::AnalyticsEngineDataset>,
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::string_slice
)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    VK INTEGRITY VERIFICATION TESTS                        */
    /* ========================================================================== */

    // ADV-VA-06-007: These tests were previously gated behind
    // #[cfg(target_arch = "wasm32")] and never ran in CI (x86_64).
    // verify_vk_integrity() compiles on all targets because its
    // console_log! calls are individually gated with #[cfg(target_arch = "wasm32")].
    #[test]
    fn test_vk_integrity_valid_checksum() {
        // Test with the actual embedded VK
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");
        let result = verify_vk_integrity(vk_bytes);

        assert!(result.is_ok(), "Valid VK should pass integrity check");
    }

    #[test]
    fn test_vk_integrity_tampered_data() {
        // Create tampered VK data by modifying a byte
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");
        let mut tampered = vk_bytes.to_vec();

        if !tampered.is_empty() {
            // Flip a bit in the middle of the file
            let middle = tampered.len() / 2;
            tampered[middle] ^= 0xFF;
        }

        let result = verify_vk_integrity(&tampered);

        assert!(result.is_err(), "Tampered VK should fail integrity check");

        if let Err(e) = result {
            let err_msg = e.to_string();
            assert!(
                err_msg.contains("checksum mismatch"),
                "Error should mention checksum mismatch, got: {}",
                err_msg
            );
        }
    }

    #[test]
    fn test_vk_integrity_empty_data() {
        let empty_vk: &[u8] = &[];
        let result = verify_vk_integrity(empty_vk);

        assert!(result.is_err(), "Empty VK should fail integrity check");
    }

    #[test]
    fn test_vk_integrity_wrong_checksum() {
        // Create data that won't match the expected checksum
        let wrong_data = vec![0xAB; 1636]; // Same size as real VK but wrong content
        let result = verify_vk_integrity(&wrong_data);

        assert!(result.is_err(), "Wrong data should fail integrity check");

        if let Err(e) = result {
            let err_msg = e.to_string();
            assert!(
                err_msg.contains("checksum mismatch"),
                "Error should mention checksum mismatch"
            );
            assert!(
                err_msg.contains(EXPECTED_VK_CHECKSUM_BLAKE2B512),
                "Error should include expected checksum"
            );
        }
    }

    #[test]
    fn test_vk_integrity_truncated_data() {
        // Truncate the VK to simulate corruption
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");
        let truncated = &vk_bytes[..vk_bytes.len() / 2];

        let result = verify_vk_integrity(truncated);

        assert!(result.is_err(), "Truncated VK should fail integrity check");
    }

    #[test]
    fn test_vk_integrity_single_bit_flip() {
        // Test that even a single bit flip is detected
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");
        let mut modified = vk_bytes.to_vec();

        if !modified.is_empty() {
            // Flip a single bit in the first byte
            modified[0] ^= 0x01;
        }

        let result = verify_vk_integrity(&modified);

        assert!(result.is_err(), "Single bit flip should be detected");
    }

    #[test]
    fn test_vk_integrity_last_byte_modified() {
        // Test modification at the end of the file
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");
        let mut modified = vk_bytes.to_vec();

        if !modified.is_empty() {
            let last = modified.len() - 1;
            modified[last] ^= 0xFF;
        }

        let result = verify_vk_integrity(&modified);

        assert!(result.is_err(), "Last byte modification should be detected");
    }

    #[test]
    fn test_vk_integrity_all_zeros() {
        // Test with all-zero data of same size
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");
        let zeros = vec![0u8; vk_bytes.len()];

        let result = verify_vk_integrity(&zeros);

        assert!(result.is_err(), "All-zero VK should fail integrity check");
    }

    #[test]
    fn test_vk_integrity_all_ones() {
        // Test with all-ones data of same size
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");
        let ones = vec![0xFFu8; vk_bytes.len()];

        let result = verify_vk_integrity(&ones);

        assert!(result.is_err(), "All-ones VK should fail integrity check");
    }

    #[test]
    fn test_vk_checksum_is_blake2b512() {
        // Verify that we're using Blake2b-512 (64-byte hash)
        let test_data = b"test";
        let mut hasher = Blake2b512::new();
        hasher.update(test_data);
        let checksum = hex::encode(hasher.finalize());

        // Blake2b-512 produces 128 hex characters (64 bytes * 2)
        assert_eq!(
            checksum.len(),
            128,
            "Blake2b-512 should produce 128 hex chars"
        );

        // Verify expected checksum is also 128 chars
        assert_eq!(
            EXPECTED_VK_CHECKSUM_BLAKE2B512.len(),
            128,
            "Expected VK checksum should be 128 hex chars"
        );
    }

    #[test]
    fn test_vk_checksum_deterministic() {
        // Verify that checksum is deterministic
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");

        let mut hasher1 = Blake2b512::new();
        hasher1.update(vk_bytes);
        let checksum1 = hex::encode(hasher1.finalize());

        let mut hasher2 = Blake2b512::new();
        hasher2.update(vk_bytes);
        let checksum2 = hex::encode(hasher2.finalize());

        assert_eq!(checksum1, checksum2, "Checksum should be deterministic");
    }

    /* ========================================================================== */
    /*                    VK_ID AND CONSTANTS TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_vk_id_constant() {
        // Verify VK_ID is set correctly
        assert_eq!(VK_ID, 914153247, "VK_ID should match expected value");
    }

    #[test]
    fn test_expected_checksum_format() {
        // Verify expected checksum is lowercase hex
        assert!(
            EXPECTED_VK_CHECKSUM_BLAKE2B512
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
            "Expected checksum should be valid hex"
        );

        assert!(
            EXPECTED_VK_CHECKSUM_BLAKE2B512
                .chars()
                .all(|c| !c.is_ascii_uppercase()),
            "Expected checksum should be lowercase"
        );
    }

    #[test]
    fn test_vk_file_exists_and_has_content() {
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");

        assert!(!vk_bytes.is_empty(), "VK file should not be empty");
        assert!(vk_bytes.len() > 100, "VK file should be substantial size");

        // The actual VK is 1636 bytes - verify it's approximately that size
        assert!(
            vk_bytes.len() > 1000 && vk_bytes.len() < 3000,
            "VK file size should be reasonable (got {} bytes)",
            vk_bytes.len()
        );
    }

    /* ========================================================================== */
    /*                    LOG_VK_INFO TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_log_vk_info_success() {
        // This test verifies log_vk_info can parse the VK successfully
        // Note: This will output to stderr during tests, which is expected
        let result = log_vk_info();

        // Should succeed with valid VK
        assert!(result.is_ok(), "log_vk_info should succeed with valid VK");
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    // Pure computation tests (proptest only available on native targets).
    // VK integrity is covered by unit tests above (tampered bytes, empty, truncated,
    // zeros, ones, wrong data). proptest can't exercise verify_vk_integrity directly
    // because it calls console_log! which is only available in the worker runtime.
    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Blake2b-512 checksum should always be 128 hex chars
        #[test]
        fn prop_blake2b512_checksum_length(data in prop::collection::vec(any::<u8>(), 0..10000)) {
            let mut hasher = Blake2b512::new();
            hasher.update(&data);
            let checksum = hex::encode(hasher.finalize());

            prop_assert_eq!(checksum.len(), 128,
                "Blake2b-512 checksum should always be 128 hex characters");
        }

        /// Property: Blake2b-512 is deterministic
        #[test]
        fn prop_blake2b512_deterministic(data in prop::collection::vec(any::<u8>(), 0..10000)) {
            let mut hasher1 = Blake2b512::new();
            hasher1.update(&data);
            let checksum1 = hex::encode(hasher1.finalize());

            let mut hasher2 = Blake2b512::new();
            hasher2.update(&data);
            let checksum2 = hex::encode(hasher2.finalize());

            prop_assert_eq!(checksum1, checksum2, "Blake2b-512 should be deterministic");
        }

        /// Property: Different data should produce different checksums
        #[test]
        fn prop_blake2b512_collision_resistance(
            data1 in prop::collection::vec(any::<u8>(), 1..1000),
            data2 in prop::collection::vec(any::<u8>(), 1..1000)
        ) {
            prop_assume!(data1 != data2);

            let mut hasher1 = Blake2b512::new();
            hasher1.update(&data1);
            let checksum1 = hex::encode(hasher1.finalize());

            let mut hasher2 = Blake2b512::new();
            hasher2.update(&data2);
            let checksum2 = hex::encode(hasher2.finalize());

            prop_assert_ne!(checksum1, checksum2,
                "Different inputs should produce different Blake2b-512 checksums");
        }
    }

    /* ========================================================================== */
    /*                    ERROR MESSAGE QUALITY TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_vk_integrity_error_message_includes_details() {
        let wrong_data = vec![0x42; 1636];
        let result = verify_vk_integrity(&wrong_data);

        assert!(result.is_err());

        if let Err(e) = result {
            let err_msg = e.to_string();

            // Error should include key information for debugging
            assert!(
                err_msg.contains("integrity verification failed")
                    || err_msg.contains("checksum mismatch"),
                "Error should describe the failure"
            );

            assert!(
                err_msg.contains("Expected") || err_msg.contains("expected"),
                "Error should mention expected checksum"
            );

            assert!(
                err_msg.contains("Got") || err_msg.contains("got"),
                "Error should mention computed checksum"
            );
        }
    }

    /* ========================================================================== */
    /*                    INTEGRATION TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_vk_integrity_in_init_sequence() {
        // This test verifies that verify_vk_integrity is called during init
        // We can't easily test the full init_crypto_once due to OnceCell,
        // but we can verify the integrity check function works as expected
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");

        // Verify integrity check passes
        let integrity_result = verify_vk_integrity(vk_bytes);
        assert!(
            integrity_result.is_ok(),
            "VK integrity should pass before initialisation"
        );
    }

    #[test]
    fn test_vk_size_matches_expected() {
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");

        // The VK file should be exactly 1732 bytes for this version
        assert_eq!(
            vk_bytes.len(),
            1732,
            "VK file size should be 1732 bytes for version 914153247"
        );
    }

    /* ========================================================================== */
    /*                    COLD START / REQUEST COUNT TESTS                       */
    /* ========================================================================== */

    #[test]
    fn test_is_cold_start_returns_bool() {
        // is_cold_start uses a global AtomicBool, so in a test process that has
        // already called it, it returns false. We simply verify it returns a
        // valid bool without panicking. The first invocation across the whole
        // test binary returns true; subsequent ones return false. Both are
        // correct behaviour.
        // Verify is_cold_start() returns without panicking. The actual
        // value depends on prior test ordering (first call: true, later: false).
        let _result: bool = is_cold_start();
    }

    #[test]
    fn test_is_cold_start_second_call_is_warm() {
        // After any prior call, the atomic has been swapped to true, so
        // subsequent calls must return false (warm).
        let _ = is_cold_start(); // ensure at least one call has happened
        let second = is_cold_start();
        assert!(
            !second,
            "Second call to is_cold_start should indicate warm (false)"
        );
    }

    #[test]
    fn test_increment_request_count_returns_nonzero() {
        // Global counter may already have been incremented by other tests, but
        // the return value must always be >= 1 (the function adds 1 via
        // saturating_add after fetch_add).
        let count = increment_request_count();
        assert!(
            count >= 1,
            "increment_request_count should return at least 1, got {}",
            count
        );
    }

    #[test]
    fn test_increment_request_count_monotonically_increases() {
        let first = increment_request_count();
        let second = increment_request_count();
        assert!(
            second > first,
            "Request count should increase monotonically: {} then {}",
            first,
            second
        );
    }

    #[test]
    fn test_get_worker_init_timestamp_returns_u64() {
        // Before record_worker_init_time is called, the timestamp is 0.
        // After, it is a positive value. Either way this must not panic.
        let ts = get_worker_init_timestamp();
        // ts is a valid u64 (could be 0 if record_worker_init_time was never called)
        assert!(
            ts == 0 || ts > 1_000_000_000_000,
            "Timestamp should be 0 or a reasonable epoch ms, got {}",
            ts
        );
    }

    #[test]
    fn test_record_worker_init_time_sets_nonzero_timestamp() {
        record_worker_init_time();
        let ts = get_worker_init_timestamp();
        assert!(
            ts > 0,
            "After recording init time, timestamp should be nonzero"
        );
    }

    #[test]
    fn test_record_worker_init_time_timestamp_is_reasonable() {
        record_worker_init_time();
        let ts = get_worker_init_timestamp();
        // Should be after 2020-01-01 (~1577836800000 ms)
        assert!(
            ts > 1_577_836_800_000,
            "Init timestamp should be after 2020, got {}",
            ts
        );
        // Should be before 2040-01-01 (~2208988800000 ms)
        assert!(
            ts < 2_208_988_800_000,
            "Init timestamp should be before 2040, got {}",
            ts
        );
    }

    /* ========================================================================== */
    /*                    CACHED VK ERROR PATH TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_get_cached_vk_error_message() {
        // On native (non-wasm) test targets, PARSED_VK is never populated by
        // init_crypto_once (which requires the wasm worker runtime). Verify the
        // error path produces a meaningful message.
        //
        // Note: if another test in the same process has populated PARSED_VK,
        // this test will get Ok, which is also acceptable.
        let result = get_cached_vk();
        match result {
            Ok(_vk) => {
                // VK was already cached by another test; that is fine.
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("init_crypto_once"),
                    "Error should reference init_crypto_once, got: {}",
                    msg
                );
            }
        }
    }

    /* ========================================================================== */
    /*                    CHECKSUM CONSTANT VALIDATION TESTS                     */
    /* ========================================================================== */

    #[test]
    fn test_expected_checksum_length_is_128() {
        assert_eq!(
            EXPECTED_VK_CHECKSUM_BLAKE2B512.len(),
            128,
            "Blake2b-512 hex checksum must be exactly 128 characters"
        );
    }

    #[test]
    fn test_expected_checksum_is_valid_hex() {
        for (i, c) in EXPECTED_VK_CHECKSUM_BLAKE2B512.chars().enumerate() {
            assert!(
                c.is_ascii_hexdigit(),
                "Character at position {} is not valid hex: '{}'",
                i,
                c
            );
        }
    }

    #[test]
    fn test_expected_checksum_is_lowercase_hex() {
        for (i, c) in EXPECTED_VK_CHECKSUM_BLAKE2B512.chars().enumerate() {
            assert!(
                !c.is_ascii_uppercase(),
                "Character at position {} should be lowercase: '{}'",
                i,
                c
            );
        }
    }

    #[test]
    fn test_expected_checksum_decodes_to_64_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = hex::decode(EXPECTED_VK_CHECKSUM_BLAKE2B512)?;
        assert_eq!(
            bytes.len(),
            64,
            "Blake2b-512 checksum should decode to 64 bytes"
        );
        Ok(())
    }

    #[test]
    fn test_expected_checksum_is_not_all_zeros() {
        let all_zeros = "0".repeat(128);
        assert_ne!(
            EXPECTED_VK_CHECKSUM_BLAKE2B512, &all_zeros,
            "Checksum should not be all zeros"
        );
    }

    #[test]
    fn test_expected_checksum_is_not_all_same_char() {
        // A valid Blake2b-512 hash of real data should have high entropy.
        let first_char = EXPECTED_VK_CHECKSUM_BLAKE2B512
            .chars()
            .next()
            .expect("checksum is non-empty");
        let all_same = first_char.to_string().repeat(128);
        assert_ne!(
            EXPECTED_VK_CHECKSUM_BLAKE2B512, &all_same,
            "Checksum should not be a single repeated character"
        );
    }

    /* ========================================================================== */
    /*                    VK BINARY VALIDATION TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_vk_binary_is_not_all_zeros() {
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");
        let all_zeros = vk_bytes.iter().all(|&b| b == 0);
        assert!(!all_zeros, "VK binary should not be all zeros");
    }

    #[test]
    fn test_vk_binary_is_not_all_ones() {
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");
        let all_ones = vk_bytes.iter().all(|&b| b == 0xFF);
        assert!(!all_ones, "VK binary should not be all 0xFF");
    }

    #[test]
    fn test_vk_binary_has_entropy() {
        // A real VK should use many distinct byte values.
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");
        let mut seen = std::collections::HashSet::new();
        for &b in vk_bytes.iter() {
            seen.insert(b);
        }
        assert!(
            seen.len() > 50,
            "VK binary should have high byte diversity, got {} distinct values",
            seen.len()
        );
    }

    #[test]
    fn test_vk_binary_checksum_matches_expected() {
        // Directly compute the checksum and compare to the constant. This runs
        // on native targets (no console_log! dependency) and validates that the
        // VK file embedded in the binary matches the expected checksum.
        let vk_bytes = include_bytes!("../assets/age_vk.914153247.bin");
        let mut hasher = Blake2b512::new();
        hasher.update(vk_bytes);
        let computed = hex::encode(hasher.finalize());

        assert_eq!(
            computed, EXPECTED_VK_CHECKSUM_BLAKE2B512,
            "Computed VK checksum should match the expected constant"
        );
    }

    /* ========================================================================== */
    /*                    VK_ID TESTS                                           */
    /* ========================================================================== */

    #[test]
    fn test_vk_id_nonzero() {
        assert_ne!(VK_ID, 0, "VK_ID should not be zero");
    }

    #[test]
    fn test_vk_id_matches_filename() {
        // The asset filename includes the VK_ID: age_vk.914153247.bin
        // Verify VK_ID matches what is embedded in the include_bytes path.
        let expected_id: u32 = 914153247;
        assert_eq!(
            VK_ID, expected_id,
            "VK_ID should match the asset filename identifier"
        );
    }

    /* ========================================================================== */
    /*                    BLAKE2B-512 EDGE CASE TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_blake2b512_empty_input() {
        let mut hasher = Blake2b512::new();
        hasher.update(b"");
        let checksum = hex::encode(hasher.finalize());
        assert_eq!(
            checksum.len(),
            128,
            "Empty input should still produce 128-char hex"
        );
    }

    #[test]
    fn test_blake2b512_single_byte() {
        let mut hasher = Blake2b512::new();
        hasher.update([0x42]);
        let checksum = hex::encode(hasher.finalize());
        assert_eq!(checksum.len(), 128);
        // Ensure it is not the same as empty input
        let mut hasher_empty = Blake2b512::new();
        hasher_empty.update(b"");
        let empty_checksum = hex::encode(hasher_empty.finalize());
        assert_ne!(
            checksum, empty_checksum,
            "Single byte hash should differ from empty hash"
        );
    }

    #[test]
    fn test_blake2b512_large_input() {
        let large_data = vec![0xAB; 1_000_000];
        let mut hasher = Blake2b512::new();
        hasher.update(&large_data);
        let checksum = hex::encode(hasher.finalize());
        assert_eq!(
            checksum.len(),
            128,
            "Large input should produce 128-char hex"
        );
    }

    #[test]
    fn test_blake2b512_incremental_vs_single_update() {
        // Feeding data in chunks should produce the same result as a single update.
        let data = b"hello world this is a test of incremental hashing";

        let mut hasher_single = Blake2b512::new();
        hasher_single.update(data);
        let single_checksum = hex::encode(hasher_single.finalize());

        let mut hasher_chunks = Blake2b512::new();
        for chunk in data.chunks(5) {
            hasher_chunks.update(chunk);
        }
        let chunks_checksum = hex::encode(hasher_chunks.finalize());

        assert_eq!(
            single_checksum, chunks_checksum,
            "Incremental hashing should match single-update hashing"
        );
    }

    /* ========================================================================== */
    /*                    CONSTANT-TIME COMPARISON TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_ct_eq_matching_slices() {
        let a = b"abcdef1234567890";
        let b = b"abcdef1234567890";
        let result: bool = a.ct_eq(b).into();
        assert!(result, "Identical slices should compare equal");
    }

    #[test]
    fn test_ct_eq_different_slices() {
        let a = b"abcdef1234567890";
        let b = b"abcdef1234567891";
        let result: bool = a.ct_eq(b).into();
        assert!(!result, "Different slices should not compare equal");
    }

    #[test]
    fn test_ct_eq_different_lengths() {
        let a = b"short";
        let b = b"longer_string";
        let result: bool = a.ct_eq(b.as_slice()).into();
        assert!(!result, "Different length slices should not compare equal");
    }

    #[test]
    fn test_ct_eq_empty_slices() {
        let a: &[u8] = b"";
        let b: &[u8] = b"";
        let result: bool = a.ct_eq(b).into();
        assert!(result, "Empty slices should compare equal");
    }

    /* ========================================================================== */
    /*                    ADDITIONAL PROPERTY-BASED TESTS                        */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Blake2b-512 output is always valid lowercase hex
        #[test]
        fn prop_blake2b512_output_is_lowercase_hex(data in prop::collection::vec(any::<u8>(), 0..5000)) {
            let mut hasher = Blake2b512::new();
            hasher.update(&data);
            let checksum = hex::encode(hasher.finalize());

            for c in checksum.chars() {
                prop_assert!(c.is_ascii_hexdigit(), "Non-hex character found: '{}'", c);
                prop_assert!(!c.is_ascii_uppercase(), "Uppercase character found: '{}'", c);
            }
        }

        /// Property: ct_eq is reflexive (a == a for any byte slice)
        #[test]
        fn prop_ct_eq_reflexive(data in prop::collection::vec(any::<u8>(), 0..1000)) {
            let result: bool = data.as_slice().ct_eq(data.as_slice()).into();
            prop_assert!(result, "ct_eq should be reflexive");
        }

        /// Property: ct_eq detects any single-byte difference
        #[test]
        fn prop_ct_eq_detects_single_byte_diff(
            data in prop::collection::vec(any::<u8>(), 1..500),
            idx in 0usize..500,
            flip in 1u8..=255
        ) {
            let idx = idx % data.len();
            let mut modified = data.clone();
            modified[idx] ^= flip;

            let result: bool = data.as_slice().ct_eq(modified.as_slice()).into();
            prop_assert!(!result, "ct_eq should detect byte difference at index {}", idx);
        }

        /// Property: increment_request_count always returns a positive value
        #[test]
        fn prop_increment_request_count_positive(_dummy in 0u8..10) {
            let count = increment_request_count();
            prop_assert!(count >= 1, "Request count should be at least 1, got {}", count);
        }
    }
}
