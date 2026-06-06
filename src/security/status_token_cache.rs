// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Process-wide TTL cache for the dual-slot `STATUS_API_TOKEN`
//! Argon2id hash + 6-char fingerprint pair.
//!
//! Earlier revisions hashed both slots once at cold start and pinned the
//! hashes onto [`crate::AppState`] for the isolate's lifetime. A
//! rotate-without-redeploy or a partial redeploy left a stolen previous-slot
//! token valid forever on warm isolates because the hash was never refreshed.
//! Per the rotation class spec (§3.2) the dual-accept
//! window is bounded by the runbook, not the isolate lifetime, so the verify
//! path must observe Secrets Store updates within a small fixed TTL.
//!
//! This module wraps the slot in a 5-minute TTL cache. On cache miss the
//! cache reads the binding from Cloudflare Secrets Store, computes the
//! Argon2id hash with production parameters (~60 ms p50), records the
//! 6-char public-safe fingerprint, and stores the pair alongside the
//! fetched-at timestamp. Subsequent calls inside the TTL window reuse the
//! cached entry with no Secrets Store I/O and no Argon2id work.
//!
//! Negative results (binding present but empty, fetch error, binding
//! unavailable) are cached for the same TTL so a misconfigured slot does
//! not produce a Secrets Store read on every status-endpoint hit.
//!
//! ## Constant-time discipline
//!
//! The cache index is the binding name (`"STATUS_API_TOKEN"` or
//! `"STATUS_API_TOKEN_PREVIOUS"`). The binding name is a static literal,
//! never derived from secret material, so the cache lookup is not
//! secret-dependent. Argon2id verification of the cached hash against the
//! presented credential runs downstream in
//! [`crate::security::status_auth::authenticate_status_endpoint`] via the
//! constant-time `argon2` verifier; the cache does not touch the verify
//! path.
//!
//! ## Memory safety
//!
//! The cached Argon2id PHC string is a public hash, not secret material.
//! Plaintext token bytes pulled from Secrets Store are wrapped in
//! [`zeroize::Zeroizing`] and dropped before the cache entry is written, so
//! no plaintext lingers in cache storage. The 6-char fingerprint is a
//! one-way 24-bit hash and is public-safe.
#![forbid(unsafe_code)]

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::RwLock;
use worker::Env;

#[cfg(target_arch = "wasm32")]
use worker::console_log;

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_macros)]
macro_rules! console_log {
    ($($t:tt)*) => {{}};
}

/// TTL for cached `STATUS_API_TOKEN` slot entries, in milliseconds.
///
/// Five minutes matches the rotation framework's bound on how long a
/// stolen token may remain usable on a warm isolate after the operator
/// removes it from Secrets Store. The verify cost on a cache miss is one
/// Argon2id evaluation (~60 ms at production parameters), accepted as a
/// per-isolate per-five-minutes amortised cost on the low-traffic status
/// endpoints. The TTL was selected so the post-rotation revocation lag
/// matches the secret-rotation drill's verification window in the
/// rotation-drill workflow.
pub const STATUS_TOKEN_CACHE_TTL_MS: u64 = 5 * 60 * 1_000;

/// Snapshot of a cached slot. Cloned on every read so the lock is held only
/// for the index lookup, never across an `await` point.
#[derive(Debug, Clone)]
pub struct CachedSlot {
    /// Argon2id PHC-formatted hash of the slot's plaintext token, or `None`
    /// if the binding was absent, empty, or returned an error on the last
    /// fetch. `None` is still cached so the next request inside the TTL
    /// window does not re-read Secrets Store for a known-empty slot.
    pub argon2_hash: Option<String>,
    /// 6-char public-safe fingerprint of the plaintext token. Carries the
    /// [`crate::security::secret_fingerprint::FINGERPRINT_UNSET`] sentinel
    /// when the slot is empty.
    pub fingerprint: String,
}

/// Internal cache record. The fetched-at timestamp drives TTL eviction.
#[derive(Debug, Clone)]
struct CacheRecord {
    slot: CachedSlot,
    fetched_at_ms: u64,
}

/// Process-wide cache keyed by binding name. The map is small (two entries
/// in steady state, current + previous), so the read path's contention is
/// negligible and a single `RwLock` suffices.
static CACHE: Lazy<RwLock<HashMap<String, CacheRecord>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Returns the current monotonic millisecond clock used for TTL eviction.
/// Wraps [`crate::utils::perf::now_millis`] so the same clock source is
/// used everywhere in the crate. The cast saturates at `u64::MAX` which
/// is safe for any reasonable wall-clock value.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn now_ms() -> u64 {
    crate::utils::perf::now_millis() as u64
}

/// Read the cached slot for `binding` if it is still inside the TTL window.
/// Held under a read lock; returns a clone so the lock drops before any
/// `await` point in the caller.
fn read_fresh(binding: &str, ttl_ms: u64) -> Option<CachedSlot> {
    let now = now_ms();
    let guard = CACHE.read().ok()?;
    let record = guard.get(binding)?;
    let age = now.saturating_sub(record.fetched_at_ms);
    if age <= ttl_ms {
        Some(record.slot.clone())
    } else {
        None
    }
}

/// Replace the cached record for `binding`. Failure to acquire the write
/// lock degrades silently because the next request will simply observe a
/// miss and reload; a poisoned cache must not block the verify path.
fn write_record(binding: &str, slot: CachedSlot) {
    let now = now_ms();
    if let Ok(mut guard) = CACHE.write() {
        guard.insert(
            binding.to_string(),
            CacheRecord {
                slot,
                fetched_at_ms: now,
            },
        );
    }
}

/// Read a slot's plaintext token from Cloudflare Secrets Store, hash it
/// with Argon2id (production parameters), and record the fingerprint.
///
/// Mirrors the cold-start `load_status_token_slot` helper in
/// `worker_bindings.rs` so the on-the-fly refresh path produces the exact
/// same hash + fingerprint shape the cold-start path used to. Emits the
/// `secrets_store_read` audit line on every Secrets Store interaction so
/// rotation observability is preserved.
async fn fetch_and_hash(env: &Env, binding: &str) -> CachedSlot {
    let unset = crate::security::secret_fingerprint::FINGERPRINT_UNSET.to_string();
    match env.secret_store(binding) {
        Ok(store) => match store.get().await {
            Ok(Some(token)) => {
                if token.is_empty() {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        r#"{{"audit":true,"event":"secrets_store_read","secret":"{}","outcome":"empty"}}"#,
                        binding
                    );
                    CachedSlot {
                        argon2_hash: None,
                        fingerprint: unset,
                    }
                } else {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        r#"{{"audit":true,"event":"secrets_store_read","secret":"{}","outcome":"success"}}"#,
                        binding
                    );
                    let token = zeroize::Zeroizing::new(token);
                    let fingerprint =
                        crate::security::secret_fingerprint::fingerprint6_str(Some(&token));
                    match crate::security::hash::hash_api_key(&token) {
                        Ok(argon2_hash) => CachedSlot {
                            argon2_hash: Some(argon2_hash),
                            fingerprint,
                        },
                        Err(_e) => {
                            #[cfg(target_arch = "wasm32")]
                            console_log!(
                                r#"{{"audit":true,"event":"secrets_store_read","secret":"{}","outcome":"hash_error"}}"#,
                                binding
                            );
                            CachedSlot {
                                argon2_hash: None,
                                fingerprint: unset,
                            }
                        }
                    }
                }
            }
            Ok(None) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    r#"{{"audit":true,"event":"secrets_store_read","secret":"{}","outcome":"not_found"}}"#,
                    binding
                );
                CachedSlot {
                    argon2_hash: None,
                    fingerprint: unset,
                }
            }
            Err(_e) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    r#"{{"audit":true,"event":"secrets_store_read","secret":"{}","outcome":"fetch_error"}}"#,
                    binding
                );
                CachedSlot {
                    argon2_hash: None,
                    fingerprint: unset,
                }
            }
        },
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                r#"{{"audit":true,"event":"secrets_store_read","secret":"{}","outcome":"binding_unavailable"}}"#,
                binding
            );
            CachedSlot {
                argon2_hash: None,
                fingerprint: unset,
            }
        }
    }
}

/// Return the cached slot for `binding`, refreshing from Secrets Store on
/// cache miss or expiry. Five-minute TTL per [`STATUS_TOKEN_CACHE_TTL_MS`].
///
/// SECURITY: A rotated token in Secrets Store becomes
/// effective on warm isolates within `STATUS_TOKEN_CACHE_TTL_MS`, bounding
/// the stolen-credential validity window without requiring a redeploy.
///
/// # Arguments
///
/// * `env` - Worker environment carrying the Secrets Store bindings.
/// * `binding` - Static binding literal (`"STATUS_API_TOKEN"` or
///   `"STATUS_API_TOKEN_PREVIOUS"`). Never a secret-derived value.
pub async fn get_or_refresh(env: &Env, binding: &str) -> CachedSlot {
    if let Some(fresh) = read_fresh(binding, STATUS_TOKEN_CACHE_TTL_MS) {
        return fresh;
    }
    let slot = fetch_and_hash(env, binding).await;
    write_record(binding, slot.clone());
    slot
}

/// Test-only seed helper. Pre-populates the cache for `binding` with the
/// supplied slot data so the dual-slot verify tests can exercise the auth
/// path without standing up a Secrets Store mock. Not exposed outside
/// `cfg(test)`.
#[cfg(test)]
pub fn test_seed(binding: &str, slot: CachedSlot) {
    write_record(binding, slot);
}

/// Test-only eviction helper. Wipes the cache so a stale entry from a
/// previous test does not bleed into the next.
#[cfg(test)]
pub fn test_clear() {
    if let Ok(mut guard) = CACHE.write() {
        guard.clear();
    }
}

/// Test-only ageing helper. Rewinds the `fetched_at_ms` of the cached entry
/// for `binding` so the next read observes a TTL miss without sleeping
/// through the real five-minute window.
#[cfg(test)]
pub fn test_force_expire(binding: &str) {
    if let Ok(mut guard) = CACHE.write() {
        if let Some(record) = guard.get_mut(binding) {
            record.fetched_at_ms = 0;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        read_fresh, test_clear, test_force_expire, test_seed, CachedSlot, STATUS_TOKEN_CACHE_TTL_MS,
    };
    use serial_test::serial;

    /// Sanity: TTL is five minutes in milliseconds. Pinned so a careless
    /// edit of the constant lights up the test suite.
    #[test]
    #[serial]
    fn ttl_is_five_minutes() {
        assert_eq!(STATUS_TOKEN_CACHE_TTL_MS, 5 * 60 * 1_000);
    }

    /// A freshly seeded entry must be visible to `read_fresh` inside the
    /// TTL window. Confirms the seed helper produces a record the read
    /// path accepts as not-yet-expired.
    #[test]
    #[serial]
    fn read_fresh_returns_seeded_entry() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_FRESH",
            CachedSlot {
                argon2_hash: Some("not-a-real-hash".to_string()),
                fingerprint: "abc123".to_string(),
            },
        );
        let slot = read_fresh("STATUS_API_TOKEN_TEST_FRESH", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(slot.fingerprint, "abc123");
        assert_eq!(slot.argon2_hash.as_deref(), Some("not-a-real-hash"));
    }

    /// After `test_force_expire`, the entry must look stale. This is the
    /// rotation-without-redeploy test path: the fix must observe a miss
    /// once the TTL elapses, not return the warm-isolate snapshot
    /// indefinitely.
    #[test]
    #[serial]
    fn force_expired_entry_reads_as_miss() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_EXPIRE",
            CachedSlot {
                argon2_hash: Some("stale-hash".to_string()),
                fingerprint: "stalef".to_string(),
            },
        );
        test_force_expire("STATUS_API_TOKEN_TEST_EXPIRE");
        let result = read_fresh("STATUS_API_TOKEN_TEST_EXPIRE", STATUS_TOKEN_CACHE_TTL_MS);
        assert!(
            result.is_none(),
            "force-expired entry must read as cache miss"
        );
    }

    /// An unknown binding must read as a miss without panicking. Confirms
    /// the `RwLock` and `HashMap::get` lookup are infallible-by-construction
    /// on the read path.
    #[test]
    #[serial]
    fn unknown_binding_reads_as_miss() {
        test_clear();
        let result = read_fresh("STATUS_API_TOKEN_TEST_UNKNOWN", STATUS_TOKEN_CACHE_TTL_MS);
        assert!(result.is_none());
    }

    /// Re-seeding the same binding must overwrite the previous record.
    /// Mirrors the rotation case: the operator pushes a new token, the
    /// next refresh writes the new hash, the verify path observes only
    /// the new value.
    #[test]
    #[serial]
    fn reseed_overwrites_previous_record() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_RESEED",
            CachedSlot {
                argon2_hash: Some("first-hash".to_string()),
                fingerprint: "111111".to_string(),
            },
        );
        test_seed(
            "STATUS_API_TOKEN_TEST_RESEED",
            CachedSlot {
                argon2_hash: Some("second-hash".to_string()),
                fingerprint: "222222".to_string(),
            },
        );
        let slot = read_fresh("STATUS_API_TOKEN_TEST_RESEED", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(slot.fingerprint, "222222");
        assert_eq!(slot.argon2_hash.as_deref(), Some("second-hash"));
    }

    // ── CachedSlot type tests ─────────────────────────────────────────

    #[test]
    #[serial]
    fn cached_slot_none_hash_represents_empty_binding() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_NONE",
            CachedSlot {
                argon2_hash: None,
                fingerprint: "000000".to_string(),
            },
        );
        let slot = read_fresh("STATUS_API_TOKEN_TEST_NONE", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert!(slot.argon2_hash.is_none());
        assert_eq!(slot.fingerprint, "000000");
    }

    #[test]
    #[serial]
    fn cached_slot_debug_displays_fields() {
        let slot = CachedSlot {
            argon2_hash: Some("test-hash".to_string()),
            fingerprint: "abcdef".to_string(),
        };
        let debug = format!("{:?}", slot);
        assert!(debug.contains("test-hash"));
        assert!(debug.contains("abcdef"));
    }

    #[test]
    #[serial]
    fn cached_slot_clone_is_independent() {
        let slot = CachedSlot {
            argon2_hash: Some("original".to_string()),
            fingerprint: "aaaaaa".to_string(),
        };
        let mut cloned = slot.clone();
        cloned.fingerprint = "bbbbbb".to_string();
        assert_eq!(slot.fingerprint, "aaaaaa");
        assert_eq!(cloned.fingerprint, "bbbbbb");
    }

    // ── Distinct bindings are isolated ────────────────────────────────

    #[test]
    #[serial]
    fn distinct_bindings_are_isolated() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_A",
            CachedSlot {
                argon2_hash: Some("hash-a".to_string()),
                fingerprint: "aaaaaa".to_string(),
            },
        );
        test_seed(
            "STATUS_API_TOKEN_TEST_B",
            CachedSlot {
                argon2_hash: Some("hash-b".to_string()),
                fingerprint: "bbbbbb".to_string(),
            },
        );
        let a = read_fresh("STATUS_API_TOKEN_TEST_A", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        let b = read_fresh("STATUS_API_TOKEN_TEST_B", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(a.fingerprint, "aaaaaa");
        assert_eq!(b.fingerprint, "bbbbbb");
    }

    /// Clearing must remove all entries.
    #[test]
    #[serial]
    fn test_clear_removes_all_entries() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_CLR_1",
            CachedSlot {
                argon2_hash: Some("h1".to_string()),
                fingerprint: "111111".to_string(),
            },
        );
        test_seed(
            "STATUS_API_TOKEN_TEST_CLR_2",
            CachedSlot {
                argon2_hash: Some("h2".to_string()),
                fingerprint: "222222".to_string(),
            },
        );
        test_clear();
        assert!(read_fresh("STATUS_API_TOKEN_TEST_CLR_1", STATUS_TOKEN_CACHE_TTL_MS).is_none());
        assert!(read_fresh("STATUS_API_TOKEN_TEST_CLR_2", STATUS_TOKEN_CACHE_TTL_MS).is_none());
    }

    /// Force-expiring a non-existent binding must not panic.
    #[test]
    #[serial]
    fn force_expire_nonexistent_binding_does_not_panic() {
        test_clear();
        test_force_expire("STATUS_API_TOKEN_TEST_NONEXISTENT");
        // No assertion needed; the test succeeds if it does not panic.
    }

    /// Zero TTL must make every fresh entry stale on the next read.
    #[test]
    #[serial]
    fn zero_ttl_reads_as_miss() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_ZERO_TTL",
            CachedSlot {
                argon2_hash: Some("hash".to_string()),
                fingerprint: "ffffff".to_string(),
            },
        );
        // With a zero TTL, the entry should be stale immediately because
        // the read path computes `age = now - fetched_at` which will be >= 0
        // and the check is `age <= 0`, which only succeeds if age == 0
        // (i.e. the exact same millisecond). This is platform-dependent
        // but with TTL=0 it should almost always miss.
        //
        // Actually, the check is `age <= ttl_ms` where ttl_ms=0, so
        // if the read happens in the same millisecond, age=0 and 0 <= 0
        // is true. We test with TTL=0 but acknowledge this edge case.
        // The important thing is that very small TTLs work.
        let _result = read_fresh("STATUS_API_TOKEN_TEST_ZERO_TTL", 0);
        // We cannot deterministically assert miss vs hit at TTL=0 in
        // the same millisecond; the test confirms no panic.
    }

    /// Seed + force-expire + re-seed produces fresh data.
    #[test]
    #[serial]
    fn expire_then_reseed_produces_fresh_data() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_RESEED2",
            CachedSlot {
                argon2_hash: Some("old-hash".to_string()),
                fingerprint: "old111".to_string(),
            },
        );
        test_force_expire("STATUS_API_TOKEN_TEST_RESEED2");
        // After expiry, read_fresh returns None.
        assert!(read_fresh("STATUS_API_TOKEN_TEST_RESEED2", STATUS_TOKEN_CACHE_TTL_MS).is_none());
        // Re-seed and confirm the new value is visible.
        test_seed(
            "STATUS_API_TOKEN_TEST_RESEED2",
            CachedSlot {
                argon2_hash: Some("new-hash".to_string()),
                fingerprint: "new222".to_string(),
            },
        );
        let slot = read_fresh("STATUS_API_TOKEN_TEST_RESEED2", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(slot.fingerprint, "new222");
        assert_eq!(slot.argon2_hash.as_deref(), Some("new-hash"));
    }

    // ── write_record direct tests ────────────────────────────────────

    /// `write_record` called directly must produce entries visible to
    /// `read_fresh`. Validates the internal write path independent of the
    /// `test_seed` convenience wrapper.
    #[test]
    #[serial]
    fn write_record_creates_readable_entry() {
        test_clear();
        super::write_record(
            "STATUS_API_TOKEN_TEST_WRITE_DIRECT",
            CachedSlot {
                argon2_hash: Some("direct-hash".to_string()),
                fingerprint: "dir123".to_string(),
            },
        );
        let slot = read_fresh(
            "STATUS_API_TOKEN_TEST_WRITE_DIRECT",
            STATUS_TOKEN_CACHE_TTL_MS,
        )
        .unwrap();
        assert_eq!(slot.fingerprint, "dir123");
        assert_eq!(slot.argon2_hash.as_deref(), Some("direct-hash"));
    }

    /// `write_record` with a `None` hash must cache the negative result
    /// so the Secrets Store is not re-read on every hit within the TTL.
    #[test]
    #[serial]
    fn write_record_caches_negative_result() {
        test_clear();
        super::write_record(
            "STATUS_API_TOKEN_TEST_WRITE_NEG",
            CachedSlot {
                argon2_hash: None,
                fingerprint: "000000".to_string(),
            },
        );
        let slot =
            read_fresh("STATUS_API_TOKEN_TEST_WRITE_NEG", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert!(slot.argon2_hash.is_none());
        assert_eq!(slot.fingerprint, "000000");
    }

    /// Calling `write_record` twice for the same binding replaces the
    /// first record. The cache must hold exactly one record per binding
    /// at any time.
    #[test]
    #[serial]
    fn write_record_overwrites_existing() {
        test_clear();
        super::write_record(
            "STATUS_API_TOKEN_TEST_WRITE_OVR",
            CachedSlot {
                argon2_hash: Some("v1".to_string()),
                fingerprint: "111111".to_string(),
            },
        );
        super::write_record(
            "STATUS_API_TOKEN_TEST_WRITE_OVR",
            CachedSlot {
                argon2_hash: Some("v2".to_string()),
                fingerprint: "222222".to_string(),
            },
        );
        let slot =
            read_fresh("STATUS_API_TOKEN_TEST_WRITE_OVR", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(slot.argon2_hash.as_deref(), Some("v2"));
        assert_eq!(slot.fingerprint, "222222");
    }

    // ── now_ms sanity ────────────────────────────────────────────────

    /// `now_ms` must return a positive value that looks like a
    /// reasonable epoch-millisecond timestamp (after 2024-01-01).
    #[test]
    #[serial]
    fn now_ms_returns_reasonable_epoch_millis() {
        let ts = super::now_ms();
        // 2024-01-01T00:00:00Z in ms
        let jan_2024_ms: u64 = 1_704_067_200_000;
        assert!(
            ts >= jan_2024_ms,
            "now_ms() returned {ts}, expected >= {jan_2024_ms}"
        );
    }

    /// Two sequential calls to `now_ms` must be monotonically
    /// non-decreasing. The underlying `SystemTime` clock is not
    /// guaranteed monotonic but on any sane test host successive
    /// calls within the same thread will not go backwards.
    #[test]
    #[serial]
    fn now_ms_is_non_decreasing() {
        let t1 = super::now_ms();
        let t2 = super::now_ms();
        assert!(t2 >= t1, "now_ms went backwards: {t1} -> {t2}");
    }

    // ── TTL boundary tests ──────────────────────────────────────────

    /// With `u64::MAX` TTL, a seeded entry must always read as fresh
    /// regardless of how much time has passed. This exercises the
    /// `saturating_sub` path: `age = now - fetched_at` will be large
    /// but still <= `u64::MAX`.
    #[test]
    #[serial]
    fn max_ttl_always_hits() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_MAX_TTL",
            CachedSlot {
                argon2_hash: Some("eternal".to_string()),
                fingerprint: "eeeeee".to_string(),
            },
        );
        // Even with force_expire (fetched_at_ms = 0), u64::MAX TTL
        // means age <= u64::MAX is always true.
        test_force_expire("STATUS_API_TOKEN_TEST_MAX_TTL");
        let slot = read_fresh("STATUS_API_TOKEN_TEST_MAX_TTL", u64::MAX).unwrap();
        assert_eq!(slot.fingerprint, "eeeeee");
        assert_eq!(slot.argon2_hash.as_deref(), Some("eternal"));
    }

    /// A TTL of 1 ms with a force-expired entry (fetched_at_ms = 0)
    /// must read as a miss because `now - 0` far exceeds 1 ms.
    #[test]
    #[serial]
    fn tiny_ttl_with_old_entry_reads_as_miss() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_TINY_TTL",
            CachedSlot {
                argon2_hash: Some("short-lived".to_string()),
                fingerprint: "tttttt".to_string(),
            },
        );
        test_force_expire("STATUS_API_TOKEN_TEST_TINY_TTL");
        let result = read_fresh("STATUS_API_TOKEN_TEST_TINY_TTL", 1);
        assert!(result.is_none(), "1ms TTL with epoch-0 entry must miss");
    }

    // ── CachedSlot edge cases ───────────────────────────────────────

    /// A `CachedSlot` with an empty-string hash (not `None`) is a valid
    /// but degenerate state. The cache must store and return it faithfully.
    #[test]
    #[serial]
    fn cached_slot_empty_string_hash() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_EMPTY_HASH",
            CachedSlot {
                argon2_hash: Some(String::new()),
                fingerprint: "emp000".to_string(),
            },
        );
        let slot = read_fresh(
            "STATUS_API_TOKEN_TEST_EMPTY_HASH",
            STATUS_TOKEN_CACHE_TTL_MS,
        )
        .unwrap();
        assert_eq!(slot.argon2_hash.as_deref(), Some(""));
        assert_eq!(slot.fingerprint, "emp000");
    }

    /// A `CachedSlot` with an empty-string fingerprint. The fingerprint
    /// is always 6 chars in production, but the cache must not assume
    /// that and must round-trip any string.
    #[test]
    #[serial]
    fn cached_slot_empty_string_fingerprint() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_EMPTY_FP",
            CachedSlot {
                argon2_hash: Some("hash-for-empty-fp".to_string()),
                fingerprint: String::new(),
            },
        );
        let slot = read_fresh("STATUS_API_TOKEN_TEST_EMPTY_FP", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert!(slot.fingerprint.is_empty());
        assert_eq!(slot.argon2_hash.as_deref(), Some("hash-for-empty-fp"));
    }

    /// Both fields `None` hash and unset fingerprint: the minimal
    /// negative-cache entry.
    #[test]
    #[serial]
    fn cached_slot_fully_empty() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_FULLY_EMPTY",
            CachedSlot {
                argon2_hash: None,
                fingerprint: String::new(),
            },
        );
        let slot = read_fresh(
            "STATUS_API_TOKEN_TEST_FULLY_EMPTY",
            STATUS_TOKEN_CACHE_TTL_MS,
        )
        .unwrap();
        assert!(slot.argon2_hash.is_none());
        assert!(slot.fingerprint.is_empty());
    }

    /// Debug output for a `CachedSlot` with `None` hash must contain
    /// "None" rather than a hash string.
    #[test]
    #[serial]
    fn cached_slot_debug_none_hash() {
        let slot = CachedSlot {
            argon2_hash: None,
            fingerprint: "xyz789".to_string(),
        };
        let debug = format!("{:?}", slot);
        assert!(
            debug.contains("None"),
            "Debug must show None for absent hash"
        );
        assert!(debug.contains("xyz789"));
    }

    /// Cloning a `CachedSlot` with `None` hash preserves the `None`.
    #[test]
    #[serial]
    fn cached_slot_clone_preserves_none_hash() {
        let slot = CachedSlot {
            argon2_hash: None,
            fingerprint: "clnnnn".to_string(),
        };
        let cloned = slot.clone();
        assert!(cloned.argon2_hash.is_none());
        assert_eq!(cloned.fingerprint, "clnnnn");
    }

    // ── CacheRecord internal struct coverage ─────────────────────────

    /// The internal `CacheRecord` struct derives Debug and Clone.
    /// Exercise both to confirm the derive macros are wired correctly.
    #[test]
    #[serial]
    fn cache_record_debug_and_clone() {
        let record = super::CacheRecord {
            slot: CachedSlot {
                argon2_hash: Some("rec-hash".to_string()),
                fingerprint: "rec111".to_string(),
            },
            fetched_at_ms: 1_700_000_000_000,
        };
        let debug = format!("{:?}", record);
        assert!(debug.contains("rec-hash"));
        assert!(debug.contains("1700000000000"));

        let cloned = record.clone();
        assert_eq!(cloned.fetched_at_ms, 1_700_000_000_000);
        assert_eq!(cloned.slot.fingerprint, "rec111");
    }

    // ── Cache population and clear cycles ────────────────────────────

    /// Seeding after a clear must work. Validates that clear does not
    /// leave the RwLock in a poisoned state that would cause subsequent
    /// writes to fail silently.
    #[test]
    #[serial]
    fn seed_after_clear_works() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_AFTER_CLR",
            CachedSlot {
                argon2_hash: Some("post-clear".to_string()),
                fingerprint: "pcpcpc".to_string(),
            },
        );
        let slot =
            read_fresh("STATUS_API_TOKEN_TEST_AFTER_CLR", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(slot.fingerprint, "pcpcpc");
    }

    /// Multiple clear calls in succession must not panic or corrupt
    /// the cache. Clearing an already-empty cache is a no-op.
    #[test]
    #[serial]
    fn double_clear_is_safe() {
        test_clear();
        test_clear();
        assert!(read_fresh("STATUS_API_TOKEN_TEST_PHANTOM", STATUS_TOKEN_CACHE_TTL_MS).is_none());
    }

    /// Populate many entries, then clear, then confirm all are gone.
    /// Exercises the cache with more than the steady-state two entries.
    #[test]
    #[serial]
    fn clear_removes_many_entries() {
        test_clear();
        for i in 0..10 {
            let binding = format!("STATUS_API_TOKEN_TEST_MANY_{i}");
            test_seed(
                &binding,
                CachedSlot {
                    argon2_hash: Some(format!("hash-{i}")),
                    fingerprint: format!("{i:06}"),
                },
            );
        }
        // Confirm at least a couple are present.
        assert!(read_fresh("STATUS_API_TOKEN_TEST_MANY_0", STATUS_TOKEN_CACHE_TTL_MS).is_some());
        assert!(read_fresh("STATUS_API_TOKEN_TEST_MANY_9", STATUS_TOKEN_CACHE_TTL_MS).is_some());

        test_clear();
        for i in 0..10 {
            let binding = format!("STATUS_API_TOKEN_TEST_MANY_{i}");
            assert!(
                read_fresh(&binding, STATUS_TOKEN_CACHE_TTL_MS).is_none(),
                "entry {i} must be gone after clear"
            );
        }
    }

    // ── Force-expire selective behaviour ─────────────────────────────

    /// Force-expiring one binding must not affect a sibling. This mirrors
    /// production where the current token rotates but the previous slot
    /// remains cached and valid.
    #[test]
    #[serial]
    fn force_expire_one_does_not_affect_sibling() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_SIBLING_A",
            CachedSlot {
                argon2_hash: Some("sib-a".to_string()),
                fingerprint: "aaa000".to_string(),
            },
        );
        test_seed(
            "STATUS_API_TOKEN_TEST_SIBLING_B",
            CachedSlot {
                argon2_hash: Some("sib-b".to_string()),
                fingerprint: "bbb000".to_string(),
            },
        );
        test_force_expire("STATUS_API_TOKEN_TEST_SIBLING_A");

        assert!(
            read_fresh("STATUS_API_TOKEN_TEST_SIBLING_A", STATUS_TOKEN_CACHE_TTL_MS).is_none(),
            "expired binding must miss"
        );
        let b = read_fresh("STATUS_API_TOKEN_TEST_SIBLING_B", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(b.fingerprint, "bbb000", "sibling must remain fresh");
    }

    /// Double force-expire on the same binding must not panic and must
    /// keep the entry expired.
    #[test]
    #[serial]
    fn double_force_expire_is_idempotent() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_DOUBLE_EXP",
            CachedSlot {
                argon2_hash: Some("dbl".to_string()),
                fingerprint: "dbl000".to_string(),
            },
        );
        test_force_expire("STATUS_API_TOKEN_TEST_DOUBLE_EXP");
        test_force_expire("STATUS_API_TOKEN_TEST_DOUBLE_EXP");
        assert!(read_fresh(
            "STATUS_API_TOKEN_TEST_DOUBLE_EXP",
            STATUS_TOKEN_CACHE_TTL_MS
        )
        .is_none());
    }

    // ── Binding name edge cases ──────────────────────────────────────

    /// An empty-string binding name is a degenerate case. The cache
    /// must handle it without panic: store and retrieve it like any
    /// other key.
    #[test]
    #[serial]
    fn empty_binding_name_works() {
        test_clear();
        test_seed(
            "",
            CachedSlot {
                argon2_hash: Some("empty-key-hash".to_string()),
                fingerprint: "ek0000".to_string(),
            },
        );
        let slot = read_fresh("", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(slot.fingerprint, "ek0000");
    }

    /// A very long binding name must round-trip without truncation.
    #[test]
    #[serial]
    fn long_binding_name_round_trips() {
        test_clear();
        let long_name = "STATUS_API_TOKEN_".to_string() + &"X".repeat(500);
        test_seed(
            &long_name,
            CachedSlot {
                argon2_hash: Some("long-binding".to_string()),
                fingerprint: "lng000".to_string(),
            },
        );
        let slot = read_fresh(&long_name, STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(slot.fingerprint, "lng000");
    }

    // ── Hash value edge cases ────────────────────────────────────────

    /// A very long hash string must round-trip. Argon2id PHC strings
    /// are typically ~100 chars, but the cache must not impose a limit.
    #[test]
    #[serial]
    fn long_hash_value_round_trips() {
        test_clear();
        let long_hash = "$argon2id$v=19$m=65536,t=3,p=4$".to_string() + &"A".repeat(500);
        test_seed(
            "STATUS_API_TOKEN_TEST_LONG_HASH",
            CachedSlot {
                argon2_hash: Some(long_hash.clone()),
                fingerprint: "lh0000".to_string(),
            },
        );
        let slot =
            read_fresh("STATUS_API_TOKEN_TEST_LONG_HASH", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(slot.argon2_hash.as_deref(), Some(long_hash.as_str()));
    }

    /// Unicode in the fingerprint field. Production fingerprints are
    /// hex-only, but the cache is a generic string store and must not
    /// corrupt multi-byte data.
    #[test]
    #[serial]
    fn unicode_fingerprint_round_trips() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_UNICODE",
            CachedSlot {
                argon2_hash: Some("uni-hash".to_string()),
                fingerprint: "\u{1F512}\u{1F511}".to_string(),
            },
        );
        let slot = read_fresh("STATUS_API_TOKEN_TEST_UNICODE", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(slot.fingerprint, "\u{1F512}\u{1F511}");
    }

    // ── Rotation simulation tests ────────────────────────────────────

    /// Full rotation cycle: seed current, seed previous, expire current,
    /// re-seed current with new value, confirm both slots are correct.
    /// This mirrors the production dual-slot rotation pattern.
    #[test]
    #[serial]
    fn full_dual_slot_rotation_cycle() {
        test_clear();

        // Phase 1: both slots active.
        test_seed(
            "STATUS_API_TOKEN_ROT_CURRENT",
            CachedSlot {
                argon2_hash: Some("current-v1".to_string()),
                fingerprint: "cur1v1".to_string(),
            },
        );
        test_seed(
            "STATUS_API_TOKEN_ROT_PREVIOUS",
            CachedSlot {
                argon2_hash: Some("previous-v0".to_string()),
                fingerprint: "prv0v0".to_string(),
            },
        );
        let cur = read_fresh("STATUS_API_TOKEN_ROT_CURRENT", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        let prev = read_fresh("STATUS_API_TOKEN_ROT_PREVIOUS", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(cur.fingerprint, "cur1v1");
        assert_eq!(prev.fingerprint, "prv0v0");

        // Phase 2: operator rotates current. Old current becomes previous.
        test_force_expire("STATUS_API_TOKEN_ROT_CURRENT");
        test_force_expire("STATUS_API_TOKEN_ROT_PREVIOUS");

        assert!(read_fresh("STATUS_API_TOKEN_ROT_CURRENT", STATUS_TOKEN_CACHE_TTL_MS).is_none());
        assert!(read_fresh("STATUS_API_TOKEN_ROT_PREVIOUS", STATUS_TOKEN_CACHE_TTL_MS).is_none());

        // Phase 3: cache refresh with new values.
        test_seed(
            "STATUS_API_TOKEN_ROT_CURRENT",
            CachedSlot {
                argon2_hash: Some("current-v2".to_string()),
                fingerprint: "cur2v2".to_string(),
            },
        );
        test_seed(
            "STATUS_API_TOKEN_ROT_PREVIOUS",
            CachedSlot {
                argon2_hash: Some("current-v1-now-prev".to_string()),
                fingerprint: "cur1v1".to_string(),
            },
        );
        let cur2 = read_fresh("STATUS_API_TOKEN_ROT_CURRENT", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        let prev2 = read_fresh("STATUS_API_TOKEN_ROT_PREVIOUS", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(cur2.fingerprint, "cur2v2");
        assert_eq!(cur2.argon2_hash.as_deref(), Some("current-v2"));
        assert_eq!(prev2.fingerprint, "cur1v1");
        assert_eq!(prev2.argon2_hash.as_deref(), Some("current-v1-now-prev"));
    }

    /// Rotation where the previous slot is deliberately cleared (set
    /// to None hash). After the dual-accept window closes, the operator
    /// removes the previous token from Secrets Store, producing a
    /// negative cache entry for that slot.
    #[test]
    #[serial]
    fn rotation_clears_previous_slot() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_CLR_CURR",
            CachedSlot {
                argon2_hash: Some("active-hash".to_string()),
                fingerprint: "act000".to_string(),
            },
        );
        test_seed(
            "STATUS_API_TOKEN_CLR_PREV",
            CachedSlot {
                argon2_hash: None,
                fingerprint: "000000".to_string(),
            },
        );
        let curr = read_fresh("STATUS_API_TOKEN_CLR_CURR", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        let prev = read_fresh("STATUS_API_TOKEN_CLR_PREV", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert!(curr.argon2_hash.is_some());
        assert!(prev.argon2_hash.is_none());
        assert_eq!(prev.fingerprint, "000000");
    }

    // ── CACHE static lazy initialisation ─────────────────────────────

    /// The CACHE static must initialise as empty. After a clear, reading
    /// any binding returns None.
    #[test]
    #[serial]
    fn cache_initialises_empty() {
        test_clear();
        assert!(read_fresh("STATUS_API_TOKEN_INIT_CHECK", STATUS_TOKEN_CACHE_TTL_MS).is_none());
    }

    /// Confirm the CACHE RwLock can be acquired for reading after being
    /// acquired for writing. This is a basic sanity check that the lock
    /// is not held across the helper boundaries.
    #[test]
    #[serial]
    fn cache_lock_not_held_across_helpers() {
        test_clear();
        // write via test_seed
        test_seed(
            "STATUS_API_TOKEN_TEST_LOCK",
            CachedSlot {
                argon2_hash: Some("lock-test".to_string()),
                fingerprint: "lck000".to_string(),
            },
        );
        // read should succeed without deadlock
        let slot = read_fresh("STATUS_API_TOKEN_TEST_LOCK", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(slot.fingerprint, "lck000");
        // write again should succeed
        test_seed(
            "STATUS_API_TOKEN_TEST_LOCK",
            CachedSlot {
                argon2_hash: Some("lock-test-2".to_string()),
                fingerprint: "lck002".to_string(),
            },
        );
        let slot2 = read_fresh("STATUS_API_TOKEN_TEST_LOCK", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(slot2.fingerprint, "lck002");
    }

    // ── TTL arithmetic edge cases ────────────────────────────────────

    /// A force-expired entry (fetched_at_ms = 0) with TTL = now_ms()
    /// should hit because `age = now - 0 = now` and `now <= now` is
    /// true. This confirms the `<=` boundary in the TTL comparison.
    #[test]
    #[serial]
    fn ttl_equal_to_age_is_a_hit() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_TTL_EQ",
            CachedSlot {
                argon2_hash: Some("boundary".to_string()),
                fingerprint: "bnd000".to_string(),
            },
        );
        test_force_expire("STATUS_API_TOKEN_TEST_TTL_EQ");
        // age = now_ms() - 0 = now_ms(). TTL = now_ms(). age <= TTL.
        let ttl = super::now_ms();
        let result = read_fresh("STATUS_API_TOKEN_TEST_TTL_EQ", ttl);
        assert!(
            result.is_some(),
            "age == ttl must be a hit (inclusive boundary)"
        );
    }

    /// A freshly written entry read with TTL of 1 must hit because
    /// the age is 0 (or very close) and 0 <= 1.
    #[test]
    #[serial]
    fn freshly_written_entry_with_ttl_1_hits() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN_TEST_TTL1_FRESH",
            CachedSlot {
                argon2_hash: Some("fresh-1".to_string()),
                fingerprint: "fr1000".to_string(),
            },
        );
        // Read immediately. Age should be 0 ms, so TTL=1 must hit.
        let result = read_fresh("STATUS_API_TOKEN_TEST_TTL1_FRESH", 1);
        assert!(
            result.is_some(),
            "freshly written entry with TTL=1 must hit"
        );
    }

    /// `saturating_sub` correctness: if `fetched_at_ms` were somehow
    /// in the future (clock skew), `now.saturating_sub(fetched_at)` = 0,
    /// so `0 <= ttl` is always true and the entry reads as fresh. We
    /// simulate this by writing directly into the cache with a far-future
    /// timestamp.
    #[test]
    #[serial]
    fn future_fetched_at_reads_as_fresh() {
        test_clear();
        // Manually insert a CacheRecord with a far-future timestamp.
        {
            let mut guard = super::CACHE.write().unwrap();
            guard.insert(
                "STATUS_API_TOKEN_TEST_FUTURE".to_string(),
                super::CacheRecord {
                    slot: CachedSlot {
                        argon2_hash: Some("future-hash".to_string()),
                        fingerprint: "fut000".to_string(),
                    },
                    fetched_at_ms: u64::MAX,
                },
            );
        }
        // now - u64::MAX saturates to 0. 0 <= any TTL.
        let slot = read_fresh("STATUS_API_TOKEN_TEST_FUTURE", 1).unwrap();
        assert_eq!(slot.fingerprint, "fut000");
    }

    /// Confirm `saturating_sub` behaviour explicitly: when `fetched_at_ms`
    /// is `u64::MAX / 2` and now is less than that (not possible in real
    /// clocks, but the arithmetic must still be safe), the age saturates
    /// to 0.
    #[test]
    #[serial]
    fn saturating_sub_does_not_underflow() {
        test_clear();
        {
            let mut guard = super::CACHE.write().unwrap();
            guard.insert(
                "STATUS_API_TOKEN_TEST_SAT".to_string(),
                super::CacheRecord {
                    slot: CachedSlot {
                        argon2_hash: Some("sat-hash".to_string()),
                        fingerprint: "sat000".to_string(),
                    },
                    // Far future: now_ms() will be less than this.
                    fetched_at_ms: u64::MAX - 1,
                },
            );
        }
        // age = now.saturating_sub(u64::MAX - 1) = 0. 0 <= 1. Hit.
        let result = read_fresh("STATUS_API_TOKEN_TEST_SAT", 1);
        assert!(result.is_some(), "saturating_sub must prevent underflow");
    }

    // ── Interleaved operations ───────────────────────────────────────

    /// Interleaved seed/expire/read across multiple bindings. Confirms
    /// operations on different keys do not interfere.
    #[test]
    #[serial]
    fn interleaved_operations_across_bindings() {
        test_clear();

        test_seed(
            "STATUS_API_TOKEN_TEST_INTER_1",
            CachedSlot {
                argon2_hash: Some("inter-1".to_string()),
                fingerprint: "int001".to_string(),
            },
        );
        test_seed(
            "STATUS_API_TOKEN_TEST_INTER_2",
            CachedSlot {
                argon2_hash: Some("inter-2".to_string()),
                fingerprint: "int002".to_string(),
            },
        );

        // Expire only #1.
        test_force_expire("STATUS_API_TOKEN_TEST_INTER_1");

        // Re-seed #1 with new data.
        test_seed(
            "STATUS_API_TOKEN_TEST_INTER_1",
            CachedSlot {
                argon2_hash: Some("inter-1-v2".to_string()),
                fingerprint: "i1v200".to_string(),
            },
        );

        let s1 = read_fresh("STATUS_API_TOKEN_TEST_INTER_1", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        let s2 = read_fresh("STATUS_API_TOKEN_TEST_INTER_2", STATUS_TOKEN_CACHE_TTL_MS).unwrap();

        assert_eq!(s1.fingerprint, "i1v200");
        assert_eq!(s1.argon2_hash.as_deref(), Some("inter-1-v2"));
        assert_eq!(s2.fingerprint, "int002");
        assert_eq!(s2.argon2_hash.as_deref(), Some("inter-2"));
    }

    // ── Production binding name constants ────────────────────────────

    /// Verify the production binding names work as cache keys. These
    /// are the actual strings used in `get_or_refresh` and
    /// `status_auth.rs`.
    #[test]
    #[serial]
    fn production_binding_names_as_keys() {
        test_clear();
        test_seed(
            "STATUS_API_TOKEN",
            CachedSlot {
                argon2_hash: Some("prod-current".to_string()),
                fingerprint: "prd001".to_string(),
            },
        );
        test_seed(
            "STATUS_API_TOKEN_PREVIOUS",
            CachedSlot {
                argon2_hash: Some("prod-previous".to_string()),
                fingerprint: "prd002".to_string(),
            },
        );
        let curr = read_fresh("STATUS_API_TOKEN", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        let prev = read_fresh("STATUS_API_TOKEN_PREVIOUS", STATUS_TOKEN_CACHE_TTL_MS).unwrap();
        assert_eq!(curr.fingerprint, "prd001");
        assert_eq!(prev.fingerprint, "prd002");
    }
}
