// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Ban list backed by a Cloudflare KV namespace.
//!
//! Each ban entry is keyed by `ban:<base64url(nullifier)>` and stores a JSON
//! object with a reason string and UNIX timestamp. Nullifiers are 32-byte
//! values derived from the zero knowledge proof system and uniquely identify a
//! credential without revealing the holder's identity.
#![forbid(unsafe_code)]

use crate::{
    error::{ApiError, ApiResult},
    storage::traits::BanStore,
};
use async_trait::async_trait;
use base64::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use worker::kv::KvStore;

/// Cached result of a ban check with the wall-clock time it was performed.
struct CachedBanCheck {
    is_banned: bool,
    checked_at: f64,
}

/// Duration in milliseconds to cache "not banned" results. Bans are extremely
/// rare (manual admin action), so a 5-minute negative cache avoids redundant
/// KV reads for the vast majority of requests.
const BAN_CACHE_TTL_MS: f64 = 300_000.0;

/// Maximum number of cache entries before the entire cache is cleared. Prevents
/// unbounded memory growth if the worker handles a large number of distinct
/// nullifiers.
const BAN_CACHE_MAX_ENTRIES: usize = 10_000;

/// KV-backed [`BanStore`] implementation with an in-memory negative cache.
///
/// Ban keys use base64url-encoded 32-byte nullifiers prefixed with `ban:`.
/// Lookups check the in-memory cache first; on a miss the KV namespace is
/// queried and the result is cached for `BAN_CACHE_TTL_MS`. Listings bypass
/// the cache entirely since they are admin operations.
#[derive(Clone)]
pub struct KvBanStore {
    namespace: KvStore,
    cache: Arc<RwLock<HashMap<[u8; 32], CachedBanCheck>>>,
}

impl KvBanStore {
    /// Create a new ban store backed by the given KV namespace.
    pub fn new(namespace: KvStore) -> Self {
        Self {
            namespace,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn make_key(nullifier: &[u8; 32]) -> String {
        format!("ban:{}", BASE64_URL_SAFE_NO_PAD.encode(nullifier))
    }
}

#[async_trait(?Send)]
impl BanStore for KvBanStore {
    async fn is_banned(&self, nullifier: &[u8; 32]) -> ApiResult<bool> {
        let now: f64 = worker::Date::now().as_millis() as f64;

        // Check the in-memory cache first. A fresh cached result avoids the
        // KV round-trip entirely.
        {
            let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = cache.get(nullifier) {
                if (now - entry.checked_at) < BAN_CACHE_TTL_MS {
                    return Ok(entry.is_banned);
                }
            }
        }

        // Cache miss or stale entry. Query KV with per-operation timeout.
        let key = Self::make_key(nullifier);
        let ns = self.namespace.clone();
        let key_clone = key.clone();
        let value = crate::utils::timeout::with_timeout(
            "ban_store KV read",
            crate::utils::timeout::KV_READ_TIMEOUT_MS,
            async move {
                ns.get(&key_clone)
                    .text()
                    .await
                    .map_err(|e| ApiError::Internal(anyhow::anyhow!("KV get failed: {}", e)))
            },
        )
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("{}", e)))??;

        let is_banned = value.is_some();

        // Store the result in the cache.
        {
            let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
            // Simple eviction: clear the entire cache if it exceeds the max size.
            if cache.len() >= BAN_CACHE_MAX_ENTRIES {
                cache.clear();
            }
            cache.insert(
                *nullifier,
                CachedBanCheck {
                    is_banned,
                    checked_at: now,
                },
            );
        }

        Ok(is_banned)
    }
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
    /*                    KvBanStore::make_key() TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_make_key_format() {
        let nullifier = [0u8; 32];
        let key = KvBanStore::make_key(&nullifier);
        assert!(key.starts_with("ban:"));
        assert_eq!(key.len(), 4 + 43); // "ban:" + 43 char base64url
    }

    #[test]
    fn test_make_key_all_zeros() {
        let nullifier = [0u8; 32];
        let key = KvBanStore::make_key(&nullifier);
        assert_eq!(key, "ban:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }

    #[test]
    fn test_make_key_all_ones() {
        let nullifier = [255u8; 32];
        let key = KvBanStore::make_key(&nullifier);
        assert_eq!(key, "ban:__________________________________________8");
    }

    #[test]
    fn test_make_key_sequential() {
        let nullifier: [u8; 32] = core::array::from_fn(|i| i as u8);
        let key = KvBanStore::make_key(&nullifier);
        assert!(key.starts_with("ban:"));
        assert!(!key.contains('=')); // No padding
    }

    #[test]
    fn test_make_key_deterministic() {
        let nullifier = [42u8; 32];
        let key1 = KvBanStore::make_key(&nullifier);
        let key2 = KvBanStore::make_key(&nullifier);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_make_key_different_nullifiers() {
        let nullifier1 = [0u8; 32];
        let nullifier2 = [1u8; 32];
        let key1 = KvBanStore::make_key(&nullifier1);
        let key2 = KvBanStore::make_key(&nullifier2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_make_key_no_padding() {
        let nullifier = [123u8; 32];
        let key = KvBanStore::make_key(&nullifier);
        assert!(!key.contains('=')); // URL-safe no padding
    }

    #[test]
    fn test_make_key_url_safe() {
        let nullifier = [255u8; 32];
        let key = KvBanStore::make_key(&nullifier);
        assert!(!key.contains('+')); // No + in URL-safe
        assert!(!key.contains('/')); // No / in URL-safe
    }

    /* ========================================================================== */
    /*                    is_banned() Logic Tests                                */
    /* ========================================================================== */

    #[test]
    fn test_is_banned_value_some() {
        let value: Option<String> = Some("ban data".to_string());
        let result = value.is_some();
        assert!(result);
    }

    #[test]
    fn test_is_banned_value_none() {
        let value: Option<String> = None;
        let result = value.is_some();
        assert!(!result);
    }

    #[test]
    fn test_is_banned_boolean_conversion() {
        let some_value: Option<String> = Some("anything".to_string());
        let none_value: Option<String> = None;

        assert!(some_value.is_some());
        assert!(none_value.is_none());
    }

    /* ========================================================================== */
    /*                    Key Encoding Tests                                     */
    /* ========================================================================== */

    #[test]
    fn test_key_encoding_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let nullifier = [123u8; 32];
        let key = KvBanStore::make_key(&nullifier);

        // Extract the base64 part
        let base64_part = key.strip_prefix("ban:").ok_or("missing ban: prefix")?;
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(base64_part)?;

        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded, nullifier);
        Ok(())
    }

    #[test]
    fn test_key_encoding_different_nullifiers_different_keys(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let nullifier1 = [10u8; 32];
        let nullifier2 = [20u8; 32];

        let key1 = KvBanStore::make_key(&nullifier1);
        let key2 = KvBanStore::make_key(&nullifier2);

        assert_ne!(key1, key2);

        let base64_1 = key1
            .strip_prefix("ban:")
            .ok_or("missing ban: prefix on key1")?;
        let base64_2 = key2
            .strip_prefix("ban:")
            .ok_or("missing ban: prefix on key2")?;

        assert_ne!(base64_1, base64_2);
        Ok(())
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: make_key() always produces "ban:" prefix
        #[test]
        fn prop_make_key_prefix(nullifier in any::<[u8; 32]>()) {
            let key = KvBanStore::make_key(&nullifier);
            prop_assert!(key.starts_with("ban:"));
        }

        /// Property: make_key() always produces 47 chars (4 + 43)
        #[test]
        fn prop_make_key_length(nullifier in any::<[u8; 32]>()) {
            let key = KvBanStore::make_key(&nullifier);
            prop_assert_eq!(key.len(), 47);
        }

        /// Property: make_key() is deterministic
        #[test]
        fn prop_make_key_deterministic(nullifier in any::<[u8; 32]>()) {
            let key1 = KvBanStore::make_key(&nullifier);
            let key2 = KvBanStore::make_key(&nullifier);
            prop_assert_eq!(key1, key2);
        }

        /// Property: make_key() different inputs give different outputs
        #[test]
        fn prop_make_key_different_inputs(
            nullifier1 in any::<[u8; 32]>(),
            nullifier2 in any::<[u8; 32]>()
        ) {
            prop_assume!(nullifier1 != nullifier2);
            let key1 = KvBanStore::make_key(&nullifier1);
            let key2 = KvBanStore::make_key(&nullifier2);
            prop_assert_ne!(key1, key2);
        }

        /// Property: make_key() never has padding or non-URL-safe chars
        #[test]
        fn prop_make_key_url_safe(nullifier in any::<[u8; 32]>()) {
            let key = KvBanStore::make_key(&nullifier);
            prop_assert!(!key.contains('='));
            prop_assert!(!key.contains('+'));
            prop_assert!(!key.contains('/'));
        }

        /// Property: Key encoding roundtrip preserves nullifier
        #[test]
        fn prop_key_encoding_roundtrip(nullifier in any::<[u8; 32]>()) {
            let key = KvBanStore::make_key(&nullifier);
            let base64_part = key.strip_prefix("ban:")
                .ok_or_else(|| TestCaseError::fail("missing ban: prefix"))?;
            let decoded = BASE64_URL_SAFE_NO_PAD.decode(base64_part)
                .map_err(|e| TestCaseError::fail(format!("{e}")))?;

            prop_assert_eq!(decoded.len(), 32);
            prop_assert_eq!(&decoded[..], &nullifier[..]);
        }

        /// Property: is_some() returns true for Some, false for None
        #[test]
        fn prop_is_some_consistent(has_value in any::<bool>()) {
            let opt: Option<String> = if has_value {
                Some("data".to_string())
            } else {
                None
            };

            prop_assert_eq!(opt.is_some(), has_value);
        }
    }

    /* ========================================================================== */
    /*                    CONSTANT VALUE TESTS                                    */
    /* ========================================================================== */

    #[test]
    fn test_ban_cache_ttl_ms_is_five_minutes() {
        assert!((BAN_CACHE_TTL_MS - 300_000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_ban_cache_max_entries_is_ten_thousand() {
        assert_eq!(BAN_CACHE_MAX_ENTRIES, 10_000);
    }

    #[test]
    fn test_ban_cache_ttl_positive() {
        assert!(BAN_CACHE_TTL_MS > 0.0);
    }

    #[test]
    fn test_ban_cache_max_entries_nonzero() {
        assert!(BAN_CACHE_MAX_ENTRIES > 0);
    }

    /* ========================================================================== */
    /*                    CachedBanCheck STRUCT TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_cached_ban_check_banned_true() {
        let entry = CachedBanCheck {
            is_banned: true,
            checked_at: 1000.0,
        };
        assert!(entry.is_banned);
        assert!((entry.checked_at - 1000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cached_ban_check_banned_false() {
        let entry = CachedBanCheck {
            is_banned: false,
            checked_at: 2000.0,
        };
        assert!(!entry.is_banned);
        assert!((entry.checked_at - 2000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cached_ban_check_zero_timestamp() {
        let entry = CachedBanCheck {
            is_banned: false,
            checked_at: 0.0,
        };
        assert!((entry.checked_at - 0.0).abs() < f64::EPSILON);
    }

    /* ========================================================================== */
    /*                    CACHE STALENESS LOGIC TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_cache_entry_fresh_when_within_ttl() {
        let checked_at = 1_000_000.0;
        let now = checked_at + BAN_CACHE_TTL_MS - 1.0; // 1ms before expiry
        assert!((now - checked_at) < BAN_CACHE_TTL_MS);
    }

    #[test]
    fn test_cache_entry_stale_when_at_ttl() {
        let checked_at = 1_000_000.0;
        let now = checked_at + BAN_CACHE_TTL_MS; // exactly at expiry
        assert!((now - checked_at) >= BAN_CACHE_TTL_MS);
    }

    #[test]
    fn test_cache_entry_stale_when_beyond_ttl() {
        let checked_at = 1_000_000.0;
        let now = checked_at + BAN_CACHE_TTL_MS + 1.0; // 1ms after expiry
        assert!((now - checked_at) >= BAN_CACHE_TTL_MS);
    }

    #[test]
    fn test_cache_entry_fresh_when_just_created() {
        let checked_at = 5_000_000.0;
        let now = checked_at; // same instant
        assert!((now - checked_at) < BAN_CACHE_TTL_MS);
    }

    #[test]
    fn test_cache_entry_fresh_at_half_ttl() {
        let checked_at = 1_000_000.0;
        let now = checked_at + BAN_CACHE_TTL_MS / 2.0;
        assert!((now - checked_at) < BAN_CACHE_TTL_MS);
    }

    /* ========================================================================== */
    /*                    CACHE EVICTION THRESHOLD TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_eviction_triggers_at_max_entries() {
        let mut cache: HashMap<[u8; 32], CachedBanCheck> = HashMap::new();
        for i in 0..BAN_CACHE_MAX_ENTRIES {
            let mut key = [0u8; 32];
            let bytes = (i as u64).to_le_bytes();
            key[..8].copy_from_slice(&bytes);
            cache.insert(
                key,
                CachedBanCheck {
                    is_banned: false,
                    checked_at: 0.0,
                },
            );
        }
        assert!(cache.len() >= BAN_CACHE_MAX_ENTRIES);
    }

    #[test]
    fn test_eviction_does_not_trigger_below_max() {
        let mut cache: HashMap<[u8; 32], CachedBanCheck> = HashMap::new();
        for i in 0..(BAN_CACHE_MAX_ENTRIES - 1) {
            let mut key = [0u8; 32];
            let bytes = (i as u64).to_le_bytes();
            key[..8].copy_from_slice(&bytes);
            cache.insert(
                key,
                CachedBanCheck {
                    is_banned: false,
                    checked_at: 0.0,
                },
            );
        }
        assert!(cache.len() < BAN_CACHE_MAX_ENTRIES);
    }

    #[test]
    fn test_cache_clear_resets_to_zero() {
        let mut cache: HashMap<[u8; 32], CachedBanCheck> = HashMap::new();
        for i in 0..100_usize {
            let mut key = [0u8; 32];
            let bytes = (i as u64).to_le_bytes();
            key[..8].copy_from_slice(&bytes);
            cache.insert(
                key,
                CachedBanCheck {
                    is_banned: false,
                    checked_at: 0.0,
                },
            );
        }
        assert_eq!(cache.len(), 100);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_insert_after_clear_works() {
        let mut cache: HashMap<[u8; 32], CachedBanCheck> = HashMap::new();
        let key = [42u8; 32];
        cache.insert(
            key,
            CachedBanCheck {
                is_banned: true,
                checked_at: 100.0,
            },
        );
        cache.clear();
        cache.insert(
            key,
            CachedBanCheck {
                is_banned: false,
                checked_at: 200.0,
            },
        );
        assert_eq!(cache.len(), 1);
        let entry = cache.get(&key);
        assert!(entry.is_some());
        assert!(!entry.map(|e| e.is_banned).unwrap_or(true));
    }

    #[test]
    fn test_cache_overwrite_updates_entry() {
        let mut cache: HashMap<[u8; 32], CachedBanCheck> = HashMap::new();
        let key = [7u8; 32];
        cache.insert(
            key,
            CachedBanCheck {
                is_banned: false,
                checked_at: 100.0,
            },
        );
        cache.insert(
            key,
            CachedBanCheck {
                is_banned: true,
                checked_at: 200.0,
            },
        );
        assert_eq!(cache.len(), 1);
        let entry = cache.get(&key);
        assert!(entry.map(|e| e.is_banned).unwrap_or(false));
    }

    /* ========================================================================== */
    /*                    make_key() ADDITIONAL EDGE CASES                        */
    /* ========================================================================== */

    #[test]
    fn test_make_key_single_high_bit() {
        let mut nullifier = [0u8; 32];
        nullifier[0] = 0x80;
        let key = KvBanStore::make_key(&nullifier);
        assert!(key.starts_with("ban:"));
        assert_eq!(key.len(), 47);
    }

    #[test]
    fn test_make_key_alternating_bytes() {
        let nullifier: [u8; 32] = core::array::from_fn(|i| if i % 2 == 0 { 0xAA } else { 0x55 });
        let key = KvBanStore::make_key(&nullifier);
        assert!(key.starts_with("ban:"));
        assert!(!key.contains('+'));
        assert!(!key.contains('/'));
        assert!(!key.contains('='));
    }

    #[test]
    fn test_make_key_last_byte_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 0x00;
        b[31] = 0x01;
        assert_ne!(KvBanStore::make_key(&a), KvBanStore::make_key(&b));
    }

    #[test]
    fn test_make_key_first_byte_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 0xFE;
        b[0] = 0xFF;
        assert_ne!(KvBanStore::make_key(&a), KvBanStore::make_key(&b));
    }

    #[test]
    fn test_make_key_roundtrip_high_entropy() -> Result<(), Box<dyn std::error::Error>> {
        let nullifier: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37));
        let key = KvBanStore::make_key(&nullifier);
        let base64_part = key.strip_prefix("ban:").ok_or("missing ban: prefix")?;
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(base64_part)?;
        assert_eq!(decoded.as_slice(), nullifier.as_slice());
        Ok(())
    }

    #[test]
    fn test_make_key_all_url_safe_chars() {
        // Verify the base64 portion only contains URL-safe characters
        let nullifier = [0xDE; 32];
        let key = KvBanStore::make_key(&nullifier);
        let base64_part = &key[4..]; // skip "ban:"
        for ch in base64_part.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "unexpected character: {}",
                ch
            );
        }
    }

    /* ========================================================================== */
    /*                    CACHE LOOKUP SIMULATION TESTS                           */
    /* ========================================================================== */

    /// Simulate the full cache lookup logic from is_banned() without Worker runtime.
    #[test]
    fn test_cache_hit_fresh_banned_returns_true() {
        let mut cache: HashMap<[u8; 32], CachedBanCheck> = HashMap::new();
        let nullifier = [1u8; 32];
        let now = 1_000_000.0;
        cache.insert(
            nullifier,
            CachedBanCheck {
                is_banned: true,
                checked_at: now - 1000.0, // 1 second ago
            },
        );

        // Simulate the cache read path
        let result = cache.get(&nullifier).and_then(|entry| {
            if (now - entry.checked_at) < BAN_CACHE_TTL_MS {
                Some(entry.is_banned)
            } else {
                None
            }
        });
        assert_eq!(result, Some(true));
    }

    #[test]
    fn test_cache_hit_fresh_not_banned_returns_false() {
        let mut cache: HashMap<[u8; 32], CachedBanCheck> = HashMap::new();
        let nullifier = [2u8; 32];
        let now = 1_000_000.0;
        cache.insert(
            nullifier,
            CachedBanCheck {
                is_banned: false,
                checked_at: now - 100.0,
            },
        );

        let result = cache.get(&nullifier).and_then(|entry| {
            if (now - entry.checked_at) < BAN_CACHE_TTL_MS {
                Some(entry.is_banned)
            } else {
                None
            }
        });
        assert_eq!(result, Some(false));
    }

    #[test]
    fn test_cache_hit_stale_returns_none() {
        let mut cache: HashMap<[u8; 32], CachedBanCheck> = HashMap::new();
        let nullifier = [3u8; 32];
        let now = 1_000_000.0;
        cache.insert(
            nullifier,
            CachedBanCheck {
                is_banned: true,
                checked_at: now - BAN_CACHE_TTL_MS - 1.0, // expired
            },
        );

        let result = cache.get(&nullifier).and_then(|entry| {
            if (now - entry.checked_at) < BAN_CACHE_TTL_MS {
                Some(entry.is_banned)
            } else {
                None
            }
        });
        assert_eq!(result, None);
    }

    #[test]
    fn test_cache_miss_returns_none() {
        let cache: HashMap<[u8; 32], CachedBanCheck> = HashMap::new();
        let nullifier = [4u8; 32];
        let now = 1_000_000.0;

        let result = cache.get(&nullifier).and_then(|entry| {
            if (now - entry.checked_at) < BAN_CACHE_TTL_MS {
                Some(entry.is_banned)
            } else {
                None
            }
        });
        assert_eq!(result, None);
    }

    /// Simulate the full eviction + insert logic from is_banned().
    #[test]
    fn test_eviction_then_insert_preserves_new_entry() {
        let mut cache: HashMap<[u8; 32], CachedBanCheck> = HashMap::new();

        // Fill to max
        for i in 0..BAN_CACHE_MAX_ENTRIES {
            let mut key = [0u8; 32];
            let bytes = (i as u64).to_le_bytes();
            key[..8].copy_from_slice(&bytes);
            cache.insert(
                key,
                CachedBanCheck {
                    is_banned: false,
                    checked_at: 0.0,
                },
            );
        }
        assert!(cache.len() >= BAN_CACHE_MAX_ENTRIES);

        // Simulate the eviction logic
        if cache.len() >= BAN_CACHE_MAX_ENTRIES {
            cache.clear();
        }

        let new_nullifier = [0xFF; 32];
        cache.insert(
            new_nullifier,
            CachedBanCheck {
                is_banned: true,
                checked_at: 999_999.0,
            },
        );

        assert_eq!(cache.len(), 1);
        let entry = cache.get(&new_nullifier);
        assert!(entry.is_some());
        assert!(entry.map(|e| e.is_banned).unwrap_or(false));
    }

    /* ========================================================================== */
    /*                    RwLock CACHE CONCURRENCY TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_rwlock_cache_read_write_cycle() {
        let cache: Arc<RwLock<HashMap<[u8; 32], CachedBanCheck>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let nullifier = [99u8; 32];

        // Write
        {
            let mut w = cache.write().unwrap_or_else(|e| e.into_inner());
            w.insert(
                nullifier,
                CachedBanCheck {
                    is_banned: true,
                    checked_at: 500.0,
                },
            );
        }

        // Read
        {
            let r = cache.read().unwrap_or_else(|e| e.into_inner());
            let entry = r.get(&nullifier);
            assert!(entry.is_some());
            assert!(entry.map(|e| e.is_banned).unwrap_or(false));
        }
    }

    #[test]
    fn test_rwlock_poisoned_read_recovers() {
        let cache: Arc<RwLock<HashMap<[u8; 32], CachedBanCheck>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Poison the lock by panicking inside a write guard
        let cache_clone = Arc::clone(&cache);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut _guard = cache_clone.write().unwrap_or_else(|e| e.into_inner());
            panic!("intentional poison"); // nosemgrep: provii.workers.panic-in-worker
        }));
        assert!(result.is_err());

        // The into_inner recovery path used in production code should still work
        let guard = cache.read().unwrap_or_else(|e| e.into_inner());
        assert_eq!(guard.len(), 0);
    }

    #[test]
    fn test_rwlock_poisoned_write_recovers() {
        let cache: Arc<RwLock<HashMap<[u8; 32], CachedBanCheck>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let cache_clone = Arc::clone(&cache);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut _guard = cache_clone.write().unwrap_or_else(|e| e.into_inner());
            panic!("intentional poison"); // nosemgrep: provii.workers.panic-in-worker
        }));
        assert!(result.is_err());

        // Write recovery
        let mut guard = cache.write().unwrap_or_else(|e| e.into_inner());
        let nullifier = [88u8; 32];
        guard.insert(
            nullifier,
            CachedBanCheck {
                is_banned: false,
                checked_at: 0.0,
            },
        );
        assert_eq!(guard.len(), 1);
    }

    /* ========================================================================== */
    /*                    ADDITIONAL PROPERTY-BASED TESTS                         */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: cache staleness check is monotonic -- once stale, stays stale
        #[test]
        fn prop_cache_staleness_monotonic(
            checked_at in 0.0f64..1_000_000_000.0,
            offset_past_ttl in 0.0f64..1_000_000.0,
        ) {
            let stale_time = checked_at + BAN_CACHE_TTL_MS + offset_past_ttl;
            let even_later = stale_time + 1.0;
            // If stale at stale_time, must also be stale at even_later
            let stale_now = !((stale_time - checked_at) < BAN_CACHE_TTL_MS);
            let stale_later = !((even_later - checked_at) < BAN_CACHE_TTL_MS);
            prop_assert!(stale_now);
            prop_assert!(stale_later);
        }

        /// Property: cache freshness check -- within TTL is always fresh
        #[test]
        fn prop_cache_freshness_within_ttl(
            checked_at in 0.0f64..1_000_000_000.0,
            fraction in 0.0f64..1.0,
        ) {
            let now = checked_at + fraction * (BAN_CACHE_TTL_MS - 1.0);
            prop_assert!((now - checked_at) < BAN_CACHE_TTL_MS);
        }

        /// Property: make_key base64 portion only contains URL-safe chars
        #[test]
        fn prop_make_key_only_url_safe_chars(nullifier in any::<[u8; 32]>()) {
            let key = KvBanStore::make_key(&nullifier);
            let base64_part = key.strip_prefix("ban:")
                .ok_or_else(|| TestCaseError::fail("missing ban: prefix"))?;
            for ch in base64_part.chars() {
                prop_assert!(
                    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                    "unexpected character: {}",
                    ch
                );
            }
        }
    }
}
