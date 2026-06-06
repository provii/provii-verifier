// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! KV store abstraction for rate limiting.
//!
//! Defines [`RateLimitKv`], the minimal trait surface used by both the expert
//! and hosted rate limiting modules. Production code uses the [`KvStoreAdapter`]
//! wrapper around `worker::kv::KvStore`. Tests use `MockKv` which stores
//! entries in a `HashMap` with optional failure injection.

use async_trait::async_trait;

/// Errors from the rate limit KV abstraction.
#[derive(Debug)]
pub struct RateLimitKvError(pub String);

impl std::fmt::Display for RateLimitKvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Minimal KV interface consumed by the rate limiting modules.
///
/// Only two operations are needed: reading a text value by key and writing a
/// text value with a TTL. This keeps the mock surface small and the production
/// adapter trivial.
#[async_trait(?Send)]
pub trait RateLimitKv {
    /// Read a text value by key. Returns `Ok(None)` if the key does not exist.
    async fn get_text(&self, key: &str) -> Result<Option<String>, RateLimitKvError>;

    /// Write a text value with a TTL (seconds). Overwrites any existing value.
    async fn put_with_ttl(
        &self,
        key: &str,
        value: &str,
        ttl_secs: u64,
    ) -> Result<(), RateLimitKvError>;
}

// ---------------------------------------------------------------------------
// Production adapter (wasm32 only)
// ---------------------------------------------------------------------------

/// Thin wrapper that implements [`RateLimitKv`] for `worker::kv::KvStore`.
pub struct KvStoreAdapter<'a>(pub &'a worker::kv::KvStore);

#[async_trait(?Send)]
impl RateLimitKv for KvStoreAdapter<'_> {
    async fn get_text(&self, key: &str) -> Result<Option<String>, RateLimitKvError> {
        let kv = self.0.clone();
        let kv_key = key.to_string();
        crate::utils::timeout::with_timeout(
            "rate_limit KV read",
            crate::utils::timeout::KV_READ_TIMEOUT_MS,
            async move { kv.get(&kv_key).text().await },
        )
        .await
        .map_err(|e| RateLimitKvError(e.to_string()))?
        .map_err(|e| RateLimitKvError(e.to_string()))
    }

    async fn put_with_ttl(
        &self,
        key: &str,
        value: &str,
        ttl_secs: u64,
    ) -> Result<(), RateLimitKvError> {
        let put = self
            .0
            .put(key, value)
            .map_err(|e| RateLimitKvError(e.to_string()))?;
        crate::utils::timeout::with_timeout(
            "rate_limit KV write",
            crate::utils::timeout::KV_WRITE_TIMEOUT_MS,
            put.expiration_ttl(ttl_secs).execute(),
        )
        .await
        .map_err(|e| RateLimitKvError(e.to_string()))?
        .map_err(|e| RateLimitKvError(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Mock implementation (test only)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Record of a `put_with_ttl` call for assertion in tests.
    #[derive(Debug, Clone)]
    pub struct PutRecord {
        pub key: String,
        pub value: String,
        pub ttl_secs: u64,
    }

    /// In-memory KV mock with failure injection and put logging.
    ///
    /// All state is behind a `Mutex` so the mock can be shared across
    /// `async` calls within a single-threaded test executor.
    pub struct MockKv {
        inner: Mutex<MockKvInner>,
    }

    struct MockKvInner {
        data: HashMap<String, String>,
        puts: Vec<PutRecord>,
        /// When `Some`, the next `get_text` call returns this error.
        get_error: Option<String>,
        /// When `Some`, the next `put_with_ttl` call returns this error.
        put_error: Option<String>,
        /// If true, errors are persistent (not consumed on use).
        persistent_errors: bool,
    }

    impl Default for MockKv {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockKv {
        /// Create an empty mock KV store.
        pub fn new() -> Self {
            Self {
                inner: Mutex::new(MockKvInner {
                    data: HashMap::new(),
                    puts: Vec::new(),
                    get_error: None,
                    put_error: None,
                    persistent_errors: false,
                }),
            }
        }

        /// Pre-populate a key with a value.
        pub fn with_entry(self, key: &str, value: &str) -> Self {
            if let Ok(mut inner) = self.inner.lock() {
                inner.data.insert(key.to_string(), value.to_string());
            }
            self
        }

        /// Inject a get error. Consumed on first use unless persistent.
        pub fn with_get_error(self, msg: &str) -> Self {
            if let Ok(mut inner) = self.inner.lock() {
                inner.get_error = Some(msg.to_string());
            }
            self
        }

        /// Inject a put error. Consumed on first use unless persistent.
        pub fn with_put_error(self, msg: &str) -> Self {
            if let Ok(mut inner) = self.inner.lock() {
                inner.put_error = Some(msg.to_string());
            }
            self
        }

        /// Make injected errors persist across calls instead of being
        /// consumed on first use.
        pub fn with_persistent_errors(self) -> Self {
            if let Ok(mut inner) = self.inner.lock() {
                inner.persistent_errors = true;
            }
            self
        }

        /// Return all recorded put operations.
        pub fn puts(&self) -> Vec<PutRecord> {
            self.inner
                .lock()
                .map(|inner| inner.puts.clone())
                .unwrap_or_default()
        }

        /// Read the current value for a key (bypasses error injection).
        pub fn read_raw(&self, key: &str) -> Option<String> {
            self.inner
                .lock()
                .ok()
                .and_then(|inner| inner.data.get(key).cloned())
        }

        /// Return number of entries currently held.
        pub fn len(&self) -> usize {
            self.inner.lock().map(|inner| inner.data.len()).unwrap_or(0)
        }

        /// Returns true if the mock store holds no entries.
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }
    }

    #[async_trait(?Send)]
    impl RateLimitKv for MockKv {
        async fn get_text(&self, key: &str) -> Result<Option<String>, RateLimitKvError> {
            let mut inner = self
                .inner
                .lock()
                .map_err(|e| RateLimitKvError(e.to_string()))?;
            if let Some(ref err) = inner.get_error {
                let msg = err.clone();
                if !inner.persistent_errors {
                    inner.get_error = None;
                }
                return Err(RateLimitKvError(msg));
            }
            Ok(inner.data.get(key).cloned())
        }

        async fn put_with_ttl(
            &self,
            key: &str,
            value: &str,
            ttl_secs: u64,
        ) -> Result<(), RateLimitKvError> {
            let mut inner = self
                .inner
                .lock()
                .map_err(|e| RateLimitKvError(e.to_string()))?;
            if let Some(ref err) = inner.put_error {
                let msg = err.clone();
                if !inner.persistent_errors {
                    inner.put_error = None;
                }
                return Err(RateLimitKvError(msg));
            }
            inner.puts.push(PutRecord {
                key: key.to_string(),
                value: value.to_string(),
                ttl_secs,
            });
            inner.data.insert(key.to_string(), value.to_string());
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // ── RateLimitKvError ─────────────────────────────────────────

        #[test]
        fn error_display() {
            let err = RateLimitKvError("something broke".to_string());
            assert_eq!(format!("{}", err), "something broke");
        }

        #[test]
        fn error_debug() {
            let err = RateLimitKvError("debug msg".to_string());
            let dbg = format!("{:?}", err);
            assert!(dbg.contains("debug msg"));
        }

        #[test]
        fn error_empty_message() {
            let err = RateLimitKvError(String::new());
            assert_eq!(format!("{}", err), "");
        }

        // ── MockKv construction and builder methods ──────────────────

        #[test]
        fn new_mock_is_empty() {
            let kv = MockKv::new();
            assert_eq!(kv.len(), 0);
            assert!(kv.puts().is_empty());
        }

        #[test]
        fn with_entry_populates_data() {
            let kv = MockKv::new().with_entry("k1", "v1").with_entry("k2", "v2");
            assert_eq!(kv.len(), 2);
            assert_eq!(kv.read_raw("k1"), Some("v1".to_string()));
            assert_eq!(kv.read_raw("k2"), Some("v2".to_string()));
        }

        #[test]
        fn with_entry_overwrites_existing() {
            let kv = MockKv::new()
                .with_entry("k1", "old")
                .with_entry("k1", "new");
            assert_eq!(kv.len(), 1);
            assert_eq!(kv.read_raw("k1"), Some("new".to_string()));
        }

        #[test]
        fn read_raw_returns_none_for_missing_key() {
            let kv = MockKv::new().with_entry("present", "val");
            assert!(kv.read_raw("absent").is_none());
        }

        // ── get_text ─────────────────────────────────────────────────

        #[tokio::test]
        async fn get_text_returns_none_for_missing_key() {
            let kv = MockKv::new();
            let result = kv.get_text("no_such_key").await;
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }

        #[tokio::test]
        async fn get_text_returns_value_for_present_key() {
            let kv = MockKv::new().with_entry("key", "val");
            let result = kv.get_text("key").await;
            assert_eq!(result.unwrap(), Some("val".to_string()));
        }

        #[tokio::test]
        async fn get_text_error_consumed_on_first_use() {
            let kv = MockKv::new().with_get_error("boom");
            let r1 = kv.get_text("k").await;
            assert!(r1.is_err());
            // Second call succeeds (error consumed)
            let r2 = kv.get_text("k").await;
            assert!(r2.is_ok());
        }

        #[tokio::test]
        async fn get_text_persistent_error_not_consumed() {
            let kv = MockKv::new()
                .with_get_error("persistent")
                .with_persistent_errors();
            let r1 = kv.get_text("k").await;
            assert!(r1.is_err());
            let r2 = kv.get_text("k").await;
            assert!(r2.is_err());
            let r3 = kv.get_text("k").await;
            assert!(r3.is_err());
        }

        // ── put_with_ttl ────────────────────────────────────────────

        #[tokio::test]
        async fn put_with_ttl_stores_value() {
            let kv = MockKv::new();
            let result = kv.put_with_ttl("k", "v", 300).await;
            assert!(result.is_ok());
            assert_eq!(kv.read_raw("k"), Some("v".to_string()));
        }

        #[tokio::test]
        async fn put_with_ttl_records_put() {
            let kv = MockKv::new();
            kv.put_with_ttl("k", "v", 3600).await.unwrap();
            let puts = kv.puts();
            assert_eq!(puts.len(), 1);
            assert_eq!(puts[0].key, "k");
            assert_eq!(puts[0].value, "v");
            assert_eq!(puts[0].ttl_secs, 3600);
        }

        #[tokio::test]
        async fn put_with_ttl_overwrites_existing() {
            let kv = MockKv::new().with_entry("k", "old");
            kv.put_with_ttl("k", "new", 60).await.unwrap();
            assert_eq!(kv.read_raw("k"), Some("new".to_string()));
        }

        #[tokio::test]
        async fn put_with_ttl_error_consumed_on_first_use() {
            let kv = MockKv::new().with_put_error("fail");
            let r1 = kv.put_with_ttl("k", "v", 60).await;
            assert!(r1.is_err());
            // Second call succeeds
            let r2 = kv.put_with_ttl("k", "v", 60).await;
            assert!(r2.is_ok());
        }

        #[tokio::test]
        async fn put_with_ttl_persistent_error_not_consumed() {
            let kv = MockKv::new()
                .with_put_error("persistent")
                .with_persistent_errors();
            assert!(kv.put_with_ttl("k", "v", 60).await.is_err());
            assert!(kv.put_with_ttl("k", "v", 60).await.is_err());
            // No puts should have been recorded
            assert!(kv.puts().is_empty());
        }

        #[tokio::test]
        async fn put_error_does_not_store_value() {
            let kv = MockKv::new().with_put_error("fail");
            let _ = kv.put_with_ttl("k", "v", 60).await;
            assert!(kv.read_raw("k").is_none());
        }

        // ── PutRecord ────────────────────────────────────────────────

        #[test]
        fn put_record_clone() {
            let rec = PutRecord {
                key: "k".to_string(),
                value: "v".to_string(),
                ttl_secs: 100,
            };
            let cloned = rec.clone();
            assert_eq!(cloned.key, "k");
            assert_eq!(cloned.value, "v");
            assert_eq!(cloned.ttl_secs, 100);
        }

        #[test]
        fn put_record_debug() {
            let rec = PutRecord {
                key: "k".to_string(),
                value: "v".to_string(),
                ttl_secs: 42,
            };
            let dbg = format!("{:?}", rec);
            assert!(dbg.contains("42"));
            assert!(dbg.contains("k"));
        }

        // ── Multiple operations ──────────────────────────────────────

        #[tokio::test]
        async fn multiple_puts_recorded_in_order() {
            let kv = MockKv::new();
            kv.put_with_ttl("a", "1", 60).await.unwrap();
            kv.put_with_ttl("b", "2", 120).await.unwrap();
            kv.put_with_ttl("c", "3", 180).await.unwrap();
            let puts = kv.puts();
            assert_eq!(puts.len(), 3);
            assert_eq!(puts[0].key, "a");
            assert_eq!(puts[1].key, "b");
            assert_eq!(puts[2].key, "c");
        }

        #[tokio::test]
        async fn get_and_put_interleave_correctly() {
            let kv = MockKv::new();
            // Key does not exist yet
            assert_eq!(kv.get_text("counter").await.unwrap(), None);
            // Write it
            kv.put_with_ttl("counter", "1", 60).await.unwrap();
            // Now it exists
            assert_eq!(kv.get_text("counter").await.unwrap(), Some("1".to_string()));
            // Overwrite
            kv.put_with_ttl("counter", "2", 60).await.unwrap();
            assert_eq!(kv.get_text("counter").await.unwrap(), Some("2".to_string()));
        }

        #[tokio::test]
        async fn get_error_then_put_succeeds() {
            let kv = MockKv::new().with_get_error("read fail");
            // Get fails
            assert!(kv.get_text("k").await.is_err());
            // Put still succeeds (error was only for get)
            assert!(kv.put_with_ttl("k", "v", 60).await.is_ok());
            assert_eq!(kv.read_raw("k"), Some("v".to_string()));
        }

        #[tokio::test]
        async fn put_error_then_get_succeeds() {
            let kv = MockKv::new()
                .with_put_error("write fail")
                .with_entry("k", "pre-existing");
            // Put fails
            assert!(kv.put_with_ttl("k", "new", 60).await.is_err());
            // Get still works and returns pre-existing value
            assert_eq!(
                kv.get_text("k").await.unwrap(),
                Some("pre-existing".to_string())
            );
        }

        // ── Builder chaining ────────────────────────────────────────

        #[test]
        fn builder_methods_chain_all_at_once() {
            let kv = MockKv::new()
                .with_entry("k", "v")
                .with_get_error("ge")
                .with_put_error("pe")
                .with_persistent_errors();
            assert_eq!(kv.len(), 1);
            assert_eq!(kv.read_raw("k"), Some("v".to_string()));
        }

        // ── Empty string values ─────────────────────────────────────

        #[tokio::test]
        async fn put_and_get_empty_string_value() {
            let kv = MockKv::new();
            kv.put_with_ttl("k", "", 60).await.unwrap();
            assert_eq!(kv.get_text("k").await.unwrap(), Some(String::new()));
        }

        #[test]
        fn with_entry_empty_key_and_value() {
            let kv = MockKv::new().with_entry("", "");
            assert_eq!(kv.len(), 1);
            assert_eq!(kv.read_raw(""), Some(String::new()));
        }

        // ── Long keys and values ────────────────────────────────────

        #[tokio::test]
        async fn put_and_get_long_key() {
            let long_key = "k".repeat(1024);
            let kv = MockKv::new();
            kv.put_with_ttl(&long_key, "v", 60).await.unwrap();
            assert_eq!(kv.get_text(&long_key).await.unwrap(), Some("v".to_string()));
        }

        // ── TTL is recorded but not enforced by mock ────────────────

        #[tokio::test]
        async fn put_records_zero_ttl() {
            let kv = MockKv::new();
            kv.put_with_ttl("k", "v", 0).await.unwrap();
            let puts = kv.puts();
            assert_eq!(puts.len(), 1);
            assert_eq!(puts[0].ttl_secs, 0);
            // Value is still readable (mock does not enforce TTL expiry).
            assert_eq!(kv.get_text("k").await.unwrap(), Some("v".to_string()));
        }

        #[tokio::test]
        async fn put_records_max_ttl() {
            let kv = MockKv::new();
            kv.put_with_ttl("k", "v", u64::MAX).await.unwrap();
            let puts = kv.puts();
            assert_eq!(puts[0].ttl_secs, u64::MAX);
        }

        // ── Error message propagation ───────────────────────────────

        #[tokio::test]
        async fn get_error_message_is_propagated() {
            let kv = MockKv::new().with_get_error("specific error msg");
            let err = kv.get_text("k").await.unwrap_err();
            assert_eq!(format!("{}", err), "specific error msg");
        }

        #[tokio::test]
        async fn put_error_message_is_propagated() {
            let kv = MockKv::new().with_put_error("write failure 42");
            let err = kv.put_with_ttl("k", "v", 60).await.unwrap_err();
            assert_eq!(format!("{}", err), "write failure 42");
        }

        // ── len after puts ──────────────────────────────────────────

        #[tokio::test]
        async fn len_increases_after_puts() {
            let kv = MockKv::new();
            assert_eq!(kv.len(), 0);
            kv.put_with_ttl("a", "1", 60).await.unwrap();
            assert_eq!(kv.len(), 1);
            kv.put_with_ttl("b", "2", 60).await.unwrap();
            assert_eq!(kv.len(), 2);
            // Overwriting does not increase len.
            kv.put_with_ttl("a", "3", 60).await.unwrap();
            assert_eq!(kv.len(), 2);
        }

        // ── Persistent errors with both get and put injected ────────

        #[tokio::test]
        async fn persistent_errors_affect_both_get_and_put() {
            let kv = MockKv::new()
                .with_get_error("get fail")
                .with_put_error("put fail")
                .with_persistent_errors();
            assert!(kv.get_text("k").await.is_err());
            assert!(kv.put_with_ttl("k", "v", 60).await.is_err());
            // Still failing on second call.
            assert!(kv.get_text("k").await.is_err());
            assert!(kv.put_with_ttl("k", "v", 60).await.is_err());
        }
    }
}
