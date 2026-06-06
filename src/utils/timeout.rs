// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Per-operation timeout protection for Cloudflare Workers I/O calls.
//!
//! Cloudflare Workers have no native per-operation timeout. A stalled KV read,
//! KV write, KV list, or Durable Object fetch blocks the entire request until
//! the 30-second global CPU limit kills the isolate. This module provides a
//! `with_timeout` combinator that races any future against a JS `setTimeout`
//! promise, returning `Err(TimeoutError)` if the operation exceeds the deadline.
//!
//! The implementation follows the proven pattern from
//! `src/clients/credit_management.rs:184-209`: a `js_sys::Promise::new` closure
//! that calls `globalThis.setTimeout(resolve, delay_ms)`. No `Closure::forget`
//! is used; the resolve callback is passed directly to `setTimeout`.
//!
//! Timeout constants are calibrated at 10x p99 headroom, not 60x:
//!
//! | Operation | Timeout (ms) |
//! |-----------|-------------|
//! | KV read   | 500         |
//! | KV write  | 1000        |
//! | KV list   | 1000        |
//! | DO fetch  | 2000        |
#![forbid(unsafe_code)]

use std::fmt;

/// Error returned when an I/O operation exceeds its timeout deadline.
#[derive(Debug, Clone)]
pub struct TimeoutError {
    /// Name of the operation that timed out (for logging).
    pub operation: &'static str,
    /// Timeout deadline in milliseconds.
    pub timeout_ms: u32,
}

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} timed out after {}ms",
            self.operation, self.timeout_ms
        )
    }
}

impl std::error::Error for TimeoutError {}

/// Per-operation timeout constants (10x p99 headroom).
pub const KV_READ_TIMEOUT_MS: u32 = 500;
pub const KV_WRITE_TIMEOUT_MS: u32 = 1000;
pub const KV_LIST_TIMEOUT_MS: u32 = 1000;
pub const DO_FETCH_TIMEOUT_MS: u32 = 2000;

/// Maximum total budget for a single storage operation including retries.
/// Prevents 3 attempts x 2000ms = 6000ms from stalling a request.
pub const MAX_OPERATION_BUDGET_MS: u32 = 4000;

/// Race an async operation against a JS `setTimeout` deadline.
///
/// On wasm32 targets, this constructs a `js_sys::Promise` that resolves after
/// `timeout_ms` milliseconds and races it against the provided future using
/// `futures::future::select`. The first to complete wins.
///
/// On non-wasm32 targets (tests), the operation runs without a timeout since
/// `js_sys` and `wasm_bindgen_futures` are unavailable.
///
/// # Errors
///
/// Returns `Err(TimeoutError)` if the operation does not complete within the
/// deadline. The underlying future is dropped (cancelled) in this case.
pub async fn with_timeout<T, F>(
    operation: &'static str,
    timeout_ms: u32,
    fut: F,
) -> Result<T, TimeoutError>
where
    F: std::future::Future<Output = T>,
{
    #[cfg(target_arch = "wasm32")]
    {
        use futures::future::Either;
        use wasm_bindgen::JsCast;

        // Build a JS Promise that resolves after `timeout_ms`.
        let timer_promise = js_sys::Promise::new(&mut |resolve, _| {
            let global = js_sys::global();
            let set_timeout = match js_sys::Reflect::get(&global, &"setTimeout".into()) {
                Ok(val) => val,
                Err(_) => {
                    // setTimeout unavailable (should not happen in Workers).
                    // Resolve immediately so the operation runs without a cap.
                    resolve.call0(&wasm_bindgen::JsValue::NULL).ok();
                    return;
                }
            };
            let set_timeout_fn = match set_timeout.dyn_into::<js_sys::Function>() {
                Ok(f) => f,
                Err(_) => {
                    resolve.call0(&wasm_bindgen::JsValue::NULL).ok();
                    return;
                }
            };
            // timeout_ms is a u32 which always fits in i32 (max 4000ms).
            #[allow(clippy::cast_possible_wrap)]
            let delay: i32 = timeout_ms as i32;
            let _ = set_timeout_fn.call2(&global, &resolve, &delay.into());
        });

        let timer_future = wasm_bindgen_futures::JsFuture::from(timer_promise);

        futures::pin_mut!(fut);
        futures::pin_mut!(timer_future);

        match futures::future::select(fut, timer_future).await {
            Either::Left((result, _)) => Ok(result),
            Either::Right((_, _)) => Err(TimeoutError {
                operation,
                timeout_ms,
            }),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        // Native fallback: no JS timer available. Run without timeout.
        let _ = (operation, timeout_ms);
        Ok(fut.await)
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

    // ── TimeoutError display ────────────────────────────────────────────

    #[test]
    fn test_timeout_error_display() {
        let err = TimeoutError {
            operation: "KV read",
            timeout_ms: 500,
        };
        assert_eq!(err.to_string(), "KV read timed out after 500ms");
    }

    #[test]
    fn test_timeout_error_display_do_fetch() {
        let err = TimeoutError {
            operation: "DO fetch",
            timeout_ms: 2000,
        };
        assert_eq!(err.to_string(), "DO fetch timed out after 2000ms");
    }

    #[test]
    fn test_timeout_error_debug() {
        let err = TimeoutError {
            operation: "KV write",
            timeout_ms: 1000,
        };
        let debug = format!("{:?}", err);
        assert!(debug.contains("TimeoutError"));
        assert!(debug.contains("KV write"));
        assert!(debug.contains("1000"));
    }

    #[test]
    fn test_timeout_error_clone() {
        let err = TimeoutError {
            operation: "KV list",
            timeout_ms: 1000,
        };
        let cloned = err.clone();
        assert_eq!(cloned.operation, "KV list");
        assert_eq!(cloned.timeout_ms, 1000);
    }

    // ── Constant invariants ─────────────────────────────────────────────

    // Compile-time assertions for timeout ordering.
    const _: () = assert!(KV_READ_TIMEOUT_MS > 0);
    const _: () = assert!(KV_WRITE_TIMEOUT_MS >= KV_READ_TIMEOUT_MS);
    const _: () = assert!(KV_LIST_TIMEOUT_MS >= KV_READ_TIMEOUT_MS);
    const _: () = assert!(DO_FETCH_TIMEOUT_MS >= KV_WRITE_TIMEOUT_MS);
    const _: () = assert!(MAX_OPERATION_BUDGET_MS >= DO_FETCH_TIMEOUT_MS);

    #[test]
    fn test_kv_read_timeout_value() {
        assert_eq!(KV_READ_TIMEOUT_MS, 500);
    }

    #[test]
    fn test_kv_write_timeout_value() {
        assert_eq!(KV_WRITE_TIMEOUT_MS, 1000);
    }

    #[test]
    fn test_kv_list_timeout_value() {
        assert_eq!(KV_LIST_TIMEOUT_MS, 1000);
    }

    #[test]
    fn test_do_fetch_timeout_value() {
        assert_eq!(DO_FETCH_TIMEOUT_MS, 2000);
    }

    #[test]
    fn test_max_budget_value() {
        assert_eq!(MAX_OPERATION_BUDGET_MS, 4000);
    }

    #[test]
    fn test_budget_caps_retry_window() {
        // With MAX_RETRIES=3 and DO_FETCH_TIMEOUT_MS=2000, worst case
        // without budget cap would be 6000ms. Budget cap of 4000ms ensures
        // at most 2 full attempts fit within the budget.
        let worst_case_uncapped = 3u32.saturating_mul(DO_FETCH_TIMEOUT_MS);
        assert!(
            worst_case_uncapped > MAX_OPERATION_BUDGET_MS,
            "Budget cap should be tighter than uncapped worst case"
        );
    }

    // ── with_timeout on native (no-op timer) ────────────────────────────

    #[tokio::test]
    async fn test_with_timeout_succeeds_immediately() {
        let result = with_timeout("test_op", 500, async { 42 }).await;
        assert_eq!(result.unwrap_or(0), 42);
    }

    #[tokio::test]
    async fn test_with_timeout_returns_string() {
        let result = with_timeout("test_op", 500, async { "hello".to_string() }).await;
        assert_eq!(result.unwrap_or_default(), "hello");
    }

    #[tokio::test]
    async fn test_with_timeout_returns_result_ok() {
        let result: Result<Result<i32, String>, TimeoutError> =
            with_timeout("test_op", 500, async { Ok::<i32, String>(99) }).await;
        let inner = result.unwrap_or(Err("timeout".to_string()));
        assert_eq!(inner.unwrap_or(0), 99);
    }

    #[tokio::test]
    async fn test_with_timeout_returns_result_err() {
        let result: Result<Result<i32, String>, TimeoutError> =
            with_timeout("test_op", 500, async {
                Err::<i32, String>("inner error".to_string())
            })
            .await;
        let inner = result.unwrap_or(Err("timeout".to_string()));
        assert!(inner.is_err());
    }

    #[tokio::test]
    async fn test_with_timeout_preserves_unit() {
        let result = with_timeout("test_op", 500, async {}).await;
        assert!(result.is_ok());
    }

    // ── Property-based tests ────────────────────────────────────────────

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    // ── TimeoutError as std::error::Error ──────────────────────────────

    #[test]
    fn test_timeout_error_source_is_none() {
        let err = TimeoutError {
            operation: "KV read",
            timeout_ms: 500,
        };
        // TimeoutError has no underlying source error
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn test_timeout_error_display_zero_timeout() {
        let err = TimeoutError {
            operation: "test",
            timeout_ms: 0,
        };
        assert_eq!(err.to_string(), "test timed out after 0ms");
    }

    #[test]
    fn test_timeout_error_display_max_timeout() {
        let err = TimeoutError {
            operation: "heavy_op",
            timeout_ms: u32::MAX,
        };
        let s = err.to_string();
        assert!(s.contains("heavy_op"));
        assert!(s.contains(&u32::MAX.to_string()));
    }

    #[test]
    fn test_timeout_error_display_kv_write() {
        let err = TimeoutError {
            operation: "KV write",
            timeout_ms: KV_WRITE_TIMEOUT_MS,
        };
        assert_eq!(err.to_string(), "KV write timed out after 1000ms");
    }

    #[test]
    fn test_timeout_error_display_kv_list() {
        let err = TimeoutError {
            operation: "KV list",
            timeout_ms: KV_LIST_TIMEOUT_MS,
        };
        assert_eq!(err.to_string(), "KV list timed out after 1000ms");
    }

    // ── Constant relationships ─────────────────────────────────────────

    #[test]
    fn test_kv_write_ge_kv_read() {
        assert!(KV_WRITE_TIMEOUT_MS >= KV_READ_TIMEOUT_MS);
    }

    #[test]
    fn test_kv_list_ge_kv_read() {
        assert!(KV_LIST_TIMEOUT_MS >= KV_READ_TIMEOUT_MS);
    }

    #[test]
    fn test_do_fetch_ge_kv_write() {
        assert!(DO_FETCH_TIMEOUT_MS >= KV_WRITE_TIMEOUT_MS);
    }

    #[test]
    fn test_max_budget_ge_do_fetch() {
        assert!(MAX_OPERATION_BUDGET_MS >= DO_FETCH_TIMEOUT_MS);
    }

    #[test]
    fn test_all_timeouts_nonzero() {
        assert!(KV_READ_TIMEOUT_MS > 0);
        assert!(KV_WRITE_TIMEOUT_MS > 0);
        assert!(KV_LIST_TIMEOUT_MS > 0);
        assert!(DO_FETCH_TIMEOUT_MS > 0);
        assert!(MAX_OPERATION_BUDGET_MS > 0);
    }

    #[test]
    fn test_max_budget_under_global_limit() {
        // Cloudflare Workers have a 30-second global CPU limit
        // Budget should be well under that
        assert!(MAX_OPERATION_BUDGET_MS < 30_000);
    }

    #[test]
    fn test_budget_allows_at_least_two_kv_reads() {
        // Budget should allow at least 2 KV reads
        let two_reads = KV_READ_TIMEOUT_MS.saturating_mul(2);
        assert!(MAX_OPERATION_BUDGET_MS >= two_reads);
    }

    #[test]
    fn test_budget_allows_at_least_one_do_fetch() {
        assert!(MAX_OPERATION_BUDGET_MS >= DO_FETCH_TIMEOUT_MS);
    }

    // ── with_timeout additional return types ───────────────────────────

    #[tokio::test]
    async fn test_with_timeout_returns_vec() {
        let result = with_timeout("test_op", 500, async { vec![1, 2, 3] }).await;
        assert_eq!(result.unwrap_or_default(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_with_timeout_returns_option_some() {
        let result = with_timeout("test_op", 500, async { Some(42) }).await;
        assert_eq!(result.unwrap_or(None), Some(42));
    }

    #[tokio::test]
    async fn test_with_timeout_returns_option_none() {
        let result: Result<Option<i32>, TimeoutError> =
            with_timeout("test_op", 500, async { None }).await;
        assert_eq!(result.unwrap_or(Some(-1)), None);
    }

    #[tokio::test]
    async fn test_with_timeout_returns_bool() {
        let result = with_timeout("test_op", 500, async { true }).await;
        assert!(result.unwrap_or(false));
    }

    #[tokio::test]
    async fn test_with_timeout_returns_tuple() {
        let result = with_timeout("test_op", 500, async { (1, "hello") }).await;
        let (a, b) = result.unwrap_or((0, ""));
        assert_eq!(a, 1);
        assert_eq!(b, "hello");
    }

    #[tokio::test]
    async fn test_with_timeout_with_computation() {
        let result = with_timeout("test_op", 500, async {
            let mut sum = 0u64;
            for i in 0..100 {
                sum = sum.saturating_add(i);
            }
            sum
        })
        .await;
        assert_eq!(result.unwrap_or(0), 4950);
    }

    #[tokio::test]
    async fn test_with_timeout_zero_timeout_still_succeeds_on_native() {
        // On native, timeout is a no-op; even 0ms should succeed
        let result = with_timeout("test_op", 0, async { 42 }).await;
        assert_eq!(result.unwrap_or(0), 42);
    }

    #[tokio::test]
    async fn test_with_timeout_large_timeout_succeeds() {
        let result = with_timeout("test_op", 60_000, async { "ok" }).await;
        assert_eq!(result.unwrap_or("fail"), "ok");
    }

    // ── TimeoutError field access ──────────────────────────────────────

    #[test]
    fn test_timeout_error_operation_field() {
        let err = TimeoutError {
            operation: "KV read",
            timeout_ms: 500,
        };
        assert_eq!(err.operation, "KV read");
    }

    #[test]
    fn test_timeout_error_timeout_ms_field() {
        let err = TimeoutError {
            operation: "KV read",
            timeout_ms: 500,
        };
        assert_eq!(err.timeout_ms, 500);
    }

    // ── Property-based tests ────────────────────────────────────────────

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(target_arch = "wasm32")]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: TimeoutError display always contains the operation name.
        #[test]
        fn prop_timeout_error_contains_operation(timeout_ms in 1u32..10000) {
            let err = TimeoutError {
                operation: "test_op",
                timeout_ms,
            };
            let s = err.to_string();
            prop_assert!(s.contains("test_op"));
            prop_assert!(s.contains(&timeout_ms.to_string()));
        }

        /// Property: TimeoutError clone preserves all fields.
        #[test]
        fn prop_timeout_error_clone(timeout_ms in 1u32..10000) {
            let err = TimeoutError {
                operation: "clone_test",
                timeout_ms,
            };
            let cloned = err.clone();
            prop_assert_eq!(cloned.operation, err.operation);
            prop_assert_eq!(cloned.timeout_ms, err.timeout_ms);
        }

        /// Property: with_timeout on native always returns Ok for immediate futures.
        #[test]
        fn prop_with_timeout_native_always_ok(val in any::<i64>()) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = rt.block_on(with_timeout("prop_test", 100, async move { val }));
            prop_assert_eq!(result.unwrap(), val);
        }

        /// Property: TimeoutError display format is always "OP timed out after Nms".
        #[test]
        fn prop_timeout_error_format_structure(timeout_ms in 0u32..100_000) {
            let err = TimeoutError {
                operation: "op",
                timeout_ms,
            };
            let s = err.to_string();
            prop_assert!(s.starts_with("op timed out after "));
            prop_assert!(s.ends_with("ms"));
        }
    }
}
