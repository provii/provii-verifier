// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Bounded retry helpers for transient Cloudflare binding I/O.
//!
//! Cloudflare Secrets Store and Durable Object storage reads are network
//! round-trips that occasionally fail transiently (a single dropped request,
//! a momentary control-plane blip). On a cold start, a single transient
//! Secrets Store read failure previously collapsed the whole `AppState` build
//! and returned a 500 to the first request that landed on the cold isolate.
//!
//! These helpers retry a small, fixed number of times with a short
//! exponential backoff so a one-off blip self-heals within the same request
//! rather than surfacing as an outage.
//!
//! # Design notes
//!
//! - The retry count and backoff schedule are deliberately small. Cold-start
//!   latency is on the critical path, so we trade at most a few hundred
//!   milliseconds of added latency on a genuinely failing read against the
//!   alternative of a hard 500.
//! - Only *transient* failures are retried. A missing binding (a
//!   configuration error) or a genuinely-absent secret (`Ok(None)`) are
//!   returned immediately: retrying them only burns cold-start budget and
//!   never changes the outcome.
//! - The backoff sleep uses `globalThis.setTimeout` on wasm32 (the same
//!   mechanism the credit-management client and `utils::timeout` use). On
//!   native targets (unit tests) the sleep is a no-op so tests stay fast and
//!   deterministic.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
use worker::{Env, SecretStore};

/// Number of attempts for a transient binding read (1 initial + 2 retries).
pub const SECRET_READ_MAX_ATTEMPTS: u32 = 3;

/// Initial backoff in milliseconds. Doubles each retry: 100ms, 200ms, 400ms.
/// The 400ms slot is only reached on the (unused) fourth attempt; with three
/// attempts the realised sleeps are 100ms then 200ms.
pub const SECRET_READ_INITIAL_BACKOFF_MS: u64 = 100;

/// Sleep for `ms` milliseconds without blocking the Workers event loop.
///
/// On wasm32 this awaits a `globalThis.setTimeout` promise. On native targets
/// it is a no-op so unit tests do not actually sleep. If `setTimeout` is
/// somehow unavailable the future resolves immediately (retry proceeds without
/// a delay rather than hanging).
pub async fn backoff_delay_ms(ms: u64) {
    #[cfg(target_arch = "wasm32")]
    {
        let promise = worker::js_sys::Promise::new(&mut |resolve, _| {
            let global = worker::js_sys::global();
            let set_timeout = match worker::js_sys::Reflect::get(&global, &"setTimeout".into()) {
                Ok(val) => val,
                Err(_) => {
                    // setTimeout unavailable: resolve now, retry without delay.
                    resolve.call0(&wasm_bindgen::JsValue::NULL).ok();
                    return;
                }
            };
            let set_timeout_fn = match set_timeout.dyn_into::<worker::js_sys::Function>() {
                Ok(f) => f,
                Err(_) => {
                    resolve.call0(&wasm_bindgen::JsValue::NULL).ok();
                    return;
                }
            };
            // The caller's backoff schedule tops out in the low hundreds of ms,
            // well within i32 range, so this cast cannot truncate in practice.
            #[allow(clippy::cast_possible_truncation)]
            let delay_ms: i32 = ms.min(i32::MAX as u64) as i32;
            let _ = set_timeout_fn.call2(&global, &resolve, &delay_ms.into());
        });
        let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = ms;
    }
}

/// Fetch a secret value from an already-resolved [`SecretStore`] handle with
/// bounded retry on transient fetch failures.
///
/// This is the lower-level primitive. It deliberately takes a `&SecretStore`
/// rather than the binding name so call sites that need to distinguish a
/// *missing binding* (the `env.secret_store(binding)` lookup failing) from a
/// *failed fetch* (`get()` failing) for audit purposes can keep doing the
/// binding lookup themselves and only delegate the retried fetch here. The
/// cold-start path in `worker_bindings` relies on that distinction for its
/// `binding_unavailable` vs `fetch_error` audit lines.
///
/// Retries [`SECRET_READ_MAX_ATTEMPTS`] times with an exponential backoff
/// ([`SECRET_READ_INITIAL_BACKOFF_MS`], doubling each attempt). `Ok(None)`
/// (the secret is genuinely absent) is returned immediately and never retried.
///
/// `binding` is used only for structured retry log lines.
///
/// # Errors
///
/// Returns the last [`worker::Error`] from `get()` after all attempts are
/// exhausted.
pub async fn get_with_retry(
    store: &SecretStore,
    binding: &str,
) -> Result<Option<String>, worker::Error> {
    let mut backoff_ms = SECRET_READ_INITIAL_BACKOFF_MS;
    let mut last_err: Option<worker::Error> = None;

    for attempt in 1..=SECRET_READ_MAX_ATTEMPTS {
        match store.get().await {
            Ok(value) => return Ok(value),
            Err(e) => {
                last_err = Some(e);
                if attempt < SECRET_READ_MAX_ATTEMPTS {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "{{\"audit\":true,\"event\":\"secrets_store_read_retry\",\"secret\":\"{}\",\"attempt\":{},\"max_attempts\":{},\"backoff_ms\":{}}}",
                        binding,
                        attempt,
                        SECRET_READ_MAX_ATTEMPTS,
                        backoff_ms
                    );
                    backoff_delay_ms(backoff_ms).await;
                    backoff_ms = backoff_ms.saturating_mul(2);
                }
            }
        }
    }

    // All attempts exhausted: surface the last fetch error. last_err is always
    // Some here because the loop runs at least once and only reaches this point
    // via the Err arm, but fall back defensively rather than unwrapping.
    Err(last_err.unwrap_or_else(|| {
        worker::Error::RustError(format!(
            "secret read for {} exhausted {} attempts with no recorded error",
            binding, SECRET_READ_MAX_ATTEMPTS
        ))
    }))
}

/// Read a single secret from the Cloudflare Secrets Store with bounded retry.
///
/// Convenience wrapper over [`get_with_retry`] that performs the binding lookup
/// for callers that do not need to distinguish a missing binding from a failed
/// fetch in their own logging.
///
/// - `Err(_)` from `env.secret_store(binding)` (binding not configured) is
///   returned immediately. A missing binding is a deployment error, not a
///   transient one, and retrying never resolves it.
/// - The fetch is retried per [`get_with_retry`].
///
/// # Errors
///
/// Returns the underlying [`worker::Error`] from the binding lookup, or the
/// last fetch error after all attempts are exhausted.
pub async fn read_secret_with_retry(
    env: &Env,
    binding: &str,
) -> Result<Option<String>, worker::Error> {
    // The binding lookup is local (no network) and a failure here is a
    // configuration error, so it is not retried.
    let store = env.secret_store(binding)?;
    get_with_retry(&store, binding).await
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn test_max_attempts_is_three() {
        assert_eq!(SECRET_READ_MAX_ATTEMPTS, 3);
    }

    #[test]
    fn test_initial_backoff_is_100ms() {
        assert_eq!(SECRET_READ_INITIAL_BACKOFF_MS, 100);
    }

    #[test]
    fn test_backoff_schedule_doubles() {
        // The realised backoff sleeps across the retry loop are 100ms then
        // 200ms (the 400ms slot is computed but never slept because the third
        // attempt is the last one). Assert the doubling arithmetic.
        let mut backoff = SECRET_READ_INITIAL_BACKOFF_MS;
        let mut schedule = Vec::new();
        for attempt in 1..=SECRET_READ_MAX_ATTEMPTS {
            if attempt < SECRET_READ_MAX_ATTEMPTS {
                schedule.push(backoff);
                backoff = backoff.saturating_mul(2);
            }
        }
        assert_eq!(schedule, vec![100, 200]);
        // The next value (had there been a fourth attempt) would be 400ms,
        // matching the documented 100/200/400 schedule.
        assert_eq!(backoff, 400);
    }

    #[test]
    fn test_backoff_saturates() {
        // The doubling must never overflow even from an absurd starting point.
        let mut backoff = u64::MAX;
        backoff = backoff.saturating_mul(2);
        assert_eq!(backoff, u64::MAX);
    }

    // backoff_delay_ms is a no-op on native targets; assert it returns without
    // blocking so the retry loop stays test-friendly off-wasm.
    #[tokio::test]
    async fn test_backoff_delay_is_noop_on_native() {
        let start = std::time::Instant::now();
        backoff_delay_ms(5_000).await;
        // Native path is a no-op; this must return effectively instantly.
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
    }
}
