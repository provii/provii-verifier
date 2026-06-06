// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Pure verification logic for provii-verifier.
//!
//! This crate contains all verification logic that does not depend on
//! Cloudflare Workers, wasm-bindgen, or any other wasm32-only runtime.
//! It is compiled and tested on native targets so that coverage is
//! measured by cargo-llvm-cov.
//!
//! The root `provii-verifier` crate delegates to functions here and
//! remains a thin Worker entry point handling `Env`/`Request`/`Response`.
#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)] // formatting-style preference, not correctness

pub mod docs_hmac;
pub mod error;
pub mod origin;
pub mod pkce;
pub mod session_binding;
