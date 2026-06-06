// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Hosted flow endpoint handlers.
//!
//! Each submodule contains a single `pub async fn` handler that will be wired
//! into the worker router by a separate task (M-058). The handlers operate on
//! `Arc<AppState>` and worker `Headers`, following the same signature pattern
//! used throughout `crate::routes::*`.

pub mod challenge;
pub mod csrf;
pub mod logout;
pub mod notify;
pub mod redeem;
pub mod session_check;
pub mod simulate;
pub mod status;
pub mod ws;
