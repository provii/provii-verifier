// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! HTTP clients for external services.
#![forbid(unsafe_code)]

pub mod credit_management;

pub use credit_management::{
    ConsumeCreditsRequest, ConsumeCreditsResponse, CreditError, CreditManagementClient,
};
