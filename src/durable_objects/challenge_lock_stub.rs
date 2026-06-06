// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Minimal stub for the deprecated `ChallengeLock` Durable Object class.
//!
//! Cloudflare requires a Worker version to export every DO class that the
//! deployed worker still depends on (error 10064). The live production
//! worker carries DOs of class `ChallengeLock` from before per-challenge DO
//! addressing replaced distributed locking. Removing the export without a
//! `delete-class` migration breaks the deploy.
//!
//! Two-step removal:
//!  1. Re-introduce this stub + the `[[durable_objects.bindings]]` entry,
//!     keep the v9 `deleted_classes` migration deferred. Deploy. The live
//!     bindings + class export are now in sync with source again.
//!  2. Remove the binding from wrangler.toml, keep this stub, deploy.
//!     Cloudflare reconciles the binding away while the class export
//!     remains, satisfying both 10061 and 10064.
//!  3. Re-introduce v9 `deleted_classes = ["ChallengeLock"]`, delete this
//!     stub file and its exports. Deploy. The class is removed cleanly.
//!
//! Until step 3 lands the stub returns 410 Gone for any inbound request,
//! so a stale binding can never silently succeed.

use worker::*;

#[durable_object]
pub struct ChallengeLock {
    #[allow(dead_code)]
    state: State,
    #[allow(dead_code)]
    env: Env,
}

impl DurableObject for ChallengeLock {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, _req: Request) -> Result<Response> {
        Response::error("Gone", 410)
    }
}
