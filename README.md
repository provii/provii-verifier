<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/provii-logo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="./assets/provii-logo-light.png">
    <img alt="Provii" src="./assets/provii-logo-light.png" width="200">
  </picture>
</p>

<h1 align="center">provii-verifier</h1>

<p align="center">Verify age. Learn nothing else.</p>

<p align="center">
  <a href="https://github.com/provii/provii-verifier/actions/workflows/ci.yml"><img src="https://github.com/provii/provii-verifier/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/licence-AGPL--3.0--only-blue?style=flat" alt="Licence"></a>
  <a href="https://docs.provii.app"><img src="https://img.shields.io/badge/docs-docs.provii.app-green?style=flat" alt="Docs"></a>
  <a href="https://github.com/provii/provii-verifier/actions/workflows/security-audit.yml"><img src="https://github.com/provii/provii-verifier/actions/workflows/security-audit.yml/badge.svg" alt="Security audit"></a>
</p>

## The problem

Age verification on the internet means handing over identity documents. Passports. Driver licences. Sometimes a selfie next to your passport. A third party stores that data on a server somewhere, and it stays there until someone breaches it, which they will, because the incentive structure guarantees it: a database of millions of identity documents is worth more to an attacker than it costs to defend.

All of this to answer a question that has exactly one bit of information in it. Is this person old enough? Yes or no.

Provii answers that one bit question without collecting any of the rest. A user's wallet holds an attested date of birth credential signed by an issuer using RedJubjub over the Jubjub curve. When a site checks age, the wallet constructs a Groth16 zero knowledge proof on BLS12-381. That proof demonstrates one thing: the holder meets the age threshold. It does not reveal who they are, when they were born, or which credential was used. The verifier receives a boolean and nothing else.

This repository is the verifier side of that exchange. It issues challenges, validates Groth16 SNARK proofs against an embedded verifying key, enforces PKCE redemption, and records the result. No identity document touches this server. Not a date of birth, not a name, not a document number, not even an age.

## Quick start

### Simple (website script tag)

For websites that want age verification without building a backend, use [provii-agegate](https://github.com/provii/provii-agegate). Drop a script tag on the page with your `pk_` public key. The hosted flow handles session management, PKCE, CSRF protection, WebSocket status updates, and cookie issuance on your behalf.

```html
<script src="https://cdn.provii.app/sdk/provii-agegate/v0.1.3/agegate.browser.js"
        data-public-key="pk_live_abc123...">
</script>
```

That is it. Two lines.

### Expert (direct API with HMAC-SHA256)

For full control, call the verifier API directly from your own backend. This path is required for mobile apps and recommended for any relying party that wants to own the session layer.

**1. Create a challenge**

```
POST /v1/challenge
```

Supply `Origin` and `X-API-Key` as headers. In the request body, include an `authorizer` block containing your `keyId`, a Unix timestamp, a 256 bit hex nonce, and an HMAC-SHA256 signature computed over `{timestamp}:{method}:{path}:{body_json}:{nonce}`. Also include a `code_challenge` (base64url, SHA-256) for PKCE.

**2. Wallet submits proof**

```
POST /v1/verify
```

The wallet sends its Groth16 proof, a credential nullifier, the issuer verifying key, and the relying party challenge. The verifier validates all public inputs against the stored challenge record and runs the SNARK verifier against the embedded BLS12-381 verifying key. On success it transitions the challenge to `proof_ok_waiting_for_redeem`.

**3. Redeem the result**

```
POST /v1/challenge/:sid/redeem
```

Your backend presents the PKCE `code_verifier`. The verifier checks it against the stored `code_challenge` using a constant time SHA-256 comparison, deducts a credit, and returns the final `verified` state.

**4. Other endpoints**

`GET /v1/challenge/:sid` for status polling. `GET /v1/challenge/by-code/:code` for short code lookup.
Full API documentation lives at [docs.provii.app](https://docs.provii.app). A runtime OpenAPI spec is served at `/v1/openapi.json` with live base URL interpolation, and `/v1/docs` renders the Swagger UI.

## Architecture

provii-verifier is a Rust application compiled to WebAssembly and deployed as a Cloudflare Worker. More than 100 source files across 17 top-level modules. The cryptographic core uses `bellman` for Groth16 verification on BLS12-381 and `provii-crypto-verifier` for the age proof circuit. At cold start the embedded verifying key is integrity checked via Blake2b-512, then parsed and cached for the lifetime of the isolate.

State lives entirely in Cloudflare primitives. KV namespaces hold origin policies, tenant configuration, the issuer registry, ban lists, and hosted session data. Durable Object classes manage the stateful parts:

| Class | Purpose |
|-------|---------|
| `ChallengeDO` | Challenge lifecycle and state transitions |
| `NonceDO` | Replay prevention with a five minute TTL |
| `IdempotencyDO` | Request deduplication for expert flow |
| `HostedNonceDO` | Replay prevention for hosted flow |
| `HostedIdempotencyDO` | Request deduplication for hosted flow |
| `ChallengeNotifyDO` | WebSocket notification delivery |

Audit events go to a queue for async processing. Credit consumption flows through a service binding to a separate credit management Worker.

Secrets (the MEK for envelope encryption, HMAC keys, session signing keys, IP hash salt) load from the Cloudflare Secrets Store at cold start. They are cached in `Zeroizing<Vec<u8>>` wrappers and never logged. Dual slot rotation is supported for every secret class, so the current and previous values coexist during a rotation window while in flight requests drain.

## Security

All comparisons of secret material use constant time primitives. PKCE verifiers, submit secrets, CSRF tokens, and VK integrity checksums go through `subtle::ConstantTimeEq`. HMAC signatures verify via `hmac::Mac::verify_slice()`, and API key hashes use Argon2's built in constant time comparison.

Secret key material is wrapped in `zeroize::Zeroizing` so it gets scrubbed from memory on drop. The crate forbids `unsafe` at the compiler level via `#![forbid(unsafe_code)]`. Clippy is configured to deny `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, and `arithmetic_side_effects`, which means the compiler rejects any code path that could panic in the library.

On the protocol side: nonce replay prevention uses Durable Objects with a five minute TTL, and idempotency deduplication prevents double submission of proofs. BOLA ownership checks (OWASP API1:2023) guard every challenge operation so one tenant cannot read or redeem another's sessions. Sec-Fetch metadata validation rejects cross origin misuse. Rate limiting is enforced per origin policy.

To report a vulnerability: [security@provii.app](mailto:security@provii.app).

## Building

You need Rust (stable), `wrangler`, `worker-build`, and a `wasm32-unknown-unknown` target installed via rustup.

```sh
# Install the WASM target if you haven't already
rustup target add wasm32-unknown-unknown

# Check that everything compiles
cargo check --target wasm32-unknown-unknown

# Run clippy (required before any PR)
cargo clippy --workspace --all-features -- -D warnings

# Run tests (native target, not WASM)
cargo test --workspace

# Build the Worker bundle for local dev
npx wrangler dev

# Deploy to sandbox
npx wrangler deploy --env sandbox

# Deploy to production
npx wrangler deploy
```

The `fuzz/` and `tools/key-rotation` directories are excluded from the workspace; `tools/key-rotation` pins its own `Cargo.lock`. Build them separately with `cargo build --manifest-path fuzz/Cargo.toml` or `cargo build --manifest-path tools/key-rotation/Cargo.toml`.

Native only CLI helpers live under `bins/`. To build one of them:

```sh
cargo build -p provii-verifier-ban-entry-decode
```

## Licence

[AGPL-3.0-only](./LICENSE)
