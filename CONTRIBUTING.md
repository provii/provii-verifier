# Contributing

Thank you for your interest in contributing to provii-verifier.

## Licence agreement

All contributors must sign the [Contributor Licence Agreement](./CLA.md) before
a pull request can be merged. Reply to the CLA bot prompt on your first PR. You
only need to sign once across all Provii repositories.

## Development setup

You need:

- Rust stable toolchain
- The `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`)
- `wrangler` CLI (install via `npm install -g wrangler`)
- `worker-build` (install via `cargo install worker-build`)

Clone the repository and its sibling crypto library:

```sh
git clone git@github.com:provii/provii-verifier.git
git clone git@github.com:provii/provii-crypto.git
```

The `Cargo.toml` references `../provii-crypto/` via local path dependencies.
Both repositories must sit next to each other on disk.

Verify compilation:

```sh
cargo check --target wasm32-unknown-unknown
```

## Coding standards

This project enforces strict safety and quality constraints at the compiler
level. The critical rules for contributors are:

- `unsafe` is forbidden (`#![forbid(unsafe_code)]`).
- Clippy denies `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, and
  `arithmetic_side_effects`. Library code must return `Result`, never panic.
- All secret material comparisons must be constant time (`subtle::ConstantTimeEq`
  or `hmac::Mac::verify_slice()`). Never branch on, index with, log, or
  debug-print secret values.
- Secret key material must be wrapped in `zeroize::Zeroizing`.
- Australian English in all written content.

## Testing

Run the full test suite before submitting a PR:

```sh
# Clippy (mandatory, treated as CI gate)
cargo clippy --workspace --all-features -- -D warnings

# Unit and integration tests
cargo test --workspace

# Security audit
cargo audit
```

Property based tests (via `proptest`) and fuzz targets (in `fuzz/`) exist for
security critical code paths. If your change touches cryptographic validation,
input parsing, or serialisation boundaries, add or extend coverage in those
harnesses.

## Pull request process

1. Fork and create a feature branch from `main`.
2. Make your changes. Keep commits atomic and descriptive.
4. Run `cargo clippy`, `cargo test`, and `cargo audit` locally.
5. Open a PR against `main`. The CI pipeline runs the same checks plus WASM
   compilation, CodeQL analysis, and a security audit workflow.

Every PR requires review approval before merge. Changes that touch
cryptographic code paths or authentication logic will be reviewed by the
security reviewer.

## Reporting security issues

Do not open a public issue for security vulnerabilities. Instead, email
[security@provii.app](mailto:security@provii.app). See [SECURITY.md](./SECURITY.md)
for full details on coordinated disclosure.
