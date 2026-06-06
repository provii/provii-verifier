# provii-verifier MEK Re-encryption Tool

CLI tool that re-encrypts all MEK-protected KV data after a Master Encryption Key rotation.

## When to use

After rotating `VERIFIER_MEK` or `HOSTED_MEK` in the Cloudflare Secrets Store, run this tool to re-encrypt existing KV data under the new key. Until re-encryption completes, the old key must remain active as the `_PREVIOUS` binding.

## What gets re-encrypted

| Command | KV Namespace | Key Pattern | Description |
|---|---|---|---|
| `rotate-mek` | VERIFIER_KV_CONFIG | `origins/*` | Per-client DEKs (envelope encryption) |
| `rotate-hosted-mek` | HOSTED_PUBLIC_KEYS | `pk_live_*`, `pk_test_*` | Hosted key data (direct AES-256-GCM) |

Sessions (HOSTED_SESSIONS) are excluded. They expire within 5 minutes.

## Build

```bash
cd tools/key-rotation
cargo build --release
```

## Usage

All commands default to dry-run mode. Pass `--commit` to write changes.

### Rotate VERIFIER_MEK

```bash
./target/release/verifier-key-rotation rotate-mek \
  --account-id "$CLOUDFLARE_ACCOUNT_ID" \
  --api-token "$CLOUDFLARE_API_TOKEN" \
  --kv-config-id "$KV_CONFIG_NAMESPACE_ID" \
  --old-mek "$OLD_VERIFIER_MEK" \
  --new-mek "$NEW_VERIFIER_MEK" \
  --commit
```

### Rotate HOSTED_MEK

```bash
./target/release/verifier-key-rotation rotate-hosted-mek \
  --account-id "$CLOUDFLARE_ACCOUNT_ID" \
  --api-token "$CLOUDFLARE_API_TOKEN" \
  --kv-public-keys-id "$KV_PUBLIC_KEYS_NAMESPACE_ID" \
  --old-mek "$OLD_HOSTED_MEK" \
  --new-mek "$NEW_HOSTED_MEK" \
  --commit
```

### Verify rotation completeness

```bash
./target/release/verifier-key-rotation verify-rotation \
  --account-id "$CLOUDFLARE_ACCOUNT_ID" \
  --api-token "$CLOUDFLARE_API_TOKEN" \
  --kv-config-id "$KV_CONFIG_NAMESPACE_ID" \
  --kv-public-keys-id "$KV_PUBLIC_KEYS_NAMESPACE_ID" \
  --current-mek "$NEW_VERIFIER_MEK" \
  --previous-mek "$OLD_VERIFIER_MEK" \
  --current-hosted-mek "$NEW_HOSTED_MEK" \
  --previous-hosted-mek "$OLD_HOSTED_MEK"
```

When `previous_key_count` reaches 0, the `_PREVIOUS` binding can be safely removed.

## Environment variables

All CLI args accept environment variable equivalents: `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`, `KV_CONFIG_NAMESPACE_ID`, `KV_PUBLIC_KEYS_NAMESPACE_ID`, `OLD_MEK`, `NEW_MEK`, `OLD_HOSTED_MEK`, `NEW_HOSTED_MEK`, `CURRENT_MEK`, `PREVIOUS_MEK`, `CURRENT_HOSTED_MEK`, `PREVIOUS_HOSTED_MEK`.

## Rotation procedure

1. Generate new MEK (32 random bytes, base64url-encode)
2. Set the new key as `VERIFIER_MEK` (or `HOSTED_MEK`) in Cloudflare Secrets Store
3. Move the old key to `VERIFIER_MEK_PREVIOUS` (or `HOSTED_MEK_PREVIOUS`)
4. Deploy the worker (it will try new key first, fall back to previous)
5. Run this tool with `--commit` to re-encrypt all data
6. Run `verify-rotation` to confirm all entries use the new key
7. Remove the `_PREVIOUS` binding
