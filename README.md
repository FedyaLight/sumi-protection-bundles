# sumi-protection-bundles

This repository builds Sumi's prepared WebKit content-blocking bundles outside the browser. Sumi consumes release assets only; it does not fetch raw lists, parse filter syntax, or run the native compiler locally.

## Pipeline

- `scripts/sumi_adblock_bundle.py` fetches the source lists described in `metadata/source-lists.json`.
- `Vendor/Brave/AdblockRustAdapter` converts raw rules to WebKit content-blocker JSON in CI.
- The generator emits `SumiAdblockBundle/manifest.json`, `diagnostics.json`, and prepared shard JSON files.
- `scripts/prepare_release_payload.py` validates bundles, flattens bundle files into release assets, and creates the browser-facing release manifest.
- `.github/workflows/publish-bundles.yml` runs weekly and via manual dispatch, uploads CI artifacts for inspection, then publishes a GitHub Release only after validation succeeds.

CI artifacts are temporary inspection/debug output. GitHub Release assets are the long-lived browser-consumable payload.

## Release Assets

Each published release contains:

- `sumi-protection-bundles-release.json`: machine-readable release manifest.
- `sumi-protection-bundles-release.json.sig`: Ed25519 signature metadata for the exact UTF-8 bytes of the release manifest.
- `sumi-protection-bundles-checksums.txt`: SHA-256 checksum list for release assets.
- `adguardAdsPrivacy-manifest.json`: prepared bundle manifest copied to `manifest.json` in Sumi's cache.
- `adguardAdsPrivacy-diagnostics.json`: bundle diagnostics copied to `diagnostics.json`.
- `adguardAdsPrivacy-*.json`: prepared WebKit rule-list shards copied to their manifest-declared relative paths.

The release manifest schema is versioned in `metadata/release-format.json`. It includes:

- release version and generation timestamp
- repository owner/name/commit
- compatibility bounds for Sumi's bundle expectation version
- required prepared bundle manifest schema
- required native CSS safety policy
- bundle id, generation id, profile id
- every asset name, role, target relative path, byte size, and SHA-256 hash

## Sumi Consumption Contract

Sumi fetches the latest GitHub Release metadata, downloads `sumi-protection-bundles-release.json` and `sumi-protection-bundles-release.json.sig`, verifies the manifest signature against pinned Ed25519 public keys in Sumi, rejects incompatible releases, then downloads only the assets listed for `adguardAdsPrivacy`. Every file is written into a staging directory and verified by byte size and SHA-256 before the cached prepared bundle is replaced.

Activation is still Sumi-owned:

- If Adblock is not the applied protection level, the downloaded bundle is cached only.
- If Adblock is already applied, Sumi compiles the prepared WebKit shards and commits the new active generation only after validation succeeds.
- A failed download, manifest mismatch, hash mismatch, or compile failure leaves the previous active bundle set untouched.

Trust boundary: this repository may perform expensive network, parsing, and native compiler work. The browser may only consume prepared release assets. GitHub TLS and SHA-256 checks are transport/integrity checks; authenticity comes from the signed release manifest, and Sumi must verify that signature before trusting manifest fields.

## Release Signing Keys

Production releases are signed with Ed25519. The private key must come only from the GitHub Actions repository secret:

`SUMI_PROTECTION_BUNDLE_ED25519_PRIVATE_KEY`

Never commit the private key, seed phrase, `.pem`, `.key`, or generated private-key artifact. The committed Sumi app pins the public key id and raw public key bytes.

Generate a key pair locally:

```sh
openssl genpkey -algorithm Ed25519 -out sumi-protection-bundles-ed25519-v1.private.pem
openssl pkey -in sumi-protection-bundles-ed25519-v1.private.pem -pubout -out sumi-protection-bundles-ed25519-v1.public.pem
openssl pkey -in sumi-protection-bundles-ed25519-v1.private.pem -pubout -outform DER | tail -c 32 | base64
```

Add the private key to GitHub without printing it in logs:

```sh
gh secret set SUMI_PROTECTION_BUNDLE_ED25519_PRIVATE_KEY < sumi-protection-bundles-ed25519-v1.private.pem
```

Add the base64 raw public key from the last command to Sumi's pinned key list for key id `sumi-protection-bundles-ed25519-v1`, then delete the local private-key file or move it into your secure secret-storage process.

Key rotation:

1. Generate a new Ed25519 key pair.
2. Add the new public key and key id to Sumi's pinned key list.
3. Ship a Sumi update containing both current and next public keys.
4. Change the GitHub secret/key id used by this workflow.
5. After the old key is no longer needed, ship a later Sumi update that removes it.

## Signing Order

The release workflow builds and verifies prepared bundles, prepares the final `sumi-protection-bundles-release.json`, signs exactly those manifest bytes, verifies the signature locally with OpenSSL before upload, refreshes checksums, verifies the signature again, and only then publishes the GitHub Release. Any mutation of the manifest after signing makes signature verification fail.

The workflow default token permission is `contents: read`; only the release publishing job requests `contents: write`. The workflow runs only on `schedule` and `workflow_dispatch`. It uses GitHub-maintained first-party Actions by version tag for now and no third-party Actions or installer scripts.

## Local Commands

```sh
python3 scripts/test_sumi_adblock_bundle.py
python3 scripts/prepare_release_payload.py self-test
python3 scripts/test_release_manifest_signature.py
scripts/build_sumi_adblock_bundle.sh --all-profiles --output .build/sumi-adblock-bundles
for bundle in .build/sumi-adblock-bundles/*/SumiAdblockBundle; do scripts/verify_sumi_adblock_bundle.sh "$bundle"; done
python3 scripts/prepare_release_payload.py prepare --bundles-root .build/sumi-adblock-bundles --output dist
python3 scripts/prepare_release_payload.py validate --release-assets dist/release-assets
SUMI_PROTECTION_BUNDLE_ED25519_PRIVATE_KEY="$(cat /path/to/private.pem)" python3 scripts/sign_release_manifest.py --manifest dist/release-assets/sumi-protection-bundles-release.json --signature dist/release-assets/sumi-protection-bundles-release.json.sig --key-id sumi-protection-bundles-ed25519-v1
SUMI_PROTECTION_BUNDLE_ED25519_PRIVATE_KEY="$(cat /path/to/private.pem)" python3 scripts/verify_release_manifest_signature.py --manifest dist/release-assets/sumi-protection-bundles-release.json --signature dist/release-assets/sumi-protection-bundles-release.json.sig --expected-key-id sumi-protection-bundles-ed25519-v1
python3 scripts/prepare_release_payload.py refresh-checksums --release-assets dist/release-assets
```
