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

Sumi fetches the latest GitHub Release metadata, downloads `sumi-protection-bundles-release.json`, rejects incompatible releases, then downloads only the assets listed for `adguardAdsPrivacy`. Every file is written into a staging directory and verified by byte size and SHA-256 before the cached prepared bundle is replaced.

Activation is still Sumi-owned:

- If Adblock is not the applied protection level, the downloaded bundle is cached only.
- If Adblock is already applied, Sumi compiles the prepared WebKit shards and commits the new active generation only after validation succeeds.
- A failed download, manifest mismatch, hash mismatch, or compile failure leaves the previous active bundle set untouched.

Trust boundary: this repository may perform expensive network, parsing, and native compiler work. The browser may only consume prepared release assets and verify metadata/hashes before storage or activation.

## Local Commands

```sh
python3 scripts/test_sumi_adblock_bundle.py
python3 scripts/prepare_release_payload.py self-test
scripts/build_sumi_adblock_bundle.sh --all-profiles --output .build/sumi-adblock-bundles
for bundle in .build/sumi-adblock-bundles/*/SumiAdblockBundle; do scripts/verify_sumi_adblock_bundle.sh "$bundle"; done
python3 scripts/prepare_release_payload.py prepare --bundles-root .build/sumi-adblock-bundles --output dist
python3 scripts/prepare_release_payload.py validate --release-assets dist/release-assets
```
