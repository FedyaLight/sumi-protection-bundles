# sumi-protection-bundles

> [!IMPORTANT]
> This repository is archived and no longer used by Sumi. The current browser
> downloads the filter lists selected by the user and generates its WebKit and
> advanced-blocking artifacts locally.

## Historical implementation

This repository built Sumi's signed, prepared content-blocking generations.
The documentation and source below are retained only as a historical record of
the retired pipeline.

## wBlock parity pipeline

`scripts/wblock_parity_bundle.py` follows wBlock's macOS default profile at
revision `15f65096ccb5a36fdea6883b526037884cb9a60a`:

- the eight default lists are declared in `metadata/profiles.json` and
  `metadata/source-lists.json`;
- rules are distributed across five Safari content-blocker slots with wBlock's
  `!#safari_cb_affinity` semantics;
- SafariConverterLib 4.3.0 at revision
  `7a2e93f0afa70479cc59985f332025236c3f0c39` produces both native WebKit JSON
  and the advanced FilterEngine input from the same slot inputs;
- the release contains a Safari 16.4–18 profile and a Safari 26+ profile, so
  Sumi uses the same converter feature set that wBlock auto-detects without
  shipping Safari 26-only triggers to older WebKit versions;
- the advanced engine artifacts and the conservatively expressible
  `$removeparam` DNR rules are emitted in the same bundle generation;
- DuckDuckGo TDS remains a separate `trackingNetwork` group used only by the
  Protection level. Adblock activates the wBlock group instead of stacking a
  second tracking matcher over it.

The generator fails if SafariConverterLib discards a native rule because of a
slot cap. Sumi verifies every artifact's path, byte size, and SHA-256 and
publishes native and advanced artifacts atomically.

## Release assets

Every release contains:

- `sumi-protection-bundles-release.json` and its Ed25519 signature;
- `sumi-protection-bundles-checksums.txt`;
- the `wblockDefault` and `wblockDefaultSafari26` manifests and diagnostics;
- five wBlock native JSON shards plus the Protection TDS shard per profile;
- FilterEngine `rules.bin`, `engine.bin`, `meta.bin`, and `rules.txt`;
- `removeparam.json`.

`scripts/prepare_release_payload.py` validates the bundle and flattens these
files into release assets while retaining their manifest-declared target paths.
Sumi downloads only assets named by the signed release manifest and leaves the
previous active generation untouched on any download, signature, schema,
compiler, hash, or activation failure.

## Updates and reproducibility

The workflow in `.github/workflows/publish-bundles.yml` runs weekly and by
manual dispatch. List updates therefore do not require a Sumi app release.
Changing the pinned wBlock or SafariConverterLib revisions is a reviewed source
change and must be accompanied by parity tests and a Sumi runtime update when
the advanced runtime version changes.

Build and validate locally:

```sh
python3 scripts/test_sumi_adblock_bundle.py
python3 scripts/test_wblock_parity_bundle.py
python3 scripts/test_tracking_network_release.py
python3 scripts/prepare_release_payload.py self-test
scripts/build_sumi_adblock_bundle.sh --all-profiles --output .build/sumi-adblock-bundles
for bundle in .build/sumi-adblock-bundles/*/SumiAdblockBundle; do scripts/verify_sumi_adblock_bundle.sh "$bundle"; done
python3 scripts/prepare_release_payload.py prepare --bundles-root .build/sumi-adblock-bundles --output dist
python3 scripts/prepare_release_payload.py validate --release-assets dist/release-assets
```

## Licensing and trust

The wBlock parity generator and Sumi are GPL-3.0-or-later. SafariConverterLib
and the copied wBlock behavior are GPL-3.0 compatible. Individual filter lists
retain their upstream licenses.

The TDS-derived `trackingNetwork` group is CC BY-NC-SA 4.0 and is restricted to
Sumi's non-commercial releases. Its source, license, generation time, hash, and
rule/shard counts are carried in every manifest; see `NOTICE.md`.

Production release manifests are signed with the repository secret
`SUMI_PROTECTION_BUNDLE_ED25519_PRIVATE_KEY`. Never commit the private key.
Sumi pins the corresponding public key and verifies the signature before it
trusts any release metadata.
