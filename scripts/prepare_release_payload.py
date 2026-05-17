#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any


RELEASE_MANIFEST_SCHEMA_VERSION = 1
RELEASE_MANIFEST_ASSET_NAME = "sumi-protection-bundles-release.json"
RELEASE_MANIFEST_SIGNATURE_ASSET_NAME = "sumi-protection-bundles-release.json.sig"
CHECKSUMS_ASSET_NAME = "sumi-protection-bundles-checksums.txt"
MINIMUM_SUMI_BUNDLE_EXPECTATION_VERSION = 1
MAXIMUM_SUMI_BUNDLE_EXPECTATION_VERSION = 1
BUNDLE_MANIFEST_SCHEMA_VERSION = 1
REQUIRED_NATIVE_CSS_SAFETY_POLICY_VERSION = "sumi-native-css-safety/0.4"


def sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_checksums(release_assets_dir: Path) -> None:
    checksum_lines = []
    for path in sorted(release_assets_dir.iterdir()):
        if path.is_file() and path.name != CHECKSUMS_ASSET_NAME:
            checksum_lines.append(f"{sha256_hex(path.read_bytes())}  {path.name}")
    (release_assets_dir / CHECKSUMS_ASSET_NAME).write_text(
        "\n".join(checksum_lines) + "\n",
        encoding="utf-8",
    )


def validate_bundle(bundle_dir: Path) -> dict[str, Any]:
    manifest_path = bundle_dir / "manifest.json"
    diagnostics_path = bundle_dir / "diagnostics.json"
    if not manifest_path.exists():
        raise SystemExit(f"Missing bundle manifest: {manifest_path}")
    if not diagnostics_path.exists():
        raise SystemExit(f"Missing bundle diagnostics: {diagnostics_path}")
    manifest = read_json(manifest_path)
    if manifest.get("schemaVersion") != BUNDLE_MANIFEST_SCHEMA_VERSION:
        raise SystemExit(f"Unsupported bundle schemaVersion: {manifest.get('schemaVersion')}")
    if manifest.get("nativeCSSSafetyPolicyVersion") != REQUIRED_NATIVE_CSS_SAFETY_POLICY_VERSION:
        raise SystemExit(
            "Unsupported native CSS safety policy: "
            f"{manifest.get('nativeCSSSafetyPolicyVersion')}"
        )
    if not manifest.get("profileId") or not manifest.get("bundleId") or not manifest.get("generationId"):
        raise SystemExit(f"Bundle manifest identity is incomplete: {manifest_path}")
    if not manifest.get("shards"):
        raise SystemExit(f"Bundle contains no shards: {manifest_path}")
    for shard in manifest["shards"]:
        relative = shard.get("relativePath")
        if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise SystemExit(f"Invalid shard path: {relative}")
        shard_path = bundle_dir / relative
        if not shard_path.exists():
            raise SystemExit(f"Missing shard: {relative}")
        data = shard_path.read_bytes()
        if len(data) != shard.get("byteSize"):
            raise SystemExit(f"Shard size mismatch: {relative}")
        if sha256_hex(data) != shard.get("hash"):
            raise SystemExit(f"Shard hash mismatch: {relative}")
        parsed = json.loads(data.decode("utf-8"))
        if not isinstance(parsed, list) or not parsed:
            raise SystemExit(f"Shard must be a non-empty JSON array: {relative}")
    return manifest


def flattened_asset_name(profile_id: str, relative_path: str) -> str:
    if relative_path == "manifest.json":
        return f"{profile_id}-manifest.json"
    if relative_path == "diagnostics.json":
        return f"{profile_id}-diagnostics.json"
    return f"{profile_id}-{Path(relative_path).name}"


def asset_role(relative_path: str, shard_kind: str | None = None) -> str:
    if relative_path == "manifest.json":
        return "bundleManifest"
    if relative_path == "diagnostics.json":
        return "diagnostics"
    if shard_kind == "nativeCSS":
        return "nativeCSSShard"
    return "networkShard"


def copy_payload_asset(
    source: Path,
    release_assets_dir: Path,
    profile_id: str,
    relative_path: str,
    role: str,
) -> dict[str, Any]:
    data = source.read_bytes()
    name = flattened_asset_name(profile_id, relative_path)
    destination = release_assets_dir / name
    shutil.copyfile(source, destination)
    return {
        "name": name,
        "role": role,
        "bundleProfileId": profile_id,
        "relativePath": relative_path,
        "byteSize": len(data),
        "sha256": sha256_hex(data),
    }


def prepare(args: argparse.Namespace) -> None:
    bundles_root = Path(args.bundles_root).resolve()
    output_dir = Path(args.output).resolve()
    release_assets_dir = output_dir / "release-assets"
    if output_dir.exists():
        shutil.rmtree(output_dir)
    release_assets_dir.mkdir(parents=True)

    generated_at = datetime.now(timezone.utc)
    bundle_entries: list[dict[str, Any]] = []
    asset_entries: list[dict[str, Any]] = []
    payload_hash_inputs: list[str] = []

    bundle_dirs = sorted(bundles_root.glob("*/SumiAdblockBundle"))
    if not bundle_dirs:
        raise SystemExit(f"No SumiAdblockBundle directories found under {bundles_root}")

    for bundle_dir in bundle_dirs:
        manifest = validate_bundle(bundle_dir)
        profile_id = manifest["profileId"]
        bundle_asset_names: list[str] = []
        for relative_path, role, source in [
            ("manifest.json", "bundleManifest", bundle_dir / "manifest.json"),
            ("diagnostics.json", "diagnostics", bundle_dir / "diagnostics.json"),
        ]:
            entry = copy_payload_asset(source, release_assets_dir, profile_id, relative_path, role)
            asset_entries.append(entry)
            bundle_asset_names.append(entry["name"])
            payload_hash_inputs.append(f"{entry['name']}:{entry['sha256']}")

        for shard in sorted(manifest["shards"], key=lambda item: item["relativePath"]):
            relative_path = shard["relativePath"]
            entry = copy_payload_asset(
                bundle_dir / relative_path,
                release_assets_dir,
                profile_id,
                relative_path,
                asset_role(relative_path, shard.get("kind")),
            )
            asset_entries.append(entry)
            bundle_asset_names.append(entry["name"])
            payload_hash_inputs.append(f"{entry['name']}:{entry['sha256']}")

        bundle_entries.append(
            {
                "profileId": profile_id,
                "bundleId": manifest["bundleId"],
                "generationId": manifest["generationId"],
                "generatedDate": manifest["generatedDate"],
                "assetNames": sorted(bundle_asset_names),
            }
        )

    payload_digest = sha256_hex("\n".join(sorted(payload_hash_inputs)).encode("utf-8"))[:12]
    version = f"{generated_at.strftime('%Y%m%dT%H%M%SZ')}-{payload_digest}"
    repository = {
        "owner": args.repository_owner,
        "name": args.repository_name,
        "commit": os.environ.get("GITHUB_SHA"),
    }
    release_manifest = {
        "schemaVersion": RELEASE_MANIFEST_SCHEMA_VERSION,
        "releaseVersion": version,
        "generatedAt": generated_at.isoformat().replace("+00:00", "Z"),
        "repository": repository,
        "compatibility": {
            "minimumSumiBundleExpectationVersion": MINIMUM_SUMI_BUNDLE_EXPECTATION_VERSION,
            "maximumSumiBundleExpectationVersion": MAXIMUM_SUMI_BUNDLE_EXPECTATION_VERSION,
            "bundleManifestSchemaVersion": BUNDLE_MANIFEST_SCHEMA_VERSION,
            "requiredNativeCSSSafetyPolicyVersion": REQUIRED_NATIVE_CSS_SAFETY_POLICY_VERSION,
        },
        "bundles": sorted(bundle_entries, key=lambda item: item["profileId"]),
        "assets": sorted(asset_entries, key=lambda item: item["name"]),
    }
    write_json(release_assets_dir / RELEASE_MANIFEST_ASSET_NAME, release_manifest)

    write_checksums(release_assets_dir)

    notes = [
        f"# Sumi protection bundles {version}",
        "",
        "Prepared WebKit content-blocking bundles generated outside Sumi.",
        "",
        "Assets:",
    ]
    for bundle in release_manifest["bundles"]:
        notes.append(
            f"- `{bundle['profileId']}`: generation `{bundle['generationId']}`, bundle `{bundle['bundleId']}`"
        )
    notes.append("")
    notes.append(
        "Sumi verifies `sumi-protection-bundles-release.json.sig` against pinned Ed25519 public keys before trusting the release manifest, then verifies every listed asset by SHA-256 before caching or activating it."
    )
    (output_dir / "release-notes.md").write_text("\n".join(notes) + "\n", encoding="utf-8")
    (output_dir / "release-version.txt").write_text(version + "\n", encoding="utf-8")
    print(version)


def validate(args: argparse.Namespace) -> None:
    release_assets_dir = Path(args.release_assets).resolve()
    manifest_path = release_assets_dir / RELEASE_MANIFEST_ASSET_NAME
    if not manifest_path.exists():
        raise SystemExit(f"Missing release manifest: {manifest_path}")
    manifest = read_json(manifest_path)
    if manifest.get("schemaVersion") != RELEASE_MANIFEST_SCHEMA_VERSION:
        raise SystemExit(f"Unsupported release manifest schema: {manifest.get('schemaVersion')}")
    asset_names = {asset["name"] for asset in manifest.get("assets", [])}
    for bundle in manifest.get("bundles", []):
        missing = sorted(set(bundle.get("assetNames", [])) - asset_names)
        if missing:
            raise SystemExit(f"Bundle {bundle.get('profileId')} references missing assets: {missing}")
    for asset in manifest.get("assets", []):
        path = release_assets_dir / asset["name"]
        if not path.exists():
            raise SystemExit(f"Missing release asset: {asset['name']}")
        data = path.read_bytes()
        if len(data) != asset["byteSize"]:
            raise SystemExit(f"Release asset size mismatch: {asset['name']}")
        if sha256_hex(data) != asset["sha256"]:
            raise SystemExit(f"Release asset hash mismatch: {asset['name']}")
        relative = asset["relativePath"]
        if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise SystemExit(f"Invalid bundle relative path: {relative}")
    print(f"validated {len(manifest.get('assets', []))} release payload assets")


def refresh_checksums(args: argparse.Namespace) -> None:
    release_assets_dir = Path(args.release_assets).resolve()
    if not release_assets_dir.exists():
        raise SystemExit(f"Missing release assets directory: {release_assets_dir}")
    write_checksums(release_assets_dir)
    print(f"refreshed checksums in {release_assets_dir}")


def self_test() -> None:
    sample = b"[]"
    assert sha256_hex(sample) == "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
    assert flattened_asset_name("adguardAdsPrivacy", "network/network-0001.json") == "adguardAdsPrivacy-network-0001.json"
    assert asset_role("nativeCSS/nativeCSS-0001.json", "nativeCSS") == "nativeCSSShard"
    with tempfile.TemporaryDirectory() as tmp:
        release_assets = Path(tmp)
        (release_assets / RELEASE_MANIFEST_ASSET_NAME).write_text("manifest\n", encoding="utf-8")
        (release_assets / RELEASE_MANIFEST_SIGNATURE_ASSET_NAME).write_text("signature\n", encoding="utf-8")
        write_checksums(release_assets)
        checksums = (release_assets / CHECKSUMS_ASSET_NAME).read_text(encoding="utf-8")
        assert RELEASE_MANIFEST_ASSET_NAME in checksums
        assert RELEASE_MANIFEST_SIGNATURE_ASSET_NAME in checksums
        assert CHECKSUMS_ASSET_NAME not in checksums


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare or validate Sumi release assets.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--bundles-root", default=".build/sumi-adblock-bundles")
    prepare_parser.add_argument("--output", default="dist")
    prepare_parser.add_argument("--repository-owner", default="FedyaLight")
    prepare_parser.add_argument("--repository-name", default="sumi-protection-bundles")
    prepare_parser.set_defaults(func=prepare)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--release-assets", default="dist/release-assets")
    validate_parser.set_defaults(func=validate)

    checksums_parser = subparsers.add_parser("refresh-checksums")
    checksums_parser.add_argument("--release-assets", default="dist/release-assets")
    checksums_parser.set_defaults(func=refresh_checksums)

    test_parser = subparsers.add_parser("self-test")
    test_parser.set_defaults(func=lambda _args: self_test())
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
