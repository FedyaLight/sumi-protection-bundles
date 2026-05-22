#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BUNDLE = load_script("sumi_adblock_bundle")
RELEASE = load_script("prepare_release_payload")


class TrackingNetworkReleaseTests(unittest.TestCase):
    def test_tracking_network_bundle_release_metadata_hashes_and_signature(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sumi-tracking-release-test-") as tmp:
            root = Path(tmp)
            adapter = self.write_fake_adapter(root / "fake-adapter.py")
            list_file = root / "adguard.txt"
            list_file.write_text("||ads.example^\n", encoding="utf-8")
            tds_file = root / "macos-tds.json"
            tds_file.write_text(json.dumps(self.tds_fixture(), sort_keys=True), encoding="utf-8")

            bundle_dir = root / "bundles" / "adguardAdsPrivacy" / "SumiAdblockBundle"
            bundle_dir.mkdir(parents=True)
            BUNDLE.build_one_bundle(
                profile_id="adguardAdsPrivacy",
                bundle_dir=bundle_dir,
                cache_dir=root / "cache",
                helper=adapter,
                refresh=False,
                offline=True,
                overrides={list_id: list_file for list_id in BUNDLE.PROFILES["adguardAdsPrivacy"]["listIds"]},
                tracking_tds_url=BUNDLE.DDG_TDS_SOURCE_URL,
                tracking_tds_file=tds_file,
                tracking_webkit_json=None,
                tracking_source_name=None,
                tracking_source_url=None,
                tracking_source_license=None,
                max_rules=2,
                max_bytes=10_000,
                include_native_css=False,
            )
            BUNDLE.verify_bundle_dir(bundle_dir, allow_empty_shards=False, quiet=True)

            manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
            tracking_group = self.group(manifest, "trackingNetwork")
            self.assertEqual(tracking_group["status"], "generated")
            self.assertEqual(tracking_group["source"]["sourceName"], BUNDLE.DDG_TDS_SOURCE_NAME)
            self.assertEqual(tracking_group["source"]["sourceLicense"], BUNDLE.DDG_TDS_SOURCE_LICENSE)
            self.assertEqual(tracking_group["source"]["sourceLicenseURL"], BUNDLE.DDG_TDS_SOURCE_LICENSE_URL)
            self.assertEqual(tracking_group["source"]["sourceSha256"], BUNDLE.sha256_hex(tds_file.read_bytes()))
            self.assertGreater(tracking_group["ruleCount"], 0)
            self.assertGreater(tracking_group["shardCount"], 0)

            release_output = root / "dist"
            RELEASE.prepare(
                self.args(
                    bundles_root=root / "bundles",
                    output=release_output,
                    repository_owner="FedyaLight",
                    repository_name="sumi-protection-bundles",
                )
            )
            RELEASE.validate(self.args(release_assets=release_output / "release-assets"))

            release_manifest_path = release_output / "release-assets" / RELEASE.RELEASE_MANIFEST_ASSET_NAME
            release_manifest = json.loads(release_manifest_path.read_text(encoding="utf-8"))
            release_bundle = release_manifest["bundles"][0]
            release_tracking_group = self.group(release_bundle, "trackingNetwork")
            self.assertTrue(release_tracking_group["assetNames"])
            self.assertEqual(release_tracking_group["source"]["sourceLicense"], BUNDLE.DDG_TDS_SOURCE_LICENSE)
            self.assertTrue(
                any(asset["role"] == "trackingNetworkShard" for asset in release_manifest["assets"])
            )

            tampered_asset = release_output / "release-assets" / release_tracking_group["assetNames"][0]
            tampered_asset.write_bytes(tampered_asset.read_bytes() + b"\n")
            with self.assertRaises(SystemExit):
                RELEASE.validate(self.args(release_assets=release_output / "release-assets"))

            RELEASE.prepare(
                self.args(
                    bundles_root=root / "bundles",
                    output=release_output,
                    repository_owner="FedyaLight",
                    repository_name="sumi-protection-bundles",
                )
            )
            self.sign_and_verify_release_manifest(release_output / "release-assets")

    def sign_and_verify_release_manifest(self, release_assets: Path) -> None:
        private_key = release_assets.parent / "test-ed25519.private.pem"
        public_key = release_assets.parent / "test-ed25519.public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private_key)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        manifest = release_assets / RELEASE.RELEASE_MANIFEST_ASSET_NAME
        signature = release_assets / RELEASE.RELEASE_MANIFEST_SIGNATURE_ASSET_NAME
        env = os.environ.copy()
        env["SUMI_PROTECTION_BUNDLE_ED25519_PRIVATE_KEY"] = private_key.read_text(encoding="utf-8")
        env["SUMI_PROTECTION_BUNDLE_ED25519_PUBLIC_KEY"] = public_key.read_text(encoding="utf-8")
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "sign_release_manifest.py"),
                "--manifest",
                str(manifest),
                "--signature",
                str(signature),
                "--key-id",
                "test-key",
            ],
            check=True,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "verify_release_manifest_signature.py"),
                "--manifest",
                str(manifest),
                "--signature",
                str(signature),
                "--expected-key-id",
                "test-key",
            ],
            check=True,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        manifest.write_text(manifest.read_text(encoding="utf-8").replace('"schemaVersion": 1', '"schemaVersion": 1 '), encoding="utf-8")
        failed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "verify_release_manifest_signature.py"),
                "--manifest",
                str(manifest),
                "--signature",
                str(signature),
                "--expected-key-id",
                "test-key",
            ],
            check=False,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(failed.returncode, 0)

    @staticmethod
    def write_fake_adapter(path: Path) -> Path:
        path.write_text(
            """#!/usr/bin/env python3
import json
import sys
sys.stdin.read()
json.dump({
  "network": [
    {"trigger": {"url-filter": ".*ads\\\\.example/.*"}, "action": {"type": "block"}},
    {"action": {"type": "block"}, "trigger": {"url-filter": ".*ads\\\\.example/.*"}}
  ],
  "native_cosmetic_css": [],
  "unsupported_or_ignored": [],
  "enhanced_resource_candidates": []
}, sys.stdout)
""",
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    @staticmethod
    def tds_fixture() -> dict:
        return {
            "trackers": {
                "tracker.example": {
                    "domain": "tracker.example",
                    "owner": {"name": "Tracker Co", "displayName": "Tracker Co"},
                    "default": "block",
                    "rules": [
                        {
                            "rule": "tracker\\.example\\/pixel",
                            "options": {"domains": ["publisher.example"], "types": ["script"]},
                        }
                    ],
                }
            },
            "entities": {
                "Tracker Co": {
                    "domains": ["tracker.example", "publisher.example"],
                    "displayName": "Tracker Co",
                }
            },
            "domains": {"tracker.example": "Tracker Co"},
            "cnames": {"alias.example": "tracker.example"},
        }

    @staticmethod
    def group(container: dict, group_id: str) -> dict:
        return next(group for group in container["groups"] if group["id"] == group_id)

    @staticmethod
    def args(**kwargs):
        return type("Args", (), kwargs)()


if __name__ == "__main__":
    unittest.main()
