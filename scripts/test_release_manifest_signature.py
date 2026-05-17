#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SIGN = ROOT / "scripts" / "sign_release_manifest.py"
VERIFY = ROOT / "scripts" / "verify_release_manifest_signature.py"
KEY_ID = "sumi-protection-bundles-ed25519-v1"


class ReleaseManifestSignatureTests(unittest.TestCase):
    def test_valid_signature_verifies_and_modified_manifest_fails(self) -> None:
        with self.fixture() as fixture:
            self.sign(fixture)
            self.verify(fixture)

            fixture.manifest.write_text(
                json.dumps({"releaseVersion": "20260517T000001Z-test"}, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            failed = self.verify(fixture, check=False)
            self.assertNotEqual(failed.returncode, 0)

    def test_wrong_public_key_fails(self) -> None:
        with self.fixture() as fixture:
            self.sign(fixture)
            wrong_private, wrong_public = self.generate_key_pair(fixture.root)
            del wrong_private
            failed = self.verify(fixture, public_key=wrong_public, check=False)
            self.assertNotEqual(failed.returncode, 0)

    def test_missing_private_key_produces_clear_error(self) -> None:
        with self.fixture() as fixture:
            env = os.environ.copy()
            env.pop("SUMI_PROTECTION_BUNDLE_ED25519_PRIVATE_KEY", None)
            completed = subprocess.run(
                [
                    "python3",
                    str(SIGN),
                    "--manifest",
                    str(fixture.manifest),
                    "--signature",
                    str(fixture.signature),
                    "--key-id",
                    KEY_ID,
                ],
                cwd=ROOT,
                env=env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Missing required signing key secret", completed.stderr)

    def test_signature_artifact_does_not_contain_private_key_material(self) -> None:
        with self.fixture() as fixture:
            self.sign(fixture)
            signature_text = fixture.signature.read_text(encoding="utf-8")
            self.assertNotIn("PRIVATE KEY", signature_text)
            self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", signature_text)
            self.assertNotIn("BEGIN PRIVATE KEY", signature_text)
            self.assertIn(KEY_ID, signature_text)

    def sign(self, fixture: "Fixture") -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["SUMI_PROTECTION_BUNDLE_ED25519_PRIVATE_KEY"] = fixture.private_key.read_text(
            encoding="utf-8"
        )
        return subprocess.run(
            [
                "python3",
                str(SIGN),
                "--manifest",
                str(fixture.manifest),
                "--signature",
                str(fixture.signature),
                "--key-id",
                KEY_ID,
            ],
            cwd=ROOT,
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def verify(
        self,
        fixture: "Fixture",
        public_key: Path | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(VERIFY),
                "--manifest",
                str(fixture.manifest),
                "--signature",
                str(fixture.signature),
                "--public-key",
                str(public_key or fixture.public_key),
                "--expected-key-id",
                KEY_ID,
            ],
            cwd=ROOT,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def fixture(self) -> "FixtureContext":
        return FixtureContext(self)

    def generate_key_pair(self, directory: Path) -> tuple[Path, Path]:
        private_key = directory / f"ed25519-{len(list(directory.iterdir()))}.pem"
        public_key = directory / f"ed25519-{len(list(directory.iterdir()))}.pub.pem"
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
        return private_key, public_key


class Fixture:
    def __init__(self, root: Path, private_key: Path, public_key: Path, manifest: Path, signature: Path):
        self.root = root
        self.private_key = private_key
        self.public_key = public_key
        self.manifest = manifest
        self.signature = signature


class FixtureContext:
    def __init__(self, tests: ReleaseManifestSignatureTests):
        self.tests = tests
        self.temporary_directory: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> Fixture:
        self.temporary_directory = tempfile.TemporaryDirectory(prefix="sumi-release-signature-tests-")
        root = Path(self.temporary_directory.name)
        private_key, public_key = self.tests.generate_key_pair(root)
        manifest = root / "sumi-protection-bundles-release.json"
        manifest.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "releaseVersion": "20260517T000000Z-test",
                    "generatedAt": "2026-05-17T00:00:00Z",
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return Fixture(root, private_key, public_key, manifest, root / "sumi-protection-bundles-release.json.sig")

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.temporary_directory:
            self.temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
