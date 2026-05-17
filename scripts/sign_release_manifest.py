#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_PRIVATE_KEY_ENV = "SUMI_PROTECTION_BUNDLE_ED25519_PRIVATE_KEY"
DEFAULT_SIGNATURE_SCHEMA_VERSION = 1
DEFAULT_ALGORITHM = "Ed25519"
DEFAULT_SIGNED_ASSET = "sumi-protection-bundles-release.json"


def openssl_command() -> str:
    configured = os.environ.get("OPENSSL")
    if configured:
        return configured
    return shutil.which("openssl") or "openssl"


def private_key_from_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(
            f"Missing required signing key secret: set {name} to an Ed25519 PEM private key."
        )
    if "BEGIN" in value and "\\n" in value and "\n" not in value:
        value = value.replace("\\n", "\n")
    if "PRIVATE KEY" not in value:
        raise SystemExit(f"{name} must contain an Ed25519 PEM private key.")
    if not value.endswith("\n"):
        value += "\n"
    return value


def run_openssl(args: list[str]) -> bytes:
    completed = subprocess.run(
        [openssl_command(), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise SystemExit(detail or "openssl command failed")
    return completed.stdout


def sign_manifest(manifest_path: Path, private_key_pem: str) -> bytes:
    with tempfile.TemporaryDirectory(prefix="sumi-signing-") as directory:
        private_key_path = Path(directory) / "ed25519-private.pem"
        private_key_path.write_text(private_key_pem, encoding="utf-8")
        private_key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        signature_path = Path(directory) / "manifest.sig.raw"
        run_openssl(
            [
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key_path),
                "-in",
                str(manifest_path),
                "-out",
                str(signature_path),
            ]
        )
        return signature_path.read_bytes()


def write_signature_envelope(
    signature_path: Path,
    *,
    key_id: str,
    signature: bytes,
    signed_asset: str,
) -> None:
    if len(signature) != 64:
        raise SystemExit(f"Ed25519 signatures must be 64 bytes; got {len(signature)} bytes.")
    envelope: dict[str, Any] = {
        "schemaVersion": DEFAULT_SIGNATURE_SCHEMA_VERSION,
        "algorithm": DEFAULT_ALGORITHM,
        "keyId": key_id,
        "signedAsset": signed_asset,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    signature_path.write_text(
        json.dumps(envelope, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sign the exact bytes of Sumi's release manifest with Ed25519."
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--private-key-env", default=DEFAULT_PRIVATE_KEY_ENV)
    parser.add_argument("--signed-asset", default=DEFAULT_SIGNED_ASSET)
    args = parser.parse_args()

    manifest_path = args.manifest.resolve()
    if not manifest_path.exists():
        raise SystemExit(f"Missing manifest to sign: {manifest_path}")
    private_key_pem = private_key_from_environment(args.private_key_env)
    signature = sign_manifest(manifest_path, private_key_pem)
    write_signature_envelope(
        args.signature.resolve(),
        key_id=args.key_id,
        signature=signature,
        signed_asset=args.signed_asset,
    )
    print(f"signed {manifest_path.name} with key {args.key_id}")


if __name__ == "__main__":
    main()
