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


DEFAULT_PUBLIC_KEY_ENV = "SUMI_PROTECTION_BUNDLE_ED25519_PUBLIC_KEY"
DEFAULT_PRIVATE_KEY_ENV = "SUMI_PROTECTION_BUNDLE_ED25519_PRIVATE_KEY"
DEFAULT_SIGNATURE_SCHEMA_VERSION = 1
DEFAULT_ALGORITHM = "Ed25519"
DEFAULT_SIGNED_ASSET = "sumi-protection-bundles-release.json"


def openssl_command() -> str:
    configured = os.environ.get("OPENSSL")
    if configured:
        return configured
    return shutil.which("openssl") or "openssl"


def normalize_pem(value: str, label: str) -> str:
    if "BEGIN" in value and "\\n" in value and "\n" not in value:
        value = value.replace("\\n", "\n")
    if label not in value:
        raise SystemExit(f"Expected PEM containing {label}.")
    if not value.endswith("\n"):
        value += "\n"
    return value


def pem_from_environment(name: str, label: str) -> str | None:
    value = os.environ.get(name)
    if not value:
        return None
    return normalize_pem(value, label)


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


def load_signature_envelope(path: Path, expected_key_id: str | None, expected_asset: str) -> tuple[str, bytes]:
    try:
        envelope: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SystemExit(f"Signature metadata is not valid JSON: {error}") from error

    if envelope.get("schemaVersion") != DEFAULT_SIGNATURE_SCHEMA_VERSION:
        raise SystemExit(f"Unsupported signature schemaVersion: {envelope.get('schemaVersion')}")
    if envelope.get("algorithm") != DEFAULT_ALGORITHM:
        raise SystemExit(f"Unsupported signature algorithm: {envelope.get('algorithm')}")
    if envelope.get("signedAsset") != expected_asset:
        raise SystemExit(f"Signature covers unexpected asset: {envelope.get('signedAsset')}")

    key_id = envelope.get("keyId")
    if not isinstance(key_id, str) or not key_id:
        raise SystemExit("Signature metadata is missing keyId.")
    if expected_key_id and key_id != expected_key_id:
        raise SystemExit(f"Signature keyId mismatch: expected {expected_key_id}, got {key_id}")

    encoded_signature = envelope.get("signature")
    if not isinstance(encoded_signature, str):
        raise SystemExit("Signature metadata is missing signature.")
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
    except ValueError as error:
        raise SystemExit("Signature is not valid base64.") from error
    if len(signature) != 64:
        raise SystemExit(f"Ed25519 signatures must be 64 bytes; got {len(signature)} bytes.")
    return key_id, signature


def verify_signature(manifest_path: Path, signature: bytes, public_key_pem: str) -> None:
    with tempfile.TemporaryDirectory(prefix="sumi-signing-verify-") as directory:
        public_key_path = Path(directory) / "ed25519-public.pem"
        public_key_path.write_text(public_key_pem, encoding="utf-8")
        public_key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        signature_path = Path(directory) / "manifest.sig.raw"
        signature_path.write_bytes(signature)
        run_openssl(
            [
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(public_key_path),
                "-in",
                str(manifest_path),
                "-sigfile",
                str(signature_path),
            ]
        )


def public_key_from_args(args: argparse.Namespace) -> str:
    if args.public_key:
        return normalize_pem(args.public_key.read_text(encoding="utf-8"), "PUBLIC KEY")

    public_key_pem = pem_from_environment(args.public_key_env, "PUBLIC KEY")
    if public_key_pem:
        return public_key_pem

    private_key_pem = pem_from_environment(args.public_key_from_private_key_env, "PRIVATE KEY")
    if private_key_pem:
        with tempfile.TemporaryDirectory(prefix="sumi-signing-pubout-") as directory:
            private_key_path = Path(directory) / "ed25519-private.pem"
            private_key_path.write_text(private_key_pem, encoding="utf-8")
            private_key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            return run_openssl(["pkey", "-in", str(private_key_path), "-pubout"]).decode("utf-8")

    raise SystemExit(
        f"Provide --public-key, {args.public_key_env}, or {args.public_key_from_private_key_env}."
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify Sumi release manifest signature metadata against exact manifest bytes."
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--public-key-env", default=DEFAULT_PUBLIC_KEY_ENV)
    parser.add_argument("--public-key-from-private-key-env", default=DEFAULT_PRIVATE_KEY_ENV)
    parser.add_argument("--expected-key-id")
    parser.add_argument("--signed-asset", default=DEFAULT_SIGNED_ASSET)
    args = parser.parse_args()

    manifest_path = args.manifest.resolve()
    signature_path = args.signature.resolve()
    if not manifest_path.exists():
        raise SystemExit(f"Missing manifest: {manifest_path}")
    if not signature_path.exists():
        raise SystemExit(f"Missing signature metadata: {signature_path}")
    key_id, signature = load_signature_envelope(
        signature_path,
        args.expected_key_id,
        args.signed_asset,
    )
    public_key_pem = public_key_from_args(args)
    verify_signature(manifest_path, signature, public_key_pem)
    print(f"verified {manifest_path.name} with key {key_id}")


if __name__ == "__main__":
    main()
