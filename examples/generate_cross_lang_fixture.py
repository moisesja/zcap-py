"""Regenerate the cross-language JCS interop fixtures from committed inputs.

Emits ``tests/fixtures/cross_lang_jcs/capability_v1.json`` and
``invocation_v1.json``. The fixtures are known-answer test vectors that
zcap-dotnet's companion test must reproduce byte-for-byte once
moisesja/zcap-dotnet#34 fixes its JCS-payload shape disagreement.

Run from the repo root:

    uv run python examples/generate_cross_lang_fixture.py

Inputs are pinned below (Ed25519 seed, document body fields, proof
metadata, timestamps), so the script is idempotent: re-running on a
clean checkout produces no diff.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zcap_py.crypto.multibase import base58btc_encode
from zcap_py.did.key import encode_did_key
from zcap_py.jcs.canonicalize import canonicalize

# ── Pinned deterministic inputs (test-only) ──

PRIVATE_KEY_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CREATED = "2026-01-01T00:00:00Z"
ROOT_CAP_ID = "urn:zcap:root:cross-lang-test"
CAPABILITY_ID = "urn:zcap:cross-lang-test:cap-v1"
INVOCATION_ID = "urn:zcap:cross-lang-test:inv-v1"
INVOCATION_TARGET = "https://api.example.com/data/tenant-a/"
INVOCATION_TARGET_LEAF = "https://api.example.com/data/tenant-a/records/42"

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "cross_lang_jcs"


def _sign_document(
    body: dict[str, object],
    proof_metadata: dict[str, object],
    private_key: Ed25519PrivateKey,
) -> tuple[dict[str, object], str]:
    """Mirror ``tests/conftest.make_proof_value``: JCS over body+proof-minus-proofValue,
    Ed25519-sign, base58btc-encode. Returns ``(wire_document, jcs_sha256_hex)``.
    """
    to_sign = {**body, "proof": proof_metadata}
    canonical = canonicalize(to_sign)
    signature = private_key.sign(canonical)
    proof = {**proof_metadata, "proofValue": base58btc_encode(signature)}
    wire = {**body, "proof": proof}
    return wire, hashlib.sha256(canonical).hexdigest()


def _build_inputs() -> tuple[Ed25519PrivateKey, str, str, str]:
    seed = bytes.fromhex(PRIVATE_KEY_HEX)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_bytes = private_key.public_key().public_bytes_raw()
    did = encode_did_key(public_bytes)
    multibase_id = did.removeprefix("did:key:")
    verification_method = f"{did}#{multibase_id}"
    return private_key, did, verification_method, public_bytes.hex()


def _build_capability_fixture(
    private_key: Ed25519PrivateKey, did: str, verification_method: str, public_key_hex: str
) -> dict[str, object]:
    body: dict[str, object] = {
        "@context": [
            "https://w3id.org/zcap/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": CAPABILITY_ID,
        "type": "Authorization",
        "controller": did,
        "parentCapability": ROOT_CAP_ID,
        "invocationTarget": INVOCATION_TARGET,
        "allowedAction": ["read", "write"],
        "expires": "2099-12-31T23:59:59Z",
        "caveat": [
            {"type": "ExpiresAt", "value": "2099-06-30T00:00:00Z"},
            {"type": "ValidFromIp", "value": "203.0.113.0/24"},
        ],
    }
    proof_metadata: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": verification_method,
        "created": CREATED,
        "proofPurpose": "capabilityDelegation",
        "capabilityChain": [ROOT_CAP_ID],
        # Extra field — locks down "every non-proofValue field is JCS'd" invariant
        # so future libraries cannot silently drop unknown proof fields.
        "nonce": "interop-cap-v1-9f3c",
    }
    wire, jcs_sha256_hex = _sign_document(body, proof_metadata, private_key)
    return {
        "description": (
            "Cross-language JCS interop known-answer for a delegated Capability. "
            "Used by zcap-py and zcap-dotnet to detect signing-payload divergence."
        ),
        "version": "1.0",
        "inputs": {
            "private_key_hex": PRIVATE_KEY_HEX,
            "public_key_hex": public_key_hex,
            "verification_method": verification_method,
        },
        "document": json.dumps(wire),
        "jcs_sha256_hex": jcs_sha256_hex,
    }


def _build_invocation_fixture(
    private_key: Ed25519PrivateKey, did: str, verification_method: str, public_key_hex: str
) -> dict[str, object]:
    body: dict[str, object] = {
        "@context": [
            "https://w3id.org/zcap/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": INVOCATION_ID,
        "type": "Invocation",
        "capability": CAPABILITY_ID,
        "invocationTarget": INVOCATION_TARGET_LEAF,
    }
    proof_metadata: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": verification_method,
        "created": CREATED,
        "proofPurpose": "capabilityInvocation",
        "capability": CAPABILITY_ID,
        "capabilityAction": "read",
        "invocationTarget": INVOCATION_TARGET_LEAF,
        "capabilityChain": [ROOT_CAP_ID, CAPABILITY_ID],
        "nonce": "interop-inv-v1-7a21",
    }
    wire, jcs_sha256_hex = _sign_document(body, proof_metadata, private_key)
    return {
        "description": (
            "Cross-language JCS interop known-answer for an Invocation. "
            "Used by zcap-py and zcap-dotnet to detect signing-payload divergence."
        ),
        "version": "1.0",
        "inputs": {
            "private_key_hex": PRIVATE_KEY_HEX,
            "public_key_hex": public_key_hex,
            "verification_method": verification_method,
        },
        "document": json.dumps(wire),
        "jcs_sha256_hex": jcs_sha256_hex,
    }


def main() -> None:
    private_key, did, verification_method, public_key_hex = _build_inputs()

    capability_fixture = _build_capability_fixture(
        private_key, did, verification_method, public_key_hex
    )
    invocation_fixture = _build_invocation_fixture(
        private_key, did, verification_method, public_key_hex
    )

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

    capability_path = FIXTURE_DIR / "capability_v1.json"
    invocation_path = FIXTURE_DIR / "invocation_v1.json"

    capability_path.write_text(json.dumps(capability_fixture, indent=2) + "\n", encoding="utf-8")
    invocation_path.write_text(json.dumps(invocation_fixture, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {capability_path}")
    print(f"wrote {invocation_path}")


if __name__ == "__main__":
    main()
