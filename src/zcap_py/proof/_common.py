"""Suite-neutral Ed25519Signature2020 proof helpers.

These helpers are independent of the canonicalization scheme and are shared by
the W3C URDNA2015 proof path. Extracted from the former JCS module so the JCS
implementation could be removed without losing the suite-neutral validation and
key-resolution logic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from zcap_py.crypto.multibase import base58btc_decode
from zcap_py.did.key import public_key_from_did_key
from zcap_py.exceptions import (
    DidParseError,
    ProofError,
    UnsupportedProofTypeError,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROOF_TYPE = "Ed25519Signature2020"
ED25519_SIGNATURE_LENGTH = 64


def _extract_proof(document: dict[str, object]) -> dict[str, object]:
    """Extract and validate the proof dict from a document."""
    proof = document.get("proof")
    if not isinstance(proof, dict):
        raise ProofError(
            "Document missing 'proof' field or proof is not an object",
            context={"has_proof": "proof" in document},
        )
    return proof


def _validate_proof_type(proof: dict[str, object]) -> None:
    """Validate the proof type is Ed25519Signature2020."""
    ptype = proof.get("type")
    if ptype != PROOF_TYPE:
        raise UnsupportedProofTypeError(
            f"Expected proof type '{PROOF_TYPE}', got '{ptype}'",
            context={"type": str(ptype)},
        )


def _decode_proof_value(proof: dict[str, object]) -> bytes:
    """Decode and validate the multibase-z ``proofValue`` into 64 raw bytes."""
    pv = proof.get("proofValue")
    if not isinstance(pv, str) or not pv.startswith("z"):
        raise ProofError(
            "proofValue must be a multibase-z string",
            context={"proofValue": str(pv)[:20] if pv else None},
        )
    try:
        decoded = base58btc_decode(pv)
    except Exception as e:
        raise ProofError(
            "proofValue base58btc decode failed",
            context={"proofValue": pv[:20]},
        ) from e
    if len(decoded) != ED25519_SIGNATURE_LENGTH:
        raise ProofError(
            f"proofValue decoded to {len(decoded)} bytes; expected {ED25519_SIGNATURE_LENGTH}",
            context={"length": len(decoded)},
        )
    return decoded


def _resolve_verification_key(proof: dict[str, object]) -> Ed25519PublicKey:
    """Resolve the Ed25519 public key from ``proof.verificationMethod``.

    Binds the proof to the key claimed in verificationMethod — prevents
    accepting a signature from key B when verificationMethod names key A.

    Raises:
        ProofError: If verificationMethod is missing, empty, or does not
            encode a valid Ed25519 did:key.
    """
    vm = proof.get("verificationMethod")
    if not isinstance(vm, str) or not vm.strip():
        raise ProofError(
            "proof.verificationMethod is missing or empty",
            context={"verificationMethod": vm},
        )
    try:
        return public_key_from_did_key(vm)
    except DidParseError as e:
        raise ProofError(
            f"Cannot resolve public key from verificationMethod: {vm}",
            context={"verificationMethod": vm},
        ) from e
