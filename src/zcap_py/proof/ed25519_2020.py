"""Ed25519Signature2020 proof verification."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature

from zcap_py.crypto.multibase import base58btc_decode

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from zcap_py.exceptions import (
    ProofError,
    SignatureVerificationError,
    UnsupportedProofTypeError,
)
from zcap_py.jcs.canonicalize import canonicalize

PROOF_TYPE = "Ed25519Signature2020"
ED25519_SIGNATURE_LENGTH = 64


def verify_document_proof(
    document: dict[str, object],
    public_key: Ed25519PublicKey,
) -> None:
    """Verify the Ed25519Signature2020 proof on a document.

    Per FR-PROOF-02: extract proof, remove proofValue from proof copy,
    merge proof copy back into document, JCS-canonicalize, verify signature.

    Raises:
        ProofError: If proof structure is malformed.
        UnsupportedProofTypeError: If proof type is not Ed25519Signature2020.
        SignatureVerificationError: If signature verification fails.
    """
    proof = _extract_proof(document)
    _validate_proof_type(proof)
    sig_bytes = _decode_proof_value(proof)

    # Build verification payload: document with proof copy minus proofValue
    proof_copy = {k: v for k, v in proof.items() if k != "proofValue"}
    doc_to_verify: dict[str, object] = {k: v for k, v in document.items() if k != "proof"}
    doc_to_verify["proof"] = proof_copy
    canonical = canonicalize(doc_to_verify)

    try:
        public_key.verify(sig_bytes, canonical)
    except InvalidSignature:
        raise SignatureVerificationError(
            "Ed25519 signature verification failed",
            context={"verificationMethod": proof.get("verificationMethod")},
        ) from None


def _extract_proof(document: dict[str, object]) -> dict[str, object]:
    """Extract and validate proof dict from document."""
    proof = document.get("proof")
    if not isinstance(proof, dict):
        raise ProofError(
            "Document missing 'proof' field or proof is not an object",
            context={"has_proof": "proof" in document},
        )
    return proof


def _validate_proof_type(proof: dict[str, object]) -> None:
    """Validate proof type is Ed25519Signature2020 (FR-PROOF-05)."""
    ptype = proof.get("type")
    if ptype != PROOF_TYPE:
        raise UnsupportedProofTypeError(
            f"Expected proof type '{PROOF_TYPE}', got '{ptype}'",
            context={"type": str(ptype)},
        )


def _decode_proof_value(proof: dict[str, object]) -> bytes:
    """Decode and validate proofValue (FR-PROOF-06)."""
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
