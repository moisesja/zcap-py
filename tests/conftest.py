"""Shared test fixtures and helpers.

All signing helpers produce W3C Ed25519Signature2020 (URDNA2015) proofs — the
only proof path in zcap-py. The legacy ``make_*`` names are kept for existing
call sites; the ``make_w3c_*`` aliases remain for explicitness.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from zcap_py.proof.ed25519_2020_w3c import sign_document_proof_w3c

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def make_signed_document(
    document_without_proof: dict[str, object],
    private_key: Ed25519PrivateKey,
    verification_method: str,
    proof_purpose: str = "capabilityDelegation",
) -> dict[str, object]:
    """Produce a document with a valid W3C Ed25519Signature2020 proof (URDNA2015)."""
    proof_metadata: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": verification_method,
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": proof_purpose,
    }
    return sign_document_proof_w3c(document_without_proof, proof_metadata, private_key)


def make_proof_value(
    document_without_proof: dict[str, object],
    proof_metadata: dict[str, object],
    private_key: Ed25519PrivateKey,
) -> str:
    """Sign a document and return its multibase-z proofValue."""
    signed = sign_document_proof_w3c(document_without_proof, proof_metadata, private_key)
    proof = signed["proof"]
    assert isinstance(proof, dict)
    return str(proof["proofValue"])


def make_misbound_document(
    document_without_proof: dict[str, object],
    signing_key: Ed25519PrivateKey,
    claimed_verification_method: str,
    proof_purpose: str = "capabilityDelegation",
) -> dict[str, object]:
    """Produce a document signed by *signing_key* but claiming a different
    identity in ``verificationMethod`` — the exact verificationMethod-mismatch
    attack scenario.
    """
    proof_metadata: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": claimed_verification_method,
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": proof_purpose,
    }
    # Signed by signing_key but proof claims a different verificationMethod.
    return sign_document_proof_w3c(document_without_proof, proof_metadata, signing_key)


# ── Explicit W3C aliases (same algorithm; kept for readability in newer tests) ──

make_w3c_signed_document = make_signed_document
make_w3c_proof_value = make_proof_value
make_w3c_misbound_document = make_misbound_document
