"""Shared test fixtures and helpers."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from zcap_py.crypto.multibase import base58btc_encode
from zcap_py.jcs.canonicalize import canonicalize
from zcap_py.jsonld.canonicalize import urdna2015_canonicalize

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def make_proof_value(
    document_without_proof: dict[str, object],
    proof_metadata: dict[str, object],
    private_key: Ed25519PrivateKey,
) -> str:
    """Sign a document and return multibase-z proofValue."""
    doc_with_proof_meta: dict[str, object] = {
        **document_without_proof,
        "proof": proof_metadata,
    }
    canonical = canonicalize(doc_with_proof_meta)
    signature = private_key.sign(canonical)
    return base58btc_encode(signature)


def make_signed_document(
    document_without_proof: dict[str, object],
    private_key: Ed25519PrivateKey,
    verification_method: str,
    proof_purpose: str = "capabilityDelegation",
) -> dict[str, object]:
    """Produce a document with a valid Ed25519Signature2020 proof."""
    proof_metadata: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": verification_method,
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": proof_purpose,
    }
    pv = make_proof_value(document_without_proof, proof_metadata, private_key)
    proof: dict[str, object] = {**proof_metadata, "proofValue": pv}
    return {**document_without_proof, "proof": proof}


def make_misbound_document(
    document_without_proof: dict[str, object],
    signing_key: Ed25519PrivateKey,
    claimed_verification_method: str,
    proof_purpose: str = "capabilityDelegation",
) -> dict[str, object]:
    """Produce a document signed by *signing_key* but claiming a
    different identity in ``verificationMethod``.

    This creates the exact attack scenario where the proof's
    verificationMethod DID does NOT match the actual signer.
    """
    proof_metadata: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": claimed_verification_method,
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": proof_purpose,
    }
    pv = make_proof_value(document_without_proof, proof_metadata, signing_key)
    proof: dict[str, object] = {**proof_metadata, "proofValue": pv}
    return {**document_without_proof, "proof": proof}


# ── W3C (URDNA2015) helpers ──


def make_w3c_proof_value(
    document_without_proof: dict[str, object],
    proof_metadata: dict[str, object],
    private_key: Ed25519PrivateKey,
) -> str:
    """Sign a document using the W3C URDNA2015 algorithm and return multibase-z proofValue."""
    # Proof options = proof metadata + document's @context
    proof_options: dict[str, object] = {**proof_metadata}
    if "@context" in document_without_proof:
        proof_options["@context"] = document_without_proof["@context"]

    canon_proof = urdna2015_canonicalize(proof_options)
    canon_doc = urdna2015_canonicalize(document_without_proof)

    proof_hash = hashlib.sha256(canon_proof.encode("utf-8")).digest()
    doc_hash = hashlib.sha256(canon_doc.encode("utf-8")).digest()
    verify_data = proof_hash + doc_hash

    signature = private_key.sign(verify_data)
    return base58btc_encode(signature)


def make_w3c_signed_document(
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
    pv = make_w3c_proof_value(document_without_proof, proof_metadata, private_key)
    proof: dict[str, object] = {**proof_metadata, "proofValue": pv}
    return {**document_without_proof, "proof": proof}


def make_w3c_misbound_document(
    document_without_proof: dict[str, object],
    signing_key: Ed25519PrivateKey,
    claimed_verification_method: str,
    proof_purpose: str = "capabilityDelegation",
) -> dict[str, object]:
    """W3C-signed document where the signer does not match verificationMethod."""
    proof_metadata: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": claimed_verification_method,
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": proof_purpose,
    }
    pv = make_w3c_proof_value(document_without_proof, proof_metadata, signing_key)
    proof: dict[str, object] = {**proof_metadata, "proofValue": pv}
    return {**document_without_proof, "proof": proof}
