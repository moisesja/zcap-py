"""JCS-based Ed25519Signature2020 proof verification (``zcap-dotnet`` interop).

This module verifies Ed25519Signature2020 proofs using JCS (RFC 8785)
canonicalization of the full document+proof payload.  This is **not** the
W3C Ed25519Signature2020 algorithm, which requires URDNA2015
canonicalization and SHA-256 hashing.

For W3C-compliant verification see
:func:`zcap_py.proof.ed25519_2020_w3c.verify_document_proof_w3c`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature

from zcap_py.crypto.multibase import base58btc_decode, base58btc_encode
from zcap_py.did.key import public_key_from_did_key
from zcap_py.exceptions import (
    DidParseError,
    ProofError,
    SignatureVerificationError,
    UnsupportedProofTypeError,
)
from zcap_py.jcs.canonicalize import canonicalize

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

PROOF_TYPE = "Ed25519Signature2020"
ED25519_SIGNATURE_LENGTH = 64


def build_canonical_payload(
    document: dict[str, object],
    proof: dict[str, object],
) -> bytes:
    """Return the JCS canonical bytes a verifier would compute for a given
    ``(document, proof)`` pair.

    Algorithm: copy ``proof`` minus ``proofValue``, merge into ``document``
    (replacing any existing ``proof`` field), JCS-canonicalize per RFC 8785.
    The returned bytes are what a conformant Ed25519Signature2020 signer
    must sign and what any conformant verifier re-canonicalizes from the
    wire body before verifying.

    Caller may pass either the wire document (with ``proof``) or the body
    alone — the existing ``document["proof"]`` is dropped either way.
    """
    proof_minus_pv = {k: v for k, v in proof.items() if k != "proofValue"}
    payload: dict[str, object] = {k: v for k, v in document.items() if k != "proof"}
    payload["proof"] = proof_minus_pv
    return canonicalize(payload)


def sign_document_proof(
    document_without_proof: dict[str, object],
    proof_metadata: dict[str, object],
    private_key: Ed25519PrivateKey,
) -> dict[str, object]:
    """Sign ``document_without_proof`` under ``proof_metadata`` and return the
    wire-ready signed document.

    ``proof_metadata`` must include the standard Data Integrity fields
    (``type``, ``created``, ``proofPurpose``, ``verificationMethod``) plus
    any kind-specific fields (``capabilityChain``, ``capability``,
    ``capabilityAction``, ``invocationTarget``, …). It must NOT include
    ``proofValue`` — this function computes and appends it.

    The returned document verifies under :func:`verify_document_proof`
    byte-for-byte.
    """
    canonical = build_canonical_payload(document_without_proof, proof_metadata)
    signature = private_key.sign(canonical)
    proof: dict[str, object] = {**proof_metadata, "proofValue": base58btc_encode(signature)}
    return {**document_without_proof, "proof": proof}


def verify_document_proof(document: dict[str, object]) -> None:
    """Verify an Ed25519Signature2020 proof using JCS canonicalization.

    This is the JCS-based verification path for ``zcap-dotnet`` interoperability.
    It is **not** the W3C Ed25519Signature2020 algorithm (which uses URDNA2015).
    For W3C-compliant verification, use :func:`verify_document_proof_w3c`.

    Algorithm: extract proof, remove ``proofValue``, merge proof back into
    document, JCS-canonicalize (RFC 8785), Ed25519-verify the canonical bytes.

    Raises:
        ProofError: If proof structure is malformed or verificationMethod
            cannot be resolved.
        UnsupportedProofTypeError: If proof type is not Ed25519Signature2020.
        SignatureVerificationError: If signature verification fails.
    """
    proof = _extract_proof(document)
    _validate_proof_type(proof)
    sig_bytes = _decode_proof_value(proof)
    public_key = _resolve_verification_key(proof)

    canonical = build_canonical_payload(document, proof)

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


def _resolve_verification_key(proof: dict[str, object]) -> Ed25519PublicKey:
    """Resolve the Ed25519 public key from proof.verificationMethod.

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
