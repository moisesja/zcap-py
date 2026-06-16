"""W3C Ed25519Signature2020 proof signing and verification (URDNA2015).

This is the only proof path in ``zcap-py`` and matches the W3C Data Integrity /
``@digitalbazaar/ed25519-signature-2020`` algorithm so proofs round-trip with
the digitalbazaar ZCAP ecosystem:

1. Build proof options = proof minus signature fields, with the document's
   ``@context`` (used verbatim — this is what digitalbazaar's ``canonizeProof``
   does, and is required for byte-identical canonicalization).
2. Build the unsigned document = document minus ``proof``.
3. URDNA2015-canonicalize proof options and document separately.
4. SHA-256 hash each canonical N-Quads form.
5. ``verify_data = sha256(proofOptions) || sha256(document)`` (proof hash first,
   matching ``jsonld-signatures`` ``createVerifyData``).
6. Ed25519 sign / verify over ``verify_data``.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature

from zcap_py.crypto.multibase import base58btc_encode
from zcap_py.exceptions import ProofError, SignatureVerificationError
from zcap_py.jsonld.canonicalize import urdna2015_canonicalize
from zcap_py.proof._common import (
    _decode_proof_value,
    _extract_proof,
    _resolve_verification_key,
    _validate_proof_type,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_PROOF_SIGNATURE_FIELDS = frozenset({"proofValue", "jws", "signatureValue"})


def _compute_verify_data(
    document_without_proof: dict[str, object],
    proof_options: dict[str, object],
) -> bytes:
    """Return the 64-byte ``verify_data`` a signer signs and a verifier checks.

    ``proof_options`` must already carry the document's ``@context``.
    """
    canon_proof = urdna2015_canonicalize(proof_options)
    canon_doc = urdna2015_canonicalize(document_without_proof)
    proof_hash = hashlib.sha256(canon_proof.encode("utf-8")).digest()
    doc_hash = hashlib.sha256(canon_doc.encode("utf-8")).digest()
    return proof_hash + doc_hash


def _build_proof_options(
    document: dict[str, object],
    proof: dict[str, object],
) -> dict[str, object]:
    """Build canonicalization proof options: proof minus signature fields, with
    the document's ``@context`` injected verbatim.

    Raises:
        ProofError: If the document has no ``@context`` (URDNA2015 of the proof
            options would otherwise drop suite-defined terms).
    """
    if "@context" not in document:
        raise ProofError(
            "Document must have an '@context' for W3C Ed25519Signature2020 proofs",
            context={"keys": sorted(document.keys())},
        )
    proof_options: dict[str, object] = {
        k: v for k, v in proof.items() if k not in _PROOF_SIGNATURE_FIELDS
    }
    proof_options["@context"] = document["@context"]
    return proof_options


def sign_document_proof_w3c(
    document_without_proof: dict[str, object],
    proof_metadata: dict[str, object],
    private_key: Ed25519PrivateKey,
) -> dict[str, object]:
    """Sign ``document_without_proof`` and return the wire-ready signed document.

    ``proof_metadata`` must include the Data Integrity fields (``type``,
    ``created``, ``proofPurpose``, ``verificationMethod``) plus any kind-specific
    fields (``capabilityChain``, ``capability``, ``capabilityAction``,
    ``invocationTarget``). It must NOT include ``proofValue`` — this function
    computes it. The returned document verifies under
    :func:`verify_document_proof_w3c` byte-for-byte.

    Raises:
        ProofError: If the document has no ``@context``.
        CanonicalizationError: If ``pyld`` is unavailable or URDNA2015 fails.
    """
    # Drop any stray ``proof`` so the signed bytes match what a verifier
    # re-canonicalizes (document minus proof); otherwise the result would not
    # round-trip through verify_document_proof_w3c.
    document_body: dict[str, object] = {
        k: v for k, v in document_without_proof.items() if k != "proof"
    }
    proof_options = _build_proof_options(document_body, proof_metadata)
    verify_data = _compute_verify_data(document_body, proof_options)
    signature = private_key.sign(verify_data)
    proof: dict[str, object] = {**proof_metadata, "proofValue": base58btc_encode(signature)}
    return {**document_body, "proof": proof}


def verify_document_proof_w3c(document: dict[str, object]) -> None:
    """Verify an Ed25519Signature2020 proof using the W3C URDNA2015 algorithm.

    Raises:
        ProofError: If proof structure is malformed or ``@context`` is missing.
        UnsupportedProofTypeError: If proof type is not Ed25519Signature2020.
        SignatureVerificationError: If signature verification fails.
        CanonicalizationError: If ``pyld`` is unavailable or URDNA2015 fails.
    """
    proof = _extract_proof(document)
    _validate_proof_type(proof)
    sig_bytes = _decode_proof_value(proof)
    public_key = _resolve_verification_key(proof)

    proof_options = _build_proof_options(document, proof)
    unsigned_document: dict[str, object] = {k: v for k, v in document.items() if k != "proof"}
    verify_data = _compute_verify_data(unsigned_document, proof_options)

    try:
        public_key.verify(sig_bytes, verify_data)
    except InvalidSignature:
        raise SignatureVerificationError(
            "Ed25519 signature verification failed (W3C URDNA2015)",
            context={"verificationMethod": proof.get("verificationMethod")},
        ) from None
