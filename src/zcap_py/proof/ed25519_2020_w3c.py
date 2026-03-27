"""W3C-compliant Ed25519Signature2020 proof verification (URDNA2015).

Implements the real W3C Ed25519Signature2020 verification algorithm:

1. Extract proof from document, strip signature fields → proof options
2. Inject document's ``@context`` into proof options
3. Remove proof from document → unsigned document
4. URDNA2015-canonicalize proof options and document separately
5. SHA-256 hash each canonical form, concatenate → 64-byte verify_data
6. Ed25519.verify(signature, verify_data, public_key)

Requires the ``jsonld`` optional extra: ``pip install zcap-py[jsonld]``
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature

from zcap_py.exceptions import SignatureVerificationError
from zcap_py.jsonld.canonicalize import urdna2015_canonicalize
from zcap_py.proof.ed25519_2020 import (
    _decode_proof_value,
    _extract_proof,
    _resolve_verification_key,
    _validate_proof_type,
)

_PROOF_SIGNATURE_FIELDS = frozenset({"proofValue", "jws", "signatureValue"})


def verify_document_proof_w3c(document: dict[str, object]) -> None:
    """Verify an Ed25519Signature2020 proof using the W3C URDNA2015 algorithm.

    Unlike ``verify_document_proof()`` (which uses JCS), this function
    implements the spec-compliant verification path:

    - Two separate URDNA2015 canonicalizations (proof options + document)
    - SHA-256 hash of each, concatenated into 64-byte ``verify_data``
    - Ed25519 signature verified against ``verify_data``

    Requires ``pyld``: ``pip install zcap-py[jsonld]``

    Raises:
        ProofError: If proof structure is malformed.
        UnsupportedProofTypeError: If proof type is not Ed25519Signature2020.
        SignatureVerificationError: If signature verification fails.
        CanonicalizationError: If ``pyld`` is not installed or URDNA2015 fails.
    """
    proof = _extract_proof(document)
    _validate_proof_type(proof)
    sig_bytes = _decode_proof_value(proof)
    public_key = _resolve_verification_key(proof)

    # Build proof options: proof minus signature fields, plus document's @context
    proof_options: dict[str, object] = {
        k: v for k, v in proof.items() if k not in _PROOF_SIGNATURE_FIELDS
    }
    if "@context" in document:
        proof_options["@context"] = document["@context"]

    # Build unsigned document: document minus proof
    unsigned_document: dict[str, object] = {k: v for k, v in document.items() if k != "proof"}

    # URDNA2015-canonicalize both
    canon_proof = urdna2015_canonicalize(proof_options)
    canon_doc = urdna2015_canonicalize(unsigned_document)

    # SHA-256 each, concatenate
    proof_hash = hashlib.sha256(canon_proof.encode("utf-8")).digest()
    doc_hash = hashlib.sha256(canon_doc.encode("utf-8")).digest()
    verify_data = proof_hash + doc_hash

    try:
        public_key.verify(sig_bytes, verify_data)
    except InvalidSignature:
        raise SignatureVerificationError(
            "Ed25519 signature verification failed (W3C URDNA2015)",
            context={"verificationMethod": proof.get("verificationMethod")},
        ) from None
