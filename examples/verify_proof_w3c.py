"""Verify an Ed25519Signature2020 proof using the W3C URDNA2015 algorithm.

This is the spec-compliant W3C verification path.
Requires: pip install zcap-py[jsonld]
"""

import hashlib

from zcap_py import (
    SignatureVerificationError,
    base58btc_encode,
    generate_ed25519_keypair,
    verify_document_proof_w3c,
)
from zcap_py.jsonld.canonicalize import urdna2015_canonicalize

keypair = generate_ed25519_keypair()

# Document must include @context for URDNA2015 canonicalization
document_body = {
    "@context": [
        "https://w3id.org/zcap/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    "id": "urn:example:cap-1",
    "type": "Authorization",
    "controller": keypair.did,
    "invocationTarget": "https://api.example.com/docs",
    "allowedAction": ["read"],
}
proof_metadata = {
    "type": "Ed25519Signature2020",
    "verificationMethod": keypair.verification_method,
    "created": "2026-01-01T00:00:00Z",
    "proofPurpose": "capabilityDelegation",
}

# W3C signing: URDNA2015-canonicalize proof options and document separately,
# SHA-256 hash each, concatenate, then Ed25519-sign the 64-byte result
proof_options = {**proof_metadata, "@context": document_body["@context"]}
canon_proof = urdna2015_canonicalize(proof_options)
canon_doc = urdna2015_canonicalize(document_body)
verify_data = (
    hashlib.sha256(canon_proof.encode()).digest() + hashlib.sha256(canon_doc.encode()).digest()
)
signature = keypair.private_key.sign(verify_data)

proof = {**proof_metadata, "proofValue": base58btc_encode(signature)}
signed_document = {**document_body, "proof": proof}

# Verify — uses URDNA2015 canonicalization internally
verify_document_proof_w3c(signed_document)

# Tampered document raises SignatureVerificationError
tampered = {**signed_document, "invocationTarget": "https://evil.example.com"}
tampered["proof"] = signed_document["proof"]
try:
    verify_document_proof_w3c(tampered)
except SignatureVerificationError as e:
    print(e.message)  # "Ed25519 signature verification failed (W3C URDNA2015)"
