"""Sign and verify an Ed25519Signature2020 proof using the W3C URDNA2015 algorithm.

This is the spec-compliant W3C path — interoperable with the digitalbazaar ZCAP
ecosystem. ``pyld`` is a core dependency, so this works out of the box.
"""

from zcap_py import (
    SignatureVerificationError,
    generate_ed25519_keypair,
    sign_document_proof_w3c,
    verify_document_proof_w3c,
)

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
# SHA-256 hash each, concatenate (proofHash || docHash), Ed25519-sign.
signed_document = sign_document_proof_w3c(document_body, proof_metadata, keypair.private_key)

# Verify — uses URDNA2015 canonicalization internally
verify_document_proof_w3c(signed_document)

# Tampered document raises SignatureVerificationError
tampered = {**signed_document, "invocationTarget": "https://evil.example.com"}
tampered["proof"] = signed_document["proof"]
try:
    verify_document_proof_w3c(tampered)
except SignatureVerificationError as e:
    print(e.message)  # "Ed25519 signature verification failed (W3C URDNA2015)"
