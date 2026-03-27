"""Verify an Ed25519Signature2020 proof using JCS canonicalization.

This is the JCS-based verification used for zcap-dotnet interop.
"""

from zcap_py import (
    SignatureVerificationError,
    base58btc_encode,
    canonicalize,
    generate_ed25519_keypair,
    verify_document_proof,
)

keypair = generate_ed25519_keypair()

# Build a document with a valid Ed25519Signature2020 proof
document_body = {
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
# Sign: canonicalize the document with proof metadata (minus proofValue), then sign
to_sign = {**document_body, "proof": proof_metadata}
signature = keypair.private_key.sign(canonicalize(to_sign))
proof = {**proof_metadata, "proofValue": base58btc_encode(signature)}
signed_document = {**document_body, "proof": proof}

# Verify — resolves the public key from proof.verificationMethod automatically
verify_document_proof(signed_document)

# Tampered document raises SignatureVerificationError
tampered = {**signed_document, "invocationTarget": "https://evil.example.com"}
tampered["proof"] = signed_document["proof"]
try:
    verify_document_proof(tampered)
except SignatureVerificationError as e:
    print(e.message)  # "Ed25519 signature verification failed"
