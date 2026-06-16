"""Parse and validate a ZCAP-LD invocation document."""

from zcap_py import (
    ZcapParser,
    generate_ed25519_keypair,
    sign_document_proof_w3c,
)

keypair = generate_ed25519_keypair()

# Build a signed invocation
inv_body = {
    "@context": [
        "https://w3id.org/zcap/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    "id": "urn:example:inv-1",
    "type": "Invocation",
    "capability": "urn:example:root-cap",
    "invocationTarget": "https://api.example.com/docs",
}
proof_metadata = {
    "type": "Ed25519Signature2020",
    "verificationMethod": keypair.verification_method,
    "created": "2026-01-01T00:00:00Z",
    "proofPurpose": "capabilityInvocation",
    "capability": "urn:example:root-cap",
    "capabilityAction": "read",
}
signed_inv = sign_document_proof_w3c(inv_body, proof_metadata, keypair.private_key)

parser = ZcapParser()
inv = parser.parse_invocation(signed_inv)

print(inv.id)  # "urn:example:inv-1"
print(inv.capability)  # "urn:example:root-cap"
print(inv.invocation_target)  # "https://api.example.com/docs"
print(inv.proof.proof_purpose)  # "capabilityInvocation"
print(inv.proof.capability_action)  # "read"
