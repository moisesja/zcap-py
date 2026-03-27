"""Sign data with a private key and verify with the corresponding public key."""

from zcap_py import SignatureVerificationError, generate_ed25519_keypair, verify_ed25519_signature

keypair = generate_ed25519_keypair()
message = b"grant access to /documents/123"

# Sign with the private key (from cryptography library)
signature = keypair.private_key.sign(message)

# Verify — returns None on success, raises on failure
verify_ed25519_signature(keypair.public_key, signature, message)

# Tampered data raises SignatureVerificationError
try:
    verify_ed25519_signature(keypair.public_key, signature, b"tampered")
except SignatureVerificationError as e:
    print(e.message)  # "Ed25519 signature verification failed"
    print(e.context)  # {"signature_length": 64, "data_length": 8}
