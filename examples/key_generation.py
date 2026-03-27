"""Generate an Ed25519 keypair with did:key identifiers."""

from zcap_py import generate_ed25519_keypair

keypair = generate_ed25519_keypair()

print(keypair.did)  # did:key:z6Mk...
print(keypair.verification_method)  # did:key:z6Mk...#z6Mk...
print(type(keypair.private_key))  # Ed25519PrivateKey
print(type(keypair.public_key))  # Ed25519PublicKey
