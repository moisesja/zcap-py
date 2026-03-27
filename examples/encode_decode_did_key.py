"""Convert between raw Ed25519 public key bytes and did:key strings."""

from zcap_py import decode_did_key, encode_did_key, generate_ed25519_keypair

keypair = generate_ed25519_keypair()

# Extract raw 32-byte public key from a DID
raw_key = decode_did_key(keypair.did)
print(len(raw_key))  # 32

# Rebuild the DID from raw bytes
did = encode_did_key(raw_key)
assert did == keypair.did
