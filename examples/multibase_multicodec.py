"""Low-level multibase and multicodec encoding utilities."""

from zcap_py import (
    base58btc_decode,
    base58btc_encode,
    decode_ed25519_pub,
    encode_ed25519_pub,
)

# Multibase z (base58btc) round-trip
encoded = base58btc_encode(b"\xed\x01" + b"\x00" * 32)
print(encoded[:2])  # "z6" — 'z' prefix indicates base58btc
raw = base58btc_decode(encoded)

# Multicodec ed25519-pub prefix round-trip
key_bytes = b"\x00" * 32  # 32-byte Ed25519 public key
prefixed = encode_ed25519_pub(key_bytes)
print(prefixed[:2].hex())  # "ed01" — the ed25519-pub multicodec prefix
assert decode_ed25519_pub(prefixed) == key_bytes
