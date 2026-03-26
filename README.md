# zcap-py

[![CI](https://github.com/moisesja/zcap-py/actions/workflows/ci.yml/badge.svg)](https://github.com/moisesja/zcap-py/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/zcap-py)](https://pypi.org/project/zcap-py/)
[![Python](https://img.shields.io/pypi/pyversions/zcap-py)](https://pypi.org/project/zcap-py/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Authorization Capabilities for Linked Data — Python verification library.**

A minimal, production-quality Python library implementing the [W3C Authorization Capabilities for Linked Data (ZCAP-LD)](https://w3c-ccg.github.io/zcap-spec/) draft specification. This is the Python counterpart to [`zcap-dotnet`](https://github.com/moisesja/zcap-dotnet).

## Features

- Ed25519 key generation and signature verification
- `did:key` encoding, decoding, and resolution (Ed25519 only)
- Multibase-z (base58btc) and multicodec support
- Strict DID URL parsing and validation
- Typed exception hierarchy for controlled error handling
- 100% type-annotated public API (`mypy --strict` compliant)
- Zero network I/O in core — fully offline verification

## Installation

```bash
pip install zcap-py
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv add zcap-py
```

## Examples

### Key Generation

Generate an Ed25519 keypair with `did:key` identifiers:

```python
from zcap_py import generate_ed25519_keypair

keypair = generate_ed25519_keypair()

print(keypair.did)                  # did:key:z6Mk...
print(keypair.verification_method)  # did:key:z6Mk...#z6Mk...
print(type(keypair.private_key))    # Ed25519PrivateKey
print(type(keypair.public_key))     # Ed25519PublicKey
```

### Signing and Verifying Messages

Sign data with a private key and verify with the corresponding public key:

```python
from zcap_py import generate_ed25519_keypair, verify_ed25519_signature, SignatureVerificationError

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
    print(e.message)   # "Ed25519 signature verification failed"
    print(e.context)   # {"signature_length": 64, "data_length": 8}
```

### Resolving a `did:key` to a Verification Method

Resolve a DID to its verification method — entirely offline, no network I/O:

```python
from zcap_py import resolve_did_key

vm = resolve_did_key("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

print(vm.id)                    # did:key:z6Mk...#z6Mk...
print(vm.type)                  # Ed25519VerificationKey2020
print(vm.controller)            # did:key:z6Mk...
print(vm.public_key_multibase)  # z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

### Encoding and Decoding `did:key` DIDs

Convert between raw Ed25519 public key bytes and `did:key` strings:

```python
from zcap_py import encode_did_key, decode_did_key, generate_ed25519_keypair

keypair = generate_ed25519_keypair()

# Extract raw 32-byte public key from a DID
raw_key = decode_did_key(keypair.did)
print(len(raw_key))  # 32

# Rebuild the DID from raw bytes
did = encode_did_key(raw_key)
assert did == keypair.did
```

### Parsing DID URLs

Strict validation of `did:key` DIDs and DID URLs:

```python
from zcap_py import parse_did, parse_did_url, strip_did_fragment, DidParseError

# Parse a bare DID
parsed = parse_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
print(parsed.method)      # "key"
print(parsed.identifier)  # "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

# Parse a DID URL (with fragment) — validates fragment matches the identifier
did_url = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
parsed_url = parse_did_url(did_url)
print(parsed_url.fragment)    # "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
print(parsed_url.did.method)  # "key"

# Strip the fragment from a DID URL
bare = strip_did_fragment(did_url)
print(bare)  # "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

# Invalid DIDs raise DidParseError
try:
    parse_did("did:web:example.com")
except DidParseError as e:
    print(e.message)  # "Invalid did:key DID: 'did:web:example.com'"
```

### Multibase and Multicodec Utilities

Low-level encoding utilities for building custom flows:

```python
from zcap_py import (
    base58btc_encode, base58btc_decode,
    encode_ed25519_pub, decode_ed25519_pub,
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
```

### Error Handling

All exceptions inherit from `ZcapError` and carry structured context:

```python
from zcap_py import ZcapError, DidParseError, SignatureVerificationError, decode_did_key

try:
    decode_did_key("not-a-did")
except DidParseError as e:
    print(e.message)             # Human-readable message
    print(e.context)             # {"did": "not-a-did"} — structured data for logging

# Catch all library errors at once
try:
    decode_did_key("not-a-did")
except ZcapError:
    print("Something went wrong with ZCAP processing")
```

## Requirements

- Python 3.11+
- Runtime dependencies: `cryptography>=41.0`, `multiformats>=0.3.1`

## Project Status

This library is in active development. Phase 1 (crypto & DID foundation) is complete. Upcoming phases will add JCS canonicalization, proof verification, delegation chain verification, invocation verification, and async support.

## Reference Specification

- [W3C ZCAP-LD Draft](https://w3c-ccg.github.io/zcap-spec/)
- [DID Core](https://www.w3.org/TR/did-core/)
- [did:key Method](https://w3c-ccg.github.io/did-method-key/)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and guidelines.

## License

[Apache-2.0](LICENSE)
