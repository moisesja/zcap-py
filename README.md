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
- RFC 8785 / JCS canonicalization
- Ed25519Signature2020 proof verification
- ZCAP-LD document parsing (Capability & Invocation)
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

### JCS Canonicalization

Produce deterministic JSON bytes per [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785):

```python
from zcap_py import canonicalize

doc = {"z": 1, "a": 2, "nested": {"b": True, "a": None}}
canonical = canonicalize(doc)

print(canonical)        # b'{"a":2,"nested":{"a":null,"b":true},"z":1}'
print(type(canonical))  # <class 'bytes'>
```

### Verifying a Document Proof

Verify an Ed25519Signature2020 proof on any JSON-LD document:

```python
from zcap_py import generate_ed25519_keypair, verify_document_proof, SignatureVerificationError
from zcap_py import canonicalize, base58btc_encode

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
```

### Parsing a Capability

Parse and validate a ZCAP-LD capability document:

```python
from zcap_py import ZcapParser, ZcapParseError

parser = ZcapParser()

# Parse a root capability (no parent, no proof required)
raw_cap = {
    "id": "urn:example:root-cap",
    "type": "Authorization",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "invocationTarget": "https://api.example.com/docs",
    "allowedAction": ["read", "write"],
}
cap = parser.parse_capability(raw_cap)

print(cap.id)                # "urn:example:root-cap"
print(cap.controller)        # "did:key:z6Mk..."
print(cap.allowed_action)    # ["read", "write"]
print(cap.is_root)           # True
print(cap.parent_capability) # None
print(cap.expires)           # None

# Parse from a JSON string
import json
cap2 = parser.parse_capability_from_json(json.dumps(raw_cap))
assert cap2.id == cap.id

# Invalid documents raise ZcapParseError with the offending field
try:
    parser.parse_capability({"id": "", "type": "Authorization"})
except ZcapParseError as e:
    print(e.message)  # "Missing or invalid field 'id'"
    print(e.field)    # "id"
```

### Parsing an Invocation

Parse and validate a ZCAP-LD invocation document:

```python
from zcap_py import (
    ZcapParser, generate_ed25519_keypair,
    canonicalize, base58btc_encode,
)

keypair = generate_ed25519_keypair()

# Build a signed invocation
inv_body = {
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
to_sign = {**inv_body, "proof": proof_metadata}
signature = keypair.private_key.sign(canonicalize(to_sign))
proof = {**proof_metadata, "proofValue": base58btc_encode(signature)}
signed_inv = {**inv_body, "proof": proof}

parser = ZcapParser()
inv = parser.parse_invocation(signed_inv)

print(inv.id)                        # "urn:example:inv-1"
print(inv.capability)                # "urn:example:root-cap"
print(inv.invocation_target)         # "https://api.example.com/docs"
print(inv.proof.proof_purpose)       # "capabilityInvocation"
print(inv.proof.capability_action)   # "read"
```

### Error Handling

All exceptions inherit from `ZcapError` and carry structured context:

```python
from zcap_py import (
    ZcapError, DidParseError, ZcapParseError,
    ProofError, UnsupportedProofTypeError,
    SignatureVerificationError, CanonicalizationError,
    decode_did_key,
)

try:
    decode_did_key("not-a-did")
except DidParseError as e:
    print(e.message)  # Human-readable message
    print(e.context)  # {"did": "not-a-did"} — structured data for logging

# ZcapParseError includes the offending field name
from zcap_py import ZcapParser
try:
    ZcapParser().parse_capability({"type": "Authorization"})
except ZcapParseError as e:
    print(e.field)    # "id"
    print(e.message)  # "Missing or invalid field 'id'"

# Catch all library errors at once
try:
    decode_did_key("not-a-did")
except ZcapError:
    print("Something went wrong with ZCAP processing")
```

## Requirements

- Python 3.11+
- Runtime dependencies: `cryptography>=41.0`, `multiformats>=0.3.1`, `rfc8785>=0.1.4`

## Project Status

This library is in active development. Phase 1 (crypto & DID foundation) and Phase 2 (JCS canonicalization, proof verification, document parsing) are complete. Upcoming phases will add delegation chain verification, invocation verification, and async support.

## Reference Specification

- [W3C ZCAP-LD Draft](https://w3c-ccg.github.io/zcap-spec/)
- [DID Core](https://www.w3.org/TR/did-core/)
- [did:key Method](https://w3c-ccg.github.io/did-method-key/)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and guidelines.

## License

[Apache-2.0](LICENSE)
