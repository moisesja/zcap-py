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
- Ed25519Signature2020 proof verification (JCS-based for `zcap-dotnet` interop)
- W3C-compliant Ed25519Signature2020 proof verification (URDNA2015, optional `pyld` dependency)
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

For W3C-compliant URDNA2015 proof verification, install with the `jsonld` extra:

```bash
pip install zcap-py[jsonld]
```

## Quick Start

```python
from zcap_py import generate_ed25519_keypair, verify_document_proof
from zcap_py import canonicalize, base58btc_encode

# Generate a did:key keypair
keypair = generate_ed25519_keypair()
print(keypair.did)                  # did:key:z6Mk...
print(keypair.verification_method)  # did:key:z6Mk...#z6Mk...

# Sign a document with an Ed25519Signature2020 proof
document = {
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
to_sign = {**document, "proof": proof_metadata}
signature = keypair.private_key.sign(canonicalize(to_sign))
signed = {**document, "proof": {**proof_metadata, "proofValue": base58btc_encode(signature)}}

# Verify — resolves the public key from proof.verificationMethod automatically
verify_document_proof(signed)
```

## Examples

Runnable examples are in the [`examples/`](examples/) directory:

| Example | Description |
|---------|-------------|
| [`key_generation.py`](examples/key_generation.py) | Generate Ed25519 keypairs with `did:key` identifiers |
| [`sign_and_verify.py`](examples/sign_and_verify.py) | Sign and verify raw messages |
| [`resolve_did_key.py`](examples/resolve_did_key.py) | Resolve a `did:key` to a verification method |
| [`encode_decode_did_key.py`](examples/encode_decode_did_key.py) | Convert between raw key bytes and `did:key` strings |
| [`parse_did_url.py`](examples/parse_did_url.py) | Strict DID and DID URL parsing |
| [`multibase_multicodec.py`](examples/multibase_multicodec.py) | Low-level multibase/multicodec utilities |
| [`jcs_canonicalization.py`](examples/jcs_canonicalization.py) | RFC 8785 / JCS canonicalization |
| [`verify_proof_jcs.py`](examples/verify_proof_jcs.py) | JCS-based proof verification (`zcap-dotnet` interop) |
| [`verify_proof_w3c.py`](examples/verify_proof_w3c.py) | W3C URDNA2015 proof verification (requires `pyld`) |
| [`parse_capability.py`](examples/parse_capability.py) | Parse and validate ZCAP-LD capabilities |
| [`parse_invocation.py`](examples/parse_invocation.py) | Parse and validate ZCAP-LD invocations |
| [`error_handling.py`](examples/error_handling.py) | Structured exception handling |

Run any example with:

```bash
uv run python examples/key_generation.py
```

## Requirements

- Python 3.11+
- Runtime dependencies: `cryptography>=41.0`, `multiformats>=0.3.1`, `rfc8785>=0.1.4`
- Optional: `pyld>=2.0` (for W3C URDNA2015 proof verification — install with `pip install zcap-py[jsonld]`)

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
