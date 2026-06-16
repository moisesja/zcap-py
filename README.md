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
- W3C `Ed25519Signature2020` proof signing and verification (URDNA2015 + dual SHA-256), interoperable with the `@digitalbazaar/zcap` ecosystem
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

W3C URDNA2015 proof verification works out of the box (`pyld` is a core dependency):

```bash
pip install zcap-py
```

## Quick Start

```python
from zcap_py import (
    generate_ed25519_keypair,
    sign_document_proof_w3c,
    verify_document_proof_w3c,
)

# Generate a did:key keypair
keypair = generate_ed25519_keypair()
print(keypair.did)                  # did:key:z6Mk...
print(keypair.verification_method)  # did:key:z6Mk...#z6Mk...

# Sign a document with a W3C Ed25519Signature2020 (URDNA2015) proof.
# An @context is required so the document can be JSON-LD canonicalized.
document = {
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
signed = sign_document_proof_w3c(document, proof_metadata, keypair.private_key)

# Verify — resolves the public key from proof.verificationMethod automatically
verify_document_proof_w3c(signed)
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
| [`verify_proof_w3c.py`](examples/verify_proof_w3c.py) | W3C URDNA2015 `Ed25519Signature2020` proof verification |
| [`parse_capability.py`](examples/parse_capability.py) | Parse and validate ZCAP-LD capabilities |
| [`parse_invocation.py`](examples/parse_invocation.py) | Parse and validate ZCAP-LD invocations |
| [`error_handling.py`](examples/error_handling.py) | Structured exception handling |

Run any example with:

```bash
uv run python examples/key_generation.py
```

## Requirements

- Python 3.11+
- Runtime dependencies: `cryptography>=41.0`, `multiformats>=0.3.1`, `pyld>=2.0`

## Project Status

This library is in active development, tracking full [W3C ZCAP-LD](https://w3c-ccg.github.io/zcap-spec/) / digitalbazaar compliance. See [`COMPLIANCE.md`](COMPLIANCE.md) for the requirement-by-requirement matrix and open issues.

Proof verification uses the W3C `Ed25519Signature2020` (URDNA2015) algorithm and is believed byte-compatible with the digitalbazaar ecosystem; a cross-implementation known-answer test against a digitalbazaar-generated proof is still pending ([#14](https://github.com/moisesja/zcap-py/issues/14)).

The invocation path is **secure-by-default** as of 0.8.0: invoking a delegated capability requires a verifiable, root-anchored chain ([#12](https://github.com/moisesja/zcap-py/issues/12)), the chain anchor must be a genuine root ([#9](https://github.com/moisesja/zcap-py/issues/9)), and `verify_delegation_chain` enforces absolute expiry ([#20](https://github.com/moisesja/zcap-py/issues/20)). Use `ZcapVerifier` (the authoritative entry point) rather than the low-level `verify_invocation` building block for trust decisions.

> ℹ️ **Remaining interop gap.** The invocation document is still modelled as a bespoke `type:"Invocation"` object rather than the digitalbazaar `capabilityInvocation` Data-Integrity-proof-over-target shape ([#11](https://github.com/moisesja/zcap-py/issues/11)), and the cross-implementation proof KAT ([#14](https://github.com/moisesja/zcap-py/issues/14)) is still pending.

## Reference Specification

- [W3C ZCAP-LD Draft](https://w3c-ccg.github.io/zcap-spec/)
- [DID Core](https://www.w3.org/TR/did-core/)
- [did:key Method](https://w3c-ccg.github.io/did-method-key/)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and guidelines.

## License

[Apache-2.0](LICENSE)
