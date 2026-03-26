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

## Quick Start

```python
from zcap_py import generate_ed25519_keypair, resolve_did_key

# Generate an Ed25519 keypair with did:key identifiers
keypair = generate_ed25519_keypair()
print(keypair.did)                  # did:key:z6Mk...
print(keypair.verification_method)  # did:key:z6Mk...#z6Mk...

# Resolve a did:key to a VerificationMethod (no network I/O)
vm = resolve_did_key(keypair.did)
print(vm.type)        # Ed25519VerificationKey2020
print(vm.controller)  # did:key:z6Mk...
```

## Requirements

- Python 3.11+
- Runtime dependencies: `cryptography>=41.0`, `base58>=2.1`

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
