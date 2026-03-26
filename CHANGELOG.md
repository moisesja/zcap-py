# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Released]

## [0.2.0] - 2026-03-26

### Added

- **JCS Canonicalization**: `canonicalize()` wrapper around RFC 8785 / JCS via the `rfc8785` library — produces deterministic JSON bytes for signature payloads
- **Proof Verification**: `verify_document_proof()` implementing Ed25519Signature2020 per FR-PROOF-02 — extracts proof, strips `proofValue`, merges proof metadata back into document, JCS-canonicalizes, and verifies Ed25519 signature
- **Proof Model**: `LinkedDataProof` frozen dataclass with `type`, `verification_method`, `created`, `proof_value`, `capability`, `capability_action`, and `proof_purpose` fields
- **ZCAP Document Models**: `Capability` and `Invocation` frozen dataclasses
  - `Capability.is_root` property (True when `parent_capability` is None)
  - `Capability` supports optional fields: `expires`, `invoker`, `caveat`, `proof`, `parent_capability`
  - `Invocation` requires `proof` (mandatory per FR-PARSE-06)
- **Document Parser**: `ZcapParser` stateless class with full field validation per FR-PARSE-05
  - `parse_capability()`, `parse_invocation()` from raw dicts
  - `parse_capability_from_json()`, `parse_invocation_from_json()` from JSON strings
  - `is_root()` static method
  - Proof sub-field validation: type, verificationMethod (valid DID URL), created (ISO 8601), proofValue (multibase-z, 64-byte Ed25519 signature)
  - All parse errors carry `field` attribute for programmatic error handling (FR-PARSE-09)
- New dependency: `rfc8785>=0.1.4` (zero-dep, Apache 2.0, Trail of Bits)

## [0.1.1] - 2026-03-26

### Fixed

- `resolve_did_key()` now validates DID URLs via `parse_did_url()` instead of silently stripping fragments — malformed or mismatched fragments raise `DidParseError`

## [0.1.0] - 2026-03-26

### Added

- Full `ZcapError` exception hierarchy with structured context and field-level error tracking
- Multibase z (base58btc) encode/decode (`base58btc_encode`, `base58btc_decode`)
- Ed25519 multicodec (0xed01) prefix handling (`encode_ed25519_pub`, `decode_ed25519_pub`)
- Ed25519 key generation and signature verification (`generate_ed25519_keypair`, `verify_ed25519_signature`)
- `DidKeyPair` frozen dataclass with `did:key` identifiers
- DID URL strict parsing and validation (`parse_did`, `parse_did_url`)
- `did:key` encode/decode/resolve for Ed25519 keys (`encode_did_key`, `decode_did_key`, `resolve_did_key`)
- `VerificationMethod` frozen dataclass
- PEP 561 `py.typed` marker for type checker support
- Project scaffolding with `uv`, `src/` layout, `hatchling` build backend
- GitHub Actions CI workflow (lint, type-check, test matrix across Python 3.11-3.13)
- GitHub Actions publish workflow (PyPI OIDC trusted publisher)
- Open-source community documents (CODE_OF_CONDUCT, SECURITY, SUPPORT, CONTRIBUTING)
- GitHub issue and pull request templates
