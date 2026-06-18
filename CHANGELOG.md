# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Released]

## [0.8.0] - 2026-06-16

W3C / digitalbazaar compliance — phase 2 (P0 invocation security). Makes the
invocation path **secure-by-default**. Tracked by [COMPLIANCE.md](COMPLIANCE.md)
and issues [#9](https://github.com/moisesja/zcap-py/issues/9) /
[#12](https://github.com/moisesja/zcap-py/issues/12) /
[#20](https://github.com/moisesja/zcap-py/issues/20).

### Security (BREAKING)

- **Invoking a delegated capability now REQUIRES a verifiable, root-anchored chain** (issue [#12](https://github.com/moisesja/zcap-py/issues/12)). Previously `ZcapVerifier.verify_invocation(invocation, capability)` with no chain verified only the invocation signature, so a forged/unanchored delegated capability was accepted as long as the invocation was signed by its stated controller. Now a non-root capability without a chain (provided or resolvable from `proof.capabilityChain`) raises `InvocationError`. Only a **root** capability may be invoked directly.
- **The delegation-chain anchor must be structurally a root, and an embedded root in invoker-supplied `proof.capabilityChain` is rejected** (issue [#9](https://github.com/moisesja/zcap-py/issues/9)). `verify_invocation` asserts `chain[0].is_root`, and a chain auto-resolved from `proof.capabilityChain` must reference the root **by id** (resolved via the trusted `document_loader`) — an embedded root dict is rejected, closing the forged-root bypass on the auto-resolve path. New optional `expected_root_id` keyword pins `chain[0].id`. **Note:** `expected_root_id` only compares the (public) id and does not validate the root's controller/target; a root passed in an explicit `chain=` is trusted by design (the root is the trust anchor — supply it from a trusted store). Making a trusted-root dereference mandatory (target-derived id + controller binding) remains tracked in #9.
- **Absolute expiry is enforced in `verify_delegation_chain`** (issue [#20](https://github.com/moisesja/zcap-py/issues/20)). The standalone function now checks every capability (root + delegations) against a `clock` (default `now`), so it is fail-closed rather than relying on the `ZcapVerifier` facade. New optional `clock` keyword on `verify_delegation_chain`.

### Security (adversarial red-team hardening)

Findings from a PoC-driven adversarial review (independently reproduced); see [COMPLIANCE.md](COMPLIANCE.md).

- **Authorization hijack fixed** (issue [#32](https://github.com/moisesja/zcap-py/issues/32), CRITICAL). `verify_invocation` verified the chain but enforced authorization (target/invoker/action/caveat) against the caller-supplied/**embedded** capability, reconciled to the verified chain only by `id` string equality — letting an attacker pair a genuine victim-signed chain with a same-`id` self-signed capability of escalated authority. Authorization is now **bound to the cryptographically verified chain leaf** (`chain[-1]`), never the supplied/embedded object.
- **Action-attenuation omission fixed** (issue [#33](https://github.com/moisesja/zcap-py/issues/33), CRITICAL). A delegated child that **omitted `allowedAction`** was treated as all-actions. `verify_delegation_chain` now tracks the **effective** allowed-action set (intersection along the chain; absent = inherit) and rejects broadening; `verify_invocation` enforces `capabilityAction` against it. New `effective_allowed_actions` helper.
- **Target dot-segment escape fixed** (issue [#26](https://github.com/moisesja/zcap-py/issues/26)). `PathPrefixAttenuator` now percent-decodes and RFC-3986 dot-segment-normalizes paths before the prefix check, so `/data/../admin` / `%2F..%2F` cannot escape the granted subtree.
- **Error-contract hardening** (issue [#34](https://github.com/moisesja/zcap-py/issues/34)). Malicious documents now raise only `ZcapError` subclasses (previously unhandled `TypeError`/`AttributeError`/`KeyError`/`UnicodeEncodeError` — unauthenticated DoS): timezone-naive `expires`/`created` are rejected (`ZcapParseError`); `document_loader` failures/None/non-dict become `InvocationError`; surrogate/UTF-8 encode errors become `CanonicalizationError`; a non-dict document to `verify_document_proof_w3c` raises `ProofError`.
- **Proof metadata coverage** — `verify_document_proof_w3c` / `sign_document_proof_w3c` now require the document `@context` to include the `ed25519-2020` suite context, so `proof.created` / `proofPurpose` / `type` are covered by the signature (previously droppable via a bare zcap-only `@context`).

### Breaking-change summary (for upgraders)

- Delegated-capability invocation now **requires** a verifiable root-anchored chain (#12).
- A chain auto-resolved from `proof.capabilityChain` must reference the **root by id**, not embed it (#9); pass an explicit `chain=` to use a caller-held root.
- `expires` / `proof.created` must be **timezone-aware** (a naive value now raises `ZcapParseError`).
- A signed document's `@context` must include the **`ed25519-2020` suite context**.

### Changed

- `ZcapVerifier.verify_invocation` gains an `expected_root_id: str | None = None` keyword.
- `verify_delegation_chain` gains a `clock: Callable[[], datetime] | None = None` keyword and raises `CapabilityExpiredError` for an expired capability.
- The low-level `zcap_py.zcap.invocation.verify_invocation` is now documented as an **internal building block** — it does not check the delegation chain, trust anchor, or absolute expiry; use `ZcapVerifier` for trust decisions.
- `.claude/settings.json` / `.claude/settings.local.json` are now git-ignored (a machine-specific copy was committed by accident during the red-team session and has been removed).

### Not yet addressed (tracked)

- **#9** — the forged-root bypass on the **auto-resolved** chain path is closed (embedded root rejected; root resolved via trusted loader). The residual: a root passed in an explicit `chain=` is trusted by design, and `expected_root_id` validates only the id — a mandatory trusted-root dereference (target-derived `urn:zcap:root:<encoded-target>` + controller binding) is still to be implemented.
- **#35 (HIGH)** — caveat *parameter* contents and out-of-context application fields are not covered by the DI signature (URDNA2015 drops out-of-context terms); needs a signed-terms boundary (caveat-as-`@json` / context terms / documented contract).
- #11 (replace `type:"Invocation"` with the digitalbazaar `capabilityInvocation` Data-Integrity-proof-over-target model) — separate breaking-interop branch.
- #24 replay protection (no nonce/freshness); #21 `document_loader` SSRF input-validation; #14 digitalbazaar cross-implementation known-answer test; remaining P1/P2 items.

## [0.7.0] - 2026-06-16

W3C / digitalbazaar compliance — phase 1 (P0/P1 high-priority). Tracked by the
[compliance matrix](COMPLIANCE.md) and issues [#9–#29](https://github.com/moisesja/zcap-py/issues).

### Changed (BREAKING)

- **W3C URDNA2015 `Ed25519Signature2020` is now the only proof path** (issue [#13](https://github.com/moisesja/zcap-py/issues/13)). `ZcapVerifier`, `verify_delegation_chain()`, and `verify_invocation()` default to `verify_document_proof_w3c`; the JCS (RFC 8785) path is **removed entirely**. JCS-signed documents no longer verify. This is the change intended to make proofs interoperate with `@digitalbazaar/zcap` / `@digitalbazaar/ed25519-signature-2020` — byte-parity is **believed** (verified by code inspection + self-consistent round-trip) but **not yet proven** against a digitalbazaar-generated proof; see [#14](https://github.com/moisesja/zcap-py/issues/14).
- **`pyld>=2.0` is now a core dependency** (was the optional `jsonld` extra); `rfc8785` is dropped. The `jsonld` extra is removed — `pip install zcap-py[jsonld]` now emits an "extra not provided" warning, so update install scripts to plain `zcap-py`.
- **`expires` is now REQUIRED on delegated capabilities** (issue [#10](https://github.com/moisesja/zcap-py/issues/10)). `ZcapParser.parse_capability()` raises `ZcapParseError` for a delegated capability with no `expires`. Root capabilities remain `expires`-free.

### Added

- **Public W3C signer** `sign_document_proof_w3c(document_without_proof, proof_metadata, private_key) -> dict` (issue [#14](https://github.com/moisesja/zcap-py/issues/14)) in `zcap_py.proof.ed25519_2020_w3c`, re-exported from `zcap_py`. Builds proof options from the document's `@context` (verbatim, for digitalbazaar byte-parity), URDNA2015-canonicalizes proof options and document, `verify_data = sha256(proofOptions) || sha256(document)`, Ed25519-signs. Round-trips with `verify_document_proof_w3c` and is believed byte-compatible with `@digitalbazaar/ed25519-signature-2020` (cross-impl KAT pending, [#14](https://github.com/moisesja/zcap-py/issues/14)). Both sign and verify now require the document to carry an `@context` (`ProofError` otherwise); the signer also strips any stray `proof` key so its output always round-trips.
- **Configurable `max_chain_length`** (default 10) on `ZcapVerifier` and `verify_delegation_chain()` (issue [#22](https://github.com/moisesja/zcap-py/issues/22)). A chain whose total length (root + delegations) exceeds the limit raises `ChainVerificationError` **before** any cryptographic work — long-chain / DoS mitigation matching `@digitalbazaar/zcap`.
- `COMPLIANCE.md` — full ZCAP-LD compliance matrix (84 requirements) with `file:line` evidence and per-gap issue links, plus a `zcap-dotnet` mirror section.
- `src/zcap_py/proof/_common.py` — suite-neutral proof helpers (`_extract_proof`, `_validate_proof_type`, `_decode_proof_value`, `_resolve_verification_key`) shared by the W3C path; relocated out of the deleted JCS module.

### Removed

- `src/zcap_py/proof/ed25519_2020.py` (JCS verify/sign/`build_canonical_payload`) and the `zcap_py.jcs` package.
- Public exports `canonicalize`, `build_canonical_payload`, `sign_document_proof`, `verify_document_proof` (JCS).
- JCS tests/examples (`test_jcs.py`, `test_proof.py`, `test_cross_language_interop.py`, `test_public_proof_api.py`; `examples/{verify_proof_jcs,jcs_canonicalization,generate_cross_lang_fixture}.py`) and the `tests/fixtures/cross_lang_jcs/` vectors. Superseded GitHub issues #5 and #8 closed.

### Not yet addressed (tracked, next phases)

- ⚠️ **The invocation path is not yet secure-by-default.** Until [#9](https://github.com/moisesja/zcap-py/issues/9) and [#12](https://github.com/moisesja/zcap-py/issues/12) land, `verify_invocation` does not require the invoked delegated capability to be anchored to a cryptographically verified chain, and standalone `verify_delegation_chain` does no absolute-expiry check ([#20](https://github.com/moisesja/zcap-py/issues/20)). Always pass and verify a full, root-anchored `chain`; do not rely on `verify_invocation` alone for trust decisions.
- Chain trust-anchor / `is_root` binding (#9), invocation requires verified chain (#12), invocation Data Integrity model vs `type:"Invocation"` (#11), fail-open expiry/caveats in the low-level path (#20), and the remaining P1/P2 items (#15–#29).
- A digitalbazaar cross-implementation known-answer test for #14 is still pending (requires a Node-generated fixture).

## [0.6.0] - 2026-05-04

### Added

- **Public W3C-flat payload helper + signing API** (issue [#6](https://github.com/moisesja/zcap-py/issues/6)): `build_canonical_payload(document, proof) -> bytes` returns the JCS canonical bytes any conformant Ed25519Signature2020 verifier would re-compute for a given `(document, proof)` pair (proof copy minus `proofValue`, merged into document, JCS-canonicalized per RFC 8785). `sign_document_proof(document_without_proof, proof_metadata, private_key) -> dict` signs and returns the wire-ready document — round-trips through `verify_document_proof` byte-for-byte. Both functions live in `zcap_py.proof.ed25519_2020` and are re-exported from the top-level `zcap_py` package. Symmetric with `zcap-dotnet 2.1.0`'s `ProofSigningPayloadBuilder`; closes the public-surface gap that forced `zcap-interop-fixtures` and downstream signers to copy-paste the assembly.
- `tests/test_public_proof_api.py` — three cases pinning the contract: `proofValue` is stripped, supplied `proof` argument overrides any `document["proof"]`, and signed documents verify byte-for-byte through the verifier.
- **Cross-language JCS interop fixture + regression test** (issue [#5](https://github.com/moisesja/zcap-py/issues/5)): `tests/fixtures/cross_lang_jcs/{capability_v1,invocation_v1}.json` — known-answer test vectors covering a delegated `Capability` (with `caveat[]`, `parentCapability`, `expires`, populated `capabilityChain`) and an `Invocation`. Each fixture pins the Ed25519 seed, signed wire-format document, and SHA-256 of the JCS canonical bytes that went into `private_key.sign(...)`. Proofs include an extra `nonce` field so the regression catches future field-stripping divergence.
- `tests/test_cross_language_interop.py` — four parametrized cases that assert (a) the JCS canonical bytes hash to the fixture's `jcs_sha256_hex`, and (b) the signature verifies under `verify_document_proof`. A failure pinpoints whether the bytes diverged or the algorithm side disagrees.
- `examples/generate_cross_lang_fixture.py` — reproducible generator that re-emits both fixtures byte-for-byte from committed inputs (deterministic seed + timestamps). Companion to [moisesja/zcap-dotnet#34](https://github.com/moisesja/zcap-dotnet/issues/34); zcap-dotnet's test re-derives the canonical bytes during its own run and asserts the SHA-256 matches.

### Changed

- `verify_document_proof` (`src/zcap_py/proof/ed25519_2020.py`): the inlined "copy proof minus `proofValue`, merge into document, JCS-canonicalize" assembly is now a single call to the new public `build_canonical_payload`. Behaviour and wire bytes are unchanged (verified by re-generating issue #5 fixtures and confirming SHA-256 stability).
- `tests/conftest.py` helpers (`make_proof_value`, `make_signed_document`, `make_misbound_document`) are now thin shims over the public `sign_document_proof`; signatures preserved so existing test modules are untouched.
- `examples/generate_cross_lang_fixture.py` now demonstrates the public API by calling `build_canonical_payload` and `sign_document_proof` directly instead of inlining the assembly.

## [0.5.0] - 2026-03-26

### Added

- **Proof Dispatcher** (`verifier.py`): `ProofVerifier` type alias and `proof_verifier` parameter on `ZcapVerifier`, `verify_delegation_chain()`, and `verify_invocation()` — allows plugging in W3C URDNA2015 (`verify_document_proof_w3c`) or any custom `Callable[[dict], None]` verifier. Default remains JCS for backward compatibility
- **Embedded Capabilities** (`parser.py`, `models.py`): Invocation `capability` field now accepts an embedded capability dict in addition to a string ID. Parsed embedded capabilities are stored as `Invocation.embedded_capability` and auto-resolved by `ZcapVerifier.verify_invocation()` when `capability=None`
- **capabilityChain in Proof** (`models.py`, `parser.py`, `verifier.py`): `LinkedDataProof.capability_chain` field parses `proof.capabilityChain` arrays (string references + embedded dict entries). `ZcapVerifier` auto-resolves all-embedded chains; string references are resolved via the configured `document_loader` (raises `InvocationError` when no loader is configured)
- **Document Loader** (`verifier.py`): `DocumentLoader` type alias (`Callable[[str], dict]`) and `document_loader` parameter on `ZcapVerifier` — enables resolution of string capability ID references in `capabilityChain` arrays per the W3C ZCAP-LD draft spec (root and ancestor capabilities referenced by ID, immediate parent embedded)
- **Ancestor Caveat Enforcement** (`verifier.py`): All capabilities in a delegation chain (not just the leaf) now have their caveats verified against the invocation. Parent/intermediate caveats are inherited per the W3C ZCAP-LD draft spec
- **Chain-to-Capability Linkage** (`verifier.py`): `ZcapVerifier.verify_invocation()` now validates that `chain[-1].id == capability.id`, ensuring the delegation chain actually terminates at the invoked capability
- **Absolute Expiry Check** (`verifier.py`): `ZcapVerifier.verify_invocation()` checks all capabilities in the chain (plus the target capability) against the injected clock. Expired capabilities raise `CapabilityExpiredError`
- **`CapabilityExpiredError`** (`exceptions.py`): New exception subclass of `InvocationError` for expired capabilities at invocation time
- **`ProofVerifier`** type alias exported from `zcap_py` top-level package
- **`DocumentLoader`** type alias exported from `zcap_py` top-level package
- 25 new tests: verifier facade (19 — expiry, linkage, ancestor caveats, proof dispatcher, embedded capabilities, capabilityChain, document loader), invocation (1 new, 1 updated), target attenuation (5 — query string)

### Changed

- **BREAKING:** `capabilityAction` is now **required** in invocation proof when the capability has `allowedAction` — previously accepted when absent, now raises `InvocationError` for proper cryptographic action binding
- **BREAKING:** `PathPrefixAttenuator` now enforces query string attenuation — parent `?tenant=a` rejects child `?tenant=b` or child without query; child may only extend with `&`-delimited params
- **BREAKING:** `ZcapVerifier.verify_invocation()` `capability` parameter is now `Capability | None` (default `None`) — when `None`, the embedded capability from the invocation is used
- `verify_delegation_chain()` and `verify_invocation()` accept optional `proof_verifier` keyword argument (non-breaking — defaults to JCS)
- `Invocation` model gains `embedded_capability: Capability | None` field
- `LinkedDataProof` model gains `capability_chain: tuple[str | dict, ...] | None` field

### Security

- Fixed ancestor caveats not being enforced — parent/intermediate capability caveats were silently skipped during invocation verification
- Fixed chain-to-capability linkage gap — delegation chain was verified but never checked to actually terminate at the invoked capability
- Fixed expired capabilities being invocable — clock was stored but never used for absolute expiry checks
- Fixed capabilityAction bypass — omitting `capabilityAction` from the proof when the capability had `allowedAction` was silently accepted
- Fixed query string attenuation bypass — `PathPrefixAttenuator` ignored query parameters, allowing `?tenant=b` to satisfy `?tenant=a`

## [0.4.0] - 2026-03-26

### Added

- **Delegation Chain Verification** (`delegation.py`): Full FR-DELEG-01 through FR-DELEG-08 implementation — walks (parent, child) pairs verifying signer authority, `parentCapability` linkage, `allowedAction` subset enforcement, `expires` attenuation, `invocationTarget` attenuation, and cryptographic proof. Errors wrapped in `ChainVerificationError` with link index context
- **Invocation Verification** (`invocation.py`): Full FR-INVOKE-01 through FR-INVOKE-07 implementation — validates `proof.capability` and body `capability` match, `invocationTarget` match, invoker identity (supports `capability.invoker` override and `controller` as `str | list[str]`), `capabilityAction` in `allowedAction`, cryptographic proof, and caveat dispatch
- **Target Attenuation** (`target_attenuation.py`): `InvocationTargetAttenuator` `@runtime_checkable` Protocol and `PathPrefixAttenuator` built-in implementation — validates that child `invocationTarget` is a path-prefix narrowing of parent (same scheme, same authority, child path starts with parent path)
- **Caveat Plugin System** (`caveats.py`): `CaveatVerifier` `@runtime_checkable` Protocol and `CaveatRegistry` — maps caveat types to verifier instances, fail-closed on unknown types (`UnknownCaveatError`), ships with zero built-in implementations per FR-CAVEAT-06
- **ZcapVerifier Facade** (`verifier.py`): Synchronous verification facade wiring delegation chain verification, invocation verification, caveat registry, and target attenuation. Accepts optional `clock` extension point for future expiry-at-invocation-time checks
- Re-exported `ZcapVerifier`, `CaveatVerifier`, `CaveatRegistry`, `InvocationTargetAttenuator`, `PathPrefixAttenuator` from top-level `zcap_py` package
- 58 new tests covering delegation chains (19), invocation verification (14), target attenuation (15), caveat system (10)

## [0.3.0] - 2026-03-26

### Added

- **W3C-Compliant Ed25519Signature2020 Verification (URDNA2015)**: `verify_document_proof_w3c()` implementing the real W3C Ed25519Signature2020 algorithm — dual URDNA2015 canonicalization (proof options + document), SHA-256 hash of each, concatenated into 64-byte verify_data, Ed25519 signature verification
- **URDNA2015 Canonicalization**: `urdna2015_canonicalize()` wrapper around `pyld.jsonld.normalize()` with lazy import and clear error messages when `pyld` is not installed
- **Offline JSON-LD Document Loader**: Bundled ZCAP v1 and Ed25519Signature2020 v1 JSON-LD contexts for zero-network-I/O URDNA2015 canonicalization. Unknown context URLs raise `CanonicalizationError` (fail-closed)
- **Optional `jsonld` Extra**: `pip install zcap-py[jsonld]` installs `pyld>=2.0` for W3C URDNA2015 support. Core library remains importable without `pyld`
- New optional dependency: `pyld>=2.0` (Digital Bazaar, BSD-3-Clause)

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
- `public_key_from_did_key()` convenience function — resolves a `did:key` DID or DID URL to an `Ed25519PublicKey` object
- New dependency: `rfc8785>=0.1.4` (zero-dep, Apache 2.0, Trail of Bits)

### Changed

- **BREAKING:** `verify_document_proof()` no longer accepts a `public_key` parameter — the public key is now resolved automatically from `proof.verificationMethod` (key binding). This fixes a vulnerability where a document signed by key B but claiming key A in `verificationMethod` would be accepted if the caller supplied key B

### Security

- Fixed key-binding vulnerability in `verify_document_proof()` — the function now resolves and verifies against the key encoded in `proof.verificationMethod` rather than trusting a caller-supplied key

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
