# PRD & Design Document — `zcap-py`

### Authorization Capabilities for Linked Data — Python Reference Implementation

**Version:** 0.1.0  
**Status:** Architecture finalized — ready for implementation  
**Author:** Moises (TurtleShell.id)  
**Reference Spec:** [W3C ZCAP-LD Draft](https://w3c-ccg.github.io/zcap-spec/)  
**Cross-language sibling:** `zcap-dotnet` (.NET 10 / C#)  
**Companion package:** `zcap-py-builder` (signing / document construction)  
**Shared fixture repo:** `zcap-ld-fixtures` (standalone, language-neutral)  
**Target Python version:** 3.11+

---

## 1. Purpose & Scope

`zcap-py` is a minimal, production-quality Python library implementing the **[W3C Authorization Capabilities for Linked Data (ZCAP-LD)]https://w3c-ccg.github.io/zcap-spec/)** draft specification. It is the Python counterpart to `zcap-dotnet` and shares the same semantic model, fixture schema, and exception taxonomy — enabling cross-language test parity.

The library is scoped to the **verifiable security kernel**: key derivation, canonicalization, proof generation/verification, capability delegation chain verification, and invocation verification. It explicitly defers full JSON-LD context processing, multi-method DID support, and transport concerns.

### 1.1 Goals

| #   | Goal                                                                                                                             |
| --- | -------------------------------------------------------------------------------------------------------------------------------- |
| G1  | Implement the ZCAP-LD delegation and invocation verification lifecycle as defined by the W3C draft                               |
| G2  | Be the canonical Python fixture consumer for cross-language test parity with `zcap-dotnet` (fixtures live in `zcap-ld-fixtures`) |
| G3  | Maintain a strict, auditable exception hierarchy — malformed input never causes raw crashes                                      |
| G4  | Provide a caveat plugin mechanism without polluting the core verification logic                                                  |
| G5  | Remain dependency-minimal and pure-Python verifiable                                                                             |
| G6  | Be consumable by TurtleShell.id's Sovereign Vault Python agents and future gRPC trust anchors                                    |
| G7  | Expose both synchronous and asynchronous verification APIs (`ZcapVerifier` and `AsyncZcapVerifier`)                              |

### 1.2 Non-Goals (Deferred or Out-of-Scope)

- Full JSON-LD context loading, expansion, or compaction (no `pyld` dependency in core)
- DID methods beyond `did:key` (Ed25519 multibase variant only)
- `did:web`, `did:dht`, `did:ethr`, `did:peer` support
- BBS+ or P-256 signature suites
- Persistence, storage, or caching of capability documents
- HTTP-layer invocation transport
- Revocation checking
- W3C ZCAP-LD test suite runner (can be added later as separate package)
- **Capability document signing and construction** — this is the responsibility of the companion package `zcap-py-builder`. The core `zcap-py` is a _verification-only_ library
- **Fixture file generation** — generation scripts live in `zcap-ld-fixtures`; `zcap-py` only _consumes_ them in tests. **Exception:** a single cross-implementation known-answer-test fixture set produced by the genuine `@digitalbazaar/zcap` stack is committed under `tests/fixtures/digitalbazaar/` (with its `generate.mjs`), because it is the concrete external anchor that locks byte-identical `Ed25519Signature2020` verify-data (issue #14); `node_modules` is not committed and Node is not required to run the Python tests

---

## 2. Background & Motivation

### 2.1 The ZCAP-LD Model (brief)

ZCAP-LD is an **object-capability (ocap) system** expressed in Linked Data. There are three primary document types:

**1. Root Capability**

The root is the trust anchor. It is issued by the resource controller to themselves, establishing the original grant of authority over an `invocationTarget`. It has no `parentCapability` field (it references itself as the root), carries no externally-signed proof, and is implicitly trusted — its authenticity is an application-layer responsibility, not the verifier's.

```jsonc
{
  "@context": [
    "https://w3id.org/zcap/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
  ],
  "id": "https://resource.example/capabilities/root", // stable, dereferenceable URI
  "type": "Authorization",
  "controller": "<root controller DID>", // the resource owner
  "invocationTarget": "https://resource.example/api/", // the resource being protected
  "allowedAction": ["read", "write"], // full authority set at root
  // NO parentCapability — this IS the root
  // NO proof — root trust is established out-of-band by the caller
}
```

Key distinctions from a delegated capability:

- `parentCapability` is **absent** (the spec treats the root's own `id` as its implicit parent reference)
- No `proof` field — the verifier does not and cannot verify the root's own signature; the caller must establish root trust separately
- `allowedAction` at root represents the complete action vocabulary; all delegations are subsets of this set
- `controller` at root is the resource owner, not a delegatee

**2. Delegated Capability**

A delegated capability grants a subset of the root (or parent) authority to a new `controller`. Each delegation link narrows — never broadens — the authority along all attenuation axes.

```jsonc
{
  "@context": ["https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
  "id": "urn:uuid:<uuid>",
  "type": "Authorization",
  "controller": "<delegatee DID>",       // the (sole) invoker identity — legacy `invoker` is not used
  "parentCapability": "<parent cap id>", // REQUIRED — links this to its parent
  "invocationTarget": "<URI>",           // == parent's target, or a narrowed sub-path
  "allowedAction": ["read"],             // ⊆ parent's allowedAction
  "expires": "2025-12-31T00:00:00Z",    // <= parent's expires if parent sets one
  "caveat": [{ "type": "...", ... }],   // optional application-layer restrictions
  "proof": { ... }                       // REQUIRED — signed by parent's controller
}
```

**3. Invocation**

Per the current ZCAP-LD spec and `@digitalbazaar/zcap`, an invocation **is** a `capabilityInvocation`
Data-Integrity proof signed over the target document — there is no bespoke `type:"Invocation"` wrapper and
no body-level duplication. The invoked `capability`, `invocationTarget`, and `capabilityAction` are carried
in the proof. `proof.capability` is either a **string id** (root invocation) or the **embedded full
capability object** (delegated invocation, carrying its own `capabilityChain`).

```jsonc
{
  "@context": [
    "https://w3id.org/zcap/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
  ],
  "id": "urn:uuid:<uuid>",                 // optional — the signed target document's id
  // …any application target-representation fields…
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "<invoker DID>#<fragment>",
    "proofPurpose": "capabilityInvocation",
    "capability": "<capability id | embedded capability object>", // invoked capability
    "invocationTarget": "<URI>",           // signed; bound to the verified-leaf target (and request)
    "capabilityAction": "read",            // must be ∈ effective allowedAction
    "created": "2025-06-01T12:00:00Z",
    "proofValue": "<multibase-z encoded Ed25519 signature>",
  },
}
```

The three document types in relation:

```
Root Capability
  └── Delegated Capability (signed by root controller → grants to Alice)
        └── Delegated Capability (signed by Alice → grants to Bob)
              └── Invocation (signed by Bob → exercises the leaf capability)
```

### 2.2 Why Python Now

The `zcap-dotnet` library addresses the .NET ecosystem. A Python counterpart serves:

- Agent-to-agent trust in AI pipelines (LangChain, CrewAI, MCP servers)
- TurtleShell.id Sovereign Vault backend logic expressed in Python microservices
- Fixture generation and cross-language parity validation
- Academic and open-source community adoption (Python is the SSI community's second language after JS)

---

## 3. Functional Requirements

### 3.1 Cryptography (FR-CRYPTO)

| ID           | Requirement                                                                                                                                          |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-CRYPTO-01 | Support **Ed25519** key generation using `cryptography>=41` (`Ed25519PrivateKey`, `Ed25519PublicKey`)                                                |
| FR-CRYPTO-02 | Support `did:key` encoding and decoding for Ed25519 keys only, using the `z6Mk...` multibase-multicodec prefix (`0xed01`)                            |
| FR-CRYPTO-03 | Expose `generate_ed25519_keypair() -> (DidKeyPair)` returning a named dataclass containing `did`, `verification_method`, `private_key`, `public_key` |
| FR-CRYPTO-04 | Verify Ed25519 signatures; raise `SignatureVerificationError` on failure                                                                             |
| FR-CRYPTO-05 | Encode/decode multibase `z` (base58btc) for key material and proof values                                                                            |

### 3.2 DID URL Parsing (FR-DID)

| ID        | Requirement                                                                                                                                                               |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-DID-01 | Parse and validate `did:key:<multibase>` DIDs                                                                                                                             |
| FR-DID-02 | Parse and validate DID URLs of the form `did:key:<multibase>#<fragment>`                                                                                                  |
| FR-DID-03 | Validate that the `#fragment` of a `did:key` verification method equals the DID's key identifier (i.e., `did == did_url.split('#')[0]` and fragment encodes the same key) |
| FR-DID-04 | Raise `DidParseError` for any malformed DID or DID URL                                                                                                                    |
| FR-DID-05 | Resolve a `did:key` DID URL to a `VerificationMethod` object without network I/O                                                                                          |

### 3.3 Canonicalization (FR-JCS)

| ID        | Requirement                                                                                                                                                                              |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-JCS-01 | Implement RFC 8785 / JCS (JSON Canonicalization Scheme) natively                                                                                                                         |
| FR-JCS-02 | Canonicalization must be deterministic across Python versions and OS platforms                                                                                                           |
| FR-JCS-03 | Canonicalize before signing and before verification — never operate on raw JSON strings                                                                                                  |
| FR-JCS-04 | Raise `CanonicalizationError` if input is not a valid JSON-serializable dict                                                                                                             |
| FR-JCS-05 | The JCS implementation must produce byte-for-byte identical output to the JavaScript `canonicalize` package and the C# `JsonCanonicalization` used in `zcap-dotnet` (fixture-verifiable) |

### 3.4 Proof Lifecycle (FR-PROOF)

| ID          | Requirement                                                                                                                                        |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-PROOF-01 | Generate `Ed25519Signature2020` proofs on arbitrary JSON-LD documents                                                                              |
| FR-PROOF-02 | Verification workflow: extract proof, remove `proofValue` from proof copy, merge proof copy back into document, JCS-canonicalize, verify signature |
| FR-PROOF-03 | `proof.verificationMethod` must parse as a valid DID URL (FR-DID-02)                                                                               |
| FR-PROOF-04 | `proof.created` must be a valid ISO 8601 datetime string; raise `ProofError` if malformed                                                          |
| FR-PROOF-05 | `proof.type` must equal `"Ed25519Signature2020"`; raise `UnsupportedProofTypeError` otherwise                                                      |
| FR-PROOF-06 | `proofValue` must be a valid multibase-z base58btc string of exactly 64 bytes decoded; raise `ProofError` otherwise                                |
| FR-PROOF-07 | **Proof dispatcher.** `ZcapVerifier`, `verify_delegation_chain()`, and `verify_invocation()` accept an optional `proof_verifier: Callable[[dict], None]` parameter. Default is JCS-based `verify_document_proof()`. W3C URDNA2015 via `verify_document_proof_w3c()` is supported as an alternative. `ProofVerifier` type alias is exported from the public API |

### 3.5 Capability Delegation Verification (FR-DELEG)

The full delegation chain verification semantics:

| ID          | Requirement                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-DELEG-01 | **Proof signer matches parent controller.** The `verificationMethod` DID (stripped of fragment) in the child's proof must equal the `controller` field of the parent capability. Raise `DelegationError`                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| FR-DELEG-02 | **parentCapability linkage.** `child.parentCapability` must equal `parent.id`. Raise `DelegationError`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| FR-DELEG-03 | **allowedAction subset.** `child.allowedAction ⊆ parent.allowedAction`. Raise `ActionAttenuationError`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| FR-DELEG-04 | **expires attenuation.** If `child.expires` is set and `parent.expires` is set, `child.expires <= parent.expires`. If `parent.expires` is set and `child.expires` is absent, the child inherits parent expiry (not an error). If `child.expires` is set but `parent.expires` is absent, the child may restrict further. Raise `ExpiryAttenuationError` on violation                                                                                                                                                                                                                                                                                            |
| FR-DELEG-05 | **invocationTarget attenuation.** By default, `child.invocationTarget` must equal `parent.invocationTarget` exactly. When `allow_target_attenuation=True` is set on the verifier, a registered `InvocationTargetAttenuator` is consulted. The built-in attenuator follows the same path-prefix narrowing rules as `zcap-dotnet`: (a) scheme and authority (`scheme://host:port`) must be identical; (b) child path must begin with parent path, after normalizing trailing slashes; (c) query string and fragment narrowing is permitted; (d) broadening (child target outside parent path) is always rejected. Raise `InvocationTargetError` on any violation |
| FR-DELEG-06 | Verify the child capability's cryptographic proof (FR-PROOF)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| FR-DELEG-07 | Support **chain verification**: given a root capability and an ordered list of delegated capabilities, verify the full chain from root to leaf. The root capability is implicitly trusted (caller responsibility); only chain links are verified                                                                                                                                                                                                                                                                                                                                                                                                               |
| FR-DELEG-08 | Raise `ChainVerificationError` wrapping the underlying cause if chain verification fails at any link                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

### 3.6 Invocation Verification (FR-INVOKE)

| ID           | Requirement                                                                                                                                                                                         |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-INVOKE-00 | **proofPurpose (verify-time).** `invocation.proof.proofPurpose` must equal `capabilityInvocation`, re-asserted at verify time independent of the parser (catches a pre-built/wrong-purpose model). Raise `InvocationError` |
| FR-INVOKE-01 | **Capability reference.** `invocation.proof.capability` (a string id, or the id of the embedded capability object) must equal `capability.id`. Raise `InvocationError`                                |
| FR-INVOKE-02 | **invocationTarget binding.** The **signed** `invocation.proof.invocationTarget` must be authorized by the (verified-leaf) `capability.invocationTarget` (exact match, or a valid narrowing when target attenuation is enabled). When an `expected_target` (the real request target) is supplied, it must likewise be authorized by `proof.invocationTarget`. Raise `InvocationError` |
| FR-INVOKE-03 | **Invoker identity (controller-only).** The DID of `invocation.proof.verificationMethod` (stripped of fragment) must equal `capability.controller`. The legacy `invoker` field is not honored. Raise `InvokerMismatchError` |
| FR-INVOKE-04 | **Verification-relationship authorization.** The invoker's verification method must be authorized by its controller for the `capabilityInvocation` relationship (for `did:key`, the single key is authorized for every relationship; pluggable via `RelationshipAuthorizer`). Raise `ProofError` |
| FR-INVOKE-05 | **capabilityAction mandatory.** When `capability.allowedAction` is set, `invocation.proof.capabilityAction` is **required** and must be a member of `allowedAction`. Raise `InvocationError` if absent or not in the set |
| FR-INVOKE-06 | Verify the invocation's cryptographic proof using the configured `proof_verifier` (defaults to W3C URDNA2015 `Ed25519Signature2020`; see FR-PROOF-07)                                              |
| FR-INVOKE-07 | Run all registered `CaveatVerifier` plugins against the invocation for the **leaf capability and all ancestor capabilities** in the chain; raise `CaveatError` if any fail                          |
| FR-INVOKE-08 | **Chain-to-capability linkage.** When a delegation chain is provided, `chain[-1].id` must equal `capability.id`. Raise `InvocationError` if the chain does not terminate at the invoked capability   |
| FR-INVOKE-09 | **Absolute expiry check.** All capabilities in the chain (plus the target capability) must be checked against the current clock. Raise `CapabilityExpiredError` if any have expired                  |
| FR-INVOKE-10 | **Embedded capability resolution.** When `capability` is `None`, the verifier resolves it from `invocation.embedded_capability` (parsed from embedded dict in `capability` field)                    |
| FR-INVOKE-11 | **capabilityChain resolution.** When `chain` is `None` and `invocation.proof.capability_chain` exists, resolve chain entries automatically: embedded dicts are parsed directly, string ID references are resolved via the configured `document_loader: Callable[[str], dict]`. Without a loader, string entries raise `InvocationError`. Per the W3C ZCAP-LD draft, chains use string references for root and ancestors, with only the immediate parent embedded |

### 3.7 Document Parsing (FR-PARSE)

Parsing of raw JSON dicts into typed models is the exclusive responsibility of `ZcapParser`. Models (`Capability`, `Invocation`) have **no** `from_dict()` classmethods. All deserialization paths flow through the parser, which owns validation of required fields, type coercion, and controlled error raising.

| ID          | Requirement                                                                                                                                                                                                                                                                                                                                                                                 |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-PARSE-01 | `ZcapParser.parse_capability(raw: dict) -> Capability` — parse and validate a raw capability document; raise `ZcapParseError` on any structural violation                                                                                                                                                                                                                                   |
| FR-PARSE-02 | `ZcapParser.parse_invocation(raw: dict) -> Invocation` — parse and validate a raw invocation document                                                                                                                                                                                                                                                                                       |
| FR-PARSE-03 | `ZcapParser.parse_capability_from_json(json_str: str) -> Capability` — convenience wrapper that decodes JSON string then delegates to FR-PARSE-01; raise `ZcapParseError` (never `json.JSONDecodeError`)                                                                                                                                                                                    |
| FR-PARSE-04 | `ZcapParser.parse_invocation_from_json(json_str: str) -> Invocation` — same as above for invocations                                                                                                                                                                                                                                                                                        |
| FR-PARSE-05 | Parser must validate: `id` is a non-empty string; `type` is the expected value; `controller` is a valid DID; `invocationTarget` is a non-empty URI string; `allowedAction` is a non-empty list of strings; `expires` parses as ISO 8601 UTC when present; `parentCapability` is a non-empty string **when present** (absence is valid for root capabilities)                                |
| FR-PARSE-06 | **`proof` is optional at parse time for `Authorization` documents.** A root capability legitimately has no proof; `ZcapParser.parse_capability()` must accept a proof-absent root without raising. `proof` is **mandatory** on `Invocation` documents and raises `ZcapParseError` if absent. When a proof is present on any document, all proof sub-fields are validated per FR-PROOF rules |
| FR-PARSE-07 | `ZcapParser` must expose `is_root(capability: Capability) -> bool` — returns `True` when `capability.parent_capability is None`. This makes root detection explicit and prevents callers from inferring rootness by inspecting `raw`                                                                                                                                                        |
| FR-PARSE-08 | `ZcapParser` must be stateless and instantiable with no arguments; a shared singleton is acceptable                                                                                                                                                                                                                                                                                         |
| FR-PARSE-09 | `ZcapParseError` must be a subclass of `ZcapError` and must carry `field: str` indicating which field failed                                                                                                                                                                                                                                                                                |

**Parser class sketch:**

```python
# zcap_py/zcap/parser.py

class ZcapParser:
    """
    Stateless parser for ZCAP-LD documents.
    All raw-dict → typed-model conversions go through here.
    ZcapParser never performs cryptographic operations.
    """

    def parse_capability(self, raw: dict) -> Capability:
        self._require_str(raw, "id")
        self._require_type(raw, "Authorization")
        self._require_did(raw, "controller")
        self._require_str(raw, "invocationTarget")
        self._require_action_list(raw, "allowedAction")
        expires = self._parse_expires(raw.get("expires"))
        proof = self._parse_proof(raw.get("proof")) if "proof" in raw else None
        return Capability(
            id=raw["id"],
            controller=raw["controller"],
            parent_capability=raw.get("parentCapability"),
            invocation_target=raw["invocationTarget"],
            allowed_action=list(raw["allowedAction"]),
            expires=expires,
            caveat=list(raw.get("caveat", [])),
            proof=proof,
            raw=raw,
        )

    def parse_invocation(self, raw: dict) -> Invocation:
        # An invocation IS a capabilityInvocation proof over the target document.
        # capability / invocationTarget / capabilityAction live in the proof; no
        # body type/capability/invocationTarget. proof.capability may be a string
        # id or an embedded capability object.
        proof = self._parse_proof(raw["proof"])  # proof is mandatory on invocations
        embedded = (
            self.parse_capability(raw["proof"]["capability"])
            if isinstance(raw["proof"].get("capability"), dict)
            else None
        )
        return Invocation(
            id=raw.get("id"),  # optional
            proof=proof,       # proof.capability / .invocation_target carry the references
            embedded_capability=embedded,
            raw=raw,
        )

    def parse_capability_from_json(self, json_str: str) -> Capability:
        try:
            raw = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ZcapParseError("Invalid JSON", field="<document>") from e
        return self.parse_capability(raw)

    def parse_invocation_from_json(self, json_str: str) -> Invocation:
        try:
            raw = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ZcapParseError("Invalid JSON", field="<document>") from e
        return self.parse_invocation(raw)

    # --- private helpers ---

    def _require_str(self, d: dict, field: str) -> str:
        v = d.get(field)
        if not isinstance(v, str) or not v.strip():
            raise ZcapParseError(f"Missing or invalid field '{field}'", field=field)
        return v

    def _require_type(self, d: dict, expected: str) -> None:
        t = d.get("type")
        if t != expected:
            raise ZcapParseError(
                f"Expected type '{expected}', got '{t}'", field="type"
            )

    def _require_did(self, d: dict, field: str) -> str:
        v = self._require_str(d, field)
        try:
            parse_did(v)   # delegates to did/url.py
        except DidParseError as e:
            raise ZcapParseError(f"Field '{field}' is not a valid DID", field=field) from e
        return v

    def _require_action_list(self, d: dict, field: str) -> list[str]:
        v = d.get(field)
        if not isinstance(v, list) or not v or not all(isinstance(a, str) for a in v):
            raise ZcapParseError(
                f"'{field}' must be a non-empty list of strings", field=field
            )
        return v

    def _parse_expires(self, value: str | None) -> datetime | None:
        if value is None:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as e:
            raise ZcapParseError("'expires' is not a valid ISO 8601 datetime", field="expires") from e

    def _parse_proof(self, proof: dict | None) -> LinkedDataProof:
        if proof is None:
            raise ZcapParseError("Missing required 'proof' field", field="proof")
        if not isinstance(proof, dict):
            raise ZcapParseError("'proof' must be an object", field="proof")
        ptype = proof.get("type")
        if ptype != "Ed25519Signature2020":
            raise ZcapParseError(
                f"Unsupported proof type '{ptype}'", field="proof.type"
            )
        vm = proof.get("verificationMethod")
        if not isinstance(vm, str) or not vm:
            raise ZcapParseError("Missing proof.verificationMethod", field="proof.verificationMethod")
        created = proof.get("created")
        if not isinstance(created, str) or not created:
            raise ZcapParseError("Missing proof.created", field="proof.created")
        pv = proof.get("proofValue")
        if not isinstance(pv, str) or not pv.startswith("z"):
            raise ZcapParseError("proof.proofValue must be a multibase-z string", field="proof.proofValue")
        return LinkedDataProof(
            type=ptype,
            verification_method=vm,
            created=created,
            proof_value=pv,
            capability=proof.get("capability"),
            capability_action=proof.get("capabilityAction"),
            proof_purpose=proof.get("proofPurpose", "capabilityDelegation"),
        )
```

### 3.8 Caveat Plugin System (FR-CAVEAT)

| ID           | Requirement                                                                                                                                                                                                  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| FR-CAVEAT-01 | Define `CaveatVerifier` as a Python `Protocol` (structural subtyping, no inheritance required)                                                                                                               |
| FR-CAVEAT-02 | `CaveatVerifier.caveat_type: str` — the string name this verifier handles                                                                                                                                    |
| FR-CAVEAT-03 | `CaveatVerifier.verify(caveat: dict, invocation: dict) -> None` — raises `CaveatError` on failure, returns `None` on success                                                                                 |
| FR-CAVEAT-04 | `ZcapVerifier` accepts a `caveat_verifiers: list[CaveatVerifier]` argument                                                                                                                                   |
| FR-CAVEAT-05 | During invocation verification, for each caveat in `capability.caveat`, look up the matching verifier by `caveat["type"]`; if no verifier is registered for a type, raise `UnknownCaveatError` (fail-closed) |
| FR-CAVEAT-06 | Core library ships with zero built-in caveat implementations; this is intentional                                                                                                                            |

### 3.9 Error Handling (FR-ERR)

**All errors must derive from `ZcapError(Exception)`.** No raw `ValueError`, `KeyError`, `AttributeError`, or parser exceptions should ever propagate to callers.

```
ZcapError
├── ZcapParseError          (field: str)
├── DidParseError
├── CanonicalizationError
├── ProofError
│   └── UnsupportedProofTypeError
│   └── SignatureVerificationError
├── DelegationError
│   └── ActionAttenuationError
│   └── ExpiryAttenuationError
│   └── InvocationTargetError
│   └── ChainVerificationError
├── InvocationError
│   ├── InvokerMismatchError
│   └── CapabilityExpiredError
└── CaveatError
    └── UnknownCaveatError
```

All `ZcapError` subclasses must:

- Accept a human-readable `message: str`
- Carry an optional `context: dict` for structured diagnostic data (e.g., the offending field values)
- Never embed raw exception tracebacks in the message

### 3.10 Cross-Language Fixture Parity (FR-FIXTURE)

| ID            | Requirement                                                                                                                                                                                                                                           |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-FIXTURE-01 | Fixture files are hosted in the **`zcap-ld-fixtures`** standalone repository; both `zcap-py` and `zcap-dotnet` reference it as a git submodule at `tests/fixtures/`                                                                                   |
| FR-FIXTURE-02 | `zcap-py` test suite consumes fixtures read-only; it does **not** generate or modify fixture files                                                                                                                                                    |
| FR-FIXTURE-03 | `zcap-ld-fixtures` contains a `generate_fixtures.py` (Python) and a `GenerateFixtures.cs` (.NET) script that both produce identical output from the same deterministic seed keys                                                                      |
| FR-FIXTURE-04 | Fixtures must include at least: valid 1-hop delegation, valid 2-hop chain, allowedAction violation, expiry violation, invocationTarget mismatch, path-narrowing attenuation (valid and invalid), invalid proof, invoker mismatch, unknown caveat type |
| FR-FIXTURE-05 | JCS output for a canonical fixture document must be byte-identical between Python and .NET (validated by a dedicated `test_jcs_parity.py` that hashes canonicalized fixture documents)                                                                |
| FR-FIXTURE-06 | Each fixture file must include a `"comment"` field, an `"expected"` field (`"valid"` or the exception class name string), and an optional `"expectedErrorField"` for parse errors                                                                     |

---

## 4. Non-Functional Requirements

| ID     | Requirement                                                                                                                                         |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| NFR-01 | **Zero transitive JSON-LD processor dependency** in core; `pyld` or `rdflib` may appear in optional extras                                          |
| NFR-02 | **Minimal dependency surface**: `cryptography>=41`, `base58>=2.1`. JCS implemented in stdlib only (`json`, `struct`). No `requests`, no network I/O |
| NFR-03 | **Python 3.11+** minimum; no `3.10` compat shims needed                                                                                             |
| NFR-04 | **100% type-annotated** public API; `mypy --strict` must pass                                                                                       |
| NFR-05 | **pytest coverage ≥ 90%** on all verification paths                                                                                                 |
| NFR-06 | **No global mutable state**; `ZcapVerifier` is instantiated per-use                                                                                 |
| NFR-07 | **Thread-safe** by construction (no shared mutable class-level state)                                                                               |
| NFR-08 | MIT or Apache-2.0 license, compatible with `zcap-dotnet`                                                                                            |

---

## 5. Architecture

### 5.1 Package Layout

#### `zcap-py` (verification core — this repo)

```
zcap_py/
├── __init__.py                  # Public API re-exports
├── crypto/
│   ├── __init__.py
│   ├── ed25519.py               # Key generation, sign, verify
│   ├── multibase.py             # z-base58btc encode/decode
│   └── multicodec.py            # 0xed01 prefix handling
├── did/
│   ├── __init__.py
│   ├── key.py                   # did:key encode/decode/resolve
│   └── url.py                   # DID URL parsing and validation
├── jcs/
│   ├── __init__.py
│   └── canonicalize.py          # RFC 8785 implementation (stdlib only)
├── proof/
│   ├── __init__.py
│   ├── ed25519_2020.py          # Ed25519Signature2020 verify only
│   └── models.py                # LinkedDataProof dataclass
├── zcap/
│   ├── __init__.py
│   ├── models.py                # Capability, Invocation, VerificationMethod dataclasses
│   ├── parser.py                # ZcapParser — raw dict → typed models
│   ├── delegation.py            # Delegation chain verifier (sync)
│   ├── invocation.py            # Invocation verifier (sync)
│   ├── caveats.py               # CaveatVerifier Protocol + CaveatRegistry
│   ├── target_attenuation.py    # InvocationTargetAttenuator Protocol + PathPrefixAttenuator
│   ├── verifier.py              # ZcapVerifier (sync facade)
│   └── async_verifier.py        # AsyncZcapVerifier (async facade)
└── exceptions.py                # Full ZcapError hierarchy

tests/
├── fixtures/                    # git submodule → zcap-ld-fixtures
├── test_crypto.py
├── test_did.py
├── test_jcs.py
├── test_jcs_parity.py           # JCS byte-identity cross-language check
├── test_proof.py
├── test_parser.py
├── test_delegation.py
├── test_invocation.py
├── test_target_attenuation.py
├── test_caveats.py
├── test_async_verifier.py
├── test_fixtures.py             # Round-trips all fixtures from submodule
└── conftest.py
```

#### `zcap-py-builder` (companion signing package — separate repo)

```
zcap_py_builder/
├── __init__.py
├── capability_builder.py        # CapabilityBuilder — fluent API for constructing capabilities
├── invocation_builder.py        # InvocationBuilder — fluent API for constructing invocations
├── signer.py                    # sign_capability(), sign_invocation()
└── proof/
    └── ed25519_2020.py          # Ed25519Signature2020 signing (extends zcap-py proof models)

tests/
├── fixtures/                    # same git submodule → zcap-ld-fixtures
├── test_builder.py
└── test_signer.py
```

#### `zcap-ld-fixtures` (language-neutral fixture repo — standalone)

```
zcap-ld-fixtures/
├── README.md
├── schema/
│   ├── capability.schema.json
│   └── invocation.schema.json
├── keypairs/
│   ├── alice.json
│   ├── bob.json
│   └── carol.json
├── valid/
│   ├── delegation_1hop.json
│   ├── delegation_2hop.json
│   ├── delegation_target_narrowed.json
│   └── invocation.json
├── invalid/
│   ├── allowedaction_violation.json
│   ├── expiry_violation.json
│   ├── invocationtarget_mismatch.json
│   ├── invocationtarget_broadened.json
│   ├── proof_invalid_signature.json
│   ├── proof_missing.json
│   ├── invoker_mismatch.json
│   └── unknown_caveat.json
└── generators/
    ├── generate_fixtures.py     # Python generator
    └── GenerateFixtures.cs      # .NET generator
```

### 5.2 Core Data Models

Models are **plain frozen dataclasses**. They have no parsing logic, no classmethods, no validators. All construction flows through `ZcapParser`.

```python
# zcap_py/zcap/models.py

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

@dataclass(frozen=True)
class VerificationMethod:
    id: str                   # full DID URL
    type: str                 # "Ed25519VerificationKey2020"
    controller: str           # bare DID
    public_key_multibase: str # "z" + base58btc(pubkey bytes)

@dataclass(frozen=True)
class LinkedDataProof:
    type: str                       # "Ed25519Signature2020"
    verification_method: str        # DID URL
    created: str                    # ISO 8601
    proof_value: str                # multibase-z
    proof_purpose: str = "capabilityDelegation"
    capability: Optional[str] = None         # invoked capability id (from string or embedded object)
    capability_action: Optional[str] = None
    invocation_target: Optional[str] = None  # signed proof.invocationTarget
    capability_chain: Optional[tuple[str | dict, ...]] = None  # capabilityChain entries

@dataclass(frozen=True)
class Capability:
    id: str
    controller: str | list[str]    # string or array of DID strings — the sole invoker identity
    parent_capability: Optional[str]   # None == this IS the root capability
    invocation_target: str
    allowed_action: Optional[list[str]]
    expires: Optional[datetime]
    caveat: list[dict] = field(default_factory=list)
    proof: Optional[LinkedDataProof] = None  # None is valid for root capabilities
    raw: dict = field(default_factory=dict, compare=False)
    # NOTE: the legacy `invoker` field was removed (current spec is controller-only).

    @property
    def is_root(self) -> bool:
        """True when this capability is a root — no parent, no externally-signed proof."""
        return self.parent_capability is None

@dataclass(frozen=True)
class Invocation:
    # An invocation IS a capabilityInvocation proof over the target document.
    proof: LinkedDataProof
    id: Optional[str] = None                          # optional target-document id
    embedded_capability: Optional[Capability] = None  # parsed when proof.capability is an embedded object
    raw: dict = field(default_factory=dict, compare=False)

    # capability / invocation_target are read-only properties over `proof`:
    @property
    def capability(self) -> Optional[str]: return self.proof.capability
    @property
    def invocation_target(self) -> Optional[str]: return self.proof.invocation_target
```

### 5.3 ZcapVerifier & AsyncZcapVerifier Facades

```python
# zcap_py/zcap/verifier.py

class ZcapVerifier:
    """
    Synchronous verification facade.
    Accepts parsed Capability/Invocation models — parsing is caller responsibility (use ZcapParser).
    """

    def __init__(
        self,
        caveat_verifiers: list[CaveatVerifier] | None = None,
        target_attenuator: InvocationTargetAttenuator | None = None,
        allow_target_attenuation: bool = False,
        clock: Callable[[], datetime] | None = None,  # injectable for testing
        proof_verifier: ProofVerifier | None = None,   # JCS default, or W3C
        document_loader: DocumentLoader | None = None, # resolve string cap IDs
    ) -> None:
        self._caveats = CaveatRegistry(caveat_verifiers or [])
        self._attenuator = target_attenuator or PathPrefixAttenuator()
        self._allow_target_attenuation = allow_target_attenuation
        self._clock = clock or (lambda: datetime.now(tz=UTC))
        self._proof_verifier = proof_verifier
        self._document_loader = document_loader

    def verify_delegation_chain(
        self,
        root: Capability,
        chain: list[Capability],  # ordered: closest-to-root first
    ) -> None:
        """Raises ZcapError subclass on any violation. Root is caller-trusted."""
        ...

    def verify_invocation(
        self,
        invocation: Invocation,
        capability: Capability | None = None,  # None → use embedded_capability
        chain: list[Capability] | None = None, # None → resolve from capabilityChain
    ) -> None:
        """Raises ZcapError subclass on any violation.

        Performs in order:
        1. Resolve capability from embedded if None
        2. Resolve chain from capabilityChain if None
        3. Verify delegation chain (if chain provided)
        4. Chain-to-capability linkage (FR-INVOKE-08)
        5. Absolute expiry check (FR-INVOKE-09)
        6. Core invocation verification (FR-INVOKE-01 through FR-INVOKE-06)
        7. Ancestor caveat enforcement (FR-INVOKE-07 extended)
        """
        ...


# zcap_py/zcap/async_verifier.py

class AsyncZcapVerifier:
    """
    Asynchronous verification facade.
    Wraps ZcapVerifier internals; all verify methods are awaitable.
    CPU-bound crypto operations run in a thread pool via asyncio.to_thread().
    I/O-bound caveat verifiers (e.g., network-based checks) may use native async.
    """

    def __init__(
        self,
        caveat_verifiers: list[AsyncCaveatVerifier | CaveatVerifier] | None = None,
        target_attenuator: InvocationTargetAttenuator | None = None,
        allow_target_attenuation: bool = False,
        clock: Callable[[], datetime] | None = None,
    ) -> None: ...

    async def verify_delegation_chain(
        self,
        root: Capability,
        chain: list[Capability],
    ) -> None:
        """Async delegation chain verification. Raises ZcapError on failure."""
        await asyncio.to_thread(self._sync_verify_delegation, root, chain)

    async def verify_invocation(
        self,
        invocation: Invocation,
        capability: Capability,
        chain: list[Capability] | None = None,
    ) -> None:
        """Async invocation verification. Raises ZcapError on failure."""
        await asyncio.to_thread(self._sync_verify_invocation, invocation, capability, chain)
        await self._run_async_caveats(capability.caveat, invocation)
```

**Async caveat protocol** — the async verifier accepts both sync `CaveatVerifier` (wrapped in `asyncio.to_thread`) and a native async variant:

```python
@runtime_checkable
class AsyncCaveatVerifier(Protocol):
    caveat_type: str

    async def verify(self, caveat: dict, invocation: dict) -> None:
        """Async caveat check. Raise CaveatError on failure."""
        ...
```

### 5.4 InvocationTargetAttenuator — Path-Prefix Rules

The attenuation rules mirror `zcap-dotnet`'s `IInvocationTargetAttenuator` / `PathPrefixAttenuator` exactly, enabling fixture cross-validation.

```python
# zcap_py/zcap/target_attenuation.py

from typing import Protocol, runtime_checkable
from urllib.parse import urlparse

@runtime_checkable
class InvocationTargetAttenuator(Protocol):
    def is_valid_attenuation(self, parent_target: str, child_target: str) -> bool:
        """
        Return True if child_target is a valid narrowing of parent_target.
        Must never raise; invalid URIs return False.
        """
        ...


class PathPrefixAttenuator:
    """
    Built-in attenuator implementing the same path-prefix narrowing rules as zcap-dotnet.

    Rules (all must hold for attenuation to be valid):
      1. Both URIs must parse successfully.
      2. scheme must be identical (case-insensitive).
      3. authority (host + port) must be identical (case-insensitive).
      4. child path must begin with parent path after normalizing trailing slashes.
         Example: parent="/api/", child="/api/resource/123" → valid
         Example: parent="/api/resource", child="/api/" → invalid (broadening)
      5. If parent has a query string, child must preserve it exactly and may only extend with '&'-delimited params. If parent has no query, child may add one freely. Fragment may differ freely.
      6. Exact match (child == parent) is always valid.
      7. Broadening (child path outside parent path scope) is always invalid.
    """

    def is_valid_attenuation(self, parent_target: str, child_target: str) -> bool:
        try:
            p = urlparse(parent_target)
            c = urlparse(child_target)
        except Exception:
            return False

        if p.scheme.lower() != c.scheme.lower():
            return False
        if p.netloc.lower() != c.netloc.lower():
            return False

        parent_path = p.path.rstrip("/") + "/"
        child_path = c.path.rstrip("/") + "/"

        if not child_path.startswith(parent_path):
            return False

        # Query string attenuation: if parent has a query, child must
        # preserve it exactly and may only extend with '&' params.
        if p.query:
            if not c.query:
                return False
            if c.query != p.query and not c.query.startswith(p.query + "&"):
                return False

        return True
```

**Fixture examples for path-prefix attenuation:**

| Parent target                   | Child target                              | Valid? | Reason           |
| ------------------------------- | ----------------------------------------- | ------ | ---------------- |
| `https://api.example.com/data/` | `https://api.example.com/data/records/42` | ✅     | Path narrowed    |
| `https://api.example.com/data/` | `https://api.example.com/data/`           | ✅     | Exact match      |
| `https://api.example.com/data/` | `https://api.example.com/`                | ❌     | Broadened        |
| `https://api.example.com/data/` | `https://other.example.com/data/`         | ❌     | Different host   |
| `https://api.example.com/data/` | `http://api.example.com/data/records/`    | ❌     | Different scheme |
| `https://api.example.com/data/` | `https://api.example.com/data/q?filter=x` | ✅     | Query added (parent has no query) |
| `https://api.example.com/data/?tenant=a` | `https://api.example.com/data/?tenant=a` | ✅     | Exact query match |
| `https://api.example.com/data/?tenant=a` | `https://api.example.com/data/?tenant=a&filter=x` | ✅     | Query extended with & |
| `https://api.example.com/data/?tenant=a` | `https://api.example.com/data/?tenant=b` | ❌     | Different query value |
| `https://api.example.com/data/?tenant=a` | `https://api.example.com/data/` | ❌     | Parent query dropped |
| `https://api.example.com/data/?a=1` | `https://api.example.com/data/?a=12` | ❌     | Value prefix attack |

### 5.5 Delegation Verification Flow

```
verify_delegation_chain(root, [cap_a, cap_b])
  ↑ inputs are already-parsed Capability objects (caller used ZcapParser)

  For each (parent, child) pair in [(root, cap_a), (cap_a, cap_b)]:
    1. Parse child.proof.verificationMethod → signer_did (strip fragment)
    2. Assert signer_did == parent.controller          → DelegationError
    3. Assert child.parentCapability == parent.id      → DelegationError
    4. Assert child.allowedAction ⊆ parent.allowedAction → ActionAttenuationError
    5. Assert child.expires attenuation valid          → ExpiryAttenuationError
    6. If child.invocationTarget == parent.invocationTarget → OK
       Else if allow_target_attenuation:
         attenuator.is_valid_attenuation(parent.invocationTarget, child.invocationTarget)
         → InvocationTargetError if False
       Else → InvocationTargetError
    7. Resolve signer_did verificationMethod from did:key
    8. JCS-canonicalize document (with proof copy, proofValue removed)
    9. Ed25519.verify(canonical_bytes, proof_value, public_key)
                                                       → SignatureVerificationError
```

### 5.6 Invocation Verification Flow

```
ZcapVerifier.verify_invocation(invocation, capability=None, chain=None)

  ── Resolve inputs ──
  1. If capability is None: use invocation.embedded_capability      → InvocationError if also None
  2. If chain is None and invocation.proof.capability_chain exists:
     Resolve all-embedded chain entries via ZcapParser              → InvocationError on string refs

  ── Chain verification ──
  3. If chain provided: verify_delegation_chain(root=chain[0], chain=chain[1:])
  4. FR-INVOKE-08: Assert chain[-1].id == capability.id             → InvocationError (linkage)

  ── Absolute expiry ──
  5. FR-INVOKE-09: For each cap in (chain ∪ {capability}):
     Assert cap.expires is None OR cap.expires > now                → CapabilityExpiredError

  ── Core invocation checks ──  (capability is rebound to the VERIFIED chain leaf chain[-1])
  6. FR-INVOKE-00: Assert invocation.proof.proofPurpose == "capabilityInvocation" → InvocationError
  7. FR-INVOKE-01: Assert invocation.proof.capability == capability.id            → InvocationError
  8. FR-INVOKE-02: Assert proof.invocationTarget authorized by capability.invocationTarget
     (exact, or narrowing if attenuation); if expected_target given, it must be authorized by
     proof.invocationTarget                                          → InvocationError
  9. Extract invoker_did = DID URL of invocation.proof.verificationMethod (strip fragment)
 10. FR-INVOKE-03: Assert invoker_did == capability.controller       → InvokerMismatchError
 11. FR-INVOKE-05: If capability.allowedAction is not None:
     Assert invocation.proof.capabilityAction is not None           → InvocationError
     Assert capabilityAction ∈ capability.allowedAction             → InvocationError
 11b. FR-INVOKE-04: relationship_authorizer(proof.verificationMethod, "capabilityInvocation") → ProofError
 12. Cryptographic proof via proof_verifier (default: W3C URDNA2015) → SignatureVerificationError
 13. For each caveat in capability.caveat:
     Find registered CaveatVerifier by caveat["type"]               → UnknownCaveatError
     verifier.verify(caveat, invocation.raw)

  ── Ancestor caveat enforcement ──
 14. FR-INVOKE-10: For each ancestor cap in chain[:-1]:
     For each caveat in ancestor.caveat:
       Find registered CaveatVerifier by caveat["type"]             → UnknownCaveatError
       verifier.verify(caveat, invocation.raw)
```

### 5.7 JCS Canonicalization (RFC 8785)

The core algorithm (no dependencies):

```python
# zcap_py/jcs/canonicalize.py

import json
import struct

def canonicalize(obj: dict | list) -> bytes:
    """
    Serialize obj to UTF-8 bytes per RFC 8785 (JCS).
    - Object keys sorted lexicographically (Unicode code point order)
    - No insignificant whitespace
    - Numbers: integers as integers, floats per ES2019 ToString rules
    - Strings: Unicode escape only for U+0000–U+001F (and surrogates)
    """
    return _serialize(obj).encode("utf-8")

def _serialize(obj) -> str:
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        return _serialize_float(obj)
    if isinstance(obj, str):
        return _serialize_string(obj)
    if isinstance(obj, list):
        return "[" + ",".join(_serialize(v) for v in obj) + "]"
    if isinstance(obj, dict):
        pairs = sorted(obj.items(), key=lambda kv: kv[0])
        return "{" + ",".join(
            _serialize_string(k) + ":" + _serialize(v) for k, v in pairs
        ) + "}"
    raise CanonicalizationError(f"Unsupported type: {type(obj).__name__}")
```

Float serialization follows ES2019 `Number::ToString` semantics (Grisu3/Dragon4). The implementation must pass the RFC 8785 Appendix B test vectors exactly.

### 5.8 Proof Verification (verify only — signing is in `zcap-py-builder`)

```python
# zcap_py/proof/ed25519_2020.py
# NOTE: sign() lives in zcap-py-builder. This module is verification-only.

PROOF_PURPOSE_DELEGATION = "capabilityDelegation"
PROOF_PURPOSE_INVOCATION = "capabilityInvocation"


def verify(document_with_proof: dict, public_key: Ed25519PublicKey) -> None:
    """
    Raises SignatureVerificationError on failure.
    Raises ProofError if proof structure is malformed.
    Caller must have already validated proof fields via ZcapParser.
    """
    proof = _extract_proof(document_with_proof)
    sig_bytes = _decode_proof_value(proof["proofValue"])

    # Build verification document: doc with proof copy minus proofValue
    proof_copy = {k: v for k, v in proof.items() if k != "proofValue"}
    doc_to_verify = {**document_with_proof, "proof": proof_copy}
    canonical = canonicalize(doc_to_verify)

    try:
        public_key.verify(sig_bytes, canonical)
    except InvalidSignature:
        raise SignatureVerificationError(
            "Ed25519 signature verification failed",
            context={"verificationMethod": proof.get("verificationMethod")}
        )


def _decode_proof_value(proof_value: str) -> bytes:
    if not proof_value.startswith("z"):
        raise ProofError("proofValue must be multibase-z encoded", context={"proofValue": proof_value})
    try:
        decoded = base58btc_decode(proof_value[1:])
    except Exception as e:
        raise ProofError("proofValue base58btc decode failed", context={"proofValue": proof_value}) from e
    if len(decoded) != 64:
        raise ProofError(
            f"proofValue decoded to {len(decoded)} bytes; expected 64",
            context={"length": len(decoded)}
        )
    return decoded
```

### 5.9 Caveat Plugin Protocol

```python
# zcap_py/zcap/caveats.py

from typing import Protocol, runtime_checkable

@runtime_checkable
class CaveatVerifier(Protocol):
    """
    Structural protocol for caveat verifiers.
    No inheritance required — duck typing is sufficient.
    """
    caveat_type: str  # class-level constant, e.g. "ExpiryTimeCaveat"

    def verify(self, caveat: dict, invocation: dict) -> None:
        """
        Verify the caveat against the invocation.
        Raise CaveatError on failure.
        Return None on success.
        """
        ...


class CaveatRegistry:
    def __init__(self, verifiers: list[CaveatVerifier] | None = None) -> None:
        self._registry: dict[str, CaveatVerifier] = {}
        for v in (verifiers or []):
            self._registry[v.caveat_type] = v

    def verify_all(self, caveats: list[dict], invocation: dict) -> None:
        for caveat in caveats:
            ctype = caveat.get("type")
            if ctype not in self._registry:
                raise UnknownCaveatError(
                    f"No verifier registered for caveat type '{ctype}'",
                    context={"caveat": caveat}
                )
            self._registry[ctype].verify(caveat, invocation)
```

---

## 6. Fixture Schema

All fixtures live in the **`zcap-ld-fixtures`** standalone repository, consumed by `zcap-py` as a git submodule at `tests/fixtures/`. The schema below is normative for both `zcap-py` and `zcap-dotnet`.

### 6.1 Keypair Fixture

Stored in `zcap-ld-fixtures/keypairs/`. Three fixed actors: `alice.json`, `bob.json`, `carol.json`.

```json
{
  "comment": "Fixed Ed25519 keypair — Alice. Deterministic seed for test reproducibility.",
  "did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "verificationMethod": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "privateKeyHex": "<32-byte seed as hex>"
}
```

### 6.2 Root Capability Fixture

Stored in `zcap-ld-fixtures/valid/`. Root capabilities are referenced by delegation fixtures; they can also appear standalone to test root parsing.

```json
{
  "comment": "Root capability — Alice is the resource controller. No proof, no parentCapability.",
  "root": {
    "@context": [
      "https://w3id.org/zcap/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": "https://resource.example/capabilities/root",
    "type": "Authorization",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "invocationTarget": "https://resource.example/api/",
    "allowedAction": ["read", "write"]
  },
  "expected": "valid"
}
```

Key invariants verified by `test_fixtures.py` for every root capability fixture:

- `parentCapability` is absent
- `proof` is absent
- `ZcapParser.is_root(cap) == True`
- `cap.allowed_action` is non-empty

### 6.3 Delegation Fixture

Stored in `zcap-ld-fixtures/valid/` or `zcap-ld-fixtures/invalid/`.

```json
{
  "comment": "Valid 1-hop delegation from Alice (root controller) to Bob",
  "root": {},
  "chain": [{}],
  "expected": "valid"
}
```

### 6.4 Invocation Fixture

```json
{
  "comment": "Valid invocation by Bob against delegated capability",
  "capability": {},
  "invocation": {},
  "expected": "valid"
}
```

### 6.5 Invalid Fixtures

```json
{
  "comment": "allowedAction violation — child claims 'write' not in parent's ['read']",
  "root": {},
  "chain": [{}],
  "expected": "ActionAttenuationError"
}
```

### 6.6 JCS Parity Fixture

Each fixture document includes a `"jcsCanonicalSha256"` field containing the hex-encoded SHA-256 of the JCS canonicalization of the root or invocation document body (excluding proof). Both `test_jcs_parity.py` (Python) and the .NET equivalent verify this hash matches, proving byte-identical canonicalization across languages.

```json
{
  "comment": "JCS parity check for root capability",
  "document": {},
  "jcsCanonicalSha256": "<64-char hex>"
}
```

---

## 7. Public API Surface

The public API exported from `zcap_py/__init__.py`. This is a **verification-only** library. Signing and document construction are in `zcap-py-builder`.

```python
# ---- Cryptographic key operations ----
from zcap_py import generate_ed25519_keypair, DidKeyPair

# ---- Parsing (raw dict → typed models) ----
from zcap_py import ZcapParser

# ---- Models ----
from zcap_py import Capability, Invocation, VerificationMethod, LinkedDataProof

# ---- Synchronous verifier ----
from zcap_py import ZcapVerifier

# ---- Proof verification dispatch ----
from zcap_py import ProofVerifier  # Callable[[dict], None] — JCS default, W3C optional

# ---- Document loader (capabilityChain string reference resolution) ----
from zcap_py import DocumentLoader  # Callable[[str], dict] — resolves cap ID → raw dict

# ---- Target attenuation ----
from zcap_py import PathPrefixAttenuator, InvocationTargetAttenuator  # Protocol

# ---- JCS (exported for cross-language parity testing) ----
from zcap_py import canonicalize

# ---- Caveat plugin protocols ----
from zcap_py import CaveatVerifier, CaveatRegistry

# ---- Exceptions ----
from zcap_py.exceptions import (
    ZcapError,
    ZcapParseError,
    DidParseError,
    CanonicalizationError,
    ProofError,
    UnsupportedProofTypeError,
    SignatureVerificationError,
    DelegationError,
    ActionAttenuationError,
    ExpiryAttenuationError,
    InvocationTargetError,
    ChainVerificationError,
    InvocationError,
    InvokerMismatchError,
    CapabilityExpiredError,
    CaveatError,
    UnknownCaveatError,
)
```

**Typical synchronous usage pattern:**

```python
from zcap_py import ZcapParser, ZcapVerifier
from zcap_py.exceptions import ZcapError

parser = ZcapParser()
verifier = ZcapVerifier(allow_target_attenuation=True)

try:
    root = parser.parse_capability(root_dict)
    cap  = parser.parse_capability(cap_dict)
    inv  = parser.parse_invocation(invocation_dict)

    verifier.verify_delegation_chain(root, [cap])
    verifier.verify_invocation(inv, cap)
except ZcapError as e:
    # All failures are controlled ZcapError subclasses
    handle_error(e)
```

**Typical async usage pattern:**

```python
from zcap_py import ZcapParser, AsyncZcapVerifier
from zcap_py.exceptions import ZcapError

parser  = ZcapParser()
verifier = AsyncZcapVerifier(
    caveat_verifiers=[my_async_caveat_verifier],
    allow_target_attenuation=True,
)

try:
    root = parser.parse_capability(root_dict)
    cap  = parser.parse_capability(cap_dict)
    inv  = parser.parse_invocation(invocation_dict)

    await verifier.verify_delegation_chain(root, [cap])
    await verifier.verify_invocation(inv, cap)
except ZcapError as e:
    handle_error(e)
```

---

## 8. Dependencies

### 8.1 Runtime (core — `zcap-py`)

| Package        | Version  | Purpose                                     |
| -------------- | -------- | ------------------------------------------- |
| `cryptography` | `>=41.0` | Ed25519 key ops, constant-time verification |
| `base58`       | `>=2.1`  | Base58btc encode/decode for multibase-z     |

No other runtime dependencies. JCS is stdlib-only. Async support uses stdlib `asyncio`.

### 8.2 Runtime (`zcap-py-builder` — separate package)

| Package        | Version   | Purpose                          |
| -------------- | --------- | -------------------------------- |
| `zcap-py`      | `>=0.1.0` | Core models, JCS, DID resolution |
| `cryptography` | `>=41.0`  | Ed25519 signing                  |

### 8.3 Development (both repos)

| Package          | Purpose                                      |
| ---------------- | -------------------------------------------- |
| `pytest`         | Testing                                      |
| `pytest-cov`     | Coverage                                     |
| `pytest-asyncio` | Async test support (`asyncio_mode = "auto"`) |
| `anyio[trio]`    | Optional: test async under Trio backend      |
| `mypy`           | Type checking (`--strict`)                   |
| `ruff`           | Linting and formatting                       |

### 8.4 Optional Extras (`zcap-py`)

```toml
[project.optional-dependencies]
jsonld = ["pyld>=2.0"]   # Future: full JSON-LD expansion support
```

---

## 9. `pyproject.toml` Skeletons

### 9.1 `zcap-py` (core verifier)

```toml
[project]
name = "zcap-py"
version = "0.1.0"
description = "Authorization Capabilities for Linked Data — Python verification library"
readme = "README.md"
license = { text = "Apache-2.0" }
requires-python = ">=3.11"
dependencies = [
    "cryptography>=41.0",
    "base58>=2.1",
]

[project.optional-dependencies]
jsonld = ["pyld>=2.0"]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "pytest-asyncio>=0.23",
    "anyio[trio]>=4.0",
    "mypy>=1.10",
    "ruff>=0.4",
]

[project.urls]
Repository = "https://github.com/moisesja/zcap-py"
Changelog  = "https://github.com/moisesja/zcap-py/blob/main/CHANGELOG.md"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.mypy]
strict = true
python_version = "3.11"

[tool.ruff]
target-version = "py311"
line-length = 100

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.coverage.run]
source = ["zcap_py"]
branch = true

[tool.coverage.report]
fail_under = 90
```

### 9.2 `zcap-py-builder` (companion signing package)

```toml
[project]
name = "zcap-py-builder"
version = "0.1.0"
description = "Authorization Capabilities for Linked Data — Python document builder and signer"
readme = "README.md"
license = { text = "Apache-2.0" }
requires-python = ">=3.11"
dependencies = [
    "zcap-py>=0.1.0",
    "cryptography>=41.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "pytest-asyncio>=0.23",
    "mypy>=1.10",
    "ruff>=0.4",
]

[project.urls]
Repository = "https://github.com/moisesja/zcap-py-builder"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.mypy]
strict = true
python_version = "3.11"

[tool.ruff]
target-version = "py311"
line-length = 100

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

---

## 10. Implementation Phases

Three repositories are built in parallel where indicated. All phases target `zcap-py` unless noted.

### Phase 1 — Crypto & DID Foundation (Week 1)

**`zcap-py`**

- [ ] `zcap_py/exceptions.py` — full `ZcapError` hierarchy including `ZcapParseError`
- [ ] `zcap_py/crypto/multibase.py` — z-base58btc encode/decode
- [ ] `zcap_py/crypto/multicodec.py` — 0xed01 Ed25519 prefix
- [ ] `zcap_py/crypto/ed25519.py` — keygen (verify-only in core; `generate_ed25519_keypair` needed for test fixtures)
- [ ] `zcap_py/did/url.py` — DID URL strict parse/validate
- [ ] `zcap_py/did/key.py` — did:key encode/decode/resolve
- [ ] Tests: `test_crypto.py`, `test_did.py`

### Phase 2 — JCS, Proof Verification & Parser (Week 1–2)

**`zcap-py`**

- [ ] `zcap_py/jcs/canonicalize.py` — RFC 8785 (stdlib only; float via ES2019 ToString)
- [ ] `zcap_py/proof/models.py` — `LinkedDataProof` dataclass
- [ ] `zcap_py/proof/ed25519_2020.py` — verification only
- [ ] `zcap_py/zcap/models.py` — `Capability`, `Invocation`, `VerificationMethod` frozen dataclasses (no parsing logic)
- [ ] `zcap_py/zcap/parser.py` — `ZcapParser` with all `_require_*` helpers
- [ ] Tests: `test_jcs.py` (RFC 8785 Appendix B vectors), `test_proof.py`, `test_parser.py`

**`zcap-py-builder`** (starts here)

- [ ] `zcap_py_builder/proof/ed25519_2020.py` — `sign()` function
- [ ] `zcap_py_builder/capability_builder.py` — fluent `CapabilityBuilder`
- [ ] `zcap_py_builder/invocation_builder.py` — fluent `InvocationBuilder`
- [ ] Tests: `test_builder.py`, `test_signer.py`

### Phase 3 — Delegation, Invocation & Target Attenuation (Week 2)

**`zcap-py`**

- [ ] `zcap_py/zcap/target_attenuation.py` — `InvocationTargetAttenuator` Protocol + `PathPrefixAttenuator`
- [ ] `zcap_py/zcap/caveats.py` — `CaveatVerifier` Protocol, `AsyncCaveatVerifier` Protocol, `CaveatRegistry`
- [ ] `zcap_py/zcap/delegation.py` — sync delegation chain verifier
- [ ] `zcap_py/zcap/invocation.py` — sync invocation verifier
- [ ] `zcap_py/zcap/verifier.py` — `ZcapVerifier` sync facade
- [ ] Tests: `test_delegation.py`, `test_invocation.py`, `test_target_attenuation.py`, `test_caveats.py`

### Phase 4 — Async Verifier & Fixture Integration (Week 3)

**`zcap-py`**

- [ ] `zcap_py/zcap/async_verifier.py` — `AsyncZcapVerifier` wrapping sync internals via `asyncio.to_thread`; native `AsyncCaveatVerifier` dispatch
- [ ] Tests: `test_async_verifier.py` — pytest-asyncio, covering both `asyncio` and `trio` backends via `anyio`

**`zcap-ld-fixtures`** (new standalone repo — initialized here)

- [ ] `generators/generate_fixtures.py` — deterministic fixture generation using fixed seed keys (Alice, Bob, Carol)
- [ ] Generates all fixture files: `valid/`, `invalid/`, `keypairs/`, plus `jcsCanonicalSha256` fields
- [ ] `generators/GenerateFixtures.cs` — .NET equivalent (produces identical JSON)
- [ ] `schema/capability.schema.json`, `schema/invocation.schema.json`

**`zcap-py`** (fixture integration)

- [ ] Add `zcap-ld-fixtures` as git submodule at `tests/fixtures/`
- [ ] `tests/test_fixtures.py` — parameterized round-trip over all fixture files
- [ ] `tests/test_jcs_parity.py` — SHA-256 hash of canonicalized documents matched against `jcsCanonicalSha256`

### Phase 5 — Cross-Language Parity Validation & Publication (Week 3–4)

- [ ] Add `zcap-ld-fixtures` submodule to `zcap-dotnet` at same path `tests/fixtures/`
- [ ] Run `zcap-dotnet` fixture suite against shared fixtures; confirm zero failures
- [ ] Confirm JCS byte-identity via `jcsCanonicalSha256` on all fixture documents
- [ ] `mypy --strict` passes on `zcap-py` and `zcap-py-builder`
- [ ] Coverage ≥ 90% on both packages
- [ ] README, CHANGELOG, API reference docs
- [ ] PyPI publish: `zcap-py` then `zcap-py-builder`

---

## 11. Design Decisions & Rationale

### 11.1 Why no `pyld` in core?

Full JSON-LD processing (expansion, compaction, framing) is complex, slow, and pulls in significant transitive dependencies including a network-capable context loader. The W3C ZCAP-LD spec requires JSON-LD semantics for full compliance, but the cryptographic security kernel operates on **the serialized document as-is** after JCS canonicalization. Deferring `pyld` means:

- The core library has zero network I/O
- JCS is applied to the raw dict before any JSON-LD transformation
- Full JSON-LD compatibility can be layered on as an optional extra without changing any core verification logic

This is consistent with the approach taken in `zcap-dotnet`.

### 11.2 Why JCS (RFC 8785) over RDF Dataset Normalization (URDNA2015)?

URDNA2015 requires a full RDF parser and a bnode canonicalization algorithm. For `did:key`-only documents with no blank nodes and deterministic key generation, JCS is sufficient for proof serialization and produces cross-language-verifiable output. URDNA2015 can be added as an optional serializer later when full JSON-LD compliance is pursued.

### 11.3 Why `cryptography` and not `PyNaCl`?

`cryptography` is the de facto standard in the Python ecosystem, maintained by the Python Cryptographic Authority, and supports Ed25519 natively since version 2.6. It avoids the libsodium binding complexity of `PyNaCl` and aligns with what most production Python applications already have installed.

### 11.4 Why `Protocol` for `CaveatVerifier` and `AsyncCaveatVerifier` instead of ABC?

Structural subtyping via `Protocol` means third-party caveat implementations don't need to import anything from `zcap-py`. A class in an entirely separate package that has `caveat_type: str` and the correct `verify` signature is automatically compatible. `runtime_checkable` enables `isinstance` checks in the registry. This is the correct Pythonic design for plugin systems — identical in spirit to the `ICaveatVerifier` interface in `zcap-dotnet`.

### 11.5 Fail-closed on unknown caveats

If a `capability.caveat` entry carries a `type` for which no verifier is registered, `zcap-py` raises `UnknownCaveatError`. This is a deliberate **fail-closed** design: an invoker cannot gain access through a capability whose caveats the verifier cannot evaluate. This mirrors the identical principle in `zcap-dotnet`.

### 11.6 Root capability is caller-trusted

`verify_delegation_chain(root, chain)` does **not** verify the root capability's own proof. The caller is responsible for establishing root trust (e.g., confirming the root was issued by a known root controller or is self-attested). This is consistent with the ZCAP-LD spec: the root is the trust anchor and its authenticity is an application-layer concern.

### 11.7 `raw: dict` on models

Each `Capability` and `Invocation` dataclass carries the original parsed `raw: dict`. This serves two purposes: (1) caveat verifiers may need fields the core model does not map; (2) round-trip serialization back to JSON is lossless. Models do not attempt to be exhaustive representations of every possible extension field.

### 11.8 `ZcapParser` as a dedicated class, not `from_dict()` classmethods (OQ-1 → resolved)

Parsing logic is concentrated in `ZcapParser`, keeping models as pure frozen value objects. This separation of concerns means:

- Models cannot be constructed in an invalid state by accident (no default-argument footguns)
- The parser is independently testable
- Future parsers (e.g., a lenient parser for migration tooling, or a streaming parser) can be introduced without touching the models
- The parser can accumulate all field errors before raising, rather than failing on the first one

### 11.9 `zcap-py-builder` as a separate package (OQ-2 → resolved)

Signing requires `Ed25519PrivateKey` material. Keeping private key handling in a separate package makes the threat surface of `zcap-py` (verification-only) auditable in isolation. An auditor reviewing `zcap-py` does not need to reason about signing paths. `zcap-py-builder` is a higher-privilege package that a deployment may choose not to install in its verifier-only components (e.g., a gateway that only verifies, never signs).

### 11.10 `zcap-ld-fixtures` as a standalone language-neutral repo (OQ-3 → resolved)

Fixtures are shared data, not code. A standalone repo with its own versioning means:

- `zcap-py` and `zcap-dotnet` both pin to the same fixture commit via git submodule
- Future language implementations (Go, Rust, TypeScript) can consume the same fixtures without cross-language build dependencies
- Fixture versioning is decoupled from library versioning — a new fixture set doesn't require a library release

### 11.11 `PathPrefixAttenuator` follows `zcap-dotnet` semantics exactly (OQ-4 → resolved)

The path-prefix narrowing rules (same scheme, same authority, child path starts with parent path after trailing-slash normalization, query/fragment freely variable) are identical to `zcap-dotnet`'s `PathPrefixAttenuator`. This enables the same `delegation_target_narrowed.json` fixture to validate in both language implementations without any semantic gap.

### 11.12 `AsyncZcapVerifier` in v0.1 via `asyncio.to_thread` (OQ-5 → resolved)

Ed25519 verification is CPU-bound, not I/O-bound. The correct async wrapper is `asyncio.to_thread()`, which offloads CPU work to the default thread pool without blocking the event loop. This makes `AsyncZcapVerifier` a thin, correct wrapper over `ZcapVerifier` internals with no code duplication. Native async is reserved for `AsyncCaveatVerifier` implementations that may need to perform network I/O (e.g., checking a revocation registry). The `anyio` test backend confirms the async API works under both `asyncio` and `trio`.

### 11.13 W3C URDNA2015 verifier as optional complement to JCS verifier

The core JCS-based `verify_document_proof()` remains the default for `zcap-dotnet` interop. A new `verify_document_proof_w3c()` uses the real W3C Ed25519Signature2020 algorithm: URDNA2015 canonicalization of proof options and document separately, SHA-256 hash of each canonical form, concatenated into a 64-byte `verify_data`, then Ed25519 signature verification. This requires `pyld` which is gated behind the `jsonld` optional extra (`pip install zcap-py[jsonld]`). Bundled JSON-LD contexts (ZCAP v1, Ed25519Signature2020 v1) eliminate network I/O. Unknown context URLs raise `CanonicalizationError` (fail-closed). The two verifiers are intentionally incompatible: a JCS-signed document will not pass the W3C verifier, and vice versa.

---

## 12. Security Considerations

| Concern                                  | Mitigation                                                                                                                                                                                                                                                                                                                                                    |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Root capability spoofing                 | Root capabilities have no verifiable proof; the verifier deliberately does not verify them. The caller must establish root trust through an out-of-band mechanism (e.g., comparing `root.id` against a known registry, or confirming `root.controller` matches the resource's known owner DID). This is documented as a contract in `verify_delegation_chain` |
| Timing attacks on signature verification | Delegated to `cryptography` library which uses constant-time comparison internally                                                                                                                                                                                                                                                                            |
| Malformed document injection             | All raw-dict input gated through `ZcapParser` before any verification; `ZcapParseError` raised before cryptographic operations begin                                                                                                                                                                                                                          |
| Malformed DID injection                  | DID parsing in `did/url.py` uses strict regex + structural validation; raises `DidParseError` on any deviation                                                                                                                                                                                                                                                |
| Proof stripping attack                   | `ZcapParser` requires `proof` on invocations unconditionally; missing proof raises `ZcapParseError` at parse time, before verification                                                                                                                                                                                                                        |
| Confused deputy                          | Invoker identity is the capability `controller` only (the legacy `invoker` override was removed — it diverged from the current spec and `@digitalbazaar/zcap`); authority binds to the cryptographically verified chain leaf, never inferred from invoker-supplied/embedded content                                                                              |
| Caveat bypass                            | Fail-closed: unknown caveat types raise `UnknownCaveatError`; verifier never silently skips unrecognized caveats                                                                                                                                                                                                                                              |
| JCS non-determinism                      | Float serialization tested against RFC 8785 Appendix B test vectors; `canonicalize()` returns `bytes`, not `str`, preventing encoding ambiguity at the boundary                                                                                                                                                                                               |
| Chain truncation                         | `verify_delegation_chain` verifies every link in order; a partial chain is detected by the `parentCapability` linkage check at the first gap                                                                                                                                                                                                                  |
| invocationTarget broadening              | `PathPrefixAttenuator.is_valid_attenuation` returns `False` on any broadening; `InvocationTargetError` is always raised, never silently allowed                                                                                                                                                                                                               |
| Async thread safety                      | `AsyncZcapVerifier` uses `asyncio.to_thread()` for CPU-bound crypto; no shared mutable state between threads; `ZcapVerifier` is stateless after construction                                                                                                                                                                                                  |

---

## 13. Relationship to `zcap-dotnet` and Ecosystem

| Aspect               | `zcap-dotnet` (C#/.NET 10)        | `zcap-py` (Python 3.11)                     |
| -------------------- | --------------------------------- | ------------------------------------------- |
| Language             | C#                                | Python                                      |
| Package role         | Verification core                 | Verification core                           |
| Signing / building   | `zcap-dotnet` (same package)      | `zcap-py-builder` (separate package)        |
| DID methods          | did:key (initial), extensible     | did:key (initial), extensible               |
| Signature suite      | Ed25519Signature2020              | Ed25519Signature2020                        |
| Canonicalization     | RFC 8785 (`JsonCanonicalization`) | RFC 8785 (stdlib native)                    |
| Document parsing     | `ZcapDocumentParser` class        | `ZcapParser` class                          |
| Exception model      | Typed exception hierarchy         | Typed `ZcapError` hierarchy                 |
| Caveat mechanism     | `ICaveatVerifier` interface       | `CaveatVerifier` Protocol (sync + async)    |
| Target attenuation   | `PathPrefixAttenuator`            | `PathPrefixAttenuator` (identical rules)    |
| Async support        | N/A (.NET Task-based)             | `AsyncZcapVerifier` + `AsyncCaveatVerifier` |
| Fixture source       | `zcap-ld-fixtures` submodule      | `zcap-ld-fixtures` submodule                |
| JSON-LD processing   | Deferred                          | Deferred                                    |
| Package distribution | NuGet                             | PyPI                                        |

---

## 14. Resolved Decisions

All open questions from the initial draft have been resolved. No open questions remain for v0.1.

| OQ   | Question                                                 | Resolution                                                                                                                                              |
| ---- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OQ-1 | `from_dict()` classmethods vs. separate `Parser` class?  | **Separate `ZcapParser` class.** Models are pure frozen value objects; all parsing, validation, and error raising is in `ZcapParser`. See §11.8         |
| OQ-2 | Signing in core or separate `zcap-py-builder` package?   | **`zcap-py-builder` — separate package.** Core is verification-only. Reduces audit surface. See §11.9                                                   |
| OQ-3 | Fixtures as submodule in `TurtleShell-id/zcap-fixtures`? | **Standalone `zcap-ld-fixtures` repo**, consumed as a git submodule by both `zcap-py` and `zcap-dotnet`. See §11.10                                     |
| OQ-4 | How to express `invocationTarget` attenuation rules?     | **Path-prefix narrowing, identical to `zcap-dotnet`'s `PathPrefixAttenuator`.** Same scheme + authority + child path ⊇ parent path. See §5.4 and §11.11 |
| OQ-5 | Async support in v0.1 or defer to v0.2?                  | **In v0.1.** `AsyncZcapVerifier` via `asyncio.to_thread`; `AsyncCaveatVerifier` Protocol for native async caveats. See §5.3 and §11.12                  |
