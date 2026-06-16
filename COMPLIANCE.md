# ZCAP-LD Compliance Matrix — `zcap-py`

**Assessed:** 2026-06-16  
**Against:** [W3C ZCAP-LD draft](https://w3c-ccg.github.io/zcap-spec/) + the digitalbazaar reference ecosystem (`@digitalbazaar/zcap`, `@digitalbazaar/ed25519-signature-2020`, `@digitalbazaar/jsonld-signatures`)  
**Library version:** 0.6.0  
**Goal:** Full interop with the W3C / digitalbazaar ZCAP ecosystem. `zcap-dotnet` mirrors each change (see [§ zcap-dotnet mirror](#zcap-dotnet-mirror)).

> Methodology: a 12-agent audit mapped each normative MUST/SHOULD/MAY to the implementation (`file:line` evidence) and to a byte-exact reference check of the `Ed25519Signature2020` verify-data construction against `@digitalbazaar/jsonld-signatures`. Each gap is tracked by a GitHub issue.

## Scorecard

| Status | All requirements | MUST-level only |
|---|---|---|
| ✅ Compliant | 24 | 21 |
| 🟡 Partial | 37 | 30 |
| ❌ Non-compliant | 18 | 12 |
| ⚪ Absent | 5 | 2 |
| **Total** | **84** | **65** |

**~29% of all requirements** and **~32% of MUST-level requirements** are currently met. The dominant gap is that the default (and only auto-wired) proof path is JCS, not the W3C `Ed25519Signature2020` (URDNA2015) algorithm — so out of the box the library does not interoperate with digitalbazaar. The audit also found several **fail-open security holes** beyond pure spec gaps (see #9, #12, #20).

## Executive summary

## zcap-py W3C ZCAP-LD / digitalbazaar compliance — current posture

**Headline:** The library has a correct, well-tested *skeleton* (did:key crypto, document parsing, delegation-chain structure, expiry/target/action attenuation, fail-closed JSON-LD loader, and a working W3C URDNA2015 verifier). But its **default and only auto-wired proof path is JCS (RFC 8785)**, which is *not* the W3C Ed25519Signature2020 algorithm and does **not** interoperate with `@digitalbazaar/zcap` or `@digitalbazaar/ed25519-signature-2020`. The compliant URDNA2015 verifier (`verify_document_proof_w3c`) exists but is orphaned — reachable only by explicitly injecting `proof_verifier=`. Out of the box, the library verifies against the wrong algorithm.

**Root dependency for all proof work:** Per the (fixed) product decision, JCS must be removed entirely, URDNA2015 must become the only path, and `pyld` must become a core dependency. This single change (`proof-w3c-default-remove-jcs`) is the foundation; almost every other proof, example, test, and doc gap cascades from it. **Existing issues #5 and #8 are JCS↔zcap-dotnet interop tasks and are obsoleted/superseded by JCS removal — they should be closed as won't-fix once `proof-w3c-default-remove-jcs` lands.**

**What full compliance requires, in dependency order:**
1. **P0 — Proof algorithm:** Make `verify_document_proof_w3c` the sole/default verifier in `delegation.py`, `invocation.py`, and `ZcapVerifier`; delete the JCS module/exports/tests/examples/fixtures; relocate the shared proof helpers; make `pyld` core, drop `rfc8785`. Add a public W3C *signer* (today the library can only *verify* W3C proofs, never *produce* them). Lock concatenation order (`proofHash || docHash`) against a real digitalbazaar known-answer vector — this is the single highest-risk interop assumption.
2. **P0 — Document shape / spec MUSTs:** Delegated `expires` must be REQUIRED; the bespoke `type:"Invocation"` wrapper diverges from the spec's "invocation IS a `capabilityInvocation` Data Integrity proof over the target" model and from digitalbazaar; the proof's `invocationTarget` is signed but never parsed/checked.
3. **P0 — Security MUSTs:** `capabilityChain[0]` is trusted as root with its proof skipped *without any `is_root` check* (forged-root / chain-substitution hole); a delegated capability invoked without a chain is accepted with its delegation proof never verified; ancestor caveats are silently skipped when no chain is supplied (fail-open); the lower-level `verify_invocation` skips expiry and caveats entirely.
4. **P1 — Structural/algorithmic:** root `id` must be `urn:zcap:root:*`; delegated `@context` must be an array; `allowedAction` must accept a string; remove legacy `invoker`; enforce `proofPurpose`/verification-relationship at verify time; add a `maxChainLength` (default 10); materialize inherited `allowedAction`/`expires`/caveats so mid-chain re-broadening is impossible; align target-attenuation default and the invocation-time target check; validate `did:key` VM fragment==identifier on every path.
5. **P1/P2 — Security hardening & docs:** replay protection hooks (nonce/created-window/domain), a revocation hook, `document_loader` SSRF guidance, expected-root/target binding; rewrite `prd-design.md` (declared source of truth), README, and CHANGELOG to mandate URDNA2015-only + pyld-core and stop advertising JCS.

When every issue below is closed, the library will verify and produce W3C Ed25519Signature2020 proofs that round-trip with the digitalbazaar ecosystem, enforce all ZCAP-LD structural and security MUSTs by default (not opt-in), and have no JCS surface remaining. The companion `zcap-dotnet` requires the mirrored changes noted per issue.

## Issue index

| Priority | Issue | Title |
|---|---|---|
| P0 | [#9](https://github.com/moisesja/zcap-py/issues/9) | P0: Enforce genuine-root trust anchor for capabilityChain (is_root + local trusted root dereference + root↔target binding); never skip proof for a non-root |
| P0 | [#10](https://github.com/moisesja/zcap-py/issues/10) | P0: Require expires on delegated capabilities (reject missing expires at parse time) |
| P0 | [#11](https://github.com/moisesja/zcap-py/issues/11) | P0: Replace the bespoke type:"Invocation" wrapper with the spec/digitalbazaar capabilityInvocation Data Integrity proof model (single proof over the target; parse & check proof.invocationTarget) |
| P0 | [#12](https://github.com/moisesja/zcap-py/issues/12) | P0: Require a verifiable, root-anchored chain to verify the invoked delegated capability's own delegation proof |
| P0 | [#13](https://github.com/moisesja/zcap-py/issues/13) | P0: Make W3C URDNA2015 the only/default proof path; remove JCS entirely (module, exports, package, rfc8785); make pyld a core dependency |
| P0 | [#14](https://github.com/moisesja/zcap-py/issues/14) | P0: Add a public W3C Ed25519Signature2020 signer + digitalbazaar cross-impl known-answer test (lock concatenation order, suite-context, @context handling) |
| P1 | [#15](https://github.com/moisesja/zcap-py/issues/15) | P1: Tighten capability structural validation (root @context string + URN id; delegated @context array + required proof; accept string allowedAction; advisory urn:uuid) |
| P1 | [#16](https://github.com/moisesja/zcap-py/issues/16) | P1: Enforce capabilityChain ordering, positional embed/reference shape, and no-duplicate/no-cycle invariants |
| P1 | [#17](https://github.com/moisesja/zcap-py/issues/17) | P1: Validate did:key VM fragment == key identifier in public_key_from_did_key (all proof paths) |
| P1 | [#18](https://github.com/moisesja/zcap-py/issues/18) | P1: Rewrite prd-design.md, README, CONTRIBUTING, and CHANGELOG to mandate URDNA2015-only + pyld-core and remove all JCS feature claims |
| P1 | [#19](https://github.com/moisesja/zcap-py/issues/19) | P1: Materialize inherited allowedAction, expires, and caveats across the chain (close mid-chain re-broadening; enforce effective restrictions at invocation) |
| P1 | [#20](https://github.com/moisesja/zcap-py/issues/20) | P1: Make the lower-level verify_invocation / verify_delegation_chain enforce absolute expiry and fail-closed caveats (no fail-open bypass via the public API) |
| P1 | [#21](https://github.com/moisesja/zcap-py/issues/21) | P1: Harden document_loader (SSRF guidance/safe default) and bind the verified chain to the signed proof.capabilityChain |
| P1 | [#22](https://github.com/moisesja/zcap-py/issues/22) | P1: Add a configurable maxChainLength (default 10) and optional delegation TTL ceiling |
| P1 | [#23](https://github.com/moisesja/zcap-py/issues/23) | P1: Remove the legacy invoker field; use controller-only for invoker identity (current spec) |
| P1 | [#24](https://github.com/moisesja/zcap-py/issues/24) | P1: Add invocation replay-protection hooks (nonce/seen-id store, created freshness window, domain/challenge binding) |
| P1 | [#25](https://github.com/moisesja/zcap-py/issues/25) | P1: Provide a pluggable revocation hook (RevocationStore) and document the persist-until-expiry requirement |
| P1 | [#26](https://github.com/moisesja/zcap-py/issues/26) | P1: Align invocationTarget attenuation default + invocation-time check + absolute-URI validation; reconcile dotnet/digitalbazaar parity claims and prefix-comparison algorithm |
| P1 | [#27](https://github.com/moisesja/zcap-py/issues/27) | P1: Remove/migrate all JCS tests, fixtures, examples, and conftest helpers to the W3C path |
| P1 | [#28](https://github.com/moisesja/zcap-py/issues/28) | P1: Enforce proofPurpose and verification-relationship authorization at verify time (not only at parse) |
| P2 | [#29](https://github.com/moisesja/zcap-py/issues/29) | P2: Expand bundled context coverage (DID v1 / security contexts), memoize the offline loader, and pin the offline loader globally |

## Compliance matrix

### Capability structure

| Requirement | Level | Status | Evidence | Gap | Issue |
|---|---|---|---|---|---|
| Root @context MUST be the bare string "https://w3id.org/zcap/v1" (reject array form for roots) | MUST | 🟡 | `parser.py:62,214-234 _validate_context accepts string OR array for all docs; root branch parser.py:69-86 does not re-restrict to string-only` | A root with an array @context is wrongly accepted | [#15](https://github.com/moisesja/zcap-py/issues/15) |
| Root id MUST be a URN and SHOULD be urn:zcap:root:<encodeURIComponent(invocationTarget)> | SHOULD | ❌ | `parser.py:63,78 _require_str only checks non-empty string; no urn:/urn:zcap:root: check` | Non-URN root ids (e.g. https URIs) accepted; not enforced/derived; breaks @digitalbazaar/zcap root derivation | [#15](https://github.com/moisesja/zcap-py/issues/15) |
| Root MUST NOT have fields beyond @context, id, controller, invocationTarget (no proof/expires/parentCapability/type/invoker) | MUST | ✅ | `parser.py:18-20 _ROOT_ALLOWED_FIELDS; parser.py:71-76 rejects extras` | — |  |
| Delegated @context MUST be an array whose first value is the zcap context | MUST | 🟡 | `parser.py:62,214-234 accepts bare string @context for delegated docs too` | String-only @context accepted on delegated caps; breaks URDNA2015 (suite context missing) | [#15](https://github.com/moisesja/zcap-py/issues/15) |
| Delegated capability MUST have an expires field (XSD date-time) | MUST | ❌ | `parser.py:91,320-323 _parse_expires returns None when absent; delegated cap built with expires possibly None` | Missing expires silently accepted; diverges from @digitalbazaar/zcap which requires it | [#10](https://github.com/moisesja/zcap-py/issues/10) |
| Delegated capability MUST have id, parentCapability, controller, AND proof | MUST | 🟡 | `id/controller/parentCapability required; proof only parsed if present (parser.py:100); delegated cap can be built with proof=None` | Standalone parse of a delegated cap with no proof wrongly succeeds | [#15](https://github.com/moisesja/zcap-py/issues/15) |
| Delegated id SHOULD be urn:uuid:<uuid> | SHOULD | ❌ | `parser.py:63,103 id only validated as non-empty string` | No urn:uuid advisory/check; documented as example only | [#15](https://github.com/moisesja/zcap-py/issues/15) |
| allowedAction MAY be a string OR an array of strings | MAY | ❌ | `parser.py:307-318 _parse_optional_action_list requires isinstance(v,list); string raises ZcapParseError` | digitalbazaar allowedAction:"read" (string) fails to parse — interop break | [#15](https://github.com/moisesja/zcap-py/issues/15) |
| Current spec does NOT define a capability "type" field; it must not be required/expected | SHOULD | 🟡 | `parser.py:89 _validate_optional_type("Authorization") rejects other types when present; invocation requires type=="Invocation" (parser.py:127)` | Legacy type:Authorization concept carried; invocation type mandatory — spec-undefined constraints | [#11](https://github.com/moisesja/zcap-py/issues/11) |
| Legacy "invoker" field is NOT part of the current spec (controller only) | SHOULD | ❌ | `models.py:24 invoker field; parser.py:109 parses it; invocation.py:77 invoker overrides controller` | Library models/honors legacy invoker, overriding controller — diverges from spec & digitalbazaar | [#23](https://github.com/moisesja/zcap-py/issues/23) |
| Delegated capability MUST have a parentCapability (non-empty string) | MUST | ✅ | `parser.py:67,93-98; delegation.py:71-78 enforces linkage` | — |  |
| controller MAY be a single URI string or an array of strings | MAY | ✅ | `parser.py:255-291 accepts str or list, validates each via parse_did; models.py:19` | Narrowed to did:key only (non-DID URIs rejected) — acceptable for scoped library, documented |  |

### Invocation model

| Requirement | Level | Status | Evidence | Gap | Issue |
|---|---|---|---|---|---|
| Invocation MUST be a Data Integrity proof (proofPurpose=capabilityInvocation) over the target; spec defines NO standalone type:"Invocation" object | MUST | ❌ | `models.py:35-44 standalone Invocation; parser.py:127 mandates type:"Invocation"; duplicated body capability/invocationTarget` | Bespoke wrapper not recognized by digitalbazaar; a real digitalbazaar invocation is rejected at parser.py:127 | [#11](https://github.com/moisesja/zcap-py/issues/11) |
| Body-level capability/invocationTarget should not be duplicated; carried in the proof | SHOULD | ❌ | `models.py:39-41; parser.py:128,131-148; invocation.py:55-63 reconcile body vs proof` | Redundant body fields require consistency checks that only exist because of the divergence | [#11](https://github.com/moisesja/zcap-py/issues/11) |
| proof.invocationTarget MUST be parsed and cross-checked against the capability/request target | MUST | 🟡 | `proof/models.py:8-19 LinkedDataProof has no invocation_target; parser.py:430-441 never extracts proof.invocationTarget; invocation.py:65-73 checks body only` | Signed proof.invocationTarget ignored; malicious proof target unchecked — interop + security gap | [#11](https://github.com/moisesja/zcap-py/issues/11) |
| Invocation verification SHOULD provide replay protection (nonce / created-window / domain / one-time id) | SHOULD | ⚪ | `No nonce/created-freshness/domain handling in invocation.py/parser.py/models.py; proof nonce parsed nowhere` | Invocation proof is a replayable bearer token; no defense or hooks | [#24](https://github.com/moisesja/zcap-py/issues/24) |

### Proof / Data Integrity

| Requirement | Level | Status | Evidence | Gap | Issue |
|---|---|---|---|---|---|
| Delegation & invocation proof verification MUST use W3C Ed25519Signature2020 (URDNA2015 + double SHA-256) as the only/default path | MUST | ❌ | `delegation.py:16,128 & invocation.py:107 default to JCS verify_document_proof; verifier.py:67 proof_verifier=None; ed25519_2020.py:83-112 is JCS` | Default path is JCS — non-conformant, incompatible with digitalbazaar; W3C path is opt-in only | [#13](https://github.com/moisesja/zcap-py/issues/13) |
| JCS proof module + zcap_py.jcs package + rfc8785 dep MUST be removed; pyld becomes core | MUST | ❌ | `ed25519_2020.py:1-182 JCS; jcs/canonicalize.py; pyproject.toml:25 rfc8785 core, :28-29 pyld optional` | JCS module/package present; pyld optional so default install cannot run W3C path | [#13](https://github.com/moisesja/zcap-py/issues/13) |
| Public API MUST NOT export JCS proof/canonicalization functions once JCS removed | MUST | ❌ | `__init__.py:35-40,73,76-78 export canonicalize, build_canonical_payload, sign_document_proof, verify_document_proof` | Four JCS symbols are first-class public API; W3C path is the suffixed afterthought | [#13](https://github.com/moisesja/zcap-py/issues/13) |
| Proof options MUST be canonicalized with document @context injected before URDNA2015 | MUST | ✅ | `ed25519_2020_w3c.py:56-61 drops sig fields, injects document @context; canonicalized :67` | — |  |
| Unsigned doc + proof options each URDNA2015-canonicalized, SHA-256, concatenated to 64-byte verify_data | MUST | ✅ | `ed25519_2020_w3c.py:64,67-73,76` | — |  |
| Concatenation order MUST be proofHash \|\| docHash, byte-identical to @digitalbazaar/jsonld-signatures createVerifyData | MUST | 🟡 | `ed25519_2020_w3c.py:73 proof_hash+doc_hash; self-consistent across conftest.py:84 & example` | No cross-library known-answer test against a digitalbazaar-generated proof to prove byte parity | [#14](https://github.com/moisesja/zcap-py/issues/14) |
| A public W3C URDNA2015 signing API MUST exist (library must PRODUCE W3C proofs, not only verify) | MUST | ❌ | `Only public signer is JCS sign_document_proof (ed25519_2020.py:60-80); W3C signing only in conftest.py:68-105 / example inline` | After JCS removal the library has NO public signer; cannot produce W3C proofs | [#14](https://github.com/moisesja/zcap-py/issues/14) |
| Bundled JSON-LD contexts MUST cover all contexts needed to canonicalize verified docs (zcap v1, ed25519-2020 v1, DID where used) | MUST | 🟡 | `context_loader.py:16-19 bundles zcap/v1 + ed25519-2020/v1 only; no did/v1 or security/v2` | Docs referencing DID/security contexts fail-closed; coverage narrower than digitalbazaar ecosystem | [#29](https://github.com/moisesja/zcap-py/issues/29) |
| JSON-LD document loader MUST fail-closed on unknown URLs (no network I/O) | MUST | ✅ | `context_loader.py:31-43 serves bundled only, raises on unknown; canonicalize.py:43 wires it` | — |  |
| Bundled contexts MUST be byte-faithful to canonical digitalbazaar contexts | MUST | ✅ | `zcap-v1.jsonld & ed25519-signature-2020-v1.jsonld match published contexts term-for-term` | — |  |
| URDNA2015 must be implemented natively or via a correct library (pyld acceptable) | MUST | ✅ | `canonicalize.py:36-45 pyld jsonld.normalize URDNA2015 / application/n-quads` | — |  |
| Verification SHOULD reject/handle documents lacking @context (degenerate URDNA2015) | SHOULD | 🟡 | `ed25519_2020_w3c.py:60-64 injects @context only if present; no required check` | Context-less doc could verify over near-empty verify_data, weakening binding | [#14](https://github.com/moisesja/zcap-py/issues/14) |
| W3C proof options MUST carry the ed25519-2020 suite context so proof terms expand identically to digitalbazaar | MUST | 🟡 | `ed25519_2020_w3c.py:56-61 copies only document @context; does not ensure suite context present` | Correctness depends on caller's document @context; suite context not injected like digitalbazaar's suite | [#14](https://github.com/moisesja/zcap-py/issues/14) |
| W3C path shared helpers (extract/validate/decode/resolve VM) MUST survive JCS-module deletion | SHOULD | 🟡 | `ed25519_2020_w3c.py:23-28 imports _extract_proof,_validate_proof_type,_decode_proof_value,_resolve_verification_key from JCS module` | Deleting JCS module wholesale would break the W3C path; helpers must be relocated | [#13](https://github.com/moisesja/zcap-py/issues/13) |

### Delegation chain

| Requirement | Level | Status | Evidence | Gap | Issue |
|---|---|---|---|---|---|
| Signer (VM DID, fragment stripped) of each link MUST be a controller of the PARENT | MUST | ✅ | `delegation.py:59-68; helper :28-32` | — |  |
| Signer MUST be authorized for the parent controller's capabilityDelegation relationship; proofPurpose MUST be honored at verify time | MUST | 🟡 | `delegation.py:59-68 string-compares signer==controller; proofPurpose only checked at parse (parser.py:100,398-411); no relationship resolution` | No controller DID-document resolution / relationship gate; proofPurpose not re-bound during chain verification | [#28](https://github.com/moisesja/zcap-py/issues/28) |
| child.parentCapability MUST equal parent.id | MUST | ✅ | `delegation.py:70-78` | — |  |
| child.allowedAction MUST be a subset of parent's; absent child must not silently re-broaden across the chain | MUST | 🟡 | `delegation.py:80-92 subset only when both non-None; per-adjacent-pair only` | Mid-chain omission of allowedAction resets to unrestricted, allowing grandchild re-broadening | [#19](https://github.com/moisesja/zcap-py/issues/19) |
| child.expires MUST NOT exceed parent.expires (attenuation) | MUST | ✅ | `delegation.py:94-102` | — |  |
| Each capability in the chain MUST NOT be expired at verification time (absolute expiry) | MUST | 🟡 | `verify_delegation_chain (delegation.py:131-173) has no clock/now check; absolute expiry only in verifier.py:145-159 invocation path` | Standalone verify_delegation_chain accepts an expired capability | [#20](https://github.com/moisesja/zcap-py/issues/20) |
| child.invocationTarget MUST equal parent's or be a valid narrowing; broadening rejected | MUST | ✅ | `delegation.py:104-125; PathPrefixAttenuator target_attenuation.py:41-71` | (Default exact-match is safe; attenuation default alignment tracked separately) |  |
| Caveats from ALL ancestors MUST be inherited/enforced (delegation-time caveats evaluated where applicable) | MUST | 🟡 | `verify_delegation_chain/_verify_delegation_link reference no caveats; enforcement only in verifier.py:169-175 invocation flow when chain>1` | Pure chain verification ignores caveats; delegation-constraining caveats never evaluated | [#19](https://github.com/moisesja/zcap-py/issues/19) |
| Chain length MUST be limited (SHOULD <= 10) to prevent long-chain/DoS | SHOULD | ⚪ | `No max-length check in delegation.py:131-173 or verifier.py` | Arbitrary-length chains processed fully; digitalbazaar default maxChainLength=10 | [#22](https://github.com/moisesja/zcap-py/issues/22) |
| Delegated expiry SHOULD NOT be > ~3 months in the future (TTL ceiling) | SHOULD | ⚪ | `No 90-day/timedelta logic anywhere in src` | TTL ceiling recommendation entirely unimplemented | [#22](https://github.com/moisesja/zcap-py/issues/22) |
| Each delegated link's proof MUST be cryptographically verified with W3C Ed25519Signature2020 | MUST | ❌ | `delegation.py:16,128 default to JCS verify_document_proof` | Secure path is opt-in; default chain verification is JCS | [#13](https://github.com/moisesja/zcap-py/issues/13) |
| Verify each (parent,child) link root→leaf; root implicitly trusted (its proof not verified) | MUST | ✅ | `delegation.py:131-173; failures wrapped with link index` | — |  |
| Empty-chain degenerate case handled safely | MAY | ✅ | `delegation.py:151-152 early return` | — |  |

### Invocation verification

| Requirement | Level | Status | Evidence | Gap | Issue |
|---|---|---|---|---|---|
| Ancestor caveats MUST be enforced root→leaf against the invocation (not just leaf) | MUST | 🟡 | `invocation.py:110-111 leaf only; verifier.py:172-175 ancestors only when chain>1; lower-level verify_invocation enforces leaf only` | Ancestor caveats silently skipped when no full chain supplied (fail-open) | [#20](https://github.com/moisesja/zcap-py/issues/20) |
| Invocation proof proofPurpose MUST be capabilityInvocation, validated at verify time | MUST | 🟡 | `Only checked at parse (parser.py:401-411); invocation.py:106-107 never re-checks purpose` | Verification layer assumes parser is the only entry; a wrong-purpose proof on a pre-built model is undetected | [#28](https://github.com/moisesja/zcap-py/issues/28) |
| Authorized set MUST be initialized from a genuine root (chain[0] must be is_root) | MUST | 🟡 | `verifier.py:133-134 treats chain[0] as root with no is_root assertion; delegation.py:140-141 skips its proof` | A non-root/forged object at chain[0] is trusted as anchor with proof bypassed | [#9](https://github.com/moisesja/zcap-py/issues/9) |
| Traverse parentCapability leaf→root, validating linkage; chain order must reflect real ancestry | MUST | 🟡 | `Pairwise linkage checked (delegation.py:70-78; verifier.py:136-143) but driven by caller-supplied order, no top-down parent-pointer walk` | Mis-ordered chain with incidental matches not independently rejected | [#16](https://github.com/moisesja/zcap-py/issues/16) |
| Absolute expiry MUST be enforced for the invoked capability even with no chain; via any public entry point | MUST | 🟡 | `verifier.py:146-159 enforces; lower-level invocation.verify_invocation has no expiry check` | Lower-level public API bypasses expiry — divergent entry points | [#20](https://github.com/moisesja/zcap-py/issues/20) |
| Invocation invocationTarget MUST match the capability's (or be a permitted narrowing), consistent with delegation rules | MUST | ❌ | `invocation.py:65-73 strict equality; never consults attenuator; dotnet VerificationService.cs:578 permits narrowing` | Invocation-time uses different (stricter) target rule than delegation-time; rejects spec/reference-valid sub-target invocations | [#26](https://github.com/moisesja/zcap-py/issues/26) |
| capabilityAction MUST be present and within effective (intersected) allowedAction including ancestors | MUST | 🟡 | `invocation.py:84-104 leaf only; ancestor subsetting only transitive at delegation time; leaf=None never checked vs ancestor` | Leaf without allowedAction but restricting ancestor: action not validated against ancestor at invocation time | [#19](https://github.com/moisesja/zcap-py/issues/19) |
| Caveats MUST be enforced fail-closed; unknown/unverifiable caveat MUST reject | MUST | 🟡 | `caveats.py:48-55 fail-closed; but invocation.py:110 skips caveats when caveat_registry is None; test_invocation.py:302-310 asserts skip` | Lower-level verify_invocation with no registry silently ignores caveats (fail-open) | [#20](https://github.com/moisesja/zcap-py/issues/20) |
| Verification steps SHOULD run in a safe order (chain/proof before trusting authorization fields) | SHOULD | 🟡 | `verifier.py order mostly safe; ancestor caveats last & conditional; bare invocation path trusts capability fields with no cap-proof verification` | Fast-path success before all constraints when no chain; caller-trusted cap fields in bare path | [#12](https://github.com/moisesja/zcap-py/issues/12) |
| The invoked delegated capability's OWN delegation proof MUST be verified during invocation (anchored to a trusted root) | MUST | 🟡 | `verifier.py:133 guard chain not None; embedded/no-chain path (verifier.py:119-126) never verifies the capability's delegation proof` | A forged/unanchored delegated capability is accepted if the invocation itself is signed by its stated controller | [#12](https://github.com/moisesja/zcap-py/issues/12) |

### Attenuation

| Requirement | Level | Status | Evidence | Gap | Issue |
|---|---|---|---|---|---|
| invocationTarget narrowing (path/query prefix) is a first-class delegation axis; default behavior must be spec/reference-aligned & documented | MUST | 🟡 | `delegation.py:104-125 gates all narrowing behind allow_target_attenuation=False default; dotnet enforces prefix unconditionally` | Default rejects spec-valid narrowed chains; conflicting parity claims (digitalbazaar opt-in vs dotnet always-on); undocumented | [#26](https://github.com/moisesja/zcap-py/issues/26) |
| child.allowedAction subset of parent; absent parent => unrestricted | MUST | ✅ | `delegation.py:80-92` | — |  |
| expires inheritance must be materialized (child absent inherits parent; effective=min across ancestors) | MUST | 🟡 | `delegation.py:95-102 per-adjacent-pair only; parser never inherits; verifier.py:150-151 checks each doc's own field` | Inheritance never materialized; mid-chain re-broadening and unbounded child possible if bounding ancestor absent from caps_to_check | [#19](https://github.com/moisesja/zcap-py/issues/19) |
| A delegated capability inherits ALL ancestor caveats; every ancestor caveat MUST be enforced at invocation | MUST | 🟡 | `verifier.py:169-175 only with full chain & len>1; parser never merges parent caveats; leaf-only path skips ancestor caveats` | Fail-open for ancestor caveats whenever chain incomplete; caveat narrowing not validated at delegation | [#19](https://github.com/moisesja/zcap-py/issues/19) |
| Unknown caveat types fail closed; capabilities may add caveats | MUST | ✅ | `caveats.py:48-55; zero built-in verifiers` | — |  |
| PathPrefixAttenuator must compare scheme+authority and segment-boundary path prefix correctly; relative/opaque targets safe | MUST | 🟡 | `target_attenuation.py:49-71 urlparse-based; dotnet uses raw-ordinal StartsWith with delimiter checks` | Structured-urlparse vs dotnet raw-ordinal not byte-identical; 'mirrors exactly' docstring overclaimed; default-port/percent-encoding parity unproven | [#26](https://github.com/moisesja/zcap-py/issues/26) |
| invocationTarget SHOULD be a valid absolute URI (attenuation soundness) | SHOULD | 🟡 | `parser.py:64 only non-empty string; dotnet validates absolute URI at creation/root` | Relative/malformed targets accepted; weakens attenuation soundness when later enabled | [#26](https://github.com/moisesja/zcap-py/issues/26) |

### did:key / VM

| Requirement | Level | Status | Evidence | Gap | Issue |
|---|---|---|---|---|---|
| did:key encode/decode MUST use 0xed01 multicodec + base58btc (z6Mk...) | MUST | ✅ | `did/key.py:29-33; crypto/multicodec.py:9,21` | — |  |
| Decode MUST reject non-Ed25519 codecs, non-32-byte keys, malformed multibase | MUST | ✅ | `did/key.py:53-62; url.py:11-14 restricts to z+base58btc` | — |  |
| For did:key the VM DID-URL #fragment MUST equal the DID's key identifier on every code path | MUST | 🟡 | `url.py:83-87 enforces in parse_did_url; but public_key_from_did_key (key.py:108-110) only strips fragment, never re-validates` | Proof with VM fragment != identifier accepted at proof layer (bypasses parser); digitalbazaar throws | [#17](https://github.com/moisesja/zcap-py/issues/17) |
| Child proof signer (fragment stripped) MUST equal parent controller; controller MAY be array | MUST | ✅ | `delegation.py:60-68; _controller_contains :28-32` | — |  |
| Invocation signer MUST equal capability controller (current spec; invoker is legacy) | MUST | 🟡 | `invocation.py:76-82 uses invoker or controller` | Honors legacy invoker override; should use controller only | [#23](https://github.com/moisesja/zcap-py/issues/23) |
| Proof key MUST be authorized by controller for the correct verification relationship (capabilityDelegation/capabilityInvocation) | MUST | 🟡 | `No controller-document resolution; bare DID==controller compare; proofPurpose only string-checked at parse` | No relationship gate/abstraction; proofPurpose not semantically enforced at verify time | [#28](https://github.com/moisesja/zcap-py/issues/28) |
| controller MUST be accepted as string or array of valid DIDs with membership semantics | MUST | ✅ | `parser.py:256-291; delegation.py:28-32; invocation.py:18-22` | — |  |
| Resolved VM type SHOULD match digitalbazaar's Ed25519 did:key emission (Ed25519VerificationKey2020) | SHOULD | 🟡 | `did/key.py:88 returns Ed25519VerificationKey2020; no Multikey/DataIntegrityProof recognition` | Only legacy representation supported (interoperable today); document scope | [#29](https://github.com/moisesja/zcap-py/issues/29) |
| Supported DID methods should be clearly bounded (did:key scope) | MAY | ✅ | `prd-design.md:37-38 out-of-scope list; url.py:14 hard-codes did:key` | — |  |
| did:key proof-key resolution MUST NOT be rooted in the JCS module slated for deletion | MUST | ❌ | `public_key_from_did_key consumed by JCS module (ed25519_2020.py:19,176) as the default path; W3C imports helpers FROM the JCS module` | did:key resolution structurally coupled to the module to be deleted; JCS is default | [#13](https://github.com/moisesja/zcap-py/issues/13) |

### capabilityChain

| Requirement | Level | Status | Evidence | Gap | Issue |
|---|---|---|---|---|---|
| capabilityChain MUST be an array | MUST | ✅ | `parser.py:415-428` | — |  |
| First entry MUST be the root zcap's ID (string reference), dereferencing to a genuine root | MUST | ❌ | `parser.py:422-428 accepts str or dict; verifier.py:133-134 trusts chain[0] as root with proof skipped; no is_root check` | Non-root/forged object at index 0 accepted as trust anchor with proof bypassed — spec + security hole | [#9](https://github.com/moisesja/zcap-py/issues/9) |
| Entries MUST be ordered root-first to leaf-last (least- to most-recent delegation) | MUST | 🟡 | `Order only enforced indirectly via per-link parentCapability matches (delegation.py:154-157,71-78)` | Mis-ordered chains with incidental matches not explicitly rejected; no closed leaf→root walk | [#16](https://github.com/moisesja/zcap-py/issues/16) |
| Immediate parent MUST be fully embedded; other ancestors referenced by ID only; never repeated | MUST | ❌ | `verifier.py:195-207 & parser.py:422-428 make no positional distinction; all-embedded chains accepted (test_verifier.py:717-761)` | Neither embed-parent nor reference-ancestors enforced; malformed shapes not rejectable | [#16](https://github.com/moisesja/zcap-py/issues/16) |
| Verifier MUST dereference the root locally via a trusted mechanism; MUST NOT require network for delegated ancestors | MUST | ❌ | `verifier.py:197-202 funnels root-by-ref through generic document_loader, raising without one; no trusted root dereferencer` | Spec-compliant wire shape (root-by-ID, parent embedded) is non-functional by default; root & ancestor loaders conflated | [#9](https://github.com/moisesja/zcap-py/issues/9) |
| Root is the trust anchor (proof not verified); verifier MUST treat ONLY a genuine, target-bound root this way | MUST | 🟡 | `delegation.py:140-141,151-157 skips root proof; no is_root guard; no root-target binding` | Proof-skipping applied to chain[0] without verifying it is the genuine root for the invocationTarget | [#9](https://github.com/moisesja/zcap-py/issues/9) |
| Delegated zcaps MUST NOT be repeated (no duplicates/cycles) | MUST | ⚪ | `No uniqueness/cycle detection in verifier.py:195-207 or delegation.py` | Duplicate/cyclic chain not detected | [#16](https://github.com/moisesja/zcap-py/issues/16) |
| Embedded ancestors used for verification SHOULD be the same bytes that were signed (no loader substitution) | SHOULD | 🟡 | `parser.py:413-440 parses chain from proof; string-ref ancestors come from loader, not signed bytes` | Loader can substitute ancestor bytes; resolved once embed-parent/reference-ancestors enforced | [#16](https://github.com/moisesja/zcap-py/issues/16) |

### Security

| Requirement | Level | Status | Evidence | Gap | Issue |
|---|---|---|---|---|---|
| Verify every link of the chain root→leaf incl. each delegated proof | MUST | ✅ | `delegation.py:151-172,128; verifier.py:133-134` | (default algorithm is JCS — tracked under proof-w3c-default-remove-jcs) |  |
| Verifier MUST be able to honor revocation (track revoked zcaps until expiry) | MUST | ⚪ | `prd-design.md:42 lists revocation as a Non-Goal; no store/hook/check in verifier.py/invocation.py` | Revoked-but-unexpired capability remains fully usable; hard spec MUST deferred | [#25](https://github.com/moisesja/zcap-py/issues/25) |
| Verification MUST NOT perform implicit network dereference; loader must be local/allow-listed (SSRF/DoS guard) | MUST | 🟡 | `Core has zero network I/O; but document_loader is caller-supplied & invoked at verify time (verifier.py:203) with no guidance/guardrails` | Naive loader => unauthenticated network deref of attacker-controlled refs (SSRF) | [#21](https://github.com/moisesja/zcap-py/issues/21) |
| Verified chain MUST be bound to the signed proof.capabilityChain and root MUST correspond to the invoked target (anti chain-substitution/confused-root) | MUST | 🟡 | `Leaf/parentCapability linkage checked; explicit chain never compared to proof.capability_chain; no expected-root/target enforcement` | Caller-supplied chain != signed chain accepted; no root↔target binding | [#21](https://github.com/moisesja/zcap-py/issues/21) |
| Verifier MUST reject expired capabilities and enforce expiry attenuation | MUST | ✅ | `verifier.py:145-159; delegation.py:94-102; injectable clock` | (also see single-path expiry gap) |  |

### Docs / PRD

| Requirement | Level | Status | Evidence | Gap | Issue |
|---|---|---|---|---|---|
| PRD (source of truth), README, CHANGELOG MUST mandate URDNA2015-only + pyld-core, not JCS-default | SHOULD | ❌ | `prd-design.md FR-PROOF-02/07, FR-INVOKE-06, FR-JCS, NFR-01/02, §11.1/11.2/11.13 mandate JCS-default/pyld-deferred; README:18-20,47-74,89-91,106; CONTRIBUTING jcs/ entry` | Authoritative docs contradict the product decision and would re-introduce JCS | [#18](https://github.com/moisesja/zcap-py/issues/18) |

## zcap-dotnet mirror

`zcap-dotnet` must track the equivalent change for each issue. Port these as matching issues in `moisesja/zcap-dotnet`:

| zcap-py issue | Equivalent change in zcap-dotnet |
|---|---|
| [#9](https://github.com/moisesja/zcap-py/issues/9) Enforce genuine-root trust anchor for capabilityChain (is_root + local | zcap-dotnet must apply the same is_root assertion and trusted local root dereference for chain[0], and bind the root to the invocationTarget (expectedRootCapability/expectedTarget semantics). |
| [#10](https://github.com/moisesja/zcap-py/issues/10) Require expires on delegated capabilities (reject missing expires at p | zcap-dotnet should likewise require expires on delegated capabilities at creation/parse, matching @digitalbazaar/zcap. |
| [#11](https://github.com/moisesja/zcap-py/issues/11) Replace the bespoke type:"Invocation" wrapper with the spec/digitalbaz | zcap-dotnet must model invocation as a capabilityInvocation proof over the target (no standalone Invocation object) and bind/verify proof.invocationTarget, matching ezcap/http-signature-zcap-invoke. |
| [#12](https://github.com/moisesja/zcap-py/issues/12) Require a verifiable, root-anchored chain to verify the invoked delega | zcap-dotnet must likewise refuse to authorize a delegated capability whose delegation proof/ancestry was not cryptographically verified to a trusted root. |
| [#13](https://github.com/moisesja/zcap-py/issues/13) Make W3C URDNA2015 the only/default proof path; remove JCS entirely (m | zcap-dotnet already uses URDNA2015 for the W3C path; ensure its JCS interop shim (the path zcap-py mirrored) is likewise demoted/removed and that no JCS-only test vectors remain as canonical. |
| [#14](https://github.com/moisesja/zcap-py/issues/14) Add a public W3C Ed25519Signature2020 signer + digitalbazaar cross-imp | Add an equivalent cross-implementation KAT in zcap-dotnet against the same digitalbazaar-generated proof so .NET and Python prove byte-identical verify_data. |
| [#15](https://github.com/moisesja/zcap-py/issues/15) Tighten capability structural validation (root @context string + URN i | Align zcap-dotnet capability validation: root @context bare string + urn:zcap:root id, delegated @context array, string-or-array allowedAction. |
| [#16](https://github.com/moisesja/zcap-py/issues/16) Enforce capabilityChain ordering, positional embed/reference shape, an | zcap-dotnet must enforce the same positional wire shape (root-by-ID first, ancestors referenced, immediate parent embedded), strict ordering, and duplicate/cycle rejection. |
| [#17](https://github.com/moisesja/zcap-py/issues/17) Validate did:key VM fragment == key identifier in public_key_from_did_ | Mirror DidKeyResolver's exact-id VM selection (throw on unmatched fragment) so .NET and Python agree on rejecting mismatched verificationMethod fragments. |
| [#18](https://github.com/moisesja/zcap-py/issues/18) Rewrite prd-design.md, README, CONTRIBUTING, and CHANGELOG to mandate  | Update zcap-dotnet docs to drop JCS-interop framing and state URDNA2015 as the canonical proof path. |
| [#19](https://github.com/moisesja/zcap-py/issues/19) Materialize inherited allowedAction, expires, and caveats across the c | zcap-dotnet must derive each capability's effective allowedAction/expires/caveats by inheriting from ancestors (not resetting to unrestricted on omission), matching reference inheritance semantics. |
| [#20](https://github.com/moisesja/zcap-py/issues/20) Make the lower-level verify_invocation / verify_delegation_chain enfor | Ensure zcap-dotnet has no lower-level entry point that skips absolute expiry or caveat enforcement; consolidate to a single canonical verify path. |
| [#21](https://github.com/moisesja/zcap-py/issues/21) Harden document_loader (SSRF guidance/safe default) and bind the verif | Document the same offline/allow-list loader contract in zcap-dotnet and add expectedRootCapability/expectedTarget-style binding of the verified chain to the signed proof. |
| [#22](https://github.com/moisesja/zcap-py/issues/22) Add a configurable maxChainLength (default 10) and optional delegation | Match @digitalbazaar/zcap maxChainLength=10 in zcap-dotnet and consider the same optional ~90-day delegation TTL ceiling policy. |
| [#23](https://github.com/moisesja/zcap-py/issues/23) Remove the legacy invoker field; use controller-only for invoker ident | zcap-dotnet should drop any invoker handling and use controller-only, matching @digitalbazaar/zcap. |
| [#24](https://github.com/moisesja/zcap-py/issues/24) Add invocation replay-protection hooks (nonce/seen-id store, created f | Provide matching replay-protection hooks (nonce store, created window, domain/challenge) in zcap-dotnet for consistent application integration. |
| [#25](https://github.com/moisesja/zcap-py/issues/25) Provide a pluggable revocation hook (RevocationStore) and document the | Add an equivalent revocation hook in zcap-dotnet so both stacks can reject revoked-but-unexpired capabilities. |
| [#26](https://github.com/moisesja/zcap-py/issues/26) Align invocationTarget attenuation default + invocation-time check + a | Reconcile with zcap-dotnet's VerificationService (ValidateAttenuation / IsValidInvocationTarget always-on prefix narrowing, raw-ordinal StartsWith); pick one canonical algorithm and prove byte parity both ways. |
| [#27](https://github.com/moisesja/zcap-py/issues/27) Remove/migrate all JCS tests, fixtures, examples, and conftest helpers | Remove the corresponding JCS interop fixtures/tests from zcap-dotnet and replace with W3C/digitalbazaar known-answer vectors. |
| [#28](https://github.com/moisesja/zcap-py/issues/28) Enforce proofPurpose and verification-relationship authorization at ve | Mirror zcap-dotnet's IVerificationRelationshipResolver / IsAuthorizedForRelationshipAsync gate so delegation proofs require capabilityDelegation and invocation proofs require capabilityInvocation at verify time. |
| [#29](https://github.com/moisesja/zcap-py/issues/29) Expand bundled context coverage (DID v1 / security contexts), memoize  | Mirror digitalbazaar's security-document-loader context set in zcap-dotnet's static loader and document the supported @context allowlist. |

## Superseded issues

Issues **#5** and **#8** (JCS ↔ `zcap-dotnet` interop) are obsoleted by the JCS removal in #13 and are closed as superseded.
