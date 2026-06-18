# P0 secure-invocation — #9 / #12 / #20

Branch: `feature/p0-secure-invocation` (off merged `main` @ 0cc414c)
Scope decision: #9/#12/#20 only — #11 (invocation DI-model redesign) is a separate breaking-interop branch.
#12 decision: require a verified root-anchored chain for delegated-capability invocation **by default** (no opt-out).

## Holes being closed

- **#9 chain-root-trust-binding** — `verify_invocation` trusts `chain[0]` as root and skips its proof without asserting `chain[0].is_root`; a forged/delegated object at index 0 is trusted with its proof bypassed.
- **#12 invocation-requires-verified-chain** — invoking a delegated capability with no chain verifies only the invocation signature; the cap's own delegation proof/ancestry is never checked → forged delegated cap accepted.
- **#20 fail-open expiry via building blocks** — standalone `verify_delegation_chain` does no absolute-expiry check; low-level `invocation.verify_invocation` checks neither expiry nor chain.

## Plan

- [ ] `delegation.py`: add optional `clock` to `verify_delegation_chain` / `_verify_delegation_link`; enforce absolute expiry per capability (root + each delegation) — default clock = now. Standalone function becomes fail-closed.
- [ ] `verifier.py` #9: when a chain is used, assert `chain[0].is_root` (reject non-root/forged anchor); add optional `expected_root_id` to pin the trust anchor; never skip proof for a non-root.
- [ ] `verifier.py` #12: if invoked `capability` is not a root and no chain is available (provided or resolvable from `proof.capabilityChain`), raise `InvocationError`. Root invoked directly stays valid. Pass the facade clock into `verify_delegation_chain`.
- [ ] `invocation.py` #20: document the low-level `verify_invocation` as an internal building block; the authoritative fail-closed entry point is `ZcapVerifier`.
- [ ] Update existing tests: delegated-cap invocations that omit a chain now need one; attenuation tests using past `expires` switch to future dates to isolate attenuation from absolute expiry.
- [ ] New negative tests: non-root/forged anchor rejected; delegated-cap-without-chain rejected; embedded-delegated-without-chain rejected; expired cap rejected via standalone `verify_delegation_chain`; root invoked directly still passes.
- [ ] Verify: pytest, coverage ≥90, ruff, `mypy src`. Update CHANGELOG (0.8.0). Commit, push, open PR linking #9/#12/#20.

## Out of scope
- #11 (type:"Invocation" → capabilityInvocation DI proof over target) — separate branch.
- #14 digitalbazaar cross-impl KAT.

## Review

Done. All three holes closed and verified:
- #20 — `verify_delegation_chain` gained `clock` and enforces absolute expiry over root + all delegations (fail-closed standalone). `delegation.py` 100% covered.
- #9 — `verify_invocation` asserts `chain[0].is_root`, never trusts a non-root anchor; added optional `expected_root_id` pin.
- #12 — invoking a delegated capability without a resolvable root-anchored chain raises `InvocationError`; only roots invocable directly. Embedded-delegated-without-chain also rejected.
- #20 docs — low-level `invocation.verify_invocation` marked an internal building block.

Tests: updated 2 expiry-attenuation tests to future dates (isolate attenuation from absolute expiry); repurposed the old fail-open `test_no_chain_skips_ancestor_caveats` into a rejection test; added `TestChainTrustAnchor` (6 cases) and `TestAbsoluteExpiry` (2 cases).

Verification: 239 passed, 95% coverage (delegation + invocation 100%), ruff clean, mypy src clean, 10 examples run. Version bumped 0.7.0 → 0.8.0; CHANGELOG, README, COMPLIANCE.md updated.

Out of scope (separate branches): #11 (invocation DI-model), #14 (digitalbazaar KAT).
