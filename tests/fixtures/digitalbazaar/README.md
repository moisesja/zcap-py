# digitalbazaar cross-implementation known-answer-test (KAT) fixtures

These JSON files are produced by the **genuine `@digitalbazaar/zcap` stack** and are consumed by
`tests/test_kat_digitalbazaar.py` to prove that `zcap-py`:

1. parses the real digitalbazaar `capabilityInvocation` Data-Integrity-proof-over-target shape
   (no bespoke `type:"Invocation"` wrapper), and
2. computes a **byte-identical** URDNA2015 verify-data (`proofHash || docHash`, dual SHA-256), so a proof
   produced by `@digitalbazaar/ed25519-signature-2020` verifies under our default verifier.

This is the cross-implementation anchor for the otherwise believed-pending byte-parity assumption (issue #14).

## Files

| File | What it is |
|------|------------|
| `root.json` | A root zcap: `id = urn:zcap:root:<encodeURIComponent(invocationTarget)>`, bare-string `@context`. |
| `delegated.json` | A capability delegated off the root (`capabilityDelegation` proof, `capabilityChain = [rootId]`). |
| `invocation.json` | A `capabilityInvocation` proof over a minimal target document. `proof.capability` embeds the **full** delegated zcap (digitalbazaar interprets a *string* `proof.capability` as a root reference); the proof carries `invocationTarget` + `capabilityAction`. |
| `meta.json` | Provenance: exact package versions + the did:key identifiers used. |

## Regenerating

The fixtures are committed and the test suite reads them statically — **Node is not required to run the
Python tests**. To regenerate (e.g. after a digitalbazaar upgrade):

```sh
cd tests/fixtures/digitalbazaar
npm install        # installs @digitalbazaar/zcap et al.; node_modules is gitignored
node generate.mjs  # emits root.json, delegated.json, invocation.json, meta.json
```

`generate.mjs` also runs `jsonld-signatures` `verify()` as a self-check; it prints
`digitalbazaar self-verification: PASSED` when the emitted invocation is a valid digitalbazaar artifact.

### Round-trip — both directions

- **digitalbazaar → zcap-py** is the committed, CI-enforced KAT: `tests/test_kat_digitalbazaar.py` verifies the
  digitalbazaar-produced `invocation.json` under zcap-py's default verifier.
- **zcap-py → digitalbazaar** is checked out-of-band by `roundtrip-verify.mjs`: it verifies a *zcap-py-produced*
  invocation under the genuine digitalbazaar `jsonld-signatures` `CapabilityInvocation` verifier. To reproduce:

  ```sh
  uv run python - <<'PY'   # (or run a script that signs with zcap_py.sign_document_proof_w3c)
  # writes /tmp/py_zcap/{root,delegated,invocation}.json
  PY
  node roundtrip-verify.mjs   # prints "py -> digitalbazaar verification: PASSED"
  ```

  This confirms byte-identical verify-data in both directions (Node is not required for the Python test suite).

Each regeneration uses freshly generated did:key keypairs and random `urn:uuid:` ids, so the fixtures differ
byte-for-byte run to run but remain valid. The `created` timestamp reflects the generation clock.

## Byte-identity guard

`tests/test_kat_digitalbazaar.py` also asserts that the bundled
`src/zcap_py/jsonld/contexts/zcap-v1.jsonld` and `ed25519-signature-2020-v1.jsonld` are byte-identical
(SHA-256) to digitalbazaar's `@digitalbazaar/zcap-context` / `ed25519-signature-2020-context`. If a future
digitalbazaar release bumps either context, that guard fails — alerting us before URDNA2015 N-Quads silently
diverge.
