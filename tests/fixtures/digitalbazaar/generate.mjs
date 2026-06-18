/**
 * Generate cross-implementation known-answer-test (KAT) fixtures using the
 * genuine @digitalbazaar/zcap stack, so zcap-py can prove byte-identical
 * URDNA2015 verify-data and that its parser accepts the real digitalbazaar
 * capabilityInvocation Data-Integrity-proof-over-target shape.
 *
 * Emits (next to this script):
 *   root.json        — a root zcap (urn:zcap:root:<encodeURIComponent(target)>)
 *   delegated.json   — a delegated capability (capabilityDelegation proof, capabilityChain=[rootId])
 *   invocation.json  — a capabilityInvocation proof over a minimal target document
 *   meta.json        — resolved package versions + did:key identifiers (provenance)
 *
 * Run:  npm install && node generate.mjs
 * node_modules is intentionally NOT committed; only the *.json fixtures are.
 */
import {writeFileSync, readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';

import jsigs from 'jsonld-signatures';
import * as zcap from '@digitalbazaar/zcap';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {Ed25519VerificationKey2020} from '@digitalbazaar/ed25519-verification-key-2020';
import {securityLoader} from '@digitalbazaar/security-document-loader';
import zcapCtx from '@digitalbazaar/zcap-context';

const {CapabilityDelegation, CapabilityInvocation} = zcap;
const HERE = dirname(fileURLToPath(import.meta.url));

const ZCAP_CONTEXT = 'https://w3id.org/zcap/v1';
const ED25519_2020_CONTEXT = 'https://w3id.org/security/suites/ed25519-2020/v1';
const INVOCATION_TARGET = 'https://api.example.com/data/';
const CAPABILITY_ACTION = 'read';
const EXPIRES = '2099-01-01T00:00:00Z';

// ── did:key signer setup ──────────────────────────────────────────────────
async function makeSigner() {
  const key = await Ed25519VerificationKey2020.generate();
  const fingerprint = key.fingerprint();
  const did = `did:key:${fingerprint}`;
  key.id = `${did}#${fingerprint}`;
  key.controller = did;
  return {key, did, vm: key.id};
}

// A document loader that serves the security contexts (digitalbazaar's own
// copies), did:key DID documents, and the in-memory capabilities by id.
function makeLoader(signers, capabilities) {
  const builder = securityLoader();
  // security-document-loader bundles the security + ed25519-2020 suite contexts
  // but not the zcap context — register digitalbazaar's own copy of it.
  builder.addStatic(zcapCtx.CONTEXT_URL, zcapCtx.CONTEXT);
  const base = builder.build();
  return async function documentLoader(url) {
    if (url.startsWith('did:key:')) {
      const did = url.split('#')[0];
      const signer = signers.find(s => s.did === did);
      if (signer) {
        const vm = {
          '@context': ED25519_2020_CONTEXT,
          id: signer.vm,
          type: 'Ed25519VerificationKey2020',
          controller: signer.did,
          publicKeyMultibase: signer.key.publicKeyMultibase,
        };
        const didDoc = {
          '@context': ['https://www.w3.org/ns/did/v1', ED25519_2020_CONTEXT],
          id: signer.did,
          verificationMethod: [vm],
          authentication: [signer.vm],
          assertionMethod: [signer.vm],
          capabilityDelegation: [signer.vm],
          capabilityInvocation: [signer.vm],
        };
        if (url === signer.did) {
          return {contextUrl: null, documentUrl: url, document: didDoc};
        }
        return {contextUrl: null, documentUrl: url, document: vm};
      }
    }
    if (capabilities.has(url)) {
      return {contextUrl: null, documentUrl: url, document: capabilities.get(url)};
    }
    return base(url);
  };
}

async function main() {
  const delegator = await makeSigner(); // root controller
  const invoker = await makeSigner();   // delegatee / invoker
  const capabilities = new Map();
  const documentLoader = makeLoader([delegator, invoker], capabilities);

  // 1) Root capability (controller = delegator) ----------------------------
  const root = zcap.createRootCapability({
    controller: delegator.did,
    invocationTarget: INVOCATION_TARGET,
  });
  capabilities.set(root.id, root);

  // 2) Delegated capability (root controller delegates to the invoker) -----
  const delegatedDraft = {
    '@context': [ZCAP_CONTEXT, ED25519_2020_CONTEXT],
    id: `urn:uuid:${crypto.randomUUID()}`,
    parentCapability: root.id,
    controller: invoker.did,
    invocationTarget: INVOCATION_TARGET,
    allowedAction: [CAPABILITY_ACTION],
    expires: EXPIRES,
  };
  const delegated = await jsigs.sign(delegatedDraft, {
    suite: new Ed25519Signature2020({key: delegator.key}),
    purpose: new CapabilityDelegation({parentCapability: root.id}),
    documentLoader,
  });
  capabilities.set(delegated.id, delegated);

  // 3) Invocation (invoker invokes the delegated capability over a target) -
  // The signed document is the invocation *target representation*. It needs at
  // least one real (in-context) term — a bare {@context,id} expands to an
  // "object with only @id" which jsonld safe mode drops. We use a tiny inline
  // context term so the document is fully self-contained and canonicalizes
  // identically offline in both jsonld (Node) and pyld (Python).
  const targetDoc = {
    '@context': [
      ZCAP_CONTEXT,
      ED25519_2020_CONTEXT,
      {action: 'https://w3id.org/zcap-py/kat#action'},
    ],
    id: `urn:uuid:${crypto.randomUUID()}`,
    action: CAPABILITY_ACTION,
  };
  // Invoking a DELEGATED capability: digitalbazaar requires the full delegated
  // zcap object embedded in proof.capability (a *string* proof.capability is
  // interpreted as a root reference). The embedded object carries its own
  // delegation proof + capabilityChain, which the verifier dereferences.
  const invocation = await jsigs.sign(targetDoc, {
    suite: new Ed25519Signature2020({key: invoker.key}),
    purpose: new CapabilityInvocation({
      capability: delegated,
      capabilityAction: CAPABILITY_ACTION,
      invocationTarget: INVOCATION_TARGET,
    }),
    documentLoader,
  });

  // 4) Emit fixtures + provenance ------------------------------------------
  const pkgLock = JSON.parse(readFileSync(join(HERE, 'package-lock.json'), 'utf8'));
  const dep = name => pkgLock.packages?.[`node_modules/${name}`]?.version ?? 'unknown';
  const meta = {
    generatedBy: '@digitalbazaar/zcap cross-impl KAT generator (tests/fixtures/digitalbazaar/generate.mjs)',
    note: 'Static fixtures committed; node_modules not committed. Re-run: npm install && node generate.mjs',
    versions: {
      '@digitalbazaar/zcap': dep('@digitalbazaar/zcap'),
      'jsonld-signatures': dep('jsonld-signatures'),
      '@digitalbazaar/ed25519-signature-2020': dep('@digitalbazaar/ed25519-signature-2020'),
      '@digitalbazaar/ed25519-verification-key-2020': dep('@digitalbazaar/ed25519-verification-key-2020'),
      '@digitalbazaar/security-document-loader': dep('@digitalbazaar/security-document-loader'),
    },
    rootController: delegator.did,
    invoker: invoker.did,
    invocationTarget: INVOCATION_TARGET,
    capabilityAction: CAPABILITY_ACTION,
  };

  const write = (name, obj) =>
    writeFileSync(join(HERE, name), JSON.stringify(obj, null, 2) + '\n');
  write('root.json', root);
  write('delegated.json', delegated);
  write('invocation.json', invocation);
  write('meta.json', meta);
  console.log('Wrote root.json, delegated.json, invocation.json, meta.json');

  // Emit the exact context documents digitalbazaar resolves, so the Python KAT
  // can deep-compare them against zcap-py's bundled copies (byte-identity guard:
  // catches a silent digitalbazaar context bump before N-Quads diverge).
  for (const [url, file] of [
    [ZCAP_CONTEXT, 'reference-contexts/zcap-v1.json'],
    [ED25519_2020_CONTEXT, 'reference-contexts/ed25519-signature-2020-v1.json'],
  ]) {
    const {document} = await documentLoader(url);
    write(file, document);
  }
  console.log('Wrote reference-contexts/{zcap-v1,ed25519-signature-2020-v1}.json');

  // 5) Sanity: digitalbazaar's own verifier accepts the invocation. This is a
  // bonus cross-check; the authoritative KAT is the zcap-py test suite reading
  // these static fixtures, so a self-verify hiccup is reported but non-fatal.
  const result = await jsigs.verify(invocation, {
    suite: new Ed25519Signature2020(),
    purpose: new CapabilityInvocation({
      expectedTarget: INVOCATION_TARGET,
      expectedAction: CAPABILITY_ACTION,
      expectedRootCapability: root.id,
      suite: new Ed25519Signature2020(),
    }),
    documentLoader,
  });
  console.log(
    'digitalbazaar self-verification:',
    result.verified ? 'PASSED' : 'FAILED (non-fatal; see error below)'
  );
  if (!result.verified) {
    console.error(JSON.stringify(result.error?.errors?.[0]?.message ?? result, null, 2));
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
