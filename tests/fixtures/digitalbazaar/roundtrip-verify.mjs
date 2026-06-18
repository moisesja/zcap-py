/**
 * Reverse-direction interop check (issue #14): verify a *zcap-py-produced*
 * invocation under the genuine @digitalbazaar/zcap verifier, proving the
 * py -> digitalbazaar direction (the committed KAT proves digitalbazaar -> py).
 *
 * Reads /tmp/py_zcap/{root,delegated,invocation}.json (written by
 * /tmp/produce_py_zcap.py) and runs jsigs.verify with the CapabilityInvocation
 * purpose. Prints PASSED/FAILED. This is a one-off out-of-band check, not part
 * of the hermetic Python test suite.
 *
 * Run: node roundtrip-verify.mjs
 */
import {readFileSync} from 'node:fs';

import jsigs from 'jsonld-signatures';
import * as zcap from '@digitalbazaar/zcap';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {securityLoader} from '@digitalbazaar/security-document-loader';
import zcapCtx from '@digitalbazaar/zcap-context';

const {CapabilityInvocation} = zcap;
const ED = 'https://w3id.org/security/suites/ed25519-2020/v1';
const TARGET = 'https://api.example.com/data/';
const DIR = '/tmp/py_zcap';

const load = name => JSON.parse(readFileSync(`${DIR}/${name}.json`, 'utf8'));
const root = load('root');
const delegated = load('delegated');
const invocation = load('invocation');

const caps = new Map([[root.id, root], [delegated.id, delegated]]);

// Resolve ANY did:key VM from its identifier (the multibase public key), plus
// the two capabilities by id, plus the security + zcap contexts.
const builder = securityLoader();
builder.addStatic(zcapCtx.CONTEXT_URL, zcapCtx.CONTEXT);
const base = builder.build();
const documentLoader = async url => {
  if (url.startsWith('did:key:')) {
    const did = url.split('#')[0];
    const mb = did.slice('did:key:'.length);
    const vm = {
      '@context': ED, id: `${did}#${mb}`, type: 'Ed25519VerificationKey2020',
      controller: did, publicKeyMultibase: mb,
    };
    const didDoc = {
      '@context': ['https://www.w3.org/ns/did/v1', ED], id: did,
      verificationMethod: [vm], capabilityDelegation: [vm.id], capabilityInvocation: [vm.id],
    };
    return {contextUrl: null, documentUrl: url, document: url === did ? didDoc : vm};
  }
  if (caps.has(url)) return {contextUrl: null, documentUrl: url, document: caps.get(url)};
  return base(url);
};

const result = await jsigs.verify(invocation, {
  suite: new Ed25519Signature2020(),
  purpose: new CapabilityInvocation({
    expectedTarget: TARGET,
    expectedAction: 'read',
    expectedRootCapability: root.id,
    suite: new Ed25519Signature2020(),
  }),
  documentLoader,
});

console.log('py -> digitalbazaar verification:', result.verified ? 'PASSED' : 'FAILED');
if (!result.verified) {
  console.error(JSON.stringify(result.error?.errors?.map(e => e.message) ?? result, null, 2));
  process.exit(1);
}
