"""Tests for W3C-compliant Ed25519Signature2020 verification (URDNA2015)."""

from __future__ import annotations

import pytest

from tests.conftest import (
    make_signed_document,
    make_w3c_misbound_document,
    make_w3c_signed_document,
)
from zcap_py.crypto.ed25519 import generate_ed25519_keypair
from zcap_py.crypto.multibase import base58btc_encode
from zcap_py.exceptions import (
    CanonicalizationError,
    ProofError,
    SignatureVerificationError,
    UnsupportedProofTypeError,
)
from zcap_py.proof.ed25519_2020_w3c import verify_document_proof_w3c

pyld = pytest.importorskip("pyld", reason="pyld required for W3C proof tests")


W3C_SAMPLE_DOC: dict[str, object] = {
    "@context": [
        "https://w3id.org/zcap/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    "id": "urn:uuid:test-doc-w3c",
    "type": "Authorization",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "invocationTarget": "https://resource.example/api/",
    "allowedAction": ["read", "write"],
}


# ── verify_document_proof_w3c ──


class TestVerifyDocumentProofW3C:
    def test_valid_w3c_signature_passes(self) -> None:
        kp = generate_ed25519_keypair()
        doc = make_w3c_signed_document(W3C_SAMPLE_DOC, kp.private_key, kp.verification_method)
        verify_document_proof_w3c(doc)

    def test_invalid_signature_raises_error(self) -> None:
        kp = generate_ed25519_keypair()
        doc = make_w3c_signed_document(W3C_SAMPLE_DOC, kp.private_key, kp.verification_method)
        bad_sig = base58btc_encode(b"\x00" * 64)
        proof = dict(doc["proof"])  # type: ignore[arg-type]
        proof["proofValue"] = bad_sig
        doc = {**doc, "proof": proof}
        with pytest.raises(SignatureVerificationError):
            verify_document_proof_w3c(doc)

    def test_tampered_document_fails(self) -> None:
        kp = generate_ed25519_keypair()
        doc = make_w3c_signed_document(W3C_SAMPLE_DOC, kp.private_key, kp.verification_method)
        doc = {**doc, "id": "urn:uuid:tampered"}
        with pytest.raises(SignatureVerificationError):
            verify_document_proof_w3c(doc)

    def test_tampered_proof_metadata_fails(self) -> None:
        kp = generate_ed25519_keypair()
        doc = make_w3c_signed_document(W3C_SAMPLE_DOC, kp.private_key, kp.verification_method)
        proof = dict(doc["proof"])  # type: ignore[arg-type]
        proof["created"] = "2099-12-31T00:00:00Z"
        doc = {**doc, "proof": proof}
        with pytest.raises(SignatureVerificationError):
            verify_document_proof_w3c(doc)

    def test_missing_proof_raises_error(self) -> None:
        with pytest.raises(ProofError, match="missing 'proof'"):
            verify_document_proof_w3c({"id": "test"})

    def test_proof_not_dict_raises_error(self) -> None:
        with pytest.raises(ProofError, match="missing 'proof'"):
            verify_document_proof_w3c({"id": "test", "proof": "not-a-dict"})

    def test_wrong_proof_type_raises_unsupported(self) -> None:
        doc: dict[str, object] = {
            "id": "test",
            "proof": {"type": "RsaSignature2018", "proofValue": "z1234"},
        }
        with pytest.raises(UnsupportedProofTypeError, match="RsaSignature2018"):
            verify_document_proof_w3c(doc)

    def test_proof_value_not_multibase_z_raises_error(self) -> None:
        doc: dict[str, object] = {
            "id": "test",
            "proof": {
                "type": "Ed25519Signature2020",
                "proofValue": "not-multibase",
            },
        }
        with pytest.raises(ProofError, match="multibase-z"):
            verify_document_proof_w3c(doc)

    def test_proof_value_wrong_length_raises_error(self) -> None:
        short_sig = base58btc_encode(b"\x00" * 32)
        doc: dict[str, object] = {
            "id": "test",
            "proof": {
                "type": "Ed25519Signature2020",
                "proofValue": short_sig,
            },
        }
        with pytest.raises(ProofError, match="expected 64"):
            verify_document_proof_w3c(doc)


# ── Key Binding (W3C) ──


class TestKeyBindingW3C:
    def test_misbound_key_rejected(self) -> None:
        """Document signed by key B but claiming key A must be rejected."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        doc = make_w3c_misbound_document(W3C_SAMPLE_DOC, bob.private_key, alice.verification_method)
        with pytest.raises(SignatureVerificationError):
            verify_document_proof_w3c(doc)

    def test_missing_verification_method_raises_proof_error(self) -> None:
        kp = generate_ed25519_keypair()
        doc = make_w3c_signed_document(W3C_SAMPLE_DOC, kp.private_key, kp.verification_method)
        proof = dict(doc["proof"])  # type: ignore[arg-type]
        del proof["verificationMethod"]
        doc = {**doc, "proof": proof}
        with pytest.raises(ProofError, match="verificationMethod"):
            verify_document_proof_w3c(doc)


# ── Cross-verification (JCS ↔ W3C are distinct) ──


class TestCrossVerification:
    def test_jcs_signed_doc_fails_w3c_verifier(self) -> None:
        """A JCS-signed document must NOT pass the W3C URDNA2015 verifier."""
        kp = generate_ed25519_keypair()
        jcs_doc = make_signed_document(W3C_SAMPLE_DOC, kp.private_key, kp.verification_method)
        with pytest.raises(SignatureVerificationError):
            verify_document_proof_w3c(jcs_doc)

    def test_w3c_signed_doc_fails_jcs_verifier(self) -> None:
        """A W3C URDNA2015-signed document must NOT pass the JCS verifier."""
        from zcap_py.proof.ed25519_2020 import verify_document_proof

        kp = generate_ed25519_keypair()
        w3c_doc = make_w3c_signed_document(W3C_SAMPLE_DOC, kp.private_key, kp.verification_method)
        with pytest.raises(SignatureVerificationError):
            verify_document_proof(w3c_doc)


# ── Context loader errors ──


class TestContextErrors:
    def test_unknown_context_url_raises_canonicalization_error(self) -> None:
        kp = generate_ed25519_keypair()
        doc_unknown_ctx: dict[str, object] = {
            "@context": ["https://unknown.example/v1"],
            "id": "urn:test",
            "type": "Authorization",
            "proof": {
                "type": "Ed25519Signature2020",
                "verificationMethod": kp.verification_method,
                "created": "2026-01-01T00:00:00Z",
                "proofPurpose": "capabilityDelegation",
                "proofValue": base58btc_encode(b"\x00" * 64),
            },
        }
        with pytest.raises(CanonicalizationError, match="Unknown JSON-LD context"):
            verify_document_proof_w3c(doc_unknown_ctx)
