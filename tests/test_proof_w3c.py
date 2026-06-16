"""Tests for W3C-compliant Ed25519Signature2020 verification (URDNA2015)."""

from __future__ import annotations

import pytest

from tests.conftest import (
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
from zcap_py.proof.ed25519_2020_w3c import (
    sign_document_proof_w3c,
    verify_document_proof_w3c,
)

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


# ── Public W3C signer (sign_document_proof_w3c) ──


class TestSignDocumentProofW3C:
    PROOF_META: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": "",  # filled per-test
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": "capabilityDelegation",
    }

    def _meta(self, vm: str) -> dict[str, object]:
        return {**self.PROOF_META, "verificationMethod": vm}

    def test_sign_then_verify_round_trips(self) -> None:
        kp = generate_ed25519_keypair()
        signed = sign_document_proof_w3c(
            W3C_SAMPLE_DOC, self._meta(kp.verification_method), kp.private_key
        )
        # Default verifier accepts our own signer's output, byte-for-byte.
        verify_document_proof_w3c(signed)

    def test_signer_does_not_include_proof_value_in_metadata(self) -> None:
        kp = generate_ed25519_keypair()
        signed = sign_document_proof_w3c(
            W3C_SAMPLE_DOC, self._meta(kp.verification_method), kp.private_key
        )
        proof = signed["proof"]
        assert isinstance(proof, dict)
        assert proof["proofValue"].startswith("z")

    def test_tampered_document_fails_verification(self) -> None:
        kp = generate_ed25519_keypair()
        signed = sign_document_proof_w3c(
            W3C_SAMPLE_DOC, self._meta(kp.verification_method), kp.private_key
        )
        tampered = {**signed, "invocationTarget": "https://resource.example/other/"}
        with pytest.raises(SignatureVerificationError):
            verify_document_proof_w3c(tampered)

    def test_sign_without_context_raises_proof_error(self) -> None:
        kp = generate_ed25519_keypair()
        no_ctx = {k: v for k, v in W3C_SAMPLE_DOC.items() if k != "@context"}
        with pytest.raises(ProofError, match="@context"):
            sign_document_proof_w3c(no_ctx, self._meta(kp.verification_method), kp.private_key)

    def test_verify_without_context_raises_proof_error(self) -> None:
        kp = generate_ed25519_keypair()
        signed = sign_document_proof_w3c(
            W3C_SAMPLE_DOC, self._meta(kp.verification_method), kp.private_key
        )
        no_ctx = {k: v for k, v in signed.items() if k != "@context"}
        with pytest.raises(ProofError, match="@context"):
            verify_document_proof_w3c(no_ctx)


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
