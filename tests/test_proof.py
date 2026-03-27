"""Tests for proof models and Ed25519Signature2020 verification."""

from __future__ import annotations

import pytest

from tests.conftest import make_misbound_document, make_signed_document
from zcap_py.crypto.ed25519 import generate_ed25519_keypair
from zcap_py.crypto.multibase import base58btc_encode
from zcap_py.exceptions import (
    ProofError,
    SignatureVerificationError,
    UnsupportedProofTypeError,
)
from zcap_py.proof.ed25519_2020 import verify_document_proof
from zcap_py.proof.models import LinkedDataProof

SAMPLE_DOC: dict[str, object] = {
    "id": "urn:uuid:test-doc",
    "type": "Authorization",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
}


# ── LinkedDataProof Model ──


class TestLinkedDataProof:
    def test_frozen_dataclass(self) -> None:
        proof = LinkedDataProof(
            type="Ed25519Signature2020",
            verification_method="did:key:z6Mk...#z6Mk...",
            created="2026-01-01T00:00:00Z",
            proof_value="zSig...",
            proof_purpose="capabilityDelegation",
        )
        with pytest.raises(AttributeError):
            proof.type = "other"  # type: ignore[misc]

    def test_proof_purpose_required(self) -> None:
        proof = LinkedDataProof(
            type="Ed25519Signature2020",
            verification_method="did:key:z6Mk...#z6Mk...",
            created="2026-01-01T00:00:00Z",
            proof_value="zSig...",
            proof_purpose="capabilityInvocation",
        )
        assert proof.proof_purpose == "capabilityInvocation"

    def test_optional_fields_default_none(self) -> None:
        proof = LinkedDataProof(
            type="Ed25519Signature2020",
            verification_method="did:key:z6Mk...#z6Mk...",
            created="2026-01-01T00:00:00Z",
            proof_value="zSig...",
            proof_purpose="capabilityDelegation",
        )
        assert proof.capability is None
        assert proof.capability_action is None


# ── verify_document_proof ──


class TestVerifyDocumentProof:
    def test_valid_signature_passes(self) -> None:
        kp = generate_ed25519_keypair()
        doc = make_signed_document(SAMPLE_DOC, kp.private_key, kp.verification_method)
        verify_document_proof(doc)

    def test_invalid_signature_raises_error(self) -> None:
        kp = generate_ed25519_keypair()
        doc = make_signed_document(SAMPLE_DOC, kp.private_key, kp.verification_method)
        bad_sig = base58btc_encode(b"\x00" * 64)
        proof = dict(doc["proof"])  # type: ignore[arg-type]
        proof["proofValue"] = bad_sig
        doc = {**doc, "proof": proof}
        with pytest.raises(SignatureVerificationError):
            verify_document_proof(doc)

    def test_tampered_document_fails(self) -> None:
        kp = generate_ed25519_keypair()
        doc = make_signed_document(SAMPLE_DOC, kp.private_key, kp.verification_method)
        doc = {**doc, "id": "urn:uuid:tampered"}
        with pytest.raises(SignatureVerificationError):
            verify_document_proof(doc)

    def test_tampered_proof_metadata_fails(self) -> None:
        kp = generate_ed25519_keypair()
        doc = make_signed_document(SAMPLE_DOC, kp.private_key, kp.verification_method)
        proof = dict(doc["proof"])  # type: ignore[arg-type]
        proof["created"] = "2099-12-31T00:00:00Z"
        doc = {**doc, "proof": proof}
        with pytest.raises(SignatureVerificationError):
            verify_document_proof(doc)

    def test_missing_proof_raises_error(self) -> None:
        with pytest.raises(ProofError, match="missing 'proof'"):
            verify_document_proof({"id": "test"})

    def test_proof_not_dict_raises_error(self) -> None:
        with pytest.raises(ProofError, match="missing 'proof'"):
            verify_document_proof({"id": "test", "proof": "not-a-dict"})

    def test_wrong_proof_type_raises_unsupported(self) -> None:
        doc: dict[str, object] = {
            "id": "test",
            "proof": {"type": "RsaSignature2018", "proofValue": "z1234"},
        }
        with pytest.raises(UnsupportedProofTypeError, match="RsaSignature2018"):
            verify_document_proof(doc)

    def test_proof_value_not_multibase_z_raises_error(self) -> None:
        doc: dict[str, object] = {
            "id": "test",
            "proof": {
                "type": "Ed25519Signature2020",
                "proofValue": "not-multibase",
            },
        }
        with pytest.raises(ProofError, match="multibase-z"):
            verify_document_proof(doc)

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
            verify_document_proof(doc)

    def test_proof_value_missing_raises_error(self) -> None:
        doc: dict[str, object] = {
            "id": "test",
            "proof": {"type": "Ed25519Signature2020"},
        }
        with pytest.raises(ProofError, match="multibase-z"):
            verify_document_proof(doc)


# ── Key Binding (verificationMethod ↔ signer) ──


class TestKeyBinding:
    def test_misbound_key_is_rejected(self) -> None:
        """Document signed by key B but claiming key A in
        verificationMethod must be rejected."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        doc = make_misbound_document(SAMPLE_DOC, bob.private_key, alice.verification_method)
        with pytest.raises(SignatureVerificationError):
            verify_document_proof(doc)

    def test_key_resolved_from_verification_method(self) -> None:
        """Verification succeeds when signer matches verificationMethod."""
        kp = generate_ed25519_keypair()
        doc = make_signed_document(SAMPLE_DOC, kp.private_key, kp.verification_method)
        verify_document_proof(doc)

    def test_missing_verification_method_raises_proof_error(self) -> None:
        kp = generate_ed25519_keypair()
        doc = make_signed_document(SAMPLE_DOC, kp.private_key, kp.verification_method)
        proof = dict(doc["proof"])  # type: ignore[arg-type]
        del proof["verificationMethod"]
        doc = {**doc, "proof": proof}
        with pytest.raises(ProofError, match="verificationMethod"):
            verify_document_proof(doc)

    def test_invalid_did_in_verification_method_raises_proof_error(self) -> None:
        kp = generate_ed25519_keypair()
        doc = make_signed_document(SAMPLE_DOC, kp.private_key, kp.verification_method)
        proof = dict(doc["proof"])  # type: ignore[arg-type]
        proof["verificationMethod"] = "not-a-did"
        doc = {**doc, "proof": proof}
        with pytest.raises(ProofError, match="verificationMethod"):
            verify_document_proof(doc)
