"""Tests for the public W3C-flat payload helper and signing API."""

from __future__ import annotations

from zcap_py.crypto.ed25519 import generate_ed25519_keypair
from zcap_py.proof.ed25519_2020 import (
    build_canonical_payload,
    sign_document_proof,
    verify_document_proof,
)


def _document_body() -> dict[str, object]:
    return {
        "id": "urn:example:cap-public-api",
        "type": "Authorization",
        "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "invocationTarget": "https://api.example.com/data/",
    }


def _proof_metadata(verification_method: str) -> dict[str, object]:
    return {
        "type": "Ed25519Signature2020",
        "verificationMethod": verification_method,
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": "capabilityDelegation",
    }


class TestBuildCanonicalPayload:
    def test_strips_proof_value(self) -> None:
        """``proofValue`` must never appear in the bytes that get signed."""
        proof_with_value = {
            "type": "Ed25519Signature2020",
            "verificationMethod": "did:key:z6Mk...#z6Mk...",
            "created": "2026-01-01T00:00:00Z",
            "proofPurpose": "capabilityDelegation",
            "proofValue": "zSHOULD_NOT_BE_IN_CANONICAL_BYTES",
        }
        canonical = build_canonical_payload(_document_body(), proof_with_value)
        assert b"proofValue" not in canonical
        assert b"SHOULD_NOT_BE_IN_CANONICAL_BYTES" not in canonical

    def test_ignores_existing_proof_on_document(self) -> None:
        """When the wire document still carries its own ``proof``, the function
        must drop it and use the supplied ``proof`` argument instead — otherwise
        passing ``on_wire`` to a verifier would canonicalize different bytes
        than passing the body alone."""
        body = _document_body()
        proof_a = _proof_metadata("did:key:zA#zA")
        proof_b = _proof_metadata("did:key:zB#zB")

        wire = {**body, "proof": {**proof_a, "proofValue": "zSIG_A"}}
        from_wire = build_canonical_payload(wire, proof_b)
        from_body = build_canonical_payload(body, proof_b)

        assert from_wire == from_body
        assert b"zA" not in from_wire
        assert b"zB" in from_wire


class TestSignDocumentProof:
    def test_round_trips_through_verify(self) -> None:
        """A document signed via the public API must verify under
        ``verify_document_proof`` byte-for-byte without raising."""
        kp = generate_ed25519_keypair()
        signed = sign_document_proof(
            _document_body(), _proof_metadata(kp.verification_method), kp.private_key
        )
        verify_document_proof(signed)
        proof = signed["proof"]
        assert isinstance(proof, dict)
        assert isinstance(proof["proofValue"], str)
        assert proof["proofValue"].startswith("z")
