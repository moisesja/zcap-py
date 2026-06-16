"""Tests for invocation verification."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tests.conftest import make_proof_value
from zcap_py.crypto.ed25519 import generate_ed25519_keypair
from zcap_py.exceptions import (
    CaveatError,
    InvocationError,
    InvokerMismatchError,
    SignatureVerificationError,
    UnknownCaveatError,
)
from zcap_py.zcap.caveats import CaveatRegistry
from zcap_py.zcap.invocation import verify_invocation
from zcap_py.zcap.parser import ZcapParser

if TYPE_CHECKING:
    from zcap_py.zcap.models import Capability

parser = ZcapParser()


def _make_cap(
    controller_did: str,
    *,
    cap_id: str = "urn:cap:leaf",
    target: str = "https://api.example.com/data/",
    actions: list[str] | None = None,
    invoker: str | None = None,
    caveat: list[dict[str, object]] | None = None,
) -> Capability:
    """Build a parsed delegated capability (with parent, no real proof needed)."""
    raw: dict[str, object] = {
        "@context": [
            "https://w3id.org/zcap/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": cap_id,
        "type": "Authorization",
        "controller": controller_did,
        "parentCapability": "urn:root:cap",
        "invocationTarget": target,
        "expires": "2099-01-01T00:00:00Z",
    }
    if actions is not None:
        raw["allowedAction"] = actions
    if invoker is not None:
        raw["invoker"] = invoker
    if caveat is not None:
        raw["caveat"] = caveat
    return parser.parse_capability(raw)


def _make_invocation(
    invoker_key: object,
    invoker_vm: str,
    *,
    cap_id: str = "urn:cap:leaf",
    target: str = "https://api.example.com/data/",
    capability_action: str | None = "read",
) -> dict[str, object]:
    """Build a signed invocation document.

    Includes capability/capabilityAction in proof BEFORE signing
    so the signature covers these fields.
    """
    base: dict[str, object] = {
        "@context": [
            "https://w3id.org/zcap/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": "urn:uuid:invocation-1",
        "type": "Invocation",
        "capability": cap_id,
        "invocationTarget": target,
    }
    proof_metadata: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": invoker_vm,
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": "capabilityInvocation",
        "capability": cap_id,
    }
    if capability_action is not None:
        proof_metadata["capabilityAction"] = capability_action
    pv = make_proof_value(base, proof_metadata, invoker_key)  # type: ignore[arg-type]
    proof: dict[str, object] = {**proof_metadata, "proofValue": pv}
    return {**base, "proof": proof}


class TestValidInvocation:
    def test_valid_invocation_passes(self) -> None:
        bob = generate_ed25519_keypair()
        cap = _make_cap(bob.did, actions=["read"])
        inv_raw = _make_invocation(bob.private_key, bob.verification_method)
        inv = parser.parse_invocation(inv_raw)

        verify_invocation(inv, cap)

    def test_capability_action_absent_raises_when_allowed_action_present(self) -> None:
        """When capability has allowedAction, capabilityAction is required."""
        bob = generate_ed25519_keypair()
        cap = _make_cap(bob.did, actions=["read"])
        inv_raw = _make_invocation(bob.private_key, bob.verification_method, capability_action=None)
        inv = parser.parse_invocation(inv_raw)

        with pytest.raises(InvocationError, match="capabilityAction"):
            verify_invocation(inv, cap)

    def test_capability_action_absent_passes_when_no_allowed_action(self) -> None:
        """When capability has no allowedAction, capabilityAction is not required."""
        bob = generate_ed25519_keypair()
        cap = _make_cap(bob.did, actions=None)
        inv_raw = _make_invocation(bob.private_key, bob.verification_method, capability_action=None)
        inv = parser.parse_invocation(inv_raw)

        verify_invocation(inv, cap)


class TestProofCapabilityMismatch:
    def test_proof_capability_mismatch_raises_error(self) -> None:
        bob = generate_ed25519_keypair()
        cap = _make_cap(bob.did, cap_id="urn:cap:real")
        # Invocation references a different capability in its proof
        inv_raw = _make_invocation(bob.private_key, bob.verification_method, cap_id="urn:cap:wrong")
        inv = parser.parse_invocation(inv_raw)

        with pytest.raises(InvocationError, match="proof.capability"):
            verify_invocation(inv, cap)


class TestBodyCapabilityMismatch:
    def test_body_capability_mismatch_raises_error(self) -> None:
        bob = generate_ed25519_keypair()
        cap = _make_cap(bob.did, cap_id="urn:cap:real")
        inv_raw = _make_invocation(bob.private_key, bob.verification_method, cap_id="urn:cap:real")
        # Tamper: change the body.capability but not proof.capability
        inv_raw["capability"] = "urn:cap:tampered"
        inv = parser.parse_invocation(inv_raw)

        with pytest.raises(InvocationError, match="body capability"):
            verify_invocation(inv, cap)


class TestInvocationTargetMismatch:
    def test_target_mismatch_raises_error(self) -> None:
        bob = generate_ed25519_keypair()
        cap = _make_cap(bob.did, target="https://api.example.com/data/")
        inv_raw = _make_invocation(
            bob.private_key,
            bob.verification_method,
            target="https://api.example.com/other/",
        )
        inv = parser.parse_invocation(inv_raw)

        with pytest.raises(InvocationError, match="invocationTarget"):
            verify_invocation(inv, cap)


class TestInvokerIdentity:
    def test_invoker_mismatch_raises_error(self) -> None:
        bob = generate_ed25519_keypair()
        eve = generate_ed25519_keypair()
        cap = _make_cap(bob.did)
        # Signed by Eve, but capability controller is Bob
        inv_raw = _make_invocation(eve.private_key, eve.verification_method)
        inv = parser.parse_invocation(inv_raw)

        with pytest.raises(InvokerMismatchError):
            verify_invocation(inv, cap)

    def test_explicit_invoker_field_used(self) -> None:
        """When capability.invoker is set, that's the expected invoker — not controller."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        cap = _make_cap(alice.did, invoker=bob.did)
        inv_raw = _make_invocation(bob.private_key, bob.verification_method)
        inv = parser.parse_invocation(inv_raw)

        verify_invocation(inv, cap)

    def test_controller_as_array_invoker_in_list(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        # Build cap with controller as array
        raw: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:cap:leaf",
            "type": "Authorization",
            "controller": [alice.did, bob.did],
            "parentCapability": "urn:root:cap",
            "invocationTarget": "https://api.example.com/data/",
            "allowedAction": ["read"],
            "expires": "2099-01-01T00:00:00Z",
        }
        cap = parser.parse_capability(raw)

        inv_raw = _make_invocation(bob.private_key, bob.verification_method)
        inv = parser.parse_invocation(inv_raw)

        verify_invocation(inv, cap)


class TestCapabilityAction:
    def test_action_not_in_allowed_raises_error(self) -> None:
        bob = generate_ed25519_keypair()
        cap = _make_cap(bob.did, actions=["read"])
        inv_raw = _make_invocation(
            bob.private_key, bob.verification_method, capability_action="write"
        )
        inv = parser.parse_invocation(inv_raw)

        with pytest.raises(InvocationError, match="capabilityAction"):
            verify_invocation(inv, cap)


class TestCryptographicProof:
    def test_invalid_signature_raises_error(self) -> None:
        bob = generate_ed25519_keypair()
        eve = generate_ed25519_keypair()
        cap = _make_cap(bob.did)
        # Sign with Eve's key but claim Bob's verificationMethod
        base: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:uuid:invocation-1",
            "type": "Invocation",
            "capability": "urn:cap:leaf",
            "invocationTarget": "https://api.example.com/data/",
        }
        proof_metadata: dict[str, object] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": bob.verification_method,
            "created": "2026-01-01T00:00:00Z",
            "proofPurpose": "capabilityInvocation",
            "capability": "urn:cap:leaf",
            "capabilityAction": "read",
        }
        # Sign with Eve's key — signature won't match Bob's public key
        pv = make_proof_value(base, proof_metadata, eve.private_key)
        proof: dict[str, object] = {**proof_metadata, "proofValue": pv}
        signed: dict[str, object] = {**base, "proof": proof}
        inv = parser.parse_invocation(signed)

        with pytest.raises(SignatureVerificationError):
            verify_invocation(inv, cap)


class TestCaveatVerification:
    def test_unknown_caveat_raises_error(self) -> None:
        bob = generate_ed25519_keypair()
        cap = _make_cap(bob.did, caveat=[{"type": "UnknownCaveat"}])
        inv_raw = _make_invocation(bob.private_key, bob.verification_method)
        inv = parser.parse_invocation(inv_raw)
        registry = CaveatRegistry()

        with pytest.raises(UnknownCaveatError):
            verify_invocation(inv, cap, caveat_registry=registry)

    def test_caveat_verifier_called(self) -> None:
        calls: list[dict[str, object]] = []

        class TestVerifier:
            caveat_type = "TestCaveat"

            def verify(self, caveat: dict[str, object], invocation: dict[str, object]) -> None:
                calls.append(caveat)

        bob = generate_ed25519_keypair()
        cap = _make_cap(bob.did, caveat=[{"type": "TestCaveat", "value": 1}])
        inv_raw = _make_invocation(bob.private_key, bob.verification_method)
        inv = parser.parse_invocation(inv_raw)
        registry = CaveatRegistry([TestVerifier()])

        verify_invocation(inv, cap, caveat_registry=registry)
        assert len(calls) == 1

    def test_failing_caveat_propagates(self) -> None:
        class FailVerifier:
            caveat_type = "FailCaveat"

            def verify(self, caveat: dict[str, object], invocation: dict[str, object]) -> None:
                raise CaveatError("Denied")

        bob = generate_ed25519_keypair()
        cap = _make_cap(bob.did, caveat=[{"type": "FailCaveat"}])
        inv_raw = _make_invocation(bob.private_key, bob.verification_method)
        inv = parser.parse_invocation(inv_raw)
        registry = CaveatRegistry([FailVerifier()])

        with pytest.raises(CaveatError, match="Denied"):
            verify_invocation(inv, cap, caveat_registry=registry)

    def test_no_registry_skips_caveat_check(self) -> None:
        """When no caveat_registry is provided, caveats are not checked."""
        bob = generate_ed25519_keypair()
        cap = _make_cap(bob.did, caveat=[{"type": "SomeCaveat"}])
        inv_raw = _make_invocation(bob.private_key, bob.verification_method)
        inv = parser.parse_invocation(inv_raw)

        # No registry provided — should pass without checking caveats
        verify_invocation(inv, cap)
