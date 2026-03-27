"""Tests for ZcapVerifier facade — F4, F2, F1, F6A."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tests.conftest import (
    make_proof_value,
    make_signed_document,
    make_w3c_proof_value,
    make_w3c_signed_document,
)
from zcap_py.crypto.ed25519 import generate_ed25519_keypair
from zcap_py.exceptions import (
    CapabilityExpiredError,
    CaveatError,
    ChainVerificationError,
    InvocationError,
    SignatureVerificationError,
)
from zcap_py.proof.ed25519_2020_w3c import verify_document_proof_w3c
from zcap_py.zcap.parser import ZcapParser
from zcap_py.zcap.verifier import ZcapVerifier

parser = ZcapParser()


def _make_root(
    controller_did: str, target: str = "https://api.example.com/data/"
) -> dict[str, object]:
    return {
        "@context": "https://w3id.org/zcap/v1",
        "id": "urn:root:cap",
        "controller": controller_did,
        "invocationTarget": target,
    }


def _make_delegated(
    *,
    parent_id: str,
    parent_key: object,
    parent_vm: str,
    controller_did: str,
    target: str = "https://api.example.com/data/",
    actions: list[str] | None = None,
    expires: str | None = None,
    caveat: list[dict[str, object]] | None = None,
    cap_id: str = "urn:delegated:cap",
) -> dict[str, object]:
    base: dict[str, object] = {
        "@context": [
            "https://w3id.org/zcap/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": cap_id,
        "type": "Authorization",
        "controller": controller_did,
        "parentCapability": parent_id,
        "invocationTarget": target,
    }
    if actions is not None:
        base["allowedAction"] = actions
    if expires is not None:
        base["expires"] = expires
    if caveat is not None:
        base["caveat"] = caveat
    return make_signed_document(base, parent_key, parent_vm)  # type: ignore[arg-type]


def _make_invocation(
    invoker_key: object,
    invoker_vm: str,
    *,
    cap_id: str = "urn:delegated:cap",
    target: str = "https://api.example.com/data/",
    capability_action: str | None = "read",
) -> dict[str, object]:
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


# ── F4: Absolute expiry at invocation time ──


class TestExpiryAtInvocationTime:
    def test_expired_capability_raises_error(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            expires="2026-01-01T00:00:00Z",
            actions=["read"],
        )
        child = parser.parse_capability(child_raw)

        inv_raw = _make_invocation(bob.private_key, bob.verification_method, cap_id=child.id)
        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier(
            clock=lambda: datetime(2026, 6, 1, tzinfo=UTC),
        )

        with pytest.raises(CapabilityExpiredError, match="expired"):
            verifier.verify_invocation(inv, child, chain=[root, child])

    def test_non_expired_capability_passes(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            expires="2027-01-01T00:00:00Z",
            actions=["read"],
        )
        child = parser.parse_capability(child_raw)

        inv_raw = _make_invocation(bob.private_key, bob.verification_method, cap_id=child.id)
        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier(
            clock=lambda: datetime(2026, 6, 1, tzinfo=UTC),
        )

        verifier.verify_invocation(inv, child, chain=[root, child])

    def test_no_expires_passes(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read"],
        )
        child = parser.parse_capability(child_raw)

        inv_raw = _make_invocation(bob.private_key, bob.verification_method, cap_id=child.id)
        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier(
            clock=lambda: datetime(2099, 1, 1, tzinfo=UTC),
        )

        verifier.verify_invocation(inv, child, chain=[root, child])

    def test_expired_ancestor_in_chain_raises_error(self) -> None:
        """Intermediate cap expired → CapabilityExpiredError even if leaf is valid."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        carol = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        # cap_a: expires 2026-06-01
        cap_a_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            expires="2026-06-01T00:00:00Z",
            actions=["read"],
            cap_id="urn:cap:a",
        )
        cap_a = parser.parse_capability(cap_a_raw)

        # cap_b: expires 2026-03-01 (before cap_a, so attenuation is valid)
        cap_b_raw = _make_delegated(
            parent_id=cap_a.id,
            parent_key=bob.private_key,
            parent_vm=bob.verification_method,
            controller_did=carol.did,
            expires="2026-03-01T00:00:00Z",
            actions=["read"],
            cap_id="urn:cap:b",
        )
        cap_b = parser.parse_capability(cap_b_raw)

        inv_raw = _make_invocation(carol.private_key, carol.verification_method, cap_id=cap_b.id)
        inv = parser.parse_invocation(inv_raw)

        # Clock is after both expiry dates
        verifier = ZcapVerifier(
            clock=lambda: datetime(2026, 7, 1, tzinfo=UTC),
        )

        with pytest.raises(CapabilityExpiredError):
            verifier.verify_invocation(inv, cap_b, chain=[root, cap_a, cap_b])


# ── F2: Chain-to-capability linkage ──


class TestChainToCapabilityLinkage:
    def test_chain_leaf_matches_capability_passes(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read"],
        )
        child = parser.parse_capability(child_raw)

        inv_raw = _make_invocation(bob.private_key, bob.verification_method, cap_id=child.id)
        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier()
        verifier.verify_invocation(inv, child, chain=[root, child])

    def test_chain_leaf_mismatch_raises_error(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        carol = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        # cap_a is in the chain
        cap_a_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read"],
            cap_id="urn:cap:a",
        )
        cap_a = parser.parse_capability(cap_a_raw)

        # cap_b is the target capability (different ID, not in chain)
        cap_b_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=carol.did,
            actions=["read"],
            cap_id="urn:cap:b",
        )
        cap_b = parser.parse_capability(cap_b_raw)

        inv_raw = _make_invocation(carol.private_key, carol.verification_method, cap_id=cap_b.id)
        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier()
        # Chain ends at cap_a but invoking cap_b
        with pytest.raises(InvocationError, match="Chain leaf"):
            verifier.verify_invocation(inv, cap_b, chain=[root, cap_a])


# ── F1: Ancestor caveat enforcement ──


class TestAncestorCaveatEnforcement:
    def test_ancestor_caveat_verifier_called(self) -> None:
        """Ancestor (non-leaf) capability's caveats must be checked."""
        calls: list[dict[str, object]] = []

        class TestVerifier:
            caveat_type = "TestCaveat"

            def verify(self, caveat: dict[str, object], invocation: dict[str, object]) -> None:
                calls.append(caveat)

        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        carol = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        # cap_a is the ancestor with a caveat
        cap_a_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            caveat=[{"type": "TestCaveat", "value": 42}],
            actions=["read"],
            cap_id="urn:cap:a",
        )
        cap_a = parser.parse_capability(cap_a_raw)

        # cap_b is the leaf (no caveats)
        cap_b_raw = _make_delegated(
            parent_id=cap_a.id,
            parent_key=bob.private_key,
            parent_vm=bob.verification_method,
            controller_did=carol.did,
            actions=["read"],
            cap_id="urn:cap:b",
        )
        cap_b = parser.parse_capability(cap_b_raw)

        inv_raw = _make_invocation(carol.private_key, carol.verification_method, cap_id=cap_b.id)
        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier(caveat_verifiers=[TestVerifier()])
        verifier.verify_invocation(inv, cap_b, chain=[root, cap_a, cap_b])

        assert len(calls) == 1
        assert calls[0]["type"] == "TestCaveat"

    def test_ancestor_caveat_failure_raises_error(self) -> None:
        class FailVerifier:
            caveat_type = "FailCaveat"

            def verify(self, caveat: dict[str, object], invocation: dict[str, object]) -> None:
                raise CaveatError("Ancestor caveat denied")

        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        carol = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        cap_a_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            caveat=[{"type": "FailCaveat"}],
            actions=["read"],
            cap_id="urn:cap:a",
        )
        cap_a = parser.parse_capability(cap_a_raw)

        cap_b_raw = _make_delegated(
            parent_id=cap_a.id,
            parent_key=bob.private_key,
            parent_vm=bob.verification_method,
            controller_did=carol.did,
            actions=["read"],
            cap_id="urn:cap:b",
        )
        cap_b = parser.parse_capability(cap_b_raw)

        inv_raw = _make_invocation(carol.private_key, carol.verification_method, cap_id=cap_b.id)
        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier(caveat_verifiers=[FailVerifier()])
        with pytest.raises(CaveatError, match="Ancestor caveat denied"):
            verifier.verify_invocation(inv, cap_b, chain=[root, cap_a, cap_b])

    def test_no_chain_skips_ancestor_caveats(self) -> None:
        """When no chain is provided, ancestor caveat check is skipped."""
        alice = generate_ed25519_keypair()

        cap_raw: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:cap:leaf",
            "type": "Authorization",
            "controller": alice.did,
            "parentCapability": "urn:root:cap",
            "invocationTarget": "https://api.example.com/data/",
            "allowedAction": ["read"],
        }
        cap = parser.parse_capability(cap_raw)

        inv_raw = _make_invocation(alice.private_key, alice.verification_method, cap_id=cap.id)
        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier()
        # No chain — should just do core invocation verification
        verifier.verify_invocation(inv, cap)


# ── F6A: Proof dispatcher ──


def _make_w3c_delegated(
    *,
    parent_id: str,
    parent_key: object,
    parent_vm: str,
    controller_did: str,
    target: str = "https://api.example.com/data/",
    actions: list[str] | None = None,
    cap_id: str = "urn:delegated:cap",
) -> dict[str, object]:
    """Build a delegated capability signed with W3C URDNA2015."""
    base: dict[str, object] = {
        "@context": [
            "https://w3id.org/zcap/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": cap_id,
        "type": "Authorization",
        "controller": controller_did,
        "parentCapability": parent_id,
        "invocationTarget": target,
    }
    if actions is not None:
        base["allowedAction"] = actions
    return make_w3c_signed_document(base, parent_key, parent_vm)  # type: ignore[arg-type]


def _make_w3c_invocation(
    invoker_key: object,
    invoker_vm: str,
    *,
    cap_id: str = "urn:delegated:cap",
    target: str = "https://api.example.com/data/",
    capability_action: str | None = "read",
) -> dict[str, object]:
    """Build an invocation signed with W3C URDNA2015."""
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
    pv = make_w3c_proof_value(base, proof_metadata, invoker_key)  # type: ignore[arg-type]
    proof: dict[str, object] = {**proof_metadata, "proofValue": pv}
    return {**base, "proof": proof}


class TestProofDispatcher:
    def test_w3c_signed_chain_verifies_with_w3c_verifier(self) -> None:
        """W3C-signed delegation + invocation pass when proof_verifier=W3C."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_w3c_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read"],
        )
        child = parser.parse_capability(child_raw)

        inv_raw = _make_w3c_invocation(bob.private_key, bob.verification_method, cap_id=child.id)
        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier(proof_verifier=verify_document_proof_w3c)
        verifier.verify_invocation(inv, child, chain=[root, child])

    def test_default_jcs_verifier_backward_compat(self) -> None:
        """Default (no proof_verifier) uses JCS — backward compatible."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read"],
        )
        child = parser.parse_capability(child_raw)

        inv_raw = _make_invocation(bob.private_key, bob.verification_method, cap_id=child.id)
        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier()  # No proof_verifier — default JCS
        verifier.verify_invocation(inv, child, chain=[root, child])

    def test_w3c_signed_fails_with_jcs_verifier(self) -> None:
        """W3C-signed doc should fail with default JCS verifier (mismatch)."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_w3c_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read"],
        )
        child = parser.parse_capability(child_raw)

        inv_raw = _make_w3c_invocation(bob.private_key, bob.verification_method, cap_id=child.id)
        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier()  # Default JCS verifier
        with pytest.raises(ChainVerificationError) as exc_info:
            verifier.verify_invocation(inv, child, chain=[root, child])
        assert isinstance(exc_info.value.__cause__, SignatureVerificationError)


# ── F6B: Embedded capabilities + capabilityChain ──


class TestEmbeddedCapability:
    def test_embedded_capability_parsed(self) -> None:
        """Invocation with embedded capability dict is parsed correctly."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root_raw = _make_root(alice.did)
        root = parser.parse_capability(root_raw)

        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read"],
        )

        # Build invocation with embedded capability (dict instead of string)
        inv_base: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:uuid:invocation-1",
            "type": "Invocation",
            "capability": child_raw,  # embedded dict
            "invocationTarget": "https://api.example.com/data/",
        }
        proof_metadata: dict[str, object] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": bob.verification_method,
            "created": "2026-01-01T00:00:00Z",
            "proofPurpose": "capabilityInvocation",
            "capability": str(child_raw["id"]),
            "capabilityAction": "read",
        }
        pv = make_proof_value(inv_base, proof_metadata, bob.private_key)
        proof: dict[str, object] = {**proof_metadata, "proofValue": pv}
        inv_raw: dict[str, object] = {**inv_base, "proof": proof}

        inv = parser.parse_invocation(inv_raw)

        assert inv.embedded_capability is not None
        assert inv.embedded_capability.id == str(child_raw["id"])
        assert inv.capability == str(child_raw["id"])

    def test_embedded_capability_used_as_default(self) -> None:
        """Verifier uses embedded capability when capability=None."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root_raw = _make_root(alice.did)
        root = parser.parse_capability(root_raw)

        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read"],
        )
        child = parser.parse_capability(child_raw)

        # Build invocation with embedded capability
        inv_base: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:uuid:invocation-1",
            "type": "Invocation",
            "capability": child_raw,  # embedded dict
            "invocationTarget": "https://api.example.com/data/",
        }
        proof_metadata: dict[str, object] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": bob.verification_method,
            "created": "2026-01-01T00:00:00Z",
            "proofPurpose": "capabilityInvocation",
            "capability": child.id,
            "capabilityAction": "read",
        }
        pv = make_proof_value(inv_base, proof_metadata, bob.private_key)
        proof_dict: dict[str, object] = {**proof_metadata, "proofValue": pv}
        inv_raw: dict[str, object] = {**inv_base, "proof": proof_dict}

        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier()
        # capability=None — should use embedded capability
        verifier.verify_invocation(inv, capability=None, chain=[root, child])


class TestCapabilityChainInProof:
    def test_capability_chain_in_proof_parsed(self) -> None:
        """capabilityChain entries (str + dict) are parsed into proof model."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        child_raw = _make_delegated(
            parent_id="urn:root:cap",
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read"],
        )

        inv_base: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:uuid:invocation-1",
            "type": "Invocation",
            "capability": str(child_raw["id"]),
            "invocationTarget": "https://api.example.com/data/",
        }
        proof_metadata: dict[str, object] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": bob.verification_method,
            "created": "2026-01-01T00:00:00Z",
            "proofPurpose": "capabilityInvocation",
            "capability": str(child_raw["id"]),
            "capabilityAction": "read",
            "capabilityChain": ["urn:root:cap", child_raw],
        }
        pv = make_proof_value(inv_base, proof_metadata, bob.private_key)
        proof_dict: dict[str, object] = {**proof_metadata, "proofValue": pv}
        inv_raw: dict[str, object] = {**inv_base, "proof": proof_dict}

        inv = parser.parse_invocation(inv_raw)

        assert inv.proof.capability_chain is not None
        assert len(inv.proof.capability_chain) == 2
        assert inv.proof.capability_chain[0] == "urn:root:cap"
        assert isinstance(inv.proof.capability_chain[1], dict)

    def test_capability_chain_string_entry_raises(self) -> None:
        """String entries in capabilityChain raise InvocationError (no loader)."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        child_raw = _make_delegated(
            parent_id="urn:root:cap",
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read"],
        )
        child = parser.parse_capability(child_raw)

        # Build invocation with capabilityChain containing string reference
        inv_base: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:uuid:invocation-1",
            "type": "Invocation",
            "capability": child.id,
            "invocationTarget": "https://api.example.com/data/",
        }
        proof_metadata: dict[str, object] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": bob.verification_method,
            "created": "2026-01-01T00:00:00Z",
            "proofPurpose": "capabilityInvocation",
            "capability": child.id,
            "capabilityAction": "read",
            "capabilityChain": ["urn:root:cap", child_raw],
        }
        pv = make_proof_value(inv_base, proof_metadata, bob.private_key)
        proof_dict: dict[str, object] = {**proof_metadata, "proofValue": pv}
        inv_raw: dict[str, object] = {**inv_base, "proof": proof_dict}

        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier()
        # chain=None → resolve from capabilityChain which has a string entry
        with pytest.raises(InvocationError, match="document loader"):
            verifier.verify_invocation(inv, child)

    def test_capability_chain_all_embedded_resolves(self) -> None:
        """capabilityChain with all embedded dicts resolves into delegation chain."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root_raw = _make_root(alice.did)

        child_raw = _make_delegated(
            parent_id="urn:root:cap",
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read"],
        )
        child = parser.parse_capability(child_raw)

        # Build invocation with capabilityChain containing all embedded dicts
        inv_base: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:uuid:invocation-1",
            "type": "Invocation",
            "capability": child.id,
            "invocationTarget": "https://api.example.com/data/",
        }
        proof_metadata: dict[str, object] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": bob.verification_method,
            "created": "2026-01-01T00:00:00Z",
            "proofPurpose": "capabilityInvocation",
            "capability": child.id,
            "capabilityAction": "read",
            "capabilityChain": [root_raw, child_raw],
        }
        pv = make_proof_value(inv_base, proof_metadata, bob.private_key)
        proof_dict: dict[str, object] = {**proof_metadata, "proofValue": pv}
        inv_raw: dict[str, object] = {**inv_base, "proof": proof_dict}

        inv = parser.parse_invocation(inv_raw)

        verifier = ZcapVerifier()
        # chain=None → auto-resolve from capabilityChain (all embedded)
        verifier.verify_invocation(inv, child)
