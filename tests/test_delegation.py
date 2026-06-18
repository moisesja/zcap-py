"""Tests for delegation chain verification."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tests.conftest import make_signed_document
from zcap_py.crypto.ed25519 import generate_ed25519_keypair
from zcap_py.exceptions import (
    ActionAttenuationError,
    CapabilityExpiredError,
    ChainVerificationError,
    DelegationError,
    ExpiryAttenuationError,
    InvocationTargetError,
)
from zcap_py.zcap.delegation import verify_delegation_chain
from zcap_py.zcap.parser import ZcapParser

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
    cap_id: str = "urn:delegated:cap",
) -> dict[str, object]:
    """Build a signed delegated capability."""
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
    # Delegated capabilities MUST have expires; default to far-future when unset.
    base["expires"] = expires if expires is not None else "2099-01-01T00:00:00Z"
    return make_signed_document(base, parent_key, parent_vm)  # type: ignore[arg-type]


class TestValidDelegation:
    def test_valid_1hop_chain(self) -> None:
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

        verify_delegation_chain(root, [child])

    def test_valid_2hop_chain(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        carol = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        cap_a_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read", "write"],
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

        verify_delegation_chain(root, [cap_a, cap_b])

    def test_empty_chain_passes(self) -> None:
        alice = generate_ed25519_keypair()
        root = parser.parse_capability(_make_root(alice.did))
        verify_delegation_chain(root, [])


class TestSignerMismatch:
    def test_wrong_signer_raises_delegation_error(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        eve = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        # Signed by Eve instead of Alice (root controller)
        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=eve.private_key,
            parent_vm=eve.verification_method,
            controller_did=bob.did,
        )
        child = parser.parse_capability(child_raw)

        with pytest.raises(ChainVerificationError) as exc_info:
            verify_delegation_chain(root, [child])
        assert isinstance(exc_info.value.__cause__, DelegationError)


class TestParentCapabilityLinkage:
    def test_wrong_parent_id_raises_delegation_error(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_delegated(
            parent_id="urn:wrong:parent",
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
        )
        child = parser.parse_capability(child_raw)

        with pytest.raises(ChainVerificationError) as exc_info:
            verify_delegation_chain(root, [child])
        assert isinstance(exc_info.value.__cause__, DelegationError)


class TestAllowedActionAttenuation:
    def test_action_not_in_parent_raises_error(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root_raw: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:root:cap",
            "type": "Authorization",
            "controller": alice.did,
            "parentCapability": "urn:trust:anchor",
            "invocationTarget": "https://api.example.com/data/",
            "allowedAction": ["read"],
            "expires": "2099-01-01T00:00:00Z",
        }
        root_signed = make_signed_document(root_raw, alice.private_key, alice.verification_method)
        parent_cap = parser.parse_capability(root_signed)

        child_raw = _make_delegated(
            parent_id=parent_cap.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read", "write"],
        )
        child = parser.parse_capability(child_raw)

        with pytest.raises(ChainVerificationError) as exc_info:
            verify_delegation_chain(parent_cap, [child])
        assert isinstance(exc_info.value.__cause__, ActionAttenuationError)

    def test_parent_none_actions_allows_any_child(self) -> None:
        """Root with no allowedAction (None) permits any child actions."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        assert root.allowed_action is None

        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read", "write", "delete"],
        )
        child = parser.parse_capability(child_raw)

        verify_delegation_chain(root, [child])

    def test_child_none_actions_is_valid(self) -> None:
        """Child with no allowedAction inherits parent's full set."""
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=None,
        )
        child = parser.parse_capability(child_raw)
        assert child.allowed_action is None

        verify_delegation_chain(root, [child])


class TestExpiryAttenuation:
    def test_child_expires_after_parent_raises_error(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        parent_raw: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:parent:cap",
            "type": "Authorization",
            "controller": alice.did,
            "parentCapability": "urn:trust:anchor",
            "invocationTarget": "https://api.example.com/data/",
            "allowedAction": ["read"],
            "expires": "2099-06-01T00:00:00Z",
        }
        parent_signed = make_signed_document(
            parent_raw, alice.private_key, alice.verification_method
        )
        parent_cap = parser.parse_capability(parent_signed)

        child_raw = _make_delegated(
            parent_id=parent_cap.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read"],
            expires="2099-12-31T00:00:00Z",
        )
        child = parser.parse_capability(child_raw)

        with pytest.raises(ChainVerificationError) as exc_info:
            verify_delegation_chain(parent_cap, [child])
        assert isinstance(exc_info.value.__cause__, ExpiryAttenuationError)

    def test_child_expires_within_parent_is_valid(self) -> None:
        """Child with an expiry at or before the parent's is valid.

        ``expires`` is required on delegated capabilities, so the only valid
        case is a child expiry that does not exceed the parent's.
        """
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        parent_raw: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:parent:cap",
            "type": "Authorization",
            "controller": alice.did,
            "parentCapability": "urn:trust:anchor",
            "invocationTarget": "https://api.example.com/data/",
            "allowedAction": ["read"],
            "expires": "2099-06-01T00:00:00Z",
        }
        parent_signed = make_signed_document(
            parent_raw, alice.private_key, alice.verification_method
        )
        parent_cap = parser.parse_capability(parent_signed)

        child_raw = _make_delegated(
            parent_id=parent_cap.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            actions=["read"],
            expires="2099-05-01T00:00:00Z",  # before parent's 2099-06-01
        )
        child = parser.parse_capability(child_raw)

        verify_delegation_chain(parent_cap, [child])


class TestAbsoluteExpiry:
    """#20 — verify_delegation_chain is fail-closed on absolute expiry."""

    def test_standalone_chain_rejects_expired_capability(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        root = parser.parse_capability(_make_root(alice.did))
        child = parser.parse_capability(
            _make_delegated(
                parent_id=root.id,
                parent_key=alice.private_key,
                parent_vm=alice.verification_method,
                controller_did=bob.did,
                actions=["read"],
                expires="2020-01-01T00:00:00Z",  # long past
            )
        )
        with pytest.raises(CapabilityExpiredError, match="expired"):
            verify_delegation_chain(root, [child])

    def test_injected_clock_before_expiry_passes(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        root = parser.parse_capability(_make_root(alice.did))
        child = parser.parse_capability(
            _make_delegated(
                parent_id=root.id,
                parent_key=alice.private_key,
                parent_vm=alice.verification_method,
                controller_did=bob.did,
                actions=["read"],
                expires="2020-06-01T00:00:00Z",
            )
        )
        # Clock before the child's expiry → not expired.
        verify_delegation_chain(
            root, [child], clock=lambda: datetime(2020, 1, 1, tzinfo=UTC)
        )


class TestInvocationTargetAttenuation:
    def test_exact_match_passes(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
        )
        child = parser.parse_capability(child_raw)

        verify_delegation_chain(root, [child])

    def test_narrowed_with_attenuation_enabled(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            target="https://api.example.com/data/records/42",
        )
        child = parser.parse_capability(child_raw)

        verify_delegation_chain(root, [child], allow_target_attenuation=True)

    def test_narrowed_without_attenuation_raises_error(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            target="https://api.example.com/data/records/42",
        )
        child = parser.parse_capability(child_raw)

        with pytest.raises(ChainVerificationError) as exc_info:
            verify_delegation_chain(root, [child])
        assert isinstance(exc_info.value.__cause__, InvocationTargetError)

    def test_broadened_target_raises_error(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            target="https://api.example.com/",
        )
        child = parser.parse_capability(child_raw)

        with pytest.raises(ChainVerificationError) as exc_info:
            verify_delegation_chain(root, [child], allow_target_attenuation=True)
        assert isinstance(exc_info.value.__cause__, InvocationTargetError)


class TestControllerAsArray:
    def test_signer_in_controller_array_passes(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        carol = generate_ed25519_keypair()

        root_raw: dict[str, object] = {
            "@context": "https://w3id.org/zcap/v1",
            "id": "urn:root:cap",
            "controller": [alice.did, carol.did],
            "invocationTarget": "https://api.example.com/data/",
        }
        root = parser.parse_capability(root_raw)

        # Signed by Alice (one of the controllers)
        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
        )
        child = parser.parse_capability(child_raw)

        verify_delegation_chain(root, [child])

    def test_signer_not_in_controller_array_raises_error(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        eve = generate_ed25519_keypair()

        root_raw: dict[str, object] = {
            "@context": "https://w3id.org/zcap/v1",
            "id": "urn:root:cap",
            "controller": [alice.did, bob.did],
            "invocationTarget": "https://api.example.com/data/",
        }
        root = parser.parse_capability(root_raw)

        # Signed by Eve (not in the controller list)
        child_raw = _make_delegated(
            parent_id=root.id,
            parent_key=eve.private_key,
            parent_vm=eve.verification_method,
            controller_did=bob.did,
        )
        child = parser.parse_capability(child_raw)

        with pytest.raises(ChainVerificationError) as exc_info:
            verify_delegation_chain(root, [child])
        assert isinstance(exc_info.value.__cause__, DelegationError)


class TestChainVerificationError:
    def test_error_wraps_cause(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        child_raw = _make_delegated(
            parent_id="urn:wrong:parent",
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
        )
        child = parser.parse_capability(child_raw)

        with pytest.raises(ChainVerificationError) as exc_info:
            verify_delegation_chain(root, [child])
        assert exc_info.value.__cause__ is not None
        assert exc_info.value.context["link"] == 0

    def test_error_at_second_link_reports_link_1(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()
        carol = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        cap_a_raw = _make_delegated(
            parent_id=root.id,
            parent_key=alice.private_key,
            parent_vm=alice.verification_method,
            controller_did=bob.did,
            cap_id="urn:cap:a",
        )
        cap_a = parser.parse_capability(cap_a_raw)

        # cap_b has wrong parentCapability
        cap_b_raw = _make_delegated(
            parent_id="urn:wrong:parent",
            parent_key=bob.private_key,
            parent_vm=bob.verification_method,
            controller_did=carol.did,
            cap_id="urn:cap:b",
        )
        cap_b = parser.parse_capability(cap_b_raw)

        with pytest.raises(ChainVerificationError) as exc_info:
            verify_delegation_chain(root, [cap_a, cap_b])
        assert exc_info.value.context["link"] == 1


class TestMissingProof:
    def test_child_without_proof_raises_error(self) -> None:
        alice = generate_ed25519_keypair()
        bob = generate_ed25519_keypair()

        root = parser.parse_capability(_make_root(alice.did))
        # Delegated cap without proof (no signing)
        child_raw: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:delegated:cap",
            "type": "Authorization",
            "controller": bob.did,
            "parentCapability": root.id,
            "invocationTarget": "https://api.example.com/data/",
            "expires": "2099-01-01T00:00:00Z",
        }
        child = parser.parse_capability(child_raw)
        assert child.proof is None

        with pytest.raises(ChainVerificationError) as exc_info:
            verify_delegation_chain(root, [child])
        assert isinstance(exc_info.value.__cause__, DelegationError)


class TestMaxChainLength:
    """Max chain length (default 10) — long-chain attack mitigation."""

    def _chain(self, alice: object, n: int) -> list:  # type: ignore[type-arg]
        # n parseable delegated caps; signatures/linkage irrelevant because the
        # length gate is enforced before any per-link work.
        caps = []
        for i in range(n):
            raw = _make_delegated(
                parent_id="urn:root:cap",
                parent_key=alice.private_key,  # type: ignore[attr-defined]
                parent_vm=alice.verification_method,  # type: ignore[attr-defined]
                controller_did=alice.did,  # type: ignore[attr-defined]
                actions=["read"],
                cap_id=f"urn:delegated:cap{i}",
            )
            caps.append(parser.parse_capability(raw))
        return caps

    def test_chain_exceeding_default_max_raises_before_crypto(self) -> None:
        alice = generate_ed25519_keypair()
        root = parser.parse_capability(_make_root(alice.did))
        chain = self._chain(alice, 10)  # 10 + root = 11 > 10

        def boom(_doc: dict[str, object]) -> None:
            raise AssertionError("crypto must not run before the length check")

        with pytest.raises(ChainVerificationError, match="exceeds maximum"):
            verify_delegation_chain(root, chain, proof_verifier=boom)

    def test_custom_max_chain_length_enforced(self) -> None:
        alice = generate_ed25519_keypair()
        root = parser.parse_capability(_make_root(alice.did))
        chain = self._chain(alice, 3)  # 3 + root = 4 > 2

        with pytest.raises(ChainVerificationError, match="exceeds maximum"):
            verify_delegation_chain(
                root, chain, max_chain_length=2, proof_verifier=lambda _doc: None
            )
