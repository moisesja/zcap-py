"""Regression tests for the adversarial red-team findings (2026-06-17).

Each test pins a confirmed exploit/crash from the red-team as now-closed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from zcap_py import (
    ZcapParser,
    ZcapVerifier,
    generate_ed25519_keypair,
    sign_document_proof_w3c,
    verify_document_proof_w3c,
)
from zcap_py.exceptions import (
    CanonicalizationError,
    InvocationError,
    ProofError,
    ZcapParseError,
)

if TYPE_CHECKING:
    from zcap_py.crypto.ed25519 import DidKeyPair

ZCAP = "https://w3id.org/zcap/v1"
SUITE = "https://w3id.org/security/suites/ed25519-2020/v1"
FUTURE = "2099-01-01T00:00:00Z"

parser = ZcapParser()


def _root(cid: str, controller: str, target: str) -> dict[str, object]:
    return {"@context": ZCAP, "id": cid, "controller": controller, "invocationTarget": target}


def _delegated(
    cid: str,
    controller: str,
    parent_id: str,
    target: str,
    signer: DidKeyPair,
    *,
    allowed_action: list[str] | None,
    invoker: str | None = None,
) -> dict[str, object]:
    base: dict[str, object] = {
        "@context": [ZCAP, SUITE],
        "id": cid,
        "type": "Authorization",
        "controller": controller,
        "parentCapability": parent_id,
        "invocationTarget": target,
        "expires": FUTURE,
    }
    if allowed_action is not None:
        base["allowedAction"] = allowed_action
    if invoker is not None:
        base["invoker"] = invoker
    meta: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": signer.verification_method,
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": "capabilityDelegation",
    }
    return sign_document_proof_w3c(base, meta, signer.private_key)


def _invocation(
    capability_field: object,
    target: str,
    invoker: DidKeyPair,
    *,
    cap_id: str,
    action: str,
    chain: list[object],
) -> dict[str, object]:
    base: dict[str, object] = {
        "@context": [ZCAP, SUITE],
        "id": "urn:uuid:inv",
        "type": "Invocation",
        "capability": capability_field,
        "invocationTarget": target,
    }
    meta: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": invoker.verification_method,
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": "capabilityInvocation",
        "capability": cap_id,
        "capabilityAction": action,
        "capabilityChain": chain,
    }
    return sign_document_proof_w3c(base, meta, invoker.private_key)


class TestAuthorizationHijack:
    """CRITICAL: authority must come from the verified chain leaf, not the
    caller-supplied/embedded capability (id-equality is not content-equality)."""

    def test_forged_embedded_cap_with_genuine_chain_is_rejected(self) -> None:
        root_ctrl = generate_ed25519_keypair()
        alice = generate_ed25519_keypair()
        attacker = generate_ed25519_keypair()
        victim = "https://bank.example/accounts/alice"
        secret = "https://bank.example/accounts/bob/secret"

        root = _root("urn:zcap:root:alice", root_ctrl.did, victim)
        legit_leaf = _delegated(
            "urn:zcap:cap-1", alice.did, root["id"], victim, root_ctrl,
            allowed_action=["read"], invoker=alice.did,
        )
        # Same id, escalated authority, self-signed by the attacker.
        forged = _delegated(
            "urn:zcap:cap-1", attacker.did, root["id"], secret, attacker,
            allowed_action=["read", "write", "transfer"], invoker=attacker.did,
        )
        inv = _invocation(
            forged, secret, attacker,
            cap_id="urn:zcap:cap-1", action="transfer", chain=[root, legit_leaf],
        )
        verifier = ZcapVerifier()
        with pytest.raises(InvocationError):
            verifier.verify_invocation(
                parser.parse_invocation(inv), expected_root_id="urn:zcap:root:alice"
            )

    def test_genuine_invocation_still_passes(self) -> None:
        root_ctrl = generate_ed25519_keypair()
        alice = generate_ed25519_keypair()
        victim = "https://bank.example/accounts/alice"
        root = _root("urn:zcap:root:alice", root_ctrl.did, victim)
        legit_leaf = _delegated(
            "urn:zcap:cap-1", alice.did, root["id"], victim, root_ctrl,
            allowed_action=["read"], invoker=alice.did,
        )
        inv = _invocation(
            legit_leaf, victim, alice,
            cap_id="urn:zcap:cap-1", action="read", chain=[root, legit_leaf],
        )
        ZcapVerifier().verify_invocation(
            parser.parse_invocation(inv), expected_root_id="urn:zcap:root:alice"
        )


class TestActionAttenuationOmission:
    """CRITICAL: a child omitting allowedAction inherits the restriction; it does
    not re-broaden to all actions."""

    def test_omitting_allowed_action_does_not_rebroaden_at_invocation(self) -> None:
        root_ctrl = generate_ed25519_keypair()
        alice = generate_ed25519_keypair()
        target = "https://api.example/r/"
        root = _root("urn:root", root_ctrl.did, target)
        alice_cap = _delegated(
            "urn:a", alice.did, root["id"], target, root_ctrl, allowed_action=["read"]
        )
        # Alice (controller of a read-only cap) mints a child that OMITS allowedAction.
        child = _delegated("urn:b", alice.did, alice_cap["id"], target, alice, allowed_action=None)
        inv = _invocation(
            child, target, alice,
            cap_id="urn:b", action="transfer", chain=[root, alice_cap, child],
        )
        with pytest.raises(InvocationError, match="effective allowedAction"):
            ZcapVerifier().verify_invocation(parser.parse_invocation(inv))

    def test_omission_then_rebroaden_in_chain_is_rejected(self) -> None:
        # root(all) -> a[read] -> b(omit, inherits read) -> c[read,write].
        # The pairwise b->c check is skipped (b omits), so the effective-set
        # check must catch c broadening beyond the inherited {read}.
        from zcap_py.exceptions import ChainVerificationError
        from zcap_py.zcap.delegation import verify_delegation_chain

        root_ctrl = generate_ed25519_keypair()
        alice = generate_ed25519_keypair()
        target = "https://api.example/r/"
        root = parser.parse_capability(_root("urn:root", root_ctrl.did, target))
        a = parser.parse_capability(
            _delegated("urn:a", alice.did, "urn:root", target, root_ctrl, allowed_action=["read"])
        )
        b = parser.parse_capability(
            _delegated("urn:b", alice.did, "urn:a", target, alice, allowed_action=None)
        )
        c = parser.parse_capability(
            _delegated("urn:c", alice.did, "urn:b", target, alice, allowed_action=["read", "write"])
        )
        with pytest.raises(ChainVerificationError):
            verify_delegation_chain(root, [a, b, c])


class TestErrorContract:
    """Malicious documents must only ever raise ZcapError subclasses."""

    def test_tz_naive_expires_raises_zcap_parse_error(self) -> None:
        kp = generate_ed25519_keypair()
        raw = _delegated("urn:c", kp.did, "urn:root", "https://x/", kp, allowed_action=["read"])
        raw["expires"] = "2099-01-01T00:00:00"  # no offset → naive
        with pytest.raises(ZcapParseError, match="timezone-aware"):
            parser.parse_capability(raw)

    def test_non_dict_document_raises_proof_error(self) -> None:
        with pytest.raises(ProofError):
            verify_document_proof_w3c("not a dict")  # type: ignore[arg-type]

    def test_lone_surrogate_field_raises_zcap_error(self) -> None:
        from zcap_py.crypto.multibase import base58btc_encode

        kp = generate_ed25519_keypair()
        doc: dict[str, object] = {
            "@context": [ZCAP, SUITE],
            "id": "urn:test\ud800",  # lone UTF-16 surrogate
            "type": "Authorization",
            "controller": kp.did,
            "invocationTarget": "https://x/",
            "proof": {
                "type": "Ed25519Signature2020",
                "verificationMethod": kp.verification_method,
                "created": "2026-01-01T00:00:00Z",
                "proofPurpose": "capabilityDelegation",
                "proofValue": base58btc_encode(b"\x00" * 64),
            },
        }
        # Must be a ZcapError (CanonicalizationError), never a raw UnicodeError.
        with pytest.raises(CanonicalizationError):
            verify_document_proof_w3c(doc)

    def test_document_loader_returning_none_raises_invocation_error(self) -> None:
        root_ctrl = generate_ed25519_keypair()
        alice = generate_ed25519_keypair()
        target = "https://api.example/r/"
        child = _delegated(
            "urn:b", alice.did, "urn:root", target, root_ctrl, allowed_action=["read"]
        )
        inv = _invocation(
            child, target, alice,
            cap_id="urn:b", action="read", chain=["urn:root", child],
        )
        # Documented .get-style loader that returns None for an unknown id.
        verifier = ZcapVerifier(document_loader=lambda _cid: None)  # type: ignore[arg-type,return-value]
        with pytest.raises(InvocationError):
            verifier.verify_invocation(parser.parse_invocation(inv))
