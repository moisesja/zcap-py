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
    meta: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": signer.verification_method,
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": "capabilityDelegation",
    }
    return sign_document_proof_w3c(base, meta, signer.private_key)


def _invocation(
    capability: object,
    target: str,
    invoker: DidKeyPair,
    *,
    action: str,
    chain: list[object],
) -> dict[str, object]:
    """A capabilityInvocation proof over a target doc.

    ``capability`` (string id or embedded full object), ``invocationTarget``,
    ``capabilityAction`` and ``capabilityChain`` are carried in the (signed)
    proof — there is no body type/capability/invocationTarget.
    """
    base: dict[str, object] = {
        "@context": [ZCAP, SUITE],
        "id": "urn:uuid:inv",
    }
    meta: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": invoker.verification_method,
        "created": "2026-01-01T00:00:00Z",
        "proofPurpose": "capabilityInvocation",
        "capability": capability,
        "invocationTarget": target,
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
            allowed_action=["read"],
        )
        # Same id, escalated authority, self-signed by the attacker.
        forged = _delegated(
            "urn:zcap:cap-1", attacker.did, root["id"], secret, attacker,
            allowed_action=["read", "write", "transfer"],
        )
        inv = _invocation(
            forged, secret, attacker,
            action="transfer", chain=[root, legit_leaf],
        )
        # Caller supplies the genuine, trusted chain (the safe pattern). The
        # forged capability is embedded in the invocation body. Authorization must
        # bind to the verified leaf, not the forged embedded capability.
        trusted_chain = [parser.parse_capability(root), parser.parse_capability(legit_leaf)]
        verifier = ZcapVerifier()
        with pytest.raises(InvocationError):
            verifier.verify_invocation(
                parser.parse_invocation(inv),
                chain=trusted_chain,
                expected_root_id="urn:zcap:root:alice",
            )

    def test_genuine_invocation_still_passes(self) -> None:
        root_ctrl = generate_ed25519_keypair()
        alice = generate_ed25519_keypair()
        victim = "https://bank.example/accounts/alice"
        root = _root("urn:zcap:root:alice", root_ctrl.did, victim)
        legit_leaf = _delegated(
            "urn:zcap:cap-1", alice.did, root["id"], victim, root_ctrl,
            allowed_action=["read"],
        )
        inv = _invocation(
            legit_leaf, victim, alice,
            action="read", chain=[root, legit_leaf],
        )
        trusted_chain = [parser.parse_capability(root), parser.parse_capability(legit_leaf)]
        ZcapVerifier().verify_invocation(
            parser.parse_invocation(inv),
            chain=trusted_chain,
            expected_root_id="urn:zcap:root:alice",
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
            action="transfer", chain=[root, alice_cap, child],
        )
        trusted_chain = [
            parser.parse_capability(root),
            parser.parse_capability(alice_cap),
            parser.parse_capability(child),
        ]
        with pytest.raises(InvocationError, match="effective allowedAction"):
            ZcapVerifier().verify_invocation(
                parser.parse_invocation(inv), chain=trusted_chain
            )

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


class TestRootTrustModel:
    """#9 root-anchor trust model — what is and is not closed.

    The root is the trust anchor; it carries no proof and cannot be
    cryptographically verified. The verifier therefore must obtain it from a
    TRUSTED source. Two safe sources: a caller-supplied ``chain`` (the caller
    vouches for the root), or a trusted ``document_loader`` resolving the root by
    id. An embedded root in the invoker-supplied ``proof.capabilityChain`` is
    NOT trusted and is rejected.
    """

    def _forged(self) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        attacker = generate_ed25519_keypair()
        known_root_id = "urn:zcap:root:alice"  # public, non-secret
        victim = "https://bank.example/accounts/victim"
        forged_root = {
            "@context": ZCAP, "id": known_root_id,
            "controller": attacker.did, "invocationTarget": victim,
        }
        leaf = _delegated(
            "urn:uuid:leaf", attacker.did, known_root_id, victim, attacker,
            allowed_action=["transfer"],
        )
        inv = _invocation(
            leaf, victim, attacker,
            action="transfer", chain=[forged_root, leaf],
        )
        return forged_root, leaf, inv

    def test_forged_root_embedded_in_proof_chain_is_rejected(self) -> None:
        # The reviewer's PoC: forged root embedded in proof.capabilityChain, with
        # expected_root_id pinned. Now rejected (root must come from a trusted
        # source, not invoker-supplied content).
        _root, _leaf, inv = self._forged()
        with pytest.raises(InvocationError, match="must be referenced by id"):
            ZcapVerifier().verify_invocation(
                parser.parse_invocation(inv), expected_root_id="urn:zcap:root:alice"
            )

    def test_caller_supplied_untrusted_root_is_trusted_by_design(self) -> None:
        # KNOWN CONTRACT (residual #9): if the application itself passes an
        # untrusted root in `chain`, the verifier trusts it — the root is the
        # trust anchor and the verifier cannot verify it. Applications MUST supply
        # a root from a trusted store. This test documents that contract.
        forged_root, leaf, inv = self._forged()
        chain = [parser.parse_capability(forged_root), parser.parse_capability(leaf)]
        # Accepted because the CALLER vouched for the (here, attacker-chosen) root.
        ZcapVerifier().verify_invocation(parser.parse_invocation(inv), chain=chain)


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

    @pytest.mark.parametrize("bad", [[], None, "a string", 42, ("t",)])
    def test_non_dict_document_to_parser_raises_zcap_parse_error(self, bad: object) -> None:
        """Red-team (2026-06-18): the public from-dict parser API must confine a
        non-dict top-level document to the ZcapError hierarchy — previously
        ``_validate_context`` called ``raw.get`` and leaked a raw AttributeError.
        """
        with pytest.raises(ZcapParseError):
            parser.parse_capability(bad)  # type: ignore[arg-type]
        with pytest.raises(ZcapParseError):
            parser.parse_invocation(bad)  # type: ignore[arg-type]

    def test_document_loader_returning_none_raises_invocation_error(self) -> None:
        root_ctrl = generate_ed25519_keypair()
        alice = generate_ed25519_keypair()
        target = "https://api.example/r/"
        child = _delegated(
            "urn:b", alice.did, "urn:root", target, root_ctrl, allowed_action=["read"]
        )
        inv = _invocation(
            child, target, alice,
            action="read", chain=["urn:root", child],
        )
        # Documented .get-style loader that returns None for an unknown id.
        verifier = ZcapVerifier(document_loader=lambda _cid: None)  # type: ignore[arg-type,return-value]
        with pytest.raises(InvocationError):
            verifier.verify_invocation(parser.parse_invocation(inv))
