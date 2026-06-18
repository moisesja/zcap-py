"""Invocation verification (FR-INVOKE-01 through FR-INVOKE-07)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from zcap_py.did.url import strip_did_fragment
from zcap_py.exceptions import InvocationError, InvokerMismatchError
from zcap_py.proof.ed25519_2020_w3c import verify_document_proof_w3c
from zcap_py.zcap.relationships import (
    CAPABILITY_INVOCATION,
    did_key_relationship_authorizer,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from zcap_py.zcap.caveats import CaveatRegistry
    from zcap_py.zcap.models import Capability, Invocation
    from zcap_py.zcap.relationships import RelationshipAuthorizer
    from zcap_py.zcap.target_attenuation import InvocationTargetAttenuator


def _controller_contains(controller: str | list[str], did: str) -> bool:
    """Check if *did* matches the controller (string or array)."""
    if isinstance(controller, list):
        return did in controller
    return did == controller


def _target_authorized(
    granted: str,
    requested: str,
    *,
    allow_target_attenuation: bool,
    target_attenuator: InvocationTargetAttenuator | None,
) -> bool:
    """Return True if *requested* target is authorized by *granted*.

    Exact match always passes. When ``allow_target_attenuation`` is set, a
    *requested* target that is a valid narrowing of *granted* (per the
    attenuator) also passes — consistent with the delegation-time target rule.
    """
    if requested == granted:
        return True
    if allow_target_attenuation and target_attenuator is not None:
        return target_attenuator.is_valid_attenuation(granted, requested)
    return False


def verify_invocation(
    invocation: Invocation,
    capability: Capability,
    *,
    expected_target: str | None = None,
    allow_target_attenuation: bool = False,
    target_attenuator: InvocationTargetAttenuator | None = None,
    caveat_registry: CaveatRegistry | None = None,
    proof_verifier: Callable[[dict[str, object]], None] | None = None,
    relationship_authorizer: RelationshipAuthorizer | None = None,
) -> None:
    """Verify an invocation against its target capability.

    An invocation is a ``capabilityInvocation`` Data-Integrity proof signed over
    the target; ``capability``, ``invocationTarget``, and ``capabilityAction``
    are read from the proof (there is no body-level duplication).

    .. warning::
        This is an **internal building block**. It performs only the
        structural, proof-purpose, invoker-identity, target, action,
        leaf-caveat, and cryptographic proof checks for a single
        ``(invocation, capability)`` pair. It does **not** verify the
        capability's delegation chain, anchor it to a trusted root, or check
        absolute expiry. Use :class:`~zcap_py.zcap.verifier.ZcapVerifier`, the
        authoritative fail-closed entry point, for trust decisions — invoking
        it directly on a delegated capability bypasses chain and expiry
        enforcement.

    Args:
        invocation: The parsed invocation document.
        capability: The capability being invoked (the cryptographically verified
            chain leaf when called via :class:`ZcapVerifier`).
        expected_target: Optional real request target. When provided, the signed
            ``proof.invocationTarget`` must authorize it (exact match, or a valid
            narrowing when ``allow_target_attenuation`` is set) — binding the
            invocation to the actual resource being accessed.
        allow_target_attenuation: Permit a narrowed target (default: exact match).
        target_attenuator: The attenuator used to validate narrowing.
        caveat_registry: Optional caveat registry for caveat verification.
        relationship_authorizer: Optional override of the verification-relationship
            authorization seam (defaults to the did:key authorizer).

    Raises:
        InvocationError: On structural mismatches, a wrong ``proofPurpose``, or a
            target that is not authorized.
        InvokerMismatchError: If the invoker DID doesn't match the controller.
        ProofError: If the invoker key is not authorized for the
            ``capabilityInvocation`` relationship.
        SignatureVerificationError: If the cryptographic proof fails.
        CaveatError / UnknownCaveatError: If caveat verification fails.
    """
    # #28: re-assert proofPurpose at VERIFY time (independent of the parser) so a
    # pre-built model or wrong-purpose proof is caught here. An invocation proof
    # MUST exercise the capabilityInvocation relationship.
    if invocation.proof.proof_purpose != CAPABILITY_INVOCATION:
        raise InvocationError(
            f"Invocation proof.proofPurpose must be '{CAPABILITY_INVOCATION}', "
            f"got '{invocation.proof.proof_purpose}'",
            context={"proof_purpose": invocation.proof.proof_purpose},
        )

    # FR-INVOKE-01: proof.capability == capability.id
    if invocation.proof.capability != capability.id:
        raise InvocationError(
            "Invocation proof.capability does not match capability id",
            context={
                "proof_capability": invocation.proof.capability,
                "capability_id": capability.id,
            },
        )

    # FR-INVOKE-02: the SIGNED proof.invocationTarget must be authorized by the
    # capability's (verified-leaf) target. The signed target — not any body
    # field — is what the verifier trusts, closing the malicious-proof-target gap.
    proof_target = invocation.proof.invocation_target
    if proof_target is None or not _target_authorized(
        capability.invocation_target,
        proof_target,
        allow_target_attenuation=allow_target_attenuation,
        target_attenuator=target_attenuator,
    ):
        raise InvocationError(
            "Invocation proof.invocationTarget is not authorized by the capability",
            context={
                "proof_invocation_target": proof_target,
                "capability_target": capability.invocation_target,
            },
        )

    # Bind the invocation to the actual request target when the caller supplies it.
    if expected_target is not None and not _target_authorized(
        proof_target,
        expected_target,
        allow_target_attenuation=allow_target_attenuation,
        target_attenuator=target_attenuator,
    ):
        raise InvocationError(
            "Invocation proof.invocationTarget does not authorize the request target",
            context={
                "proof_invocation_target": proof_target,
                "expected_target": expected_target,
            },
        )

    # FR-INVOKE-03: Invoker identity — controller-only (legacy invoker removed).
    invoker_did = strip_did_fragment(invocation.proof.verification_method)
    if not _controller_contains(capability.controller, invoker_did):
        raise InvokerMismatchError(
            f"Invoker '{invoker_did}' does not match controller '{capability.controller}'",
            context={"invoker": invoker_did, "controller": capability.controller},
        )

    # FR-INVOKE-05: capabilityAction check
    # When capability has allowedAction, capabilityAction is REQUIRED for cryptographic binding
    if capability.allowed_action is not None:
        if invocation.proof.capability_action is None:
            raise InvocationError(
                "Invocation proof must include 'capabilityAction' when "
                "capability has 'allowedAction'",
                context={
                    "allowed_actions": capability.allowed_action,
                    "capability_action": None,
                },
            )
        if invocation.proof.capability_action not in capability.allowed_action:
            raise InvocationError(
                f"capabilityAction '{invocation.proof.capability_action}' "
                f"not in capability's allowedAction",
                context={
                    "capability_action": invocation.proof.capability_action,
                    "allowed_actions": capability.allowed_action,
                },
            )

    # #28: verification-relationship authorization gate — confirm the invoker's
    # key is authorized by its controller for the capabilityInvocation
    # relationship (trivially true for did:key; the seam for non-did:key methods).
    (relationship_authorizer or did_key_relationship_authorizer)(
        invocation.proof.verification_method, CAPABILITY_INVOCATION
    )

    # FR-INVOKE-06: Cryptographic proof verification (W3C URDNA2015 by default)
    (proof_verifier or verify_document_proof_w3c)(invocation.raw)

    # FR-INVOKE-07: Caveat verification
    if caveat_registry is not None and capability.caveat:
        caveat_registry.verify_all(capability.caveat, invocation.raw)
