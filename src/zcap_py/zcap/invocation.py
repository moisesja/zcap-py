"""Invocation verification (FR-INVOKE-01 through FR-INVOKE-07)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from zcap_py.did.url import strip_did_fragment
from zcap_py.exceptions import InvocationError, InvokerMismatchError
from zcap_py.proof.ed25519_2020 import verify_document_proof

if TYPE_CHECKING:
    from zcap_py.zcap.caveats import CaveatRegistry
    from zcap_py.zcap.models import Capability, Invocation


def _controller_contains(controller: str | list[str], did: str) -> bool:
    """Check if *did* matches the controller (string or array)."""
    if isinstance(controller, list):
        return did in controller
    return did == controller


def verify_invocation(
    invocation: Invocation,
    capability: Capability,
    *,
    caveat_registry: CaveatRegistry | None = None,
) -> None:
    """Verify an invocation against its target capability.

    Args:
        invocation: The parsed invocation document.
        capability: The capability being invoked.
        caveat_registry: Optional caveat registry for caveat verification.

    Raises:
        InvocationError: On structural mismatches.
        InvokerMismatchError: If the invoker DID doesn't match the capability.
        SignatureVerificationError: If the cryptographic proof fails.
        CaveatError / UnknownCaveatError: If caveat verification fails.
    """
    # FR-INVOKE-01: proof.capability == capability.id
    if invocation.proof.capability != capability.id:
        raise InvocationError(
            "Invocation proof.capability does not match capability id",
            context={
                "proof_capability": invocation.proof.capability,
                "capability_id": capability.id,
            },
        )

    # FR-INVOKE-04: body.capability == capability.id (proof/body consistency)
    if invocation.capability != capability.id:
        raise InvocationError(
            "Invocation body capability does not match capability id",
            context={
                "invocation_capability": invocation.capability,
                "capability_id": capability.id,
            },
        )

    # FR-INVOKE-02: invocationTarget match
    if invocation.invocation_target != capability.invocation_target:
        raise InvocationError(
            "Invocation invocationTarget does not match capability",
            context={
                "invocation_target": invocation.invocation_target,
                "capability_target": capability.invocation_target,
            },
        )

    # FR-INVOKE-03: Invoker identity
    invoker_did = strip_did_fragment(invocation.proof.verification_method)
    expected = capability.invoker if capability.invoker else capability.controller
    if not _controller_contains(expected, invoker_did):
        raise InvokerMismatchError(
            f"Invoker '{invoker_did}' does not match expected '{expected}'",
            context={"invoker": invoker_did, "expected": expected},
        )

    # FR-INVOKE-05: capabilityAction check
    if (
        invocation.proof.capability_action is not None
        and capability.allowed_action is not None
        and invocation.proof.capability_action not in capability.allowed_action
    ):
        raise InvocationError(
            f"capabilityAction '{invocation.proof.capability_action}' "
            f"not in capability's allowedAction",
            context={
                "capability_action": invocation.proof.capability_action,
                "allowed_actions": capability.allowed_action,
            },
        )

    # FR-INVOKE-06: Cryptographic proof verification
    verify_document_proof(invocation.raw)

    # FR-INVOKE-07: Caveat verification
    if caveat_registry is not None and capability.caveat:
        caveat_registry.verify_all(capability.caveat, invocation.raw)
