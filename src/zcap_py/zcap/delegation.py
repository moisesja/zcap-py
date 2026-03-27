"""Delegation chain verification (FR-DELEG-01 through FR-DELEG-08)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from zcap_py.did.url import strip_did_fragment
from zcap_py.exceptions import (
    ActionAttenuationError,
    ChainVerificationError,
    DelegationError,
    ExpiryAttenuationError,
    InvocationTargetError,
    ZcapError,
)
from zcap_py.proof.ed25519_2020 import verify_document_proof
from zcap_py.zcap.target_attenuation import (
    InvocationTargetAttenuator,
    PathPrefixAttenuator,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from zcap_py.zcap.models import Capability


def _controller_contains(controller: str | list[str], did: str) -> bool:
    """Check if *did* matches the controller (string or array)."""
    if isinstance(controller, list):
        return did in controller
    return did == controller


def _verify_delegation_link(
    parent: Capability,
    child: Capability,
    *,
    allow_target_attenuation: bool = False,
    target_attenuator: InvocationTargetAttenuator | None = None,
    proof_verifier: Callable[[dict[str, object]], None] | None = None,
) -> None:
    """Verify a single delegation link from *parent* to *child*.

    Raises:
        DelegationError: On structural violations.
        ActionAttenuationError: If child's actions exceed parent's.
        ExpiryAttenuationError: If child's expiry exceeds parent's.
        InvocationTargetError: If invocation target is invalid.
        SignatureVerificationError: If the cryptographic proof fails.
    """
    # Child must have a proof
    if child.proof is None:
        raise DelegationError(
            "Delegated capability is missing a proof",
            context={"child_id": child.id},
        )

    # FR-DELEG-01: Signer matches parent controller
    signer_did = strip_did_fragment(child.proof.verification_method)
    if not _controller_contains(parent.controller, signer_did):
        raise DelegationError(
            f"Proof signer '{signer_did}' is not the parent controller",
            context={
                "signer": signer_did,
                "parent_controller": parent.controller,
            },
        )

    # FR-DELEG-02: parentCapability linkage
    if child.parent_capability != parent.id:
        raise DelegationError(
            f"parentCapability '{child.parent_capability}' does not match parent id '{parent.id}'",
            context={
                "parent_capability": child.parent_capability,
                "parent_id": parent.id,
            },
        )

    # FR-DELEG-03: allowedAction subset
    if child.allowed_action is not None and parent.allowed_action is not None:
        child_set = set(child.allowed_action)
        parent_set = set(parent.allowed_action)
        extra = child_set - parent_set
        if extra:
            raise ActionAttenuationError(
                f"Child actions {sorted(extra)} not in parent's allowedAction",
                context={
                    "child_actions": child.allowed_action,
                    "parent_actions": parent.allowed_action,
                },
            )

    # FR-DELEG-04: expires attenuation
    if child.expires is not None and parent.expires is not None and child.expires > parent.expires:
        raise ExpiryAttenuationError(
            "Child expiry exceeds parent expiry",
            context={
                "child_expires": child.expires.isoformat(),
                "parent_expires": parent.expires.isoformat(),
            },
        )

    # FR-DELEG-05: invocationTarget
    if child.invocation_target != parent.invocation_target:
        if allow_target_attenuation:
            attenuator = target_attenuator or PathPrefixAttenuator()
            if not attenuator.is_valid_attenuation(
                parent.invocation_target, child.invocation_target
            ):
                raise InvocationTargetError(
                    "Child invocationTarget is not a valid narrowing of parent",
                    context={
                        "parent_target": parent.invocation_target,
                        "child_target": child.invocation_target,
                    },
                )
        else:
            raise InvocationTargetError(
                "invocationTarget mismatch and target attenuation is disabled",
                context={
                    "parent_target": parent.invocation_target,
                    "child_target": child.invocation_target,
                },
            )

    # FR-DELEG-06: Cryptographic proof verification
    (proof_verifier or verify_document_proof)(child.raw)


def verify_delegation_chain(
    root: Capability,
    chain: list[Capability],
    *,
    allow_target_attenuation: bool = False,
    target_attenuator: InvocationTargetAttenuator | None = None,
    proof_verifier: Callable[[dict[str, object]], None] | None = None,
) -> None:
    """Verify a full delegation chain from *root* to the leaf.

    The root capability is caller-trusted — its own proof is NOT verified.
    Only the chain links (each parent → child pair) are verified.

    Args:
        root: The trust anchor capability (implicitly trusted).
        chain: Ordered list of delegated capabilities, closest-to-root first.

    Raises:
        ChainVerificationError: Wrapping the underlying cause if any link fails.
    """
    if not chain:
        return

    pairs: list[tuple[Capability, Capability]] = []
    pairs.append((root, chain[0]))
    for i in range(len(chain) - 1):
        pairs.append((chain[i], chain[i + 1]))

    for i, (parent, child) in enumerate(pairs):
        try:
            _verify_delegation_link(
                parent,
                child,
                allow_target_attenuation=allow_target_attenuation,
                target_attenuator=target_attenuator,
                proof_verifier=proof_verifier,
            )
        except ZcapError as exc:
            raise ChainVerificationError(
                f"Delegation chain verification failed at link {i}",
                context={"link": i, "parent_id": parent.id, "child_id": child.id},
            ) from exc
