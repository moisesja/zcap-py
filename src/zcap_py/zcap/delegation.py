"""Delegation chain verification (FR-DELEG-01 through FR-DELEG-08)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from zcap_py.did.url import strip_did_fragment
from zcap_py.exceptions import (
    ActionAttenuationError,
    CapabilityExpiredError,
    ChainVerificationError,
    DelegationError,
    ExpiryAttenuationError,
    InvocationTargetError,
    ZcapError,
)
from zcap_py.proof.ed25519_2020_w3c import verify_document_proof_w3c
from zcap_py.zcap.relationships import (
    CAPABILITY_DELEGATION,
    did_key_relationship_authorizer,
)
from zcap_py.zcap.target_attenuation import (
    InvocationTargetAttenuator,
    PathPrefixAttenuator,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from zcap_py.zcap.models import Capability
    from zcap_py.zcap.relationships import RelationshipAuthorizer


def _controller_contains(controller: str | list[str], did: str) -> bool:
    """Check if *did* matches the controller (string or array)."""
    if isinstance(controller, list):
        return did in controller
    return did == controller


def effective_allowed_actions(caps: list[Capability]) -> set[str] | None:
    """Return the effective allowed-action set across an ordered capability list.

    Intersects every capability's ``allowedAction``; a capability that omits
    ``allowedAction`` inherits the restriction so far (it does not broaden).
    Returns ``None`` only when no capability in the list restricts actions
    (i.e. all actions are permitted — the root grants the full vocabulary).
    """
    effective: set[str] | None = None
    for cap in caps:
        if cap.allowed_action is not None:
            declared = set(cap.allowed_action)
            effective = declared if effective is None else (effective & declared)
    return effective


def _verify_delegation_link(
    parent: Capability,
    child: Capability,
    *,
    allow_target_attenuation: bool = False,
    target_attenuator: InvocationTargetAttenuator | None = None,
    proof_verifier: Callable[[dict[str, object]], None] | None = None,
    relationship_authorizer: RelationshipAuthorizer | None = None,
) -> None:
    """Verify a single delegation link from *parent* to *child*.

    Raises:
        DelegationError: On structural violations (including a proof whose
            ``proofPurpose`` is not ``capabilityDelegation``).
        ActionAttenuationError: If child's actions exceed parent's.
        ExpiryAttenuationError: If child's expiry exceeds parent's.
        InvocationTargetError: If invocation target is invalid.
        ProofError: If the signer's key is not authorized for the
            ``capabilityDelegation`` relationship.
        SignatureVerificationError: If the cryptographic proof fails.
    """
    # Child must have a proof
    if child.proof is None:
        raise DelegationError(
            "Delegated capability is missing a proof",
            context={"child_id": child.id},
        )

    # #28: re-assert proofPurpose at VERIFY time (independent of the parser) so
    # a pre-built model or wrong-purpose proof is caught here, not silently
    # accepted. A delegation proof MUST exercise the capabilityDelegation
    # relationship.
    if child.proof.proof_purpose != CAPABILITY_DELEGATION:
        raise DelegationError(
            f"Delegation proof.proofPurpose must be '{CAPABILITY_DELEGATION}', "
            f"got '{child.proof.proof_purpose}'",
            context={"child_id": child.id, "proof_purpose": child.proof.proof_purpose},
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

    # #28: verification-relationship authorization gate — confirm the signer's
    # key is authorized by its controller for the capabilityDelegation
    # relationship (trivially true for did:key; the seam for non-did:key methods).
    (relationship_authorizer or did_key_relationship_authorizer)(
        child.proof.verification_method, CAPABILITY_DELEGATION
    )

    # FR-DELEG-06: Cryptographic proof verification (W3C URDNA2015 by default)
    (proof_verifier or verify_document_proof_w3c)(child.raw)


DEFAULT_MAX_CHAIN_LENGTH = 10


def verify_delegation_chain(
    root: Capability,
    chain: list[Capability],
    *,
    allow_target_attenuation: bool = False,
    target_attenuator: InvocationTargetAttenuator | None = None,
    proof_verifier: Callable[[dict[str, object]], None] | None = None,
    relationship_authorizer: RelationshipAuthorizer | None = None,
    max_chain_length: int = DEFAULT_MAX_CHAIN_LENGTH,
    clock: Callable[[], datetime] | None = None,
) -> None:
    """Verify a full delegation chain from *root* to the leaf.

    The root capability is caller-trusted — its own proof is NOT verified.
    Only the chain links (each parent → child pair) are verified.

    Args:
        root: The trust anchor capability (implicitly trusted).
        chain: Ordered list of delegated capabilities, closest-to-root first.
        max_chain_length: Maximum total capabilities (root + delegations)
            allowed. Mitigates long-chain / DoS attacks. Matches the
            ``@digitalbazaar/zcap`` default of 10. Enforced before any
            cryptographic work.
        clock: Source of "now" for the absolute-expiry check. Defaults to
            ``datetime.now(UTC)``. Every capability in the chain (root +
            delegations) must be unexpired — this makes the standalone
            function fail-closed rather than relying on the caller.

    Raises:
        ChainVerificationError: Wrapping the underlying cause if any link fails,
            or if the chain exceeds ``max_chain_length``.
        CapabilityExpiredError: If any capability in the chain has expired.
    """
    if not chain:
        return

    # Enforce chain-length bound BEFORE any per-link cryptographic verification.
    # ``total`` counts the full chain: the root trust anchor + every delegation.
    # @digitalbazaar/zcap's maxChainLength bounds the dereferenced capabilityChain
    # (which includes the root by reference); if it instead counted delegations
    # only, this gate would be one stricter — a safe direction, never looser.
    total = len(chain) + 1  # +1 for the root trust anchor
    if total > max_chain_length:
        raise ChainVerificationError(
            f"Delegation chain length {total} exceeds maximum {max_chain_length}",
            context={"length": total, "max_chain_length": max_chain_length},
        )

    # Absolute expiry — every capability (root + delegations) must be unexpired.
    # Enforced here (not only in ZcapVerifier) so the standalone function cannot
    # be used as a fail-open bypass.
    now = (clock or (lambda: datetime.now(tz=UTC)))()
    for cap in (root, *chain):
        if cap.expires is not None and cap.expires <= now:
            raise CapabilityExpiredError(
                f"Capability '{cap.id}' expired at {cap.expires.isoformat()}",
                context={
                    "capability_id": cap.id,
                    "expires": cap.expires.isoformat(),
                    "now": now.isoformat(),
                },
            )

    pairs: list[tuple[Capability, Capability]] = []
    pairs.append((root, chain[0]))
    for i in range(len(chain) - 1):
        pairs.append((chain[i], chain[i + 1]))

    # Track the EFFECTIVE allowed-action set inherited from the root downward.
    # An absent ``allowedAction`` inherits the ancestor restriction — it does NOT
    # re-broaden to "all actions". A child declaring actions outside the inherited
    # effective set is broadening and is rejected.
    effective: set[str] | None = (
        set(root.allowed_action) if root.allowed_action is not None else None
    )
    for i, (parent, child) in enumerate(pairs):
        try:
            _verify_delegation_link(
                parent,
                child,
                allow_target_attenuation=allow_target_attenuation,
                target_attenuator=target_attenuator,
                proof_verifier=proof_verifier,
                relationship_authorizer=relationship_authorizer,
            )
            if child.allowed_action is not None:
                declared = set(child.allowed_action)
                if effective is not None and not declared <= effective:
                    extra = sorted(declared - effective)
                    raise ActionAttenuationError(
                        f"Child allowedAction broadens beyond inherited effective set: {extra}",
                        context={
                            "child_actions": child.allowed_action,
                            "effective": sorted(effective),
                        },
                    )
                effective = declared if effective is None else (effective & declared)
            # child omits allowedAction → inherits ``effective`` unchanged.
        except ZcapError as exc:
            raise ChainVerificationError(
                f"Delegation chain verification failed at link {i}",
                context={"link": i, "parent_id": parent.id, "child_id": child.id},
            ) from exc
