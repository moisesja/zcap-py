"""Verification-relationship authorization seam (issue #28).

ZCAP-LD requires that a delegation proof's key be a ``capabilityDelegation``
verification method of the controller, and an invocation proof's key be a
``capabilityInvocation`` method — i.e. ``proofPurpose`` must match the
verification relationship the key is actually authorized for. For ``did:key``
the single key is implicitly a method for *every* relationship, so the check
is benign today; but verification must be self-contained, and non-``did:key``
controllers will need real controller-document resolution.

This module provides that seam. It mirrors zcap-dotnet's
``IVerificationRelationshipResolver`` / ``IsAuthorizedForRelationshipAsync``:
the default authorizer handles ``did:key``, and callers may inject their own
:data:`RelationshipAuthorizer` (e.g. resolving a ``did:web`` controller
document) via :class:`~zcap_py.zcap.verifier.ZcapVerifier`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeAlias

from zcap_py.did.key import resolve_did_key
from zcap_py.exceptions import DidParseError, ProofError

if TYPE_CHECKING:
    from collections.abc import Callable

#: A callable ``(verification_method, relationship) -> None`` that raises a
#: :class:`~zcap_py.exceptions.ProofError` when *verification_method*'s
#: controller does NOT authorize it for *relationship*.
RelationshipAuthorizer: TypeAlias = "Callable[[str, str], None]"

CAPABILITY_DELEGATION = "capabilityDelegation"
CAPABILITY_INVOCATION = "capabilityInvocation"


def did_key_relationship_authorizer(verification_method: str, relationship: str) -> None:
    """Authorize a ``did:key`` verification method for *relationship*.

    For ``did:key`` the single Ed25519 key is implicitly a verification method
    for every relationship, so authorization reduces to confirming the
    verification method is a resolvable ``did:key`` URL. :func:`resolve_did_key`
    also validates ``fragment == key identifier`` (FR-DID-03), so a key whose
    fragment does not match its own identifier is rejected here too.

    Raises:
        ProofError: If *verification_method* is not a resolvable ``did:key``
            verification method (and therefore not authorized for any
            relationship).
    """
    try:
        resolve_did_key(verification_method)
    except DidParseError as e:
        raise ProofError(
            f"verificationMethod '{verification_method}' is not a resolvable did:key "
            f"method authorized for the '{relationship}' verification relationship",
            context={
                "verificationMethod": verification_method,
                "relationship": relationship,
            },
        ) from e
