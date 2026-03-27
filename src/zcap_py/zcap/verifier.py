"""ZcapVerifier — synchronous verification facade."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from zcap_py.zcap.caveats import CaveatRegistry, CaveatVerifier
from zcap_py.zcap.delegation import verify_delegation_chain as _verify_chain
from zcap_py.zcap.invocation import verify_invocation as _verify_invocation
from zcap_py.zcap.target_attenuation import (
    InvocationTargetAttenuator,
    PathPrefixAttenuator,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from zcap_py.zcap.models import Capability, Invocation


class ZcapVerifier:
    """Synchronous verification facade for ZCAP-LD documents.

    Accepts parsed :class:`Capability` / :class:`Invocation` models —
    parsing is the caller's responsibility (use :class:`ZcapParser`).

    Example::

        parser = ZcapParser()
        verifier = ZcapVerifier(allow_target_attenuation=True)

        root = parser.parse_capability(root_dict)
        cap  = parser.parse_capability(cap_dict)
        inv  = parser.parse_invocation(inv_dict)

        verifier.verify_delegation_chain(root, [cap])
        verifier.verify_invocation(inv, cap)
    """

    def __init__(
        self,
        caveat_verifiers: list[CaveatVerifier] | None = None,
        target_attenuator: InvocationTargetAttenuator | None = None,
        allow_target_attenuation: bool = False,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._caveats = CaveatRegistry(caveat_verifiers)
        self._attenuator = target_attenuator or PathPrefixAttenuator()
        self._allow_target_attenuation = allow_target_attenuation
        self._clock = clock or (lambda: datetime.now(tz=UTC))

    def verify_delegation_chain(
        self,
        root: Capability,
        chain: list[Capability],
    ) -> None:
        """Verify a full delegation chain from *root* to the leaf.

        The root capability is caller-trusted — its own proof is NOT verified.

        Raises:
            ChainVerificationError: Wrapping the underlying cause if any link fails.
        """
        _verify_chain(
            root,
            chain,
            allow_target_attenuation=self._allow_target_attenuation,
            target_attenuator=self._attenuator,
        )

    def verify_invocation(
        self,
        invocation: Invocation,
        capability: Capability,
        chain: list[Capability] | None = None,
    ) -> None:
        """Verify an invocation against its target capability.

        If *chain* is provided, ``chain[0]`` is treated as the root and
        ``chain[1:]`` as the delegation chain; the chain is verified first.

        Raises:
            ChainVerificationError: If delegation chain verification fails.
            InvocationError: On structural mismatches.
            InvokerMismatchError: If the invoker DID doesn't match.
            SignatureVerificationError: If the cryptographic proof fails.
            CaveatError / UnknownCaveatError: If caveat verification fails.
        """
        if chain is not None and len(chain) > 0:
            self.verify_delegation_chain(chain[0], chain[1:])

        _verify_invocation(
            invocation,
            capability,
            caveat_registry=self._caveats,
        )
