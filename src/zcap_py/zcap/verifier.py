"""ZcapVerifier — synchronous verification facade."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, TypeAlias

from zcap_py.exceptions import CapabilityExpiredError, InvocationError
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

ProofVerifier: TypeAlias = "Callable[[dict[str, object]], None]"
DocumentLoader: TypeAlias = "Callable[[str], dict[str, object]]"


class ZcapVerifier:
    """Synchronous verification facade for ZCAP-LD documents.

    Accepts parsed :class:`Capability` / :class:`Invocation` models —
    parsing is the caller's responsibility (use :class:`ZcapParser`).

    Parameters:
        document_loader: Optional callable that resolves a capability ID
            (string) to its raw dict representation.  Required for
            spec-compliant ``capabilityChain`` arrays that contain string
            references for root and ancestor capabilities.

    Example::

        parser = ZcapParser()
        verifier = ZcapVerifier(
            allow_target_attenuation=True,
            document_loader=lambda cap_id: my_store.get(cap_id),
        )

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
        proof_verifier: ProofVerifier | None = None,
        document_loader: DocumentLoader | None = None,
    ) -> None:
        self._caveats = CaveatRegistry(caveat_verifiers)
        self._attenuator = target_attenuator or PathPrefixAttenuator()
        self._allow_target_attenuation = allow_target_attenuation
        self._clock = clock or (lambda: datetime.now(tz=UTC))
        self._proof_verifier = proof_verifier
        self._document_loader = document_loader

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
            proof_verifier=self._proof_verifier,
        )

    def verify_invocation(
        self,
        invocation: Invocation,
        capability: Capability | None = None,
        chain: list[Capability] | None = None,
    ) -> None:
        """Verify an invocation against its target capability.

        If *capability* is ``None``, the invocation's embedded capability
        is used (if present).

        If *chain* is ``None`` and the invocation proof contains a
        ``capabilityChain``, entries are resolved automatically: embedded
        dicts are parsed directly, string references are resolved via
        the configured ``document_loader``.  Without a loader, string
        entries raise :class:`InvocationError`.

        If *chain* is provided, ``chain[0]`` is treated as the root and
        ``chain[1:]`` as the delegation chain; the chain is verified first.

        Raises:
            ChainVerificationError: If delegation chain verification fails.
            InvocationError: On structural mismatches or chain-leaf linkage failure.
            CapabilityExpiredError: If any capability in the chain has expired.
            InvokerMismatchError: If the invoker DID doesn't match.
            SignatureVerificationError: If the cryptographic proof fails.
            CaveatError / UnknownCaveatError: If caveat verification fails.
        """
        # --- Resolve capability from embedded if not provided ---
        if capability is None:
            if invocation.embedded_capability is not None:
                capability = invocation.embedded_capability
            else:
                raise InvocationError(
                    "No capability provided and invocation has no embedded capability",
                    context={"invocation_id": invocation.id},
                )

        # --- Resolve chain from capabilityChain if not provided ---
        if chain is None and invocation.proof.capability_chain is not None:
            chain = self._resolve_capability_chain(invocation.proof.capability_chain)

        # --- Chain verification ---
        if chain is not None and len(chain) > 0:
            self.verify_delegation_chain(chain[0], chain[1:])

            # FR-INVOKE-08: Chain-to-capability linkage
            leaf_id = chain[-1].id
            if leaf_id != capability.id:
                raise InvocationError(
                    f"Chain leaf capability '{leaf_id}' does not match "
                    f"invoked capability '{capability.id}'",
                    context={"chain_leaf_id": leaf_id, "capability_id": capability.id},
                )

        # --- Absolute expiry check (FR-INVOKE-09) ---
        now = self._clock()
        caps_to_check: list[Capability] = list(chain) if chain else []
        if capability not in caps_to_check:
            caps_to_check.append(capability)
        for cap in caps_to_check:
            if cap.expires is not None and cap.expires <= now:
                raise CapabilityExpiredError(
                    f"Capability '{cap.id}' expired at {cap.expires.isoformat()}",
                    context={
                        "capability_id": cap.id,
                        "expires": cap.expires.isoformat(),
                        "now": now.isoformat(),
                    },
                )

        # --- Core invocation verification (checks leaf caveats) ---
        _verify_invocation(
            invocation,
            capability,
            caveat_registry=self._caveats,
            proof_verifier=self._proof_verifier,
        )

        # --- Ancestor caveat enforcement (FR-INVOKE-07 extended) ---
        # All capabilities in the chain except the leaf (already checked above)
        # must also have their caveats verified against the invocation.
        if chain is not None and len(chain) > 1:
            for cap in chain[:-1]:
                if cap.caveat:
                    self._caveats.verify_all(cap.caveat, invocation.raw)

    def _resolve_capability_chain(
        self,
        chain_entries: tuple[str | dict[str, object], ...],
    ) -> list[Capability]:
        """Resolve capabilityChain entries into Capability objects.

        Embedded (dict) entries are parsed directly.  String entries are
        resolved via the configured ``document_loader``.  If no loader is
        configured, string entries raise :class:`InvocationError`.

        Raises:
            InvocationError: If a string entry is encountered without a
                configured document loader.
        """
        from zcap_py.zcap.parser import ZcapParser

        p = ZcapParser()
        result: list[Capability] = []
        for i, entry in enumerate(chain_entries):
            if isinstance(entry, str):
                if self._document_loader is None:
                    raise InvocationError(
                        f"capabilityChain[{i}] is a string reference '{entry}'; "
                        "document loader required but not available",
                        context={"index": i, "reference": entry},
                    )
                raw = self._document_loader(entry)
                result.append(p.parse_capability(raw))
            else:
                result.append(p.parse_capability(entry))
        return result
