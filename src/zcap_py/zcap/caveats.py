"""Caveat verifier plugin system.

The core library ships with zero built-in caveat implementations (FR-CAVEAT-06).
Unknown caveat types are fail-closed: ``UnknownCaveatError`` is raised.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from zcap_py.exceptions import UnknownCaveatError


@runtime_checkable
class CaveatVerifier(Protocol):
    """Structural protocol for sync caveat verifiers.

    No inheritance required — duck typing is sufficient.
    A plain class with ``caveat_type: str`` and a matching
    ``verify()`` signature is automatically compatible.
    """

    caveat_type: str

    def verify(self, caveat: dict[str, object], invocation: dict[str, object]) -> None:
        """Verify the caveat against the invocation.

        Raise :class:`CaveatError` on failure, return ``None`` on success.
        """
        ...


class CaveatRegistry:
    """Registry mapping caveat types to their verifiers."""

    def __init__(self, verifiers: list[CaveatVerifier] | None = None) -> None:
        self._registry: dict[str, CaveatVerifier] = {}
        for v in verifiers or []:
            self._registry[v.caveat_type] = v

    def verify_all(self, caveats: list[dict[str, object]], invocation: dict[str, object]) -> None:
        """Run all registered verifiers against the caveat list.

        Raises:
            UnknownCaveatError: If no verifier is registered for a caveat type.
            CaveatError: If any verifier rejects the invocation.
        """
        for caveat in caveats:
            ctype = caveat.get("type")
            if not isinstance(ctype, str) or ctype not in self._registry:
                raise UnknownCaveatError(
                    f"No verifier registered for caveat type '{ctype}'",
                    context={"caveat": caveat},
                )
            self._registry[ctype].verify(caveat, invocation)
