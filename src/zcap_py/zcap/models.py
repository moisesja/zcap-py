"""ZCAP-LD document models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from zcap_py.proof.models import LinkedDataProof


@dataclass(frozen=True)
class Capability:
    """A parsed ZCAP-LD capability (root or delegated)."""

    id: str
    controller: str | list[str]
    parent_capability: str | None
    invocation_target: str
    allowed_action: list[str] | None
    expires: datetime | None
    caveat: list[dict[str, object]] = field(default_factory=list)
    proof: LinkedDataProof | None = None
    raw: dict[str, object] = field(default_factory=dict, compare=False)

    @property
    def is_root(self) -> bool:
        """True when this capability is a root — no parent."""
        return self.parent_capability is None


@dataclass(frozen=True)
class Invocation:
    """A parsed ZCAP-LD invocation.

    Per the current ZCAP-LD spec and ``@digitalbazaar/zcap``, an invocation IS a
    ``capabilityInvocation`` Data-Integrity proof signed over the target document
    — there is no bespoke ``type:"Invocation"`` wrapper and no body-level
    duplication. The invoked ``capability``, ``invocationTarget``, and
    ``capabilityAction`` are carried in the proof; the convenience properties
    below derive them from :attr:`proof`.

    ``id`` is the optional ``id`` of the signed target document (a digitalbazaar
    HTTP/target invocation may omit it). ``embedded_capability`` is populated when
    ``proof.capability`` embeds the full capability object (the delegated-invocation
    shape) rather than referencing it by id string (the root-invocation shape).
    """

    proof: LinkedDataProof
    id: str | None = None
    embedded_capability: Capability | None = None
    raw: dict[str, object] = field(default_factory=dict, compare=False)

    @property
    def capability(self) -> str | None:
        """The invoked capability's id, carried in ``proof.capability``."""
        return self.proof.capability

    @property
    def invocation_target(self) -> str | None:
        """The invocation target, carried in ``proof.invocationTarget``."""
        return self.proof.invocation_target
