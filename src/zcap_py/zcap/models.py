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
    invoker: str | None
    caveat: list[dict[str, object]] = field(default_factory=list)
    proof: LinkedDataProof | None = None
    raw: dict[str, object] = field(default_factory=dict, compare=False)

    @property
    def is_root(self) -> bool:
        """True when this capability is a root — no parent."""
        return self.parent_capability is None


@dataclass(frozen=True)
class Invocation:
    """A parsed ZCAP-LD invocation."""

    id: str
    capability: str
    invocation_target: str
    proof: LinkedDataProof
    embedded_capability: Capability | None = None
    raw: dict[str, object] = field(default_factory=dict, compare=False)
