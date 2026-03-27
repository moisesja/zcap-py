"""Linked Data Proof dataclass."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LinkedDataProof:
    """Ed25519Signature2020 proof structure."""

    type: str
    verification_method: str
    created: str
    proof_value: str
    proof_purpose: str
    capability: str | None = None
    capability_action: str | None = None
    capability_chain: tuple[str | dict[str, object], ...] | None = None
