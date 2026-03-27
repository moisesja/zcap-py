"""Invocation target attenuation — path-prefix narrowing rules.

Mirrors ``zcap-dotnet``'s ``PathPrefixAttenuator`` semantics exactly,
enabling cross-language fixture validation.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable
from urllib.parse import urlparse


@runtime_checkable
class InvocationTargetAttenuator(Protocol):
    """Structural protocol for invocation target attenuation checks."""

    def is_valid_attenuation(self, parent_target: str, child_target: str) -> bool:
        """Return True if *child_target* is a valid narrowing of *parent_target*.

        Must never raise; invalid URIs return False.
        """
        ...


class PathPrefixAttenuator:
    """Built-in attenuator implementing path-prefix narrowing rules.

    Rules (all must hold for attenuation to be valid):
      1. Both URIs must parse successfully.
      2. Scheme must be identical (case-insensitive).
      3. Authority (host + port) must be identical (case-insensitive).
      4. Child path must begin with parent path after normalizing trailing slashes.
      5. Query string and fragment may differ freely.
      6. Exact match (child == parent) is always valid.
      7. Broadening (child path outside parent path scope) is always invalid.
    """

    def is_valid_attenuation(self, parent_target: str, child_target: str) -> bool:
        """Check if *child_target* is a valid path-prefix narrowing of *parent_target*."""
        try:
            p = urlparse(parent_target)
            c = urlparse(child_target)
        except Exception:
            return False

        if not p.scheme or not c.scheme:
            return False

        if p.scheme.lower() != c.scheme.lower():
            return False
        if p.netloc.lower() != c.netloc.lower():
            return False

        parent_path = p.path.rstrip("/") + "/"
        child_path = c.path.rstrip("/") + "/"

        return child_path.startswith(parent_path)
