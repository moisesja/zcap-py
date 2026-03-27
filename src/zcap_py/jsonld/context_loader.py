"""Offline JSON-LD document loader serving bundled contexts.

Provides a custom ``pyld`` document loader that resolves known context URLs
from package-bundled ``.jsonld`` files.  Unknown URLs raise
``CanonicalizationError`` (fail-closed, zero network I/O).
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

from zcap_py.exceptions import CanonicalizationError

_CONTEXT_MAP: dict[str, str] = {
    "https://w3id.org/zcap/v1": "zcap-v1.jsonld",
    "https://w3id.org/security/suites/ed25519-2020/v1": "ed25519-signature-2020-v1.jsonld",
}


def _load_bundled_context(filename: str) -> dict[str, Any]:
    """Load a bundled JSON-LD context file from package resources."""
    ctx_dir = resources.files("zcap_py.jsonld") / "contexts"
    ctx_file = ctx_dir / filename
    content: str = ctx_file.read_text(encoding="utf-8")
    result: dict[str, Any] = json.loads(content)
    return result


def offline_document_loader(url: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """``pyld`` document loader that serves bundled contexts only.

    Raises:
        CanonicalizationError: If the URL is not a known bundled context.
    """
    filename = _CONTEXT_MAP.get(url)
    if filename is None:
        raise CanonicalizationError(
            f"Unknown JSON-LD context URL: {url}. "
            "Only bundled ZCAP-LD contexts are supported (zero network I/O).",
            context={"url": url},
        )
    doc = _load_bundled_context(filename)
    return {
        "contextUrl": None,
        "documentUrl": url,
        "document": doc,
    }
