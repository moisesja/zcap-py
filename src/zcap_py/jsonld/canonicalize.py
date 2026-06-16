"""URDNA2015 (RDF Dataset Canonicalization) via ``pyld``.

``pyld`` is a core dependency of ``zcap-py``.
"""

from __future__ import annotations

from typing import Any

from zcap_py.exceptions import CanonicalizationError
from zcap_py.jsonld.context_loader import offline_document_loader


def _get_pyld_jsonld() -> Any:  # noqa: ANN401
    """Lazy import of ``pyld.jsonld``; raises if not installed."""
    try:
        from pyld import jsonld

        return jsonld
    except ImportError:
        raise CanonicalizationError(
            "pyld is required for W3C URDNA2015 canonicalization but is not "
            "installed; reinstall zcap-py to pull its dependencies.",
        ) from None


def urdna2015_canonicalize(document: dict[str, object]) -> str:
    """Canonicalize a JSON-LD document using URDNA2015.

    Returns the canonical N-Quads string.

    Raises:
        CanonicalizationError: If ``pyld`` is not installed or
            canonicalization fails.
    """
    jsonld: Any = _get_pyld_jsonld()
    try:
        result: str = jsonld.normalize(
            document,
            {
                "algorithm": "URDNA2015",
                "format": "application/n-quads",
                "documentLoader": offline_document_loader,
            },
        )
    except CanonicalizationError:
        raise
    except Exception as e:
        raise CanonicalizationError(
            f"URDNA2015 canonicalization failed: {e}",
            context={"error": str(e)},
        ) from e
    return result
