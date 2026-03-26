"""RFC 8785 / JCS canonicalization wrapper."""

from __future__ import annotations

import rfc8785 as _rfc8785

from zcap_py.exceptions import CanonicalizationError


def canonicalize(obj: dict[str, object] | list[object]) -> bytes:
    """Serialize obj to UTF-8 bytes per RFC 8785 (JCS).

    Args:
        obj: A JSON-serializable dict or list.

    Returns:
        Canonical UTF-8 bytes.

    Raises:
        CanonicalizationError: If input is not valid JSON-serializable.
    """
    if not isinstance(obj, (dict, list)):
        raise CanonicalizationError(
            f"Expected dict or list, got {type(obj).__name__}",
            context={"type": type(obj).__name__},
        )
    try:
        return _rfc8785.dumps(obj)  # type: ignore[arg-type]
    except Exception as e:
        raise CanonicalizationError(
            f"JCS canonicalization failed: {e}",
            context={"error": str(e)},
        ) from e
