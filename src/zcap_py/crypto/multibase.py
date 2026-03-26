"""Multibase z (base58btc) encoding and decoding via multiformats."""

from __future__ import annotations

from multiformats import multibase

from zcap_py.exceptions import ZcapError


def base58btc_encode(data: bytes) -> str:
    """Encode bytes to a multibase-z (base58btc) string (includes 'z' prefix)."""
    if not data:
        raise ZcapError("Cannot encode empty data", context={"data_length": 0})
    result: str = multibase.encode(data, "base58btc")
    return result


def base58btc_decode(multibase_str: str) -> bytes:
    """Decode a multibase-z (base58btc) string to bytes (expects 'z' prefix)."""
    if not multibase_str:
        raise ZcapError("Cannot decode empty string")
    if not multibase_str.startswith("z"):
        raise ZcapError(
            f"Expected multibase prefix 'z', got '{multibase_str[0]}'",
            context={"prefix": multibase_str[0]},
        )
    try:
        return bytes(multibase.decode(multibase_str))
    except Exception as e:
        raise ZcapError(
            "base58btc decode failed",
            context={"input": multibase_str},
        ) from e
