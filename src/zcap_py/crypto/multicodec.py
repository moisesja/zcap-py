"""Ed25519 multicodec (0xed01) prefix handling via multiformats."""

from __future__ import annotations

from multiformats import multicodec

from zcap_py.exceptions import ZcapError

ED25519_CODEC_NAME = "ed25519-pub"
ED25519_PUB_KEY_LENGTH: int = 32


def encode_ed25519_pub(public_key_bytes: bytes) -> bytes:
    """Wrap raw Ed25519 public key bytes with the multicodec prefix."""
    if len(public_key_bytes) != ED25519_PUB_KEY_LENGTH:
        raise ZcapError(
            f"Ed25519 public key must be {ED25519_PUB_KEY_LENGTH} bytes, "
            f"got {len(public_key_bytes)}",
            context={"length": len(public_key_bytes)},
        )
    result: bytes = multicodec.wrap(ED25519_CODEC_NAME, public_key_bytes)
    return result


def decode_ed25519_pub(prefixed_bytes: bytes) -> bytes:
    """Unwrap the multicodec prefix, returning raw Ed25519 public key bytes."""
    try:
        codec, raw = multicodec.unwrap(prefixed_bytes)
    except Exception as e:
        raise ZcapError(
            "Failed to unwrap multicodec prefix",
            context={"data_hex": prefixed_bytes[:4].hex()},
        ) from e

    if codec.name != ED25519_CODEC_NAME:
        raise ZcapError(
            f"Expected codec '{ED25519_CODEC_NAME}', got '{codec.name}'",
            context={"codec": codec.name},
        )
    if len(raw) != ED25519_PUB_KEY_LENGTH:
        raise ZcapError(
            f"Ed25519 public key must be {ED25519_PUB_KEY_LENGTH} bytes after prefix, "
            f"got {len(raw)}",
            context={"length": len(raw)},
        )
    return bytes(raw)
