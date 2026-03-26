"""did:key encode, decode, and resolve for Ed25519 keys."""

from __future__ import annotations

from dataclasses import dataclass

from multiformats import multibase, multicodec

from zcap_py.did.url import parse_did, parse_did_url
from zcap_py.exceptions import DidParseError

ED25519_PUB_KEY_LENGTH: int = 32


@dataclass(frozen=True)
class VerificationMethod:
    """Resolved verification method from a did:key DID."""

    id: str
    type: str
    controller: str
    public_key_multibase: str


def encode_did_key(public_key_bytes: bytes) -> str:
    """Encode raw Ed25519 public key bytes to a did:key DID string."""
    wrapped: bytes = multicodec.wrap("ed25519-pub", public_key_bytes)
    mb: str = multibase.encode(wrapped, "base58btc")
    return f"did:key:{mb}"


def decode_did_key(did: str) -> bytes:
    """Decode a did:key DID to raw Ed25519 public key bytes.

    Raises:
        DidParseError: If DID is malformed or key type mismatch.
    """
    parsed = parse_did(did)

    try:
        decoded = multibase.decode(parsed.identifier)
        codec, raw = multicodec.unwrap(decoded)
    except Exception as e:
        raise DidParseError(
            f"Failed to decode did:key identifier: {parsed.identifier}",
            context={"identifier": parsed.identifier},
        ) from e

    if codec.name != "ed25519-pub":
        raise DidParseError(
            f"Expected ed25519-pub codec, got '{codec.name}'",
            context={"codec": codec.name, "did": did},
        )
    if len(raw) != ED25519_PUB_KEY_LENGTH:
        raise DidParseError(
            f"Invalid Ed25519 key length: expected {ED25519_PUB_KEY_LENGTH}, got {len(raw)}",
            context={"did": did, "length": len(raw)},
        )
    return bytes(raw)


def resolve_did_key(did_or_url: str) -> VerificationMethod:
    """Resolve a did:key DID or DID URL to a VerificationMethod.

    No network I/O — purely local decoding (FR-DID-05).

    Raises:
        DidParseError: If the DID/URL is malformed or fragment is invalid.
    """
    if "#" in did_or_url:
        parsed_url = parse_did_url(did_or_url)
        base_did = parsed_url.did.full_did
        multibase_key = parsed_url.did.identifier
    else:
        parsed = parse_did(did_or_url)
        base_did = parsed.full_did
        multibase_key = parsed.identifier

    # Validate key bytes are valid Ed25519
    decode_did_key(base_did)

    return VerificationMethod(
        id=f"{base_did}#{multibase_key}",
        type="Ed25519VerificationKey2020",
        controller=base_did,
        public_key_multibase=multibase_key,
    )
