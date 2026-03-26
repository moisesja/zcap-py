"""Ed25519 key generation and signature verification."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from multiformats import multibase, multicodec

from zcap_py.exceptions import SignatureVerificationError


@dataclass(frozen=True)
class DidKeyPair:
    """Ed25519 keypair with did:key identifiers."""

    did: str
    verification_method: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    def __hash__(self) -> int:  # pragma: no cover
        return hash(self.did)


def generate_ed25519_keypair() -> DidKeyPair:
    """Generate a fresh Ed25519 keypair and derive did:key identifiers."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    wrapped: bytes = multicodec.wrap("ed25519-pub", public_key.public_bytes_raw())
    mb: str = multibase.encode(wrapped, "base58btc")

    did = f"did:key:{mb}"
    verification_method = f"{did}#{mb}"

    return DidKeyPair(
        did=did,
        verification_method=verification_method,
        private_key=private_key,
        public_key=public_key,
    )


def verify_ed25519_signature(
    public_key: Ed25519PublicKey,
    signature: bytes,
    data: bytes,
) -> None:
    """Verify an Ed25519 signature.

    Raises:
        SignatureVerificationError: If verification fails.
    """
    try:
        public_key.verify(signature, data)
    except InvalidSignature:
        raise SignatureVerificationError(
            "Ed25519 signature verification failed",
            context={"signature_length": len(signature), "data_length": len(data)},
        ) from None
