"""Tests for crypto modules: multibase, multicodec, ed25519."""

from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from zcap_py.crypto.ed25519 import (
    DidKeyPair,
    generate_ed25519_keypair,
    verify_ed25519_signature,
)
from zcap_py.crypto.multibase import base58btc_decode, base58btc_encode
from zcap_py.crypto.multicodec import (
    ED25519_PUB_KEY_LENGTH,
    decode_ed25519_pub,
    encode_ed25519_pub,
)
from zcap_py.exceptions import SignatureVerificationError, ZcapError

# ── Multibase ──


class TestBase58btcEncode:
    def test_encode_returns_z_prefix(self) -> None:
        result = base58btc_encode(b"\x01\x02\x03")
        assert result.startswith("z")

    def test_encode_decode_roundtrip(self) -> None:
        data = os.urandom(32)
        encoded = base58btc_encode(data)
        decoded = base58btc_decode(encoded)
        assert decoded == data

    def test_encode_empty_raises_error(self) -> None:
        with pytest.raises(ZcapError, match="Cannot encode empty data"):
            base58btc_encode(b"")

    def test_encode_single_byte(self) -> None:
        result = base58btc_encode(b"\xff")
        assert result.startswith("z")
        assert base58btc_decode(result) == b"\xff"


class TestBase58btcDecode:
    def test_decode_empty_raises_error(self) -> None:
        with pytest.raises(ZcapError, match="Cannot decode empty string"):
            base58btc_decode("")

    def test_decode_wrong_prefix_raises_error(self) -> None:
        with pytest.raises(ZcapError, match="Expected multibase prefix 'z'"):
            base58btc_decode("m3yZe7d")

    def test_decode_valid_multibase(self) -> None:
        original = b"\xed\x01" + b"\x00" * 32
        encoded = base58btc_encode(original)
        decoded = base58btc_decode(encoded)
        assert decoded == original


# ── Multicodec ──


class TestEncodeEd25519Pub:
    def test_prepends_ed25519_prefix(self) -> None:
        key_bytes = os.urandom(32)
        result = encode_ed25519_pub(key_bytes)
        # ed25519-pub prefix is 0xed01 (2 bytes)
        assert result[:2] == bytes([0xED, 0x01])
        assert result[2:] == key_bytes

    def test_wrong_length_31_raises_error(self) -> None:
        with pytest.raises(ZcapError, match="must be 32 bytes"):
            encode_ed25519_pub(b"\x00" * 31)

    def test_wrong_length_33_raises_error(self) -> None:
        with pytest.raises(ZcapError, match="must be 32 bytes"):
            encode_ed25519_pub(b"\x00" * 33)


class TestDecodeEd25519Pub:
    def test_strips_prefix(self) -> None:
        key_bytes = os.urandom(32)
        encoded = encode_ed25519_pub(key_bytes)
        result = decode_ed25519_pub(encoded)
        assert result == key_bytes
        assert len(result) == ED25519_PUB_KEY_LENGTH

    def test_wrong_prefix_raises_error(self) -> None:
        bad = b"\x00\x00" + b"\x00" * 32
        with pytest.raises(ZcapError):
            decode_ed25519_pub(bad)

    def test_wrong_length_after_prefix_raises_error(self) -> None:
        # Manually construct ed25519-pub prefix + wrong-length data
        encoded = encode_ed25519_pub(os.urandom(32))
        truncated = encoded[:-1]  # remove last byte
        with pytest.raises(ZcapError, match="must be 32 bytes after prefix"):
            decode_ed25519_pub(truncated)

    def test_encode_decode_roundtrip(self) -> None:
        key_bytes = os.urandom(32)
        assert decode_ed25519_pub(encode_ed25519_pub(key_bytes)) == key_bytes


# ── Ed25519 Key Generation ──


class TestGenerateEd25519Keypair:
    def test_did_starts_with_did_key_z6mk(self) -> None:
        kp = generate_ed25519_keypair()
        assert kp.did.startswith("did:key:z6Mk")

    def test_verification_method_contains_fragment(self) -> None:
        kp = generate_ed25519_keypair()
        assert "#" in kp.verification_method
        did_part, fragment = kp.verification_method.split("#", 1)
        assert did_part == kp.did
        assert fragment.startswith("z6Mk")

    def test_unique_keys(self) -> None:
        kp1 = generate_ed25519_keypair()
        kp2 = generate_ed25519_keypair()
        assert kp1.did != kp2.did

    def test_private_key_type(self) -> None:
        kp = generate_ed25519_keypair()
        assert isinstance(kp.private_key, Ed25519PrivateKey)

    def test_public_key_type(self) -> None:
        kp = generate_ed25519_keypair()
        assert isinstance(kp.public_key, Ed25519PublicKey)

    def test_is_frozen_dataclass(self) -> None:
        kp = generate_ed25519_keypair()
        assert isinstance(kp, DidKeyPair)
        with pytest.raises(AttributeError):
            kp.did = "something"  # type: ignore[misc]


# ── Ed25519 Signature Verification ──


class TestVerifyEd25519Signature:
    def test_valid_signature_passes(self) -> None:
        kp = generate_ed25519_keypair()
        data = b"test message"
        signature = kp.private_key.sign(data)
        verify_ed25519_signature(kp.public_key, signature, data)

    def test_invalid_signature_raises_error(self) -> None:
        kp = generate_ed25519_keypair()
        bad_sig = b"\x00" * 64
        with pytest.raises(SignatureVerificationError, match="verification failed"):
            verify_ed25519_signature(kp.public_key, bad_sig, b"test message")

    def test_wrong_data_raises_error(self) -> None:
        kp = generate_ed25519_keypair()
        signature = kp.private_key.sign(b"correct data")
        with pytest.raises(SignatureVerificationError):
            verify_ed25519_signature(kp.public_key, signature, b"wrong data")

    def test_wrong_key_raises_error(self) -> None:
        kp1 = generate_ed25519_keypair()
        kp2 = generate_ed25519_keypair()
        signature = kp1.private_key.sign(b"test message")
        with pytest.raises(SignatureVerificationError):
            verify_ed25519_signature(kp2.public_key, signature, b"test message")

    def test_error_has_context(self) -> None:
        kp = generate_ed25519_keypair()
        with pytest.raises(SignatureVerificationError) as exc_info:
            verify_ed25519_signature(kp.public_key, b"\x00" * 64, b"data")
        assert "signature_length" in exc_info.value.context
        assert exc_info.value.context["signature_length"] == 64
