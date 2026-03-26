"""Tests for DID parsing, did:key encode/decode, and resolution."""

from __future__ import annotations

import pytest

from zcap_py.crypto.ed25519 import generate_ed25519_keypair
from zcap_py.did.key import (
    VerificationMethod,
    decode_did_key,
    encode_did_key,
    resolve_did_key,
)
from zcap_py.did.url import (
    ParsedDid,
    ParsedDidUrl,
    parse_did,
    parse_did_url,
    strip_did_fragment,
)
from zcap_py.exceptions import DidParseError

# Known DID from the PRD fixture (Alice)
ALICE_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
ALICE_VM = f"{ALICE_DID}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


# ── DID Parsing ──


class TestParseDid:
    def test_valid_did_key(self) -> None:
        result = parse_did(ALICE_DID)
        assert isinstance(result, ParsedDid)
        assert result.method == "key"
        assert result.full_did == ALICE_DID

    def test_returns_correct_identifier(self) -> None:
        result = parse_did(ALICE_DID)
        assert result.identifier == "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

    def test_empty_string_raises_error(self) -> None:
        with pytest.raises(DidParseError, match="empty"):
            parse_did("")

    def test_not_did_key_raises_error(self) -> None:
        with pytest.raises(DidParseError, match="Invalid did:key"):
            parse_did("did:web:example.com")

    def test_missing_identifier_raises_error(self) -> None:
        with pytest.raises(DidParseError, match="Invalid did:key"):
            parse_did("did:key:")

    def test_no_z_prefix_raises_error(self) -> None:
        with pytest.raises(DidParseError, match="Invalid did:key"):
            parse_did("did:key:6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

    def test_invalid_base58_chars_raises_error(self) -> None:
        # 'O' and '0' are not in base58btc alphabet
        with pytest.raises(DidParseError, match="Invalid did:key"):
            parse_did("did:key:z6MkhaXgBZDvOtDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

    def test_generated_keypair_did_parses(self) -> None:
        kp = generate_ed25519_keypair()
        result = parse_did(kp.did)
        assert result.method == "key"
        assert result.full_did == kp.did


# ── DID URL Parsing ──


class TestParseDidUrl:
    def test_valid_did_url(self) -> None:
        result = parse_did_url(ALICE_VM)
        assert isinstance(result, ParsedDidUrl)
        assert result.full_url == ALICE_VM
        assert result.did.full_did == ALICE_DID

    def test_fragment_matches_identifier(self) -> None:
        result = parse_did_url(ALICE_VM)
        assert result.fragment == result.did.identifier

    def test_fragment_mismatch_raises_error(self) -> None:
        mismatched = f"{ALICE_DID}#z6MkDifferentFragmentAAAAAAAAAAAAAAAAAAAAAAAA"
        with pytest.raises(DidParseError, match="does not match"):
            parse_did_url(mismatched)

    def test_no_fragment_raises_error(self) -> None:
        with pytest.raises(DidParseError, match="must contain a '#' fragment"):
            parse_did_url(ALICE_DID)

    def test_empty_raises_error(self) -> None:
        with pytest.raises(DidParseError, match="empty"):
            parse_did_url("")

    def test_invalid_url_raises_error(self) -> None:
        with pytest.raises(DidParseError, match="Invalid did:key"):
            parse_did_url("not-a-did#fragment")

    def test_generated_keypair_vm_parses(self) -> None:
        kp = generate_ed25519_keypair()
        result = parse_did_url(kp.verification_method)
        assert result.did.full_did == kp.did


class TestStripDidFragment:
    def test_removes_fragment(self) -> None:
        assert strip_did_fragment(ALICE_VM) == ALICE_DID

    def test_no_fragment_unchanged(self) -> None:
        assert strip_did_fragment(ALICE_DID) == ALICE_DID


# ── did:key Encode/Decode ──


class TestEncodeDidKey:
    def test_produces_valid_did(self) -> None:
        kp = generate_ed25519_keypair()
        pub_bytes = kp.public_key.public_bytes_raw()
        did = encode_did_key(pub_bytes)
        assert did.startswith("did:key:z")

    def test_matches_generate_keypair_did(self) -> None:
        kp = generate_ed25519_keypair()
        pub_bytes = kp.public_key.public_bytes_raw()
        did = encode_did_key(pub_bytes)
        assert did == kp.did


class TestDecodeDidKey:
    def test_returns_32_bytes(self) -> None:
        kp = generate_ed25519_keypair()
        raw = decode_did_key(kp.did)
        assert len(raw) == 32

    def test_roundtrip(self) -> None:
        kp = generate_ed25519_keypair()
        pub_bytes = kp.public_key.public_bytes_raw()
        did = encode_did_key(pub_bytes)
        decoded = decode_did_key(did)
        assert decoded == pub_bytes

    def test_invalid_did_raises_error(self) -> None:
        with pytest.raises(DidParseError):
            decode_did_key("did:key:zBadData")

    def test_known_alice_did_decodes(self) -> None:
        raw = decode_did_key(ALICE_DID)
        assert len(raw) == 32


# ── did:key Resolution ──


class TestResolveDidKey:
    def test_returns_verification_method(self) -> None:
        result = resolve_did_key(ALICE_DID)
        assert isinstance(result, VerificationMethod)
        assert result.type == "Ed25519VerificationKey2020"

    def test_controller_is_bare_did(self) -> None:
        result = resolve_did_key(ALICE_DID)
        assert result.controller == ALICE_DID
        assert "#" not in result.controller

    def test_id_contains_fragment(self) -> None:
        result = resolve_did_key(ALICE_DID)
        assert "#" in result.id
        assert result.id == ALICE_VM

    def test_from_url_strips_fragment(self) -> None:
        result = resolve_did_key(ALICE_VM)
        assert result.controller == ALICE_DID

    def test_public_key_multibase_starts_with_z(self) -> None:
        result = resolve_did_key(ALICE_DID)
        assert result.public_key_multibase.startswith("z")

    def test_invalid_did_raises_error(self) -> None:
        with pytest.raises(DidParseError):
            resolve_did_key("did:web:example.com")

    def test_generated_keypair_resolves(self) -> None:
        kp = generate_ed25519_keypair()
        result = resolve_did_key(kp.did)
        assert result.controller == kp.did
        assert result.id == kp.verification_method
