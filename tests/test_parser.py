"""Tests for ZcapParser document parsing and validation."""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from tests.conftest import make_signed_document
from zcap_py.crypto.ed25519 import generate_ed25519_keypair
from zcap_py.exceptions import ZcapParseError
from zcap_py.zcap.models import Capability, Invocation
from zcap_py.zcap.parser import ZcapParser

ALICE_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
ALICE_VM = f"{ALICE_DID}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
BOB_DID = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"


def _root_cap() -> dict[str, object]:
    """Spec-minimal root capability: only @context, id, controller, invocationTarget."""
    return {
        "@context": "https://w3id.org/zcap/v1",
        "id": "https://resource.example/capabilities/root",
        "controller": ALICE_DID,
        "invocationTarget": "https://resource.example/api/",
    }


def _delegated_cap_base() -> dict[str, object]:
    """Delegated capability base (no proof) for field validation tests."""
    return {
        "@context": [
            "https://w3id.org/zcap/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": "urn:uuid:delegated-cap",
        "type": "Authorization",
        "controller": ALICE_DID,
        "parentCapability": "https://resource.example/capabilities/root",
        "invocationTarget": "https://resource.example/api/",
        "allowedAction": ["read", "write"],
        "expires": "2026-12-31T00:00:00Z",
    }


def _delegated_cap_with_proof() -> dict[str, object]:
    kp = generate_ed25519_keypair()
    base: dict[str, object] = {
        "@context": [
            "https://w3id.org/zcap/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": "urn:uuid:delegated-cap",
        "type": "Authorization",
        "controller": kp.did,
        "parentCapability": "https://resource.example/capabilities/root",
        "invocationTarget": "https://resource.example/api/",
        "allowedAction": ["read"],
        "expires": "2026-12-31T00:00:00Z",
    }
    return make_signed_document(base, kp.private_key, kp.verification_method)


def _invocation_with_proof() -> dict[str, object]:
    kp = generate_ed25519_keypair()
    base: dict[str, object] = {
        "@context": [
            "https://w3id.org/zcap/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": "urn:uuid:test-invocation",
        "type": "Invocation",
        "capability": "urn:uuid:delegated-cap",
        "invocationTarget": "https://resource.example/api/docs/1",
    }
    signed = make_signed_document(
        base, kp.private_key, kp.verification_method, "capabilityInvocation"
    )
    # Invocation proofs must carry capability and capabilityAction per ZCAP-LD spec
    proof = dict(signed["proof"])  # type: ignore[arg-type]
    proof["capability"] = "urn:uuid:delegated-cap"
    proof["capabilityAction"] = "read"
    signed["proof"] = proof
    return signed


# ── parse_capability ──


class TestParseCapability:
    def test_root_capability_no_proof(self) -> None:
        parser = ZcapParser()
        cap = parser.parse_capability(_root_cap())
        assert isinstance(cap, Capability)
        assert cap.id == "https://resource.example/capabilities/root"
        assert cap.controller == ALICE_DID
        assert cap.proof is None

    def test_is_root_true_for_root(self) -> None:
        parser = ZcapParser()
        cap = parser.parse_capability(_root_cap())
        assert cap.is_root is True
        assert ZcapParser.is_root(cap) is True

    def test_delegated_capability_with_proof(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_with_proof()
        cap = parser.parse_capability(raw)
        assert cap.parent_capability == "https://resource.example/capabilities/root"
        assert cap.proof is not None
        assert cap.proof.type == "Ed25519Signature2020"

    def test_is_root_false_for_delegated(self) -> None:
        parser = ZcapParser()
        cap = parser.parse_capability(_delegated_cap_with_proof())
        assert cap.is_root is False

    def test_expires_parsed_as_datetime(self) -> None:
        parser = ZcapParser()
        cap = parser.parse_capability(_delegated_cap_with_proof())
        assert isinstance(cap.expires, datetime)
        assert cap.expires.year == 2026

    def test_invoker_parsed(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["invoker"] = ALICE_DID
        cap = parser.parse_capability(raw)
        assert cap.invoker == ALICE_DID

    def test_caveat_parsed(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["caveat"] = [{"type": "ExpiresCaveat"}]
        cap = parser.parse_capability(raw)
        assert len(cap.caveat) == 1

    def test_caveat_not_list_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["caveat"] = "not-a-list"
        with pytest.raises(ZcapParseError, match="caveat"):
            parser.parse_capability(raw)

    def test_caveat_non_object_entries_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["caveat"] = ["not-an-object"]
        with pytest.raises(ZcapParseError, match="caveat"):
            parser.parse_capability(raw)

    def test_caveat_absent_defaults_to_empty(self) -> None:
        parser = ZcapParser()
        cap = parser.parse_capability(_delegated_cap_base())
        assert cap.caveat == []

    def test_raw_dict_preserved(self) -> None:
        parser = ZcapParser()
        raw = _root_cap()
        cap = parser.parse_capability(raw)
        assert cap.raw["id"] == raw["id"]

    def test_allowed_action_values(self) -> None:
        parser = ZcapParser()
        cap = parser.parse_capability(_delegated_cap_base())
        assert cap.allowed_action == ["read", "write"]

    # ── field validation errors ──

    def test_missing_id_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _root_cap()
        del raw["id"]
        with pytest.raises(ZcapParseError, match="id") as exc_info:
            parser.parse_capability(raw)
        assert exc_info.value.field == "id"

    def test_empty_id_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _root_cap()
        raw["id"] = "   "
        with pytest.raises(ZcapParseError, match="id"):
            parser.parse_capability(raw)

    def test_wrong_type_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["type"] = "Invocation"
        with pytest.raises(ZcapParseError, match="type") as exc_info:
            parser.parse_capability(raw)
        assert exc_info.value.field == "type"

    def test_missing_type_accepted(self) -> None:
        """type is optional per spec — missing is valid for delegated capabilities."""
        parser = ZcapParser()
        raw = _delegated_cap_base()
        del raw["type"]
        cap = parser.parse_capability(raw)
        assert cap.parent_capability is not None

    def test_invalid_controller_did_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _root_cap()
        raw["controller"] = "not-a-did"
        with pytest.raises(ZcapParseError, match="controller") as exc_info:
            parser.parse_capability(raw)
        assert exc_info.value.field == "controller"

    def test_missing_controller_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _root_cap()
        del raw["controller"]
        with pytest.raises(ZcapParseError, match="controller"):
            parser.parse_capability(raw)

    def test_missing_invocation_target_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _root_cap()
        del raw["invocationTarget"]
        with pytest.raises(ZcapParseError, match="invocationTarget"):
            parser.parse_capability(raw)

    def test_empty_allowed_action_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["allowedAction"] = []
        with pytest.raises(ZcapParseError, match="allowedAction"):
            parser.parse_capability(raw)

    def test_allowed_action_not_list_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["allowedAction"] = "read"
        with pytest.raises(ZcapParseError, match="allowedAction"):
            parser.parse_capability(raw)

    def test_allowed_action_non_string_items_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["allowedAction"] = [1, 2]
        with pytest.raises(ZcapParseError, match="allowedAction"):
            parser.parse_capability(raw)

    def test_invalid_expires_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["expires"] = "not-a-date"
        with pytest.raises(ZcapParseError, match="expires") as exc_info:
            parser.parse_capability(raw)
        assert exc_info.value.field == "expires"

    def test_delegated_capability_missing_expires_raises(self) -> None:
        """expires is REQUIRED on delegated capabilities (spec MUST)."""
        parser = ZcapParser()
        raw = _delegated_cap_base()
        del raw["expires"]
        with pytest.raises(ZcapParseError, match="expires") as exc_info:
            parser.parse_capability(raw)
        assert exc_info.value.field == "expires"

    def test_empty_parent_capability_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["parentCapability"] = "   "
        with pytest.raises(ZcapParseError, match="parentCapability"):
            parser.parse_capability(raw)

    # ── proof sub-field validation (delegated caps) ──

    def test_proof_wrong_type_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["proof"] = {"type": "RsaSignature2018"}
        with pytest.raises(ZcapParseError, match="proof.type"):
            parser.parse_capability(raw)

    def test_proof_missing_verification_method_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["proof"] = {"type": "Ed25519Signature2020"}
        with pytest.raises(ZcapParseError, match="proof.verificationMethod"):
            parser.parse_capability(raw)

    def test_proof_invalid_verification_method_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["proof"] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": "not-a-did-url",
        }
        with pytest.raises(ZcapParseError, match="proof.verificationMethod"):
            parser.parse_capability(raw)

    def test_proof_missing_created_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["proof"] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": ALICE_VM,
        }
        with pytest.raises(ZcapParseError, match="proof.created"):
            parser.parse_capability(raw)

    def test_proof_invalid_created_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["proof"] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": ALICE_VM,
            "created": "not-a-date",
        }
        with pytest.raises(ZcapParseError, match="proof.created"):
            parser.parse_capability(raw)

    def test_proof_missing_proof_value_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["proof"] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": ALICE_VM,
            "created": "2026-01-01T00:00:00Z",
        }
        with pytest.raises(ZcapParseError, match="proof.proofValue"):
            parser.parse_capability(raw)

    def test_proof_value_not_multibase_z_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["proof"] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": ALICE_VM,
            "created": "2026-01-01T00:00:00Z",
            "proofValue": "not-multibase",
        }
        with pytest.raises(ZcapParseError, match="proof.proofValue"):
            parser.parse_capability(raw)

    def test_proof_value_wrong_length_raises_error(self) -> None:
        from zcap_py.crypto.multibase import base58btc_encode

        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["proof"] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": ALICE_VM,
            "created": "2026-01-01T00:00:00Z",
            "proofValue": base58btc_encode(b"\x00" * 32),
        }
        with pytest.raises(ZcapParseError, match="expected 64"):
            parser.parse_capability(raw)

    def test_error_carries_field_name(self) -> None:
        parser = ZcapParser()
        raw = _root_cap()
        del raw["id"]
        with pytest.raises(ZcapParseError) as exc_info:
            parser.parse_capability(raw)
        assert exc_info.value.field == "id"


# ── parse_invocation ──


class TestParseInvocation:
    def test_valid_invocation(self) -> None:
        parser = ZcapParser()
        raw = _invocation_with_proof()
        inv = parser.parse_invocation(raw)
        assert isinstance(inv, Invocation)
        assert inv.id == "urn:uuid:test-invocation"
        assert inv.proof.type == "Ed25519Signature2020"

    def test_missing_proof_raises_error(self) -> None:
        parser = ZcapParser()
        raw: dict[str, object] = {
            "@context": ["https://w3id.org/zcap/v1"],
            "id": "urn:uuid:test",
            "type": "Invocation",
            "capability": "urn:uuid:cap",
            "invocationTarget": "https://example.com/api",
        }
        with pytest.raises(ZcapParseError, match="proof") as exc_info:
            parser.parse_invocation(raw)
        assert exc_info.value.field == "proof"

    def test_missing_capability_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _invocation_with_proof()
        del raw["capability"]
        with pytest.raises(ZcapParseError, match="capability"):
            parser.parse_invocation(raw)

    def test_wrong_type_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _invocation_with_proof()
        raw["type"] = "Authorization"
        with pytest.raises(ZcapParseError, match="type"):
            parser.parse_invocation(raw)

    def test_invocation_proof_purpose_is_capability_invocation(self) -> None:
        parser = ZcapParser()
        inv = parser.parse_invocation(_invocation_with_proof())
        assert inv.proof.proof_purpose == "capabilityInvocation"

    def test_invocation_proof_capability_parsed(self) -> None:
        parser = ZcapParser()
        inv = parser.parse_invocation(_invocation_with_proof())
        assert inv.proof.capability == "urn:uuid:delegated-cap"

    def test_missing_proof_purpose_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _invocation_with_proof()
        proof = dict(raw["proof"])  # type: ignore[arg-type]
        del proof["proofPurpose"]
        raw["proof"] = proof
        with pytest.raises(ZcapParseError, match="proof.proofPurpose"):
            parser.parse_invocation(raw)

    def test_wrong_proof_purpose_raises_error(self) -> None:
        """Invocation with proofPurpose=capabilityDelegation must be rejected."""
        parser = ZcapParser()
        raw = _invocation_with_proof()
        proof = dict(raw["proof"])  # type: ignore[arg-type]
        proof["proofPurpose"] = "capabilityDelegation"
        raw["proof"] = proof
        with pytest.raises(ZcapParseError, match="proofPurpose"):
            parser.parse_invocation(raw)

    def test_missing_capability_in_invocation_proof_raises_error(self) -> None:
        """Invocation proof without 'capability' must be rejected."""
        parser = ZcapParser()
        raw = _invocation_with_proof()
        proof = dict(raw["proof"])  # type: ignore[arg-type]
        del proof["capability"]
        raw["proof"] = proof
        with pytest.raises(ZcapParseError, match="capability"):
            parser.parse_invocation(raw)

    def test_raw_dict_preserved(self) -> None:
        parser = ZcapParser()
        raw = _invocation_with_proof()
        inv = parser.parse_invocation(raw)
        assert inv.raw["id"] == raw["id"]


# ── Capability proof proofPurpose validation ──


class TestCapabilityProofPurpose:
    def test_delegation_proof_purpose_accepted(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_with_proof()
        cap = parser.parse_capability(raw)
        assert cap.proof is not None
        assert cap.proof.proof_purpose == "capabilityDelegation"

    def test_missing_proof_purpose_on_capability_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_with_proof()
        proof = dict(raw["proof"])  # type: ignore[arg-type]
        del proof["proofPurpose"]
        raw["proof"] = proof
        with pytest.raises(ZcapParseError, match="proof.proofPurpose"):
            parser.parse_capability(raw)

    def test_wrong_proof_purpose_on_capability_raises_error(self) -> None:
        """Capability with proofPurpose=capabilityInvocation must be rejected."""
        parser = ZcapParser()
        raw = _delegated_cap_with_proof()
        proof = dict(raw["proof"])  # type: ignore[arg-type]
        proof["proofPurpose"] = "capabilityInvocation"
        raw["proof"] = proof
        with pytest.raises(ZcapParseError, match="proofPurpose"):
            parser.parse_capability(raw)


# ── @context validation ──


class TestContextValidation:
    def test_missing_context_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _root_cap()
        del raw["@context"]
        with pytest.raises(ZcapParseError, match="@context") as exc_info:
            parser.parse_capability(raw)
        assert exc_info.value.field == "@context"

    def test_context_as_string_accepted(self) -> None:
        parser = ZcapParser()
        cap = parser.parse_capability(_root_cap())
        assert cap.id == "https://resource.example/capabilities/root"

    def test_context_as_array_accepted(self) -> None:
        parser = ZcapParser()
        raw: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "urn:example:root",
            "controller": ALICE_DID,
            "invocationTarget": "https://example.com/api",
        }
        cap = parser.parse_capability(raw)
        assert cap.id == "urn:example:root"

    def test_context_wrong_url_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _root_cap()
        raw["@context"] = "https://other.example/v1"
        with pytest.raises(ZcapParseError, match="@context"):
            parser.parse_capability(raw)

    def test_context_array_wrong_first_element_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _root_cap()
        raw["@context"] = ["https://other.example/v1", "https://w3id.org/zcap/v1"]
        with pytest.raises(ZcapParseError, match="@context"):
            parser.parse_capability(raw)

    def test_invocation_missing_context_raises_error(self) -> None:
        parser = ZcapParser()
        raw = _invocation_with_proof()
        del raw["@context"]
        with pytest.raises(ZcapParseError, match="@context"):
            parser.parse_invocation(raw)


# ── Spec-compliant root capability ──


class TestSpecRootCapability:
    def test_spec_minimal_root_cap_parses(self) -> None:
        """Root cap with only the 4 spec-required fields parses successfully."""
        parser = ZcapParser()
        cap = parser.parse_capability(_root_cap())
        assert cap.is_root is True
        assert cap.allowed_action is None
        assert cap.proof is None

    def test_root_cap_without_type_parses(self) -> None:
        parser = ZcapParser()
        cap = parser.parse_capability(_root_cap())
        assert cap.id == "https://resource.example/capabilities/root"

    def test_root_cap_without_allowed_action_parses(self) -> None:
        parser = ZcapParser()
        cap = parser.parse_capability(_root_cap())
        assert cap.allowed_action is None

    def test_root_cap_with_extra_fields_rejected(self) -> None:
        """Root caps MUST NOT have fields beyond @context, id, controller, invocationTarget."""
        parser = ZcapParser()
        raw: dict[str, object] = {
            "@context": "https://w3id.org/zcap/v1",
            "id": "urn:example:root",
            "controller": ALICE_DID,
            "invocationTarget": "https://example.com/api",
            "type": "Authorization",
            "allowedAction": ["read"],
        }
        with pytest.raises(ZcapParseError, match="disallowed fields"):
            parser.parse_capability(raw)

    def test_root_cap_wrong_type_rejected(self) -> None:
        """Extra field 'type' on root is rejected as disallowed field."""
        parser = ZcapParser()
        raw: dict[str, object] = {
            "@context": "https://w3id.org/zcap/v1",
            "id": "urn:example:root",
            "type": "Invocation",
            "controller": ALICE_DID,
            "invocationTarget": "https://example.com/api",
        }
        with pytest.raises(ZcapParseError, match="disallowed fields"):
            parser.parse_capability(raw)


# ── Controller as string or array ──


class TestControllerArray:
    def test_controller_as_string_accepted(self) -> None:
        parser = ZcapParser()
        cap = parser.parse_capability(_root_cap())
        assert cap.controller == ALICE_DID

    def test_controller_as_array_accepted(self) -> None:
        parser = ZcapParser()
        raw: dict[str, object] = {
            "@context": "https://w3id.org/zcap/v1",
            "id": "urn:example:root",
            "controller": [ALICE_DID, BOB_DID],
            "invocationTarget": "https://example.com/api",
        }
        cap = parser.parse_capability(raw)
        assert isinstance(cap.controller, list)
        assert len(cap.controller) == 2
        assert cap.controller[0] == ALICE_DID
        assert cap.controller[1] == BOB_DID

    def test_controller_empty_array_raises_error(self) -> None:
        parser = ZcapParser()
        raw: dict[str, object] = {
            "@context": "https://w3id.org/zcap/v1",
            "id": "urn:example:root",
            "controller": [],
            "invocationTarget": "https://example.com/api",
        }
        with pytest.raises(ZcapParseError, match="controller"):
            parser.parse_capability(raw)

    def test_controller_array_with_invalid_did_raises_error(self) -> None:
        parser = ZcapParser()
        raw: dict[str, object] = {
            "@context": "https://w3id.org/zcap/v1",
            "id": "urn:example:root",
            "controller": [ALICE_DID, "not-a-did"],
            "invocationTarget": "https://example.com/api",
        }
        with pytest.raises(ZcapParseError, match="controller"):
            parser.parse_capability(raw)

    def test_controller_array_with_non_string_items_raises_error(self) -> None:
        parser = ZcapParser()
        raw: dict[str, object] = {
            "@context": "https://w3id.org/zcap/v1",
            "id": "urn:example:root",
            "controller": [ALICE_DID, 42],
            "invocationTarget": "https://example.com/api",
        }
        with pytest.raises(ZcapParseError, match="controller"):
            parser.parse_capability(raw)

    def test_controller_as_array_on_delegated_cap(self) -> None:
        parser = ZcapParser()
        raw = _delegated_cap_base()
        raw["controller"] = [ALICE_DID, BOB_DID]
        cap = parser.parse_capability(raw)
        assert isinstance(cap.controller, list)
        assert len(cap.controller) == 2


# ── parse_*_from_json ──


class TestParseCapabilityFromJson:
    def test_valid_json(self) -> None:
        parser = ZcapParser()
        cap = parser.parse_capability_from_json(json.dumps(_root_cap()))
        assert cap.id == "https://resource.example/capabilities/root"

    def test_invalid_json_raises_parse_error(self) -> None:
        parser = ZcapParser()
        with pytest.raises(ZcapParseError, match="Invalid JSON") as exc_info:
            parser.parse_capability_from_json("{bad json")
        assert exc_info.value.field == "<document>"

    def test_json_array_raises_parse_error(self) -> None:
        parser = ZcapParser()
        with pytest.raises(ZcapParseError, match="Expected JSON object"):
            parser.parse_capability_from_json("[1, 2, 3]")


class TestParseInvocationFromJson:
    def test_valid_json(self) -> None:
        parser = ZcapParser()
        raw = _invocation_with_proof()
        inv = parser.parse_invocation_from_json(json.dumps(raw))
        assert inv.id == "urn:uuid:test-invocation"

    def test_invalid_json_raises_parse_error(self) -> None:
        parser = ZcapParser()
        with pytest.raises(ZcapParseError, match="Invalid JSON"):
            parser.parse_invocation_from_json("not json")


# ── is_root ──


class TestIsRoot:
    def test_true_for_root(self) -> None:
        parser = ZcapParser()
        cap = parser.parse_capability(_root_cap())
        assert ZcapParser.is_root(cap) is True

    def test_false_for_delegated(self) -> None:
        parser = ZcapParser()
        cap = parser.parse_capability(_delegated_cap_with_proof())
        assert ZcapParser.is_root(cap) is False
