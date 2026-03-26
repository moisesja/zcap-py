"""Stateless parser for ZCAP-LD documents."""

from __future__ import annotations

import json
from datetime import datetime

from zcap_py.crypto.multibase import base58btc_decode
from zcap_py.did.url import parse_did, parse_did_url
from zcap_py.exceptions import DidParseError, ZcapParseError
from zcap_py.proof.models import LinkedDataProof
from zcap_py.zcap.models import Capability, Invocation

ED25519_SIGNATURE_LENGTH = 64


def _parse_caveat_list(value: object) -> list[dict[str, object]]:
    """Extract caveat list from raw value, defaulting to empty list."""
    if value is None:
        return []
    if not isinstance(value, list):
        return []
    return [dict(c) for c in value if isinstance(c, dict)]


class ZcapParser:
    """Stateless parser for ZCAP-LD documents.

    All raw-dict to typed-model conversions go through here.
    ZcapParser never performs cryptographic operations.
    """

    def parse_capability(self, raw: dict[str, object]) -> Capability:
        """Parse and validate a raw capability dict (FR-PARSE-01).

        Raises:
            ZcapParseError: If any required field is missing or invalid.
        """
        self._require_str(raw, "id")
        self._require_type(raw, "Authorization")
        self._require_did(raw, "controller")
        self._require_str(raw, "invocationTarget")
        self._require_action_list(raw, "allowedAction")
        expires = self._parse_expires(raw.get("expires"))

        parent_cap = raw.get("parentCapability")
        if parent_cap is not None and (not isinstance(parent_cap, str) or not parent_cap.strip()):
            raise ZcapParseError(
                "'parentCapability' must be a non-empty string when present",
                field="parentCapability",
            )

        # FR-PARSE-06: proof is optional on Authorization documents
        proof = self._parse_proof(raw["proof"]) if "proof" in raw else None

        return Capability(
            id=str(raw["id"]),
            controller=str(raw["controller"]),
            parent_capability=str(parent_cap) if parent_cap else None,
            invocation_target=str(raw["invocationTarget"]),
            allowed_action=self._require_action_list(raw, "allowedAction"),
            expires=expires,
            invoker=str(raw["invoker"]) if raw.get("invoker") else None,
            caveat=_parse_caveat_list(raw.get("caveat")),
            proof=proof,
            raw=dict(raw),
        )

    def parse_invocation(self, raw: dict[str, object]) -> Invocation:
        """Parse and validate a raw invocation dict (FR-PARSE-02).

        Raises:
            ZcapParseError: If any required field is missing or invalid.
        """
        self._require_str(raw, "id")
        self._require_type(raw, "Invocation")
        self._require_str(raw, "capability")
        self._require_str(raw, "invocationTarget")

        # FR-PARSE-06: proof is mandatory on Invocation documents
        if "proof" not in raw:
            raise ZcapParseError("Missing required 'proof' field", field="proof")
        proof = self._parse_proof(raw["proof"])

        return Invocation(
            id=str(raw["id"]),
            capability=str(raw["capability"]),
            invocation_target=str(raw["invocationTarget"]),
            proof=proof,
            raw=dict(raw),
        )

    def parse_capability_from_json(self, json_str: str) -> Capability:
        """Parse a capability from a JSON string (FR-PARSE-03).

        Raises:
            ZcapParseError: On invalid JSON or invalid document.
        """
        raw = self._parse_json(json_str)
        return self.parse_capability(raw)

    def parse_invocation_from_json(self, json_str: str) -> Invocation:
        """Parse an invocation from a JSON string (FR-PARSE-04).

        Raises:
            ZcapParseError: On invalid JSON or invalid document.
        """
        raw = self._parse_json(json_str)
        return self.parse_invocation(raw)

    @staticmethod
    def is_root(capability: Capability) -> bool:
        """Returns True when capability has no parent (FR-PARSE-07)."""
        return capability.parent_capability is None

    # ── Private helpers ──

    @staticmethod
    def _parse_json(json_str: str) -> dict[str, object]:
        try:
            raw = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ZcapParseError(f"Invalid JSON: {e}", field="<document>") from e
        if not isinstance(raw, dict):
            raise ZcapParseError("Expected JSON object", field="<document>")
        return raw

    @staticmethod
    def _require_str(d: dict[str, object], field: str) -> str:
        v = d.get(field)
        if not isinstance(v, str) or not v.strip():
            raise ZcapParseError(f"Missing or invalid field '{field}'", field=field)
        return v

    @staticmethod
    def _require_type(d: dict[str, object], expected: str) -> None:
        t = d.get("type")
        if t != expected:
            raise ZcapParseError(
                f"Expected type '{expected}', got '{t}'",
                field="type",
            )

    @staticmethod
    def _require_did(d: dict[str, object], field: str) -> str:
        v = d.get(field)
        if not isinstance(v, str) or not v.strip():
            raise ZcapParseError(f"Missing or invalid field '{field}'", field=field)
        try:
            parse_did(v)
        except DidParseError as e:
            raise ZcapParseError(
                f"Field '{field}' is not a valid DID: {v}",
                field=field,
            ) from e
        return v

    @staticmethod
    def _require_action_list(d: dict[str, object], field: str) -> list[str]:
        v = d.get(field)
        if not isinstance(v, list) or not v or not all(isinstance(a, str) for a in v):
            raise ZcapParseError(
                f"'{field}' must be a non-empty list of strings",
                field=field,
            )
        return v

    @staticmethod
    def _parse_expires(value: object) -> datetime | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ZcapParseError("'expires' must be a string", field="expires")
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as e:
            raise ZcapParseError(
                "'expires' is not a valid ISO 8601 datetime",
                field="expires",
            ) from e

    @staticmethod
    def _parse_proof(proof: object) -> LinkedDataProof:
        if not isinstance(proof, dict):
            raise ZcapParseError("'proof' must be an object", field="proof")

        # FR-PROOF-05
        ptype = proof.get("type")
        if ptype != "Ed25519Signature2020":
            raise ZcapParseError(
                f"Unsupported proof type '{ptype}'",
                field="proof.type",
            )

        # FR-PROOF-03
        vm = proof.get("verificationMethod")
        if not isinstance(vm, str) or not vm:
            raise ZcapParseError(
                "Missing proof.verificationMethod",
                field="proof.verificationMethod",
            )
        try:
            parse_did_url(vm)
        except DidParseError as e:
            raise ZcapParseError(
                f"proof.verificationMethod is not a valid DID URL: {vm}",
                field="proof.verificationMethod",
            ) from e

        # FR-PROOF-04
        created = proof.get("created")
        if not isinstance(created, str) or not created:
            raise ZcapParseError(
                "Missing proof.created",
                field="proof.created",
            )
        try:
            datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError as e:
            raise ZcapParseError(
                "proof.created is not a valid ISO 8601 datetime",
                field="proof.created",
            ) from e

        # FR-PROOF-06
        pv = proof.get("proofValue")
        if not isinstance(pv, str) or not pv.startswith("z"):
            raise ZcapParseError(
                "proof.proofValue must be a multibase-z string",
                field="proof.proofValue",
            )
        try:
            decoded = base58btc_decode(pv)
        except Exception as e:
            raise ZcapParseError(
                "proof.proofValue base58btc decode failed",
                field="proof.proofValue",
            ) from e
        if len(decoded) != ED25519_SIGNATURE_LENGTH:
            raise ZcapParseError(
                f"proof.proofValue decoded to {len(decoded)} bytes;"
                f" expected {ED25519_SIGNATURE_LENGTH}",
                field="proof.proofValue",
            )

        return LinkedDataProof(
            type=str(ptype),
            verification_method=str(vm),
            created=str(created),
            proof_value=str(pv),
            capability=str(proof["capability"]) if proof.get("capability") else None,
            capability_action=(
                str(proof["capabilityAction"]) if proof.get("capabilityAction") else None
            ),
            proof_purpose=str(proof.get("proofPurpose", "capabilityDelegation")),
        )
