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
ZCAP_CONTEXT_URL = "https://w3id.org/zcap/v1"

# The spec says a root zcap "MUST NOT have any other fields" beyond these four.
_ROOT_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {"@context", "id", "controller", "invocationTarget"}
)


def _parse_caveat_list(value: object) -> list[dict[str, object]]:
    """Parse caveat list, rejecting malformed entries.

    Raises:
        ZcapParseError: If value is not a list or contains non-object entries.
    """
    if value is None:
        return []
    if not isinstance(value, list):
        raise ZcapParseError("'caveat' must be an array", field="caveat")
    if not all(isinstance(c, dict) for c in value):
        raise ZcapParseError("'caveat' entries must be objects", field="caveat")
    return [dict(c) for c in value]


class ZcapParser:
    """Stateless parser for ZCAP-LD documents.

    All raw-dict to typed-model conversions go through here.
    ZcapParser never performs cryptographic operations.
    """

    def parse_capability(self, raw: dict[str, object]) -> Capability:
        """Parse and validate a raw capability dict (FR-PARSE-01).

        Root capabilities (no ``parentCapability``) are restricted to the
        four spec-required fields: ``@context``, ``id``, ``controller``,
        ``invocationTarget``.  Extra fields are rejected per the ZCAP-LD
        spec's "MUST NOT have any other fields" constraint.

        Delegated capabilities (``parentCapability`` present) may include
        additional fields like ``type``, ``allowedAction``, ``expires``,
        ``invoker``, ``caveat``, and ``proof``.

        ``controller`` may be a single DID string or an array of DID strings.

        Raises:
            ZcapParseError: If any required field is missing or invalid.
        """
        self._validate_context(raw)
        self._require_str(raw, "id")
        controller = self._require_controller(raw)
        self._require_str(raw, "invocationTarget")

        is_root = "parentCapability" not in raw

        if is_root:
            # Spec: root zcap MUST NOT have any fields beyond the four required.
            extra = set(raw.keys()) - _ROOT_ALLOWED_FIELDS
            if extra:
                raise ZcapParseError(
                    f"Root capability has disallowed fields: {sorted(extra)}",
                    field=", ".join(sorted(extra)),
                )
            return Capability(
                id=str(raw["id"]),
                controller=controller,
                parent_capability=None,
                invocation_target=str(raw["invocationTarget"]),
                allowed_action=None,
                expires=None,
                invoker=None,
                raw=dict(raw),
            )

        # ── Delegated capability ──
        self._validate_optional_type(raw, "Authorization")
        allowed_action = self._parse_optional_action_list(raw)
        expires = self._parse_expires(raw.get("expires"))

        parent_cap = raw.get("parentCapability")
        if not isinstance(parent_cap, str) or not parent_cap.strip():
            raise ZcapParseError(
                "'parentCapability' must be a non-empty string",
                field="parentCapability",
            )

        proof = self._parse_proof(raw["proof"], "capabilityDelegation") if "proof" in raw else None

        return Capability(
            id=str(raw["id"]),
            controller=controller,
            parent_capability=str(parent_cap),
            invocation_target=str(raw["invocationTarget"]),
            allowed_action=allowed_action,
            expires=expires,
            invoker=str(raw["invoker"]) if raw.get("invoker") else None,
            caveat=_parse_caveat_list(raw.get("caveat")),
            proof=proof,
            raw=dict(raw),
        )

    def parse_invocation(self, raw: dict[str, object]) -> Invocation:
        """Parse and validate a raw invocation dict (FR-PARSE-02).

        The ``capability`` field may be a string (capability ID) or an
        embedded capability object.  When embedded, the object is parsed
        via :meth:`parse_capability` and stored as ``embedded_capability``.

        Raises:
            ZcapParseError: If any required field is missing or invalid.
        """
        self._validate_context(raw)
        self._require_str(raw, "id")
        self._require_type(raw, "Invocation")
        self._require_str(raw, "invocationTarget")

        # capability — required, string or embedded object
        cap_value = raw.get("capability")
        embedded_capability: Capability | None = None
        if isinstance(cap_value, dict):
            cap_id_raw = cap_value.get("id")
            if not isinstance(cap_id_raw, str) or not cap_id_raw.strip():
                raise ZcapParseError(
                    "Embedded capability must have a string 'id'",
                    field="capability.id",
                )
            cap_id = cap_id_raw
            embedded_capability = self.parse_capability(cap_value)
        elif isinstance(cap_value, str) and cap_value.strip():
            cap_id = cap_value
        else:
            raise ZcapParseError(
                "Missing or invalid field 'capability'",
                field="capability",
            )

        # FR-PARSE-06: proof is mandatory on Invocation documents
        if "proof" not in raw:
            raise ZcapParseError("Missing required 'proof' field", field="proof")
        proof = self._parse_proof(raw["proof"], "capabilityInvocation")

        # ZCAP-LD spec: invocation proofs must carry a capability reference
        if proof.capability is None:
            raise ZcapParseError(
                "Invocation proof must include 'capability'",
                field="proof.capability",
            )

        return Invocation(
            id=str(raw["id"]),
            capability=cap_id,
            invocation_target=str(raw["invocationTarget"]),
            proof=proof,
            embedded_capability=embedded_capability,
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
    def _validate_context(d: dict[str, object]) -> None:
        """Validate that ``@context`` is present and includes the ZCAP-LD URL."""
        ctx = d.get("@context")
        if ctx is None:
            raise ZcapParseError(
                "Missing required '@context' field",
                field="@context",
            )
        if isinstance(ctx, str):
            if ctx != ZCAP_CONTEXT_URL:
                raise ZcapParseError(
                    f"'@context' must be or start with '{ZCAP_CONTEXT_URL}'",
                    field="@context",
                )
            return
        if isinstance(ctx, list) and ctx and ctx[0] == ZCAP_CONTEXT_URL:
            return
        raise ZcapParseError(
            f"'@context' must be or start with '{ZCAP_CONTEXT_URL}'",
            field="@context",
        )

    @staticmethod
    def _require_type(d: dict[str, object], expected: str) -> None:
        t = d.get("type")
        if t != expected:
            raise ZcapParseError(
                f"Expected type '{expected}', got '{t}'",
                field="type",
            )

    @staticmethod
    def _validate_optional_type(d: dict[str, object], expected: str) -> None:
        """Validate ``type`` only if present — it is optional per spec."""
        t = d.get("type")
        if t is not None and t != expected:
            raise ZcapParseError(
                f"Expected type '{expected}', got '{t}'",
                field="type",
            )

    @staticmethod
    def _require_controller(d: dict[str, object]) -> str | list[str]:
        """Parse ``controller`` — string or array of DID strings per spec."""
        v = d.get("controller")
        if isinstance(v, str):
            if not v.strip():
                raise ZcapParseError(
                    "Missing or invalid field 'controller'",
                    field="controller",
                )
            try:
                parse_did(v)
            except DidParseError as e:
                raise ZcapParseError(
                    f"Field 'controller' is not a valid DID: {v}",
                    field="controller",
                ) from e
            return v
        if isinstance(v, list):
            if not v or not all(isinstance(s, str) for s in v):
                raise ZcapParseError(
                    "'controller' must be a non-empty string or array of DID strings",
                    field="controller",
                )
            for item in v:
                try:
                    parse_did(item)
                except DidParseError as e:
                    raise ZcapParseError(
                        f"'controller' contains invalid DID: {item}",
                        field="controller",
                    ) from e
            return v
        raise ZcapParseError(
            "Missing or invalid field 'controller'",
            field="controller",
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
    def _parse_optional_action_list(d: dict[str, object]) -> list[str] | None:
        """Parse ``allowedAction`` — optional per spec, validated when present."""
        v = d.get("allowedAction")
        if v is None:
            return None
        if not isinstance(v, list) or not v or not all(isinstance(a, str) for a in v):
            raise ZcapParseError(
                "'allowedAction' must be a non-empty list of strings",
                field="allowedAction",
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
    def _parse_proof(proof: object, expected_purpose: str) -> LinkedDataProof:
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

        # proofPurpose — required, must match the expected purpose for the
        # document type (capabilityDelegation for Authorization,
        # capabilityInvocation for Invocation).
        pp = proof.get("proofPurpose")
        if not isinstance(pp, str) or not pp.strip():
            raise ZcapParseError(
                "Missing required 'proof.proofPurpose'",
                field="proof.proofPurpose",
            )
        if pp != expected_purpose:
            raise ZcapParseError(
                f"Expected proofPurpose '{expected_purpose}', got '{pp}'",
                field="proof.proofPurpose",
            )

        # capabilityChain — optional list of str/dict entries
        capability_chain: tuple[str | dict[str, object], ...] | None = None
        chain_raw = proof.get("capabilityChain")
        if chain_raw is not None:
            if not isinstance(chain_raw, list):
                raise ZcapParseError(
                    "'proof.capabilityChain' must be an array",
                    field="proof.capabilityChain",
                )
            for i, entry in enumerate(chain_raw):
                if not isinstance(entry, (str, dict)):
                    raise ZcapParseError(
                        f"'proof.capabilityChain[{i}]' must be a string or object",
                        field="proof.capabilityChain",
                    )
            capability_chain = tuple(chain_raw)

        return LinkedDataProof(
            type=str(ptype),
            verification_method=str(vm),
            created=str(created),
            proof_value=str(pv),
            proof_purpose=str(pp),
            capability=str(proof["capability"]) if proof.get("capability") else None,
            capability_action=(
                str(proof["capabilityAction"]) if proof.get("capabilityAction") else None
            ),
            capability_chain=capability_chain,
        )
