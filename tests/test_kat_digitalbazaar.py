"""Cross-implementation known-answer test against genuine @digitalbazaar/zcap (#14).

These fixtures were produced by the real digitalbazaar stack
(``@digitalbazaar/zcap`` + ``jsonld-signatures`` + ``@digitalbazaar/ed25519-signature-2020``)
— see ``tests/fixtures/digitalbazaar/README.md`` and ``generate.mjs``. They lock two
otherwise-believed-pending interop assumptions to a concrete external answer:

1. **Parser parity** — zcap-py parses the real digitalbazaar ``capabilityInvocation``
   Data-Integrity-proof-over-target shape (no bespoke ``type:"Invocation"`` wrapper;
   ``capability`` embeds the full delegated zcap; ``invocationTarget``/``capabilityAction``
   in the proof).
2. **Verify-data byte parity** — a proof produced by ``@digitalbazaar/ed25519-signature-2020``
   verifies under zcap-py's default URDNA2015 verifier, proving the
   ``proofHash || docHash`` concatenation order and canonicalization are byte-identical.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from zcap_py.exceptions import SignatureVerificationError
from zcap_py.zcap.parser import ZcapParser
from zcap_py.zcap.verifier import ZcapVerifier

_FIXTURES = Path(__file__).parent / "fixtures" / "digitalbazaar"
_BUNDLED_CONTEXTS = (
    Path(__file__).parents[1] / "src" / "zcap_py" / "jsonld" / "contexts"
)

parser = ZcapParser()


def _load(name: str) -> dict[str, object]:
    return json.loads((_FIXTURES / name).read_text())


def _chain() -> tuple[object, object, object]:
    root = parser.parse_capability(_load("root.json"))
    delegated = parser.parse_capability(_load("delegated.json"))
    invocation = parser.parse_invocation(_load("invocation.json"))
    return root, delegated, invocation


class TestDigitalbazaarKAT:
    def test_parser_accepts_digitalbazaar_invocation_shape(self) -> None:
        """The real digitalbazaar invocation parses: no body type; capability +
        invocationTarget + capabilityAction read from the proof; the delegated
        capability embedded in proof.capability is surfaced."""
        raw = _load("invocation.json")
        assert "type" not in raw  # no bespoke type:"Invocation" wrapper
        inv = parser.parse_invocation(raw)
        assert inv.proof.proof_purpose == "capabilityInvocation"
        assert inv.capability is not None
        assert inv.invocation_target == "https://api.example.com/data/"
        assert inv.proof.capability_action == "read"
        # proof.capability embeds the full delegated zcap (string proof.capability
        # is reserved for root invocations in the digitalbazaar model).
        assert inv.embedded_capability is not None
        assert inv.embedded_capability.id == inv.capability

    def test_digitalbazaar_invocation_verifies_under_default_verifier(self) -> None:
        """A genuine digitalbazaar Ed25519Signature2020 proof verifies under our
        default URDNA2015 verifier — byte-identical verify-data."""
        root, delegated, invocation = self._chain_or_skip()
        ZcapVerifier().verify_invocation(invocation, chain=[root, delegated])

    def test_expected_target_binds_to_request(self) -> None:
        root, delegated, invocation = self._chain_or_skip()
        ZcapVerifier().verify_invocation(
            invocation,
            chain=[root, delegated],
            expected_target="https://api.example.com/data/",
        )

    def test_wrong_expected_target_rejected(self) -> None:
        from zcap_py.exceptions import InvocationError

        root, delegated, invocation = self._chain_or_skip()
        with pytest.raises(InvocationError):
            ZcapVerifier().verify_invocation(
                invocation,
                chain=[root, delegated],
                expected_target="https://api.example.com/other/",
            )

    def test_tampered_proof_value_rejected(self) -> None:
        """Flipping one base58 char of the digitalbazaar proofValue fails."""
        raw = _load("invocation.json")
        proof = dict(raw["proof"])  # type: ignore[arg-type]
        pv = str(proof["proofValue"])
        # Swap a character in the middle of the multibase value.
        idx = len(pv) // 2
        swap = "1" if pv[idx] != "1" else "2"
        proof["proofValue"] = pv[:idx] + swap + pv[idx + 1 :]
        raw["proof"] = proof
        inv = parser.parse_invocation(raw)
        root = parser.parse_capability(_load("root.json"))
        delegated = parser.parse_capability(_load("delegated.json"))
        with pytest.raises(SignatureVerificationError):
            ZcapVerifier().verify_invocation(inv, chain=[root, delegated])

    @staticmethod
    def _chain_or_skip() -> tuple[object, object, object]:
        return _chain()


class TestBundledContextByteIdentity:
    """Guard: bundled JSON-LD contexts must stay byte-identical (semantically) to
    digitalbazaar's, or URDNA2015 N-Quads silently diverge and the KAT is moot."""

    @pytest.mark.parametrize(
        ("bundled", "reference"),
        [
            ("zcap-v1.jsonld", "zcap-v1.json"),
            ("ed25519-signature-2020-v1.jsonld", "ed25519-signature-2020-v1.json"),
        ],
    )
    def test_bundled_context_matches_digitalbazaar(self, bundled: str, reference: str) -> None:
        ours = json.loads((_BUNDLED_CONTEXTS / bundled).read_text())
        theirs = json.loads((_FIXTURES / "reference-contexts" / reference).read_text())
        assert ours == theirs, (
            f"Bundled context '{bundled}' diverged from digitalbazaar's "
            f"'{reference}'. Regenerate fixtures and reconcile the bundled context."
        )
