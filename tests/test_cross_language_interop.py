"""Cross-language JCS interop regression test against committed fixtures.

The fixtures under ``tests/fixtures/cross_lang_jcs/`` are known-answer test
vectors. zcap-dotnet's companion test re-derives the canonical bytes during
its own run and asserts the SHA-256 matches; if either side drifts
(e.g. wrapping the JCS payload in ``{capability, proof}``, or silently
dropping unknown proof fields like ``nonce``), exactly one of these tests
fails — pinpointing whether the bytes diverged or whether the algorithm
side disagrees.

See GitHub issue #5 and the companion zcap-dotnet#34 for context.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from zcap_py.proof.ed25519_2020 import build_canonical_payload, verify_document_proof

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "cross_lang_jcs"
FIXTURE_FILES = ["capability_v1.json", "invocation_v1.json"]


@pytest.fixture(params=FIXTURE_FILES, ids=lambda n: n.removesuffix(".json"))
def fixture(request: pytest.FixtureRequest) -> dict[str, object]:
    path = FIXTURE_DIR / request.param
    return json.loads(path.read_text(encoding="utf-8"))


def test_signature_canonicalizes_to_known_jcs_bytes(fixture: dict[str, object]) -> None:
    """The bytes that go into ``private_key.sign(...)`` must match the
    fixture's ``jcs_sha256_hex``. A mismatch means the two libraries built
    different signing payloads (e.g. wrapped vs flat shape)."""
    on_wire = json.loads(fixture["document"])  # type: ignore[arg-type]
    canonical = build_canonical_payload(on_wire, on_wire["proof"])
    assert hashlib.sha256(canonical).hexdigest() == fixture["jcs_sha256_hex"]


def test_signature_verifies_with_zcap_py(fixture: dict[str, object]) -> None:
    """The signature in the fixture must verify under zcap-py's JCS verifier.
    A failure here with the hash test passing means the bytes match but the
    algorithm side disagrees (e.g. key encoding or signature format)."""
    on_wire = json.loads(fixture["document"])  # type: ignore[arg-type]
    verify_document_proof(on_wire)
