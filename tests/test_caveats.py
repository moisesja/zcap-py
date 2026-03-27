"""Tests for CaveatVerifier protocol and CaveatRegistry."""

from __future__ import annotations

import pytest

from zcap_py.exceptions import CaveatError, UnknownCaveatError
from zcap_py.zcap.caveats import CaveatRegistry, CaveatVerifier


class _StubVerifier:
    """Minimal duck-typed caveat verifier — no inheritance needed."""

    caveat_type = "TestCaveat"

    def verify(self, caveat: dict[str, object], invocation: dict[str, object]) -> None:
        pass


class _FailingVerifier:
    """Caveat verifier that always rejects."""

    caveat_type = "FailCaveat"

    def verify(self, caveat: dict[str, object], invocation: dict[str, object]) -> None:
        raise CaveatError("Caveat check failed", context={"caveat": caveat})


class TestCaveatVerifierProtocol:
    def test_duck_typed_class_satisfies_protocol(self) -> None:
        assert isinstance(_StubVerifier(), CaveatVerifier)

    def test_class_missing_verify_does_not_satisfy(self) -> None:
        class Bad:
            caveat_type = "X"

        assert not isinstance(Bad(), CaveatVerifier)


class TestCaveatRegistry:
    def test_empty_caveats_passes(self) -> None:
        registry = CaveatRegistry([_StubVerifier()])
        registry.verify_all([], {})

    def test_known_caveat_dispatched(self) -> None:
        calls: list[dict[str, object]] = []

        class Tracker:
            caveat_type = "Track"

            def verify(self, caveat: dict[str, object], invocation: dict[str, object]) -> None:
                calls.append(caveat)

        registry = CaveatRegistry([Tracker()])
        registry.verify_all([{"type": "Track", "value": 42}], {"id": "inv-1"})
        assert len(calls) == 1
        assert calls[0]["value"] == 42

    def test_unknown_caveat_raises_error(self) -> None:
        registry = CaveatRegistry([_StubVerifier()])
        with pytest.raises(UnknownCaveatError, match="UnknownType"):
            registry.verify_all([{"type": "UnknownType"}], {})

    def test_caveat_without_type_raises_error(self) -> None:
        registry = CaveatRegistry([_StubVerifier()])
        with pytest.raises(UnknownCaveatError, match="None"):
            registry.verify_all([{"value": "no-type"}], {})

    def test_failing_verifier_propagates_error(self) -> None:
        registry = CaveatRegistry([_FailingVerifier()])
        with pytest.raises(CaveatError, match="Caveat check failed"):
            registry.verify_all([{"type": "FailCaveat"}], {})

    def test_multiple_caveats_all_verified(self) -> None:
        calls: list[str] = []

        class V1:
            caveat_type = "A"

            def verify(self, caveat: dict[str, object], invocation: dict[str, object]) -> None:
                calls.append("A")

        class V2:
            caveat_type = "B"

            def verify(self, caveat: dict[str, object], invocation: dict[str, object]) -> None:
                calls.append("B")

        registry = CaveatRegistry([V1(), V2()])
        registry.verify_all([{"type": "A"}, {"type": "B"}], {})
        assert calls == ["A", "B"]

    def test_no_verifiers_and_no_caveats_passes(self) -> None:
        registry = CaveatRegistry()
        registry.verify_all([], {})

    def test_no_verifiers_with_caveats_raises(self) -> None:
        registry = CaveatRegistry()
        with pytest.raises(UnknownCaveatError):
            registry.verify_all([{"type": "Any"}], {})
