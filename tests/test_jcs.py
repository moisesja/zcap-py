"""Tests for JCS (RFC 8785) canonicalization."""

from __future__ import annotations

import json

import pytest

from zcap_py.exceptions import CanonicalizationError
from zcap_py.jcs.canonicalize import canonicalize


class TestCanonicalize:
    def test_sorted_keys(self) -> None:
        result = canonicalize({"b": 2, "a": 1})
        assert result == b'{"a":1,"b":2}'

    def test_nested_objects_sorted(self) -> None:
        result = canonicalize({"z": {"b": 2, "a": 1}, "a": 0})
        assert result == b'{"a":0,"z":{"a":1,"b":2}}'

    def test_array_order_preserved(self) -> None:
        result = canonicalize({"a": [3, 1, 2]})
        assert result == b'{"a":[3,1,2]}'

    def test_returns_bytes(self) -> None:
        result = canonicalize({"key": "value"})
        assert isinstance(result, bytes)

    def test_unicode_strings(self) -> None:
        result = canonicalize({"emoji": "\u20ac"})
        parsed = json.loads(result)
        assert parsed["emoji"] == "\u20ac"

    def test_null_value(self) -> None:
        result = canonicalize({"a": None})
        assert result == b'{"a":null}'

    def test_boolean_values(self) -> None:
        result = canonicalize({"t": True, "f": False})
        assert result == b'{"f":false,"t":true}'

    def test_integer_values(self) -> None:
        result = canonicalize({"n": 42})
        assert result == b'{"n":42}'

    def test_empty_dict(self) -> None:
        assert canonicalize({}) == b"{}"

    def test_empty_list(self) -> None:
        assert canonicalize([]) == b"[]"

    def test_list_at_root(self) -> None:
        result = canonicalize([{"b": 1, "a": 2}])
        assert result == b'[{"a":2,"b":1}]'

    def test_non_dict_non_list_raises_error(self) -> None:
        with pytest.raises(CanonicalizationError, match="Expected dict or list"):
            canonicalize("string")  # type: ignore[arg-type]

    def test_non_dict_int_raises_error(self) -> None:
        with pytest.raises(CanonicalizationError, match="Expected dict or list"):
            canonicalize(42)  # type: ignore[arg-type]

    def test_root_capability_fixture_deterministic(self) -> None:
        doc: dict[str, object] = {
            "@context": [
                "https://w3id.org/zcap/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": "https://resource.example/capabilities/root",
            "type": "Authorization",
            "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "invocationTarget": "https://resource.example/api/",
            "allowedAction": ["read", "write"],
        }
        result = canonicalize(doc)
        parsed = json.loads(result)
        keys = list(parsed.keys())
        # Keys must be sorted by Unicode code point order
        assert keys == sorted(keys)
        assert keys[0] == "@context"

    def test_deterministic_across_calls(self) -> None:
        doc: dict[str, object] = {"b": [1, 2], "a": {"x": 1}}
        assert canonicalize(doc) == canonicalize(doc)

    def test_different_key_order_same_output(self) -> None:
        a: dict[str, object] = {"z": 1, "a": 2, "m": 3}
        b: dict[str, object] = {"a": 2, "m": 3, "z": 1}
        assert canonicalize(a) == canonicalize(b)
