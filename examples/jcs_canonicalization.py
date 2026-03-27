"""Produce deterministic JSON bytes per RFC 8785 / JCS."""

from zcap_py import canonicalize

doc = {"z": 1, "a": 2, "nested": {"b": True, "a": None}}
canonical = canonicalize(doc)

print(canonical)  # b'{"a":2,"nested":{"a":null,"b":true},"z":1}'
print(type(canonical))  # <class 'bytes'>
