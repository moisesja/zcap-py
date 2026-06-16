"""Parse and validate a ZCAP-LD capability document."""

import json

from zcap_py import ZcapParseError, ZcapParser

parser = ZcapParser()

# Spec-minimal root capability: only @context, id, controller, invocationTarget
spec_root = {
    "@context": "https://w3id.org/zcap/v1",
    "id": "urn:example:root-cap",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "invocationTarget": "https://api.example.com/docs",
}
cap = parser.parse_capability(spec_root)

print(cap.id)  # "urn:example:root-cap"
print(cap.controller)  # "did:key:z6Mk..."
print(cap.allowed_action)  # None (not allowed on root caps)
print(cap.is_root)  # True
print(cap.parent_capability)  # None
print(cap.expires)  # None

# Root caps with controller as an array of DIDs
multi_controller_root = {
    "@context": "https://w3id.org/zcap/v1",
    "id": "urn:example:root-cap-2",
    "controller": [
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
    ],
    "invocationTarget": "https://api.example.com/docs",
}
cap2 = parser.parse_capability(multi_controller_root)
print(cap2.controller)  # ["did:key:z6Mk...", "did:key:z6Mk..."]

# Delegated capability with type and allowedAction
delegated = {
    "@context": [
        "https://w3id.org/zcap/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    "id": "urn:example:delegated-cap",
    "type": "Authorization",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "parentCapability": "urn:example:root-cap",
    "invocationTarget": "https://api.example.com/docs",
    "allowedAction": ["read", "write"],
    "expires": "2026-12-31T00:00:00Z",  # required on delegated capabilities
}
cap3 = parser.parse_capability(delegated)
print(cap3.allowed_action)  # ["read", "write"]
print(cap3.is_root)  # False

# Parse from a JSON string
cap4 = parser.parse_capability_from_json(json.dumps(spec_root))
assert cap4.id == cap.id

# Invalid documents raise ZcapParseError with the offending field
try:
    parser.parse_capability({"@context": "https://w3id.org/zcap/v1", "id": ""})
except ZcapParseError as e:
    print(e.message)  # "Missing or invalid field 'id'"
    print(e.field)  # "id"

# Root caps with extra fields are rejected per spec
try:
    parser.parse_capability(
        {
            "@context": "https://w3id.org/zcap/v1",
            "id": "urn:example:root",
            "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "invocationTarget": "https://api.example.com/docs",
            "type": "Authorization",
        }
    )
except ZcapParseError as e:
    print(e.message)  # "Root capability has disallowed fields: ['type']"
