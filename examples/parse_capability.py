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
print(cap.allowed_action)  # None (not required on root caps)
print(cap.is_root)  # True
print(cap.parent_capability)  # None
print(cap.expires)  # None

# Root capability with optional type and allowedAction (also valid)
extended_root = {
    "@context": [
        "https://w3id.org/zcap/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    "id": "urn:example:root-cap-2",
    "type": "Authorization",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "invocationTarget": "https://api.example.com/docs",
    "allowedAction": ["read", "write"],
}
cap2 = parser.parse_capability(extended_root)
print(cap2.allowed_action)  # ["read", "write"]

# Parse from a JSON string
cap3 = parser.parse_capability_from_json(json.dumps(extended_root))
assert cap3.id == cap2.id

# Invalid documents raise ZcapParseError with the offending field
try:
    parser.parse_capability({"@context": "https://w3id.org/zcap/v1", "id": ""})
except ZcapParseError as e:
    print(e.message)  # "Missing or invalid field 'id'"
    print(e.field)  # "id"
