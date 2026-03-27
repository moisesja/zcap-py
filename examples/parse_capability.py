"""Parse and validate a ZCAP-LD capability document."""

import json

from zcap_py import ZcapParseError, ZcapParser

parser = ZcapParser()

# Parse a root capability (no parent, no proof required)
raw_cap = {
    "id": "urn:example:root-cap",
    "type": "Authorization",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "invocationTarget": "https://api.example.com/docs",
    "allowedAction": ["read", "write"],
}
cap = parser.parse_capability(raw_cap)

print(cap.id)  # "urn:example:root-cap"
print(cap.controller)  # "did:key:z6Mk..."
print(cap.allowed_action)  # ["read", "write"]
print(cap.is_root)  # True
print(cap.parent_capability)  # None
print(cap.expires)  # None

# Parse from a JSON string
cap2 = parser.parse_capability_from_json(json.dumps(raw_cap))
assert cap2.id == cap.id

# Invalid documents raise ZcapParseError with the offending field
try:
    parser.parse_capability({"id": "", "type": "Authorization"})
except ZcapParseError as e:
    print(e.message)  # "Missing or invalid field 'id'"
    print(e.field)  # "id"
