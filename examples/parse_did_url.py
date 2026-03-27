"""Strict validation of did:key DIDs and DID URLs."""

from zcap_py import DidParseError, parse_did, parse_did_url, strip_did_fragment

# Parse a bare DID
parsed = parse_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
print(parsed.method)  # "key"
print(parsed.identifier)  # "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

# Parse a DID URL (with fragment) — validates fragment matches the identifier
did_url = (
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    "#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
)
parsed_url = parse_did_url(did_url)
print(parsed_url.fragment)  # "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
print(parsed_url.did.method)  # "key"

# Strip the fragment from a DID URL
bare = strip_did_fragment(did_url)
print(bare)  # "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

# Invalid DIDs raise DidParseError
try:
    parse_did("did:web:example.com")
except DidParseError as e:
    print(e.message)  # "Invalid did:key DID: 'did:web:example.com'"
