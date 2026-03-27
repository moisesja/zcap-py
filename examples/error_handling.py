"""Structured error handling — all exceptions inherit from ZcapError."""

from zcap_py import (
    DidParseError,
    ZcapError,
    ZcapParseError,
    ZcapParser,
    decode_did_key,
)

try:
    decode_did_key("not-a-did")
except DidParseError as e:
    print(e.message)  # Human-readable message
    print(e.context)  # {"did": "not-a-did"} — structured data for logging

# ZcapParseError includes the offending field name
try:
    ZcapParser().parse_capability({"type": "Authorization"})
except ZcapParseError as e:
    print(e.field)  # "id"
    print(e.message)  # "Missing or invalid field 'id'"

# Catch all library errors at once
try:
    decode_did_key("not-a-did")
except ZcapError:
    print("Something went wrong with ZCAP processing")
