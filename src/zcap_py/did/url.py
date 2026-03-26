"""DID URL strict parsing and validation for did:key method."""

from __future__ import annotations

import re
from dataclasses import dataclass

from zcap_py.exceptions import DidParseError

# Base58btc alphabet (no 0, O, I, l)
_B58_CHARS = r"[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]"

# did:key:<z-multibase>
_DID_KEY_RE = re.compile(rf"^did:key:(z{_B58_CHARS}+)$")

# did:key:<z-multibase>#<z-multibase>
_DID_URL_RE = re.compile(rf"^did:key:(z{_B58_CHARS}+)#(z{_B58_CHARS}+)$")


@dataclass(frozen=True)
class ParsedDid:
    """Parsed did:key DID."""

    method: str
    identifier: str
    full_did: str


@dataclass(frozen=True)
class ParsedDidUrl:
    """Parsed did:key DID URL with fragment."""

    did: ParsedDid
    fragment: str
    full_url: str


def parse_did(did_string: str) -> ParsedDid:
    """Parse and validate a did:key DID string.

    Raises:
        DidParseError: If the DID is malformed.
    """
    if not did_string:
        raise DidParseError("DID string is empty")

    match = _DID_KEY_RE.match(did_string)
    if not match:
        raise DidParseError(
            f"Invalid did:key DID: '{did_string}'",
            context={"did": did_string},
        )

    return ParsedDid(method="key", identifier=match.group(1), full_did=did_string)


def parse_did_url(url_string: str) -> ParsedDidUrl:
    """Parse and validate a did:key DID URL with fragment.

    Validates that the fragment equals the DID's key identifier (FR-DID-03).

    Raises:
        DidParseError: If the DID URL is malformed or fragment doesn't match.
    """
    if not url_string:
        raise DidParseError("DID URL string is empty")

    match = _DID_URL_RE.match(url_string)
    if not match:
        if _DID_KEY_RE.match(url_string):
            raise DidParseError(
                f"DID URL must contain a '#' fragment: '{url_string}'",
                context={"url": url_string},
            )
        raise DidParseError(
            f"Invalid did:key DID URL: '{url_string}'",
            context={"url": url_string},
        )

    identifier = match.group(1)
    fragment = match.group(2)

    if fragment != identifier:
        raise DidParseError(
            f"DID URL fragment '{fragment}' does not match DID identifier '{identifier}'",
            context={"identifier": identifier, "fragment": fragment},
        )

    did = ParsedDid(method="key", identifier=identifier, full_did=f"did:key:{identifier}")
    return ParsedDidUrl(did=did, fragment=fragment, full_url=url_string)


def strip_did_fragment(did_url_or_did: str) -> str:
    """Return the bare DID from a DID URL by stripping the fragment."""
    return did_url_or_did.split("#")[0]
