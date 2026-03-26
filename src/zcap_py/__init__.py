"""Authorization Capabilities for Linked Data — Python verification library."""

from __future__ import annotations

from zcap_py.crypto.ed25519 import DidKeyPair, generate_ed25519_keypair, verify_ed25519_signature
from zcap_py.crypto.multibase import base58btc_decode, base58btc_encode
from zcap_py.crypto.multicodec import decode_ed25519_pub, encode_ed25519_pub
from zcap_py.did.key import VerificationMethod, decode_did_key, encode_did_key, resolve_did_key
from zcap_py.did.url import ParsedDid, ParsedDidUrl, parse_did, parse_did_url, strip_did_fragment
from zcap_py.exceptions import (
    ActionAttenuationError,
    CanonicalizationError,
    CaveatError,
    ChainVerificationError,
    DelegationError,
    DidParseError,
    ExpiryAttenuationError,
    InvocationError,
    InvocationTargetError,
    InvokerMismatchError,
    ProofError,
    SignatureVerificationError,
    UnknownCaveatError,
    UnsupportedProofTypeError,
    ZcapError,
    ZcapParseError,
)
from zcap_py.jcs.canonicalize import canonicalize
from zcap_py.proof.ed25519_2020 import verify_document_proof
from zcap_py.proof.models import LinkedDataProof
from zcap_py.zcap.models import Capability, Invocation
from zcap_py.zcap.parser import ZcapParser

__version__ = "0.2.0"

__all__ = [
    "__version__",
    # Crypto
    "DidKeyPair",
    "generate_ed25519_keypair",
    "verify_ed25519_signature",
    "base58btc_decode",
    "base58btc_encode",
    "decode_ed25519_pub",
    "encode_ed25519_pub",
    # DID
    "VerificationMethod",
    "decode_did_key",
    "encode_did_key",
    "resolve_did_key",
    "ParsedDid",
    "ParsedDidUrl",
    "parse_did",
    "parse_did_url",
    "strip_did_fragment",
    # JCS
    "canonicalize",
    # Proof
    "LinkedDataProof",
    "verify_document_proof",
    # ZCAP Models & Parser
    "Capability",
    "Invocation",
    "ZcapParser",
    # Exceptions
    "ZcapError",
    "ZcapParseError",
    "DidParseError",
    "CanonicalizationError",
    "ProofError",
    "UnsupportedProofTypeError",
    "SignatureVerificationError",
    "DelegationError",
    "ActionAttenuationError",
    "ExpiryAttenuationError",
    "InvocationTargetError",
    "ChainVerificationError",
    "InvocationError",
    "InvokerMismatchError",
    "CaveatError",
    "UnknownCaveatError",
]
