"""Authorization Capabilities for Linked Data — Python verification library."""

from __future__ import annotations

from zcap_py.crypto.ed25519 import DidKeyPair, generate_ed25519_keypair, verify_ed25519_signature
from zcap_py.crypto.multibase import base58btc_decode, base58btc_encode
from zcap_py.crypto.multicodec import decode_ed25519_pub, encode_ed25519_pub
from zcap_py.did.key import (
    VerificationMethod,
    decode_did_key,
    encode_did_key,
    public_key_from_did_key,
    resolve_did_key,
)
from zcap_py.did.url import ParsedDid, ParsedDidUrl, parse_did, parse_did_url, strip_did_fragment
from zcap_py.exceptions import (
    ActionAttenuationError,
    CanonicalizationError,
    CapabilityExpiredError,
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
from zcap_py.proof.ed25519_2020_w3c import (
    sign_document_proof_w3c,
    verify_document_proof_w3c,
)
from zcap_py.proof.models import LinkedDataProof
from zcap_py.zcap.caveats import CaveatRegistry, CaveatVerifier
from zcap_py.zcap.models import Capability, Invocation
from zcap_py.zcap.parser import ZcapParser
from zcap_py.zcap.relationships import RelationshipAuthorizer, did_key_relationship_authorizer
from zcap_py.zcap.target_attenuation import InvocationTargetAttenuator, PathPrefixAttenuator
from zcap_py.zcap.verifier import DocumentLoader, ProofVerifier, ZcapVerifier

__version__ = "0.9.0"

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
    "public_key_from_did_key",
    "resolve_did_key",
    "ParsedDid",
    "ParsedDidUrl",
    "parse_did",
    "parse_did_url",
    "strip_did_fragment",
    # Proof (W3C Ed25519Signature2020 / URDNA2015)
    "LinkedDataProof",
    "sign_document_proof_w3c",
    "verify_document_proof_w3c",
    # ZCAP Models, Parser & Verification
    "Capability",
    "Invocation",
    "ZcapParser",
    "ZcapVerifier",
    "CaveatVerifier",
    "CaveatRegistry",
    "InvocationTargetAttenuator",
    "PathPrefixAttenuator",
    "ProofVerifier",
    "DocumentLoader",
    "RelationshipAuthorizer",
    "did_key_relationship_authorizer",
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
    "CapabilityExpiredError",
    "CaveatError",
    "UnknownCaveatError",
]
