"""Full ZcapError exception hierarchy for ZCAP-LD verification."""

from __future__ import annotations


class ZcapError(Exception):
    """Base exception for all ZCAP-LD errors."""

    def __init__(self, message: str, *, context: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, object] = context or {}


# --- Parsing ---


class ZcapParseError(ZcapError):
    """Raised when document parsing fails."""

    def __init__(
        self, message: str, *, field: str, context: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, context=context)
        self.field = field


class DidParseError(ZcapError):
    """Raised when DID or DID URL parsing fails."""


# --- Canonicalization ---


class CanonicalizationError(ZcapError):
    """Raised when JCS canonicalization fails."""


# --- Proof ---


class ProofError(ZcapError):
    """Base for proof-related errors."""


class UnsupportedProofTypeError(ProofError):
    """Raised when proof type is not supported."""


class SignatureVerificationError(ProofError):
    """Raised when Ed25519 signature verification fails."""


# --- Delegation ---


class DelegationError(ZcapError):
    """Base for delegation chain errors."""


class ActionAttenuationError(DelegationError):
    """Raised when child allowedAction is not a subset of parent."""


class ExpiryAttenuationError(DelegationError):
    """Raised when child expires is later than parent expires."""


class InvocationTargetError(DelegationError):
    """Raised when invocationTarget attenuation is invalid."""


class ChainVerificationError(DelegationError):
    """Raised wrapping the underlying cause when chain verification fails."""


# --- Invocation ---


class InvocationError(ZcapError):
    """Base for invocation verification errors."""


class InvokerMismatchError(InvocationError):
    """Raised when invoker DID does not match capability controller/invoker."""


# --- Caveats ---


class CaveatError(ZcapError):
    """Base for caveat evaluation errors."""


class UnknownCaveatError(CaveatError):
    """Raised when no verifier is registered for a caveat type."""
