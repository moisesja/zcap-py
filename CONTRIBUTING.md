# Contributing

Thanks for contributing to `zcap-py`.

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- Git

## Local Setup

```bash
git clone git@github.com:moisesja/zcap-py.git
cd zcap-py
uv sync
uv run pytest
```

All tests should pass with zero warnings.

## Project Structure

```
src/zcap_py/
├── __init__.py                  # Public API re-exports
├── py.typed                     # PEP 561 typed marker
├── exceptions.py                # Full ZcapError hierarchy
├── crypto/
│   ├── ed25519.py               # Key generation, verify
│   ├── multibase.py             # z-base58btc encode/decode (via multiformats)
│   └── multicodec.py            # 0xed01 prefix handling (via multiformats)
├── did/
│   ├── key.py                   # did:key encode/decode/resolve
│   └── url.py                   # DID URL parsing and validation
├── jcs/
│   └── canonicalize.py          # RFC 8785 (stdlib only)
├── proof/
│   ├── ed25519_2020.py          # Ed25519Signature2020 verify only
│   └── models.py                # LinkedDataProof dataclass
└── zcap/
    ├── models.py                # Capability, Invocation dataclasses
    ├── parser.py                # ZcapParser
    ├── delegation.py            # Delegation chain verifier
    ├── invocation.py            # Invocation verifier
    ├── caveats.py               # CaveatVerifier Protocol
    ├── target_attenuation.py    # PathPrefixAttenuator
    ├── verifier.py              # ZcapVerifier (sync)
    └── async_verifier.py        # AsyncZcapVerifier
```

## Code Style

This project uses `ruff` for linting and formatting, and `mypy --strict` for type checking.

```bash
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv run mypy --strict src/zcap_py/
```

Key conventions:

- 100-character line length
- Type annotations on all public APIs
- `from __future__ import annotations` in all modules
- Frozen dataclasses for value objects
- All exceptions must be `ZcapError` subclasses

## Testing Conventions

Tests use **pytest**. Test files are named `test_*.py` in the `tests/` directory.

### Naming convention

```
test_<what>_<condition>_<expected>
```

Examples:

```python
def test_parse_did_valid_did_key_returns_parsed():
def test_multibase_decode_invalid_prefix_raises_error():
def test_verify_signature_invalid_raises_verification_error():
```

### Running tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=zcap_py --cov-report=term-missing

# Run a specific test file
uv run pytest tests/test_crypto.py

# Run a specific test
uv run pytest tests/test_crypto.py::TestGenerateEd25519Keypair::test_did_starts_with_did_key_z6mk
```

## Contribution Scope

Good contributions include:

- Spec compliance improvements
- Security hardening
- Bug fixes and regression tests
- Documentation and examples
- CI/CD improvements

## Pull Request Checklist

- [ ] Tests pass locally (`uv run pytest`)
- [ ] Lint passes (`uv run ruff check src/ tests/`)
- [ ] Format passes (`uv run ruff format --check src/ tests/`)
- [ ] Type check passes (`uv run mypy --strict src/zcap_py/`)
- [ ] New/changed behavior is covered by tests
- [ ] Relevant docs updated (README.md, CHANGELOG.md, etc.)
- [ ] No unrelated file churn

## Commit Guidance

Use clear commit messages describing intent and impact.

Examples:

- `fix: enforce capability chain root-id validation`
- `feat: add did:key encode/decode/resolve`
- `test: cover delegation chain expiry attenuation`
- `docs: add PyPI release workflow instructions`

## Release Process (Maintainers)

1. Merge PRs into `main`.
2. Ensure CI is green.
3. Tag release: `v<major>.<minor>.<patch>` (e.g., `v0.1.0`).
4. Push tag to GitHub.
5. Release workflow publishes to PyPI via OIDC trusted publisher.

## Security Reporting

For security-sensitive issues, open a private security advisory or contact maintainers directly before publishing a public issue. See [SECURITY.md](SECURITY.md).

## AI-Assisted Workflows

This project supports AI-assisted development. See [AGENTS.md](AGENTS.md) for instructions on using AI agents with this codebase, including plan mode requirements, subagent strategy, and verification procedures.
