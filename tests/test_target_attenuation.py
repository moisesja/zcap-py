"""Tests for InvocationTargetAttenuator and PathPrefixAttenuator."""

from __future__ import annotations

from zcap_py.zcap.target_attenuation import (
    InvocationTargetAttenuator,
    PathPrefixAttenuator,
)


class TestPathPrefixAttenuator:
    def setup_method(self) -> None:
        self.att = PathPrefixAttenuator()

    # ── valid attenuations ──

    def test_exact_match(self) -> None:
        assert self.att.is_valid_attenuation(
            "https://api.example.com/data/", "https://api.example.com/data/"
        )

    def test_path_narrowed(self) -> None:
        assert self.att.is_valid_attenuation(
            "https://api.example.com/data/", "https://api.example.com/data/records/42"
        )

    def test_query_added(self) -> None:
        assert self.att.is_valid_attenuation(
            "https://api.example.com/data/",
            "https://api.example.com/data/q?filter=x",
        )

    def test_fragment_added(self) -> None:
        assert self.att.is_valid_attenuation(
            "https://api.example.com/data/",
            "https://api.example.com/data/page#section",
        )

    def test_trailing_slash_normalization(self) -> None:
        assert self.att.is_valid_attenuation(
            "https://api.example.com/data",
            "https://api.example.com/data/records",
        )

    def test_both_no_trailing_slash(self) -> None:
        assert self.att.is_valid_attenuation(
            "https://api.example.com/data",
            "https://api.example.com/data",
        )

    # ── invalid attenuations ──

    def test_broadened(self) -> None:
        assert not self.att.is_valid_attenuation(
            "https://api.example.com/data/", "https://api.example.com/"
        )

    def test_different_host(self) -> None:
        assert not self.att.is_valid_attenuation(
            "https://api.example.com/data/", "https://other.example.com/data/"
        )

    def test_different_scheme(self) -> None:
        assert not self.att.is_valid_attenuation(
            "https://api.example.com/data/", "http://api.example.com/data/records/"
        )

    def test_different_port(self) -> None:
        assert not self.att.is_valid_attenuation(
            "https://api.example.com:8080/data/",
            "https://api.example.com:9090/data/",
        )

    def test_sibling_path(self) -> None:
        assert not self.att.is_valid_attenuation(
            "https://api.example.com/data/",
            "https://api.example.com/other/",
        )

    def test_empty_string_returns_false(self) -> None:
        assert not self.att.is_valid_attenuation("", "")

    def test_not_a_url_returns_false(self) -> None:
        assert not self.att.is_valid_attenuation("not-a-url", "also-not-a-url")

    # ── query string attenuation ──

    def test_parent_query_child_same_query(self) -> None:
        assert self.att.is_valid_attenuation(
            "https://api.example.com/data/?tenant=a",
            "https://api.example.com/data/?tenant=a",
        )

    def test_parent_query_child_extends_with_ampersand(self) -> None:
        assert self.att.is_valid_attenuation(
            "https://api.example.com/data/?tenant=a",
            "https://api.example.com/data/?tenant=a&filter=x",
        )

    def test_parent_query_child_different_query(self) -> None:
        assert not self.att.is_valid_attenuation(
            "https://api.example.com/data/?tenant=a",
            "https://api.example.com/data/?tenant=b",
        )

    def test_parent_query_child_drops_query(self) -> None:
        assert not self.att.is_valid_attenuation(
            "https://api.example.com/data/?tenant=a",
            "https://api.example.com/data/",
        )

    def test_parent_query_child_value_prefix_attack(self) -> None:
        """?a=1 must not accept ?a=12 (boundary check at &)."""
        assert not self.att.is_valid_attenuation(
            "https://api.example.com/data/?a=1",
            "https://api.example.com/data/?a=12",
        )

    # ── scheme case-insensitive ──

    def test_scheme_case_insensitive(self) -> None:
        assert self.att.is_valid_attenuation(
            "HTTPS://api.example.com/data/", "https://api.example.com/data/records"
        )

    # ── protocol compliance ──

    def test_satisfies_protocol(self) -> None:
        assert isinstance(PathPrefixAttenuator(), InvocationTargetAttenuator)

    # ── RFC-3986 dot-segment / percent-encoding escapes (red-team) ──

    def test_dot_segment_escape_rejected(self) -> None:
        # /data/../admin resolves to /admin — outside the granted subtree.
        assert not self.att.is_valid_attenuation(
            "https://api.example.com/data/", "https://api.example.com/data/../admin"
        )

    def test_encoded_slash_dot_escape_rejected(self) -> None:
        assert not self.att.is_valid_attenuation(
            "https://api.example.com/data/", "https://api.example.com/data%2F..%2Fadmin"
        )

    def test_dot_segment_within_subtree_still_valid(self) -> None:
        # /data/x/../y resolves to /data/y — still within the subtree.
        assert self.att.is_valid_attenuation(
            "https://api.example.com/data/", "https://api.example.com/data/x/../y"
        )
