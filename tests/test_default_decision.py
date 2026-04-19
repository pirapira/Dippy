"""Tests for `set default {allow,ask,deny}` — decision for unmatched commands."""

from __future__ import annotations

from pathlib import Path

from dippy.core.analyzer import analyze
from dippy.core.config import Config, Rule


def _analyze(cmd: str, default: str = "ask", rules: list[Rule] | None = None):
    cfg = Config(default=default, rules=rules or [])
    return analyze(cmd, cfg, Path.cwd())


class TestDefaultAsk:
    """Default behavior (unchanged) - unmatched commands ask."""

    def test_unknown_command_asks(self):
        assert _analyze("somecmd foo").action == "ask"

    def test_known_safe_still_allows(self):
        assert _analyze("ls").action == "allow"


class TestDefaultDeny:
    """With `set default deny`, unmatched commands are denied."""

    def test_unknown_command_denies(self):
        assert _analyze("somecmd foo", default="deny").action == "deny"

    def test_safe_command_still_allows(self):
        # SIMPLE_SAFE commands aren't "unmatched"; they're allowed.
        assert _analyze("ls", default="deny").action == "allow"

    def test_allow_rule_overrides_default(self):
        rules = [Rule(decision="allow", pattern="somecmd *")]
        assert _analyze("somecmd foo", default="deny", rules=rules).action == "allow"

    def test_explicit_ask_rule_still_asks(self):
        rules = [Rule(decision="ask", pattern="somecmd *")]
        assert _analyze("somecmd foo", default="deny", rules=rules).action == "ask"

    def test_unknown_construct_denies(self):
        # Weird / unrecognized input falls through to default.
        # Parse errors still ask (unchanged by design).
        result = _analyze("foo && bar baz", default="deny")
        # `bar baz` is unmatched -> deny; combined -> deny.
        assert result.action == "deny"


class TestDefaultAllow:
    """With `set default allow`, unmatched commands are approved."""

    def test_unknown_command_allows(self):
        assert _analyze("somecmd foo", default="allow").action == "allow"

    def test_deny_rule_still_denies(self):
        rules = [Rule(decision="deny", pattern="somecmd *")]
        assert _analyze("somecmd foo", default="allow", rules=rules).action == "deny"

    def test_explicit_ask_rule_still_asks(self):
        rules = [Rule(decision="ask", pattern="somecmd *")]
        assert _analyze("somecmd foo", default="allow", rules=rules).action == "ask"
