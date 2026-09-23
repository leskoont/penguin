"""Tests for penguin.config - configuration loading."""
import os
import tempfile
from pathlib import Path

import pytest

from penguin.config import (
    NET_PROFILES,
    Config,
    apply_net_profile,
    load,
    load_targets,
    resolve_profile_name,
)


class TestLoadConfig:
    """Test load() function for loading config from YAML."""

    def test_load_nonexistent_file_returns_defaults(self):
        """Loading nonexistent file returns default Config."""
        cfg = load("/nonexistent/path/config.yaml")
        assert cfg is not None
        # Default net profile is the conservative "slirp" bundle.
        assert cfg.general.threads == 15
        assert cfg.general.timeout == 30
        assert cfg.stages["infra"] is True
        assert cfg.stages["web"] is True

    def test_load_empty_config_returns_defaults(self):
        """Loading empty YAML file returns defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text("", encoding="utf-8")
            cfg = load(config_file)
            assert cfg.general.threads == 15
            assert cfg.general.timeout == 30

    def test_load_general_config(self):
        """Loading general config section works."""
        yaml_content = """\
general:
  threads: 100
  timeout: 60
  retry_attempts: 5
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(yaml_content, encoding="utf-8")
            cfg = load(config_file)
            assert cfg.general.threads == 100
            assert cfg.general.timeout == 60
            assert cfg.general.retry_attempts == 5

    def test_load_stages_config(self):
        """Loading stages config section works."""
        yaml_content = """\
stages:
  infra: true
  web: false
  cloud_db: true
  elite: false
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(yaml_content, encoding="utf-8")
            cfg = load(config_file)
            assert cfg.stages["infra"] is True
            assert cfg.stages["web"] is False
            assert cfg.stages["cloud_db"] is True
            assert cfg.stages["elite"] is False

    def test_load_tools_config(self):
        """Loading tools config section works."""
        yaml_content = """\
tools:
  amass:
    timeout: 300
  nuclei:
    timeout: 600
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(yaml_content, encoding="utf-8")
            cfg = load(config_file)
            assert cfg.tools["amass"]["timeout"] == 300
            assert cfg.tools["nuclei"]["timeout"] == 600

    def test_load_proxies_config(self):
        """Loading proxies config section works."""
        yaml_content = """\
proxies:
  enabled: false
  validate: true
  timeout: 10
  validate_workers: 100
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(yaml_content, encoding="utf-8")
            cfg = load(config_file)
            assert cfg.proxies.enabled is False
            assert cfg.proxies.validate is True
            assert cfg.proxies.timeout == 10
            assert cfg.proxies.validate_workers == 100

    def test_load_notify_config(self):
        """Loading notify config section works."""
        yaml_content = """\
notify:
  enabled: true
  provider: slack
  webhook_env: MY_WEBHOOK
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(yaml_content, encoding="utf-8")
            cfg = load(config_file)
            assert cfg.notify.enabled is True
            assert cfg.notify.provider == "slack"
            assert cfg.notify.webhook_env == "MY_WEBHOOK"

    def test_load_continuous_config(self):
        """Loading continuous config section works."""
        yaml_content = """\
continuous:
  enabled: true
  interval: 12h
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(yaml_content, encoding="utf-8")
            cfg = load(config_file)
            assert cfg.continuous.enabled is True
            assert cfg.continuous.interval == "12h"

    def test_load_raw_preserves_original_yaml(self):
        """load() preserves raw YAML in cfg.raw."""
        yaml_content = """\
general:
  threads: 75
stages:
  web: false
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text(yaml_content, encoding="utf-8")
            cfg = load(config_file)
            assert "general" in cfg.raw
            assert cfg.raw["general"]["threads"] == 75
            assert cfg.raw["stages"]["web"] is False


class TestLoadTargets:
    """Test load_targets() function for parsing targets.txt."""

    def test_load_nonexistent_file_returns_empty(self):
        """Loading nonexistent file returns empty list."""
        targets = load_targets("/nonexistent/targets.txt")
        assert targets == []

    def test_load_empty_file_returns_empty(self):
        """Loading empty file returns empty list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = Path(tmpdir) / "targets.txt"
            targets_file.write_text("", encoding="utf-8")
            targets = load_targets(targets_file)
            assert targets == []

    def test_load_bare_domain_values(self):
        """Bare domain values get type: domain."""
        content = "example.com\ntest.org\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = Path(tmpdir) / "targets.txt"
            targets_file.write_text(content, encoding="utf-8")
            targets = load_targets(targets_file)
            assert len(targets) == 2
            assert targets[0] == {"type": "domain", "value": "example.com"}
            assert targets[1] == {"type": "domain", "value": "test.org"}

    def test_load_explicit_type_prefixes(self):
        """Explicit type:value prefixes work."""
        content = "domain:example.com\nasn:AS1234\ncidr:192.168.0.0/24\norg:TestCorp\nurl:https://example.com\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = Path(tmpdir) / "targets.txt"
            targets_file.write_text(content, encoding="utf-8")
            targets = load_targets(targets_file)
            assert len(targets) == 5
            assert targets[0] == {"type": "domain", "value": "example.com"}
            assert targets[1] == {"type": "asn", "value": "AS1234"}
            assert targets[2] == {"type": "cidr", "value": "192.168.0.0/24"}
            assert targets[3] == {"type": "org", "value": "TestCorp"}
            assert targets[4] == {"type": "url", "value": "https://example.com"}

    def test_load_ignores_comments(self):
        """Lines starting with # are ignored."""
        content = "# This is a comment\nexample.com\n# Another comment\ntest.org\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = Path(tmpdir) / "targets.txt"
            targets_file.write_text(content, encoding="utf-8")
            targets = load_targets(targets_file)
            assert len(targets) == 2
            assert targets[0]["value"] == "example.com"
            assert targets[1]["value"] == "test.org"

    def test_load_ignores_empty_lines(self):
        """Empty lines are ignored."""
        content = "example.com\n\ntest.org\n\n  \n"
        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = Path(tmpdir) / "targets.txt"
            targets_file.write_text(content, encoding="utf-8")
            targets = load_targets(targets_file)
            assert len(targets) == 2
            assert targets[0]["value"] == "example.com"
            assert targets[1]["value"] == "test.org"

    def test_load_strips_whitespace(self):
        """Whitespace is stripped from values."""
        content = "  example.com  \n   test.org\t\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = Path(tmpdir) / "targets.txt"
            targets_file.write_text(content, encoding="utf-8")
            targets = load_targets(targets_file)
            assert len(targets) == 2
            assert targets[0]["value"] == "example.com"
            assert targets[1]["value"] == "test.org"

    def test_load_unknown_prefix_treated_as_domain(self):
        """Unknown type prefix is treated as bare domain."""
        content = "invalid:example.com\ntest.org\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = Path(tmpdir) / "targets.txt"
            targets_file.write_text(content, encoding="utf-8")
            targets = load_targets(targets_file)
            assert len(targets) == 2
            # "invalid:example.com" has unknown prefix, treated as domain
            assert targets[0] == {"type": "domain", "value": "invalid:example.com"}
            assert targets[1] == {"type": "domain", "value": "test.org"}

    def test_load_mixed_types_and_bare(self):
        """Mix of typed and bare values."""
        content = "example.com\ndomain:test.org\nurl:https://api.example.com\nfoo.bar\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = Path(tmpdir) / "targets.txt"
            targets_file.write_text(content, encoding="utf-8")
            targets = load_targets(targets_file)
            assert len(targets) == 4
            assert targets[0] == {"type": "domain", "value": "example.com"}
            assert targets[1] == {"type": "domain", "value": "test.org"}
            assert targets[2] == {"type": "url", "value": "https://api.example.com"}
            assert targets[3] == {"type": "domain", "value": "foo.bar"}

    def test_load_type_prefix_with_colon_in_value(self):
        """Type prefix with colons in the value (e.g., URLs)."""
        content = "url:https://example.com:8080/path\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = Path(tmpdir) / "targets.txt"
            targets_file.write_text(content, encoding="utf-8")
            targets = load_targets(targets_file)
            assert len(targets) == 1
            assert targets[0]["type"] == "url"
            assert targets[0]["value"] == "https://example.com:8080/path"


class TestNetProfiles:
    """Network profile resolution, application, and precedence."""

    def test_resolve_known_and_aliases(self):
        assert resolve_profile_name("slirp") == "slirp"
        assert resolve_profile_name("MINIMAL") == "minimal"
        assert resolve_profile_name("throttle") == "minimal"
        assert resolve_profile_name("safe") == "slirp"
        assert resolve_profile_name("bridge") == "wsl"

    def test_resolve_unknown_returns_none(self):
        assert resolve_profile_name("nope") is None
        assert resolve_profile_name("") is None
        assert resolve_profile_name(None) is None

    def test_default_profile_reproduces_slirp_values(self):
        cfg = load("/nonexistent/config.yaml")
        assert cfg.general.net_profile == "slirp"
        assert cfg.general.threads == 15
        assert cfg.general.rate_limit == 100
        assert cfg.general.dns_rate_limit == 150
        assert cfg.general.max_parallel_tools == 3
        assert cfg.proxies.validate_workers == 40

    def test_minimal_profile_lowers_all_knobs(self):
        cfg = load("/nonexistent/config.yaml", profile="minimal")
        assert cfg.general.net_profile == "minimal"
        assert cfg.general.threads == 8
        assert cfg.general.max_parallel_tools == 1
        assert cfg.general.max_global_concurrency == 8
        assert cfg.proxies.validate_workers == 8

    def test_throttle_alias_maps_to_minimal(self):
        cfg = load("/nonexistent/config.yaml", profile="throttle")
        assert cfg.general.net_profile == "minimal"
        assert cfg.general.threads == 8

    def test_vps_profile_is_aggressive(self):
        cfg = load("/nonexistent/config.yaml", profile="vps")
        assert cfg.general.threads == 50
        assert cfg.general.dns_rate_limit == 1000
        assert cfg.general.max_parallel_tools == 8

    def test_unknown_profile_keeps_defaults_no_crash(self):
        cfg = load("/nonexistent/config.yaml", profile="bogus")
        # label recorded but values stay at defaults
        assert cfg.general.net_profile == "bogus"
        assert cfg.general.threads == 15

    def test_explicit_yaml_knob_overrides_profile(self):
        yaml_content = "general:\n  net_profile: vps\n  threads: 7\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            cf = Path(tmpdir) / "config.yaml"
            cf.write_text(yaml_content, encoding="utf-8")
            cfg = load(cf)
            assert cfg.general.net_profile == "vps"
            assert cfg.general.threads == 7          # pinned wins
            assert cfg.general.rate_limit == 300     # from vps profile

    def test_arg_beats_env_beats_yaml(self):
        yaml_content = "general:\n  net_profile: vps\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            cf = Path(tmpdir) / "config.yaml"
            cf.write_text(yaml_content, encoding="utf-8")
            old = os.environ.get("PENGUIN_NET_PROFILE")
            try:
                os.environ["PENGUIN_NET_PROFILE"] = "minimal"
                # env beats yaml
                cfg = load(cf)
                assert cfg.general.net_profile == "minimal"
                # explicit arg beats env
                cfg2 = load(cf, profile="wsl")
                assert cfg2.general.net_profile == "wsl"
            finally:
                if old is None:
                    os.environ.pop("PENGUIN_NET_PROFILE", None)
                else:
                    os.environ["PENGUIN_NET_PROFILE"] = old

    def test_apply_net_profile_direct(self):
        cfg = Config()
        assert apply_net_profile(cfg, "minimal") is True
        assert cfg.general.threads == 8
        assert apply_net_profile(cfg, "bogus") is False


class TestClampWorkers:
    """Global concurrency budget clamp."""

    def test_clamp_binds_to_ceiling(self):
        cfg = Config()
        cfg.general.max_global_concurrency = 8
        assert cfg.general.clamp_workers(40) == 8
        assert cfg.general.clamp_workers(3) == 3

    def test_clamp_zero_ceiling_disables(self):
        cfg = Config()
        cfg.general.max_global_concurrency = 0
        assert cfg.general.clamp_workers(40) == 40

    def test_clamp_never_below_one(self):
        cfg = Config()
        cfg.general.max_global_concurrency = 8
        assert cfg.general.clamp_workers(0) == 1
        assert cfg.general.clamp_workers(-5) == 1

    def test_every_profile_has_required_keys(self):
        for name, prof in NET_PROFILES.items():
            g = prof.get("general", {})
            assert "max_global_concurrency" in g, name
            assert "max_parallel_tools" in g, name
