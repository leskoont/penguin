"""Tests for penguin.state - run state store and diff engine."""
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from penguin.config import Config
from penguin.state import RunState, Artifacts, ARTIFACTS


class TestAddLines:
    """Test RunState.add_lines() - deduplication and accumulation."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test artifacts."""
        tmpdir = tempfile.mkdtemp()
        yield tmpdir
        shutil.rmtree(tmpdir)

    @pytest.fixture
    def mock_config(self, temp_dir):
        """Create a mock Config with temp output directory."""
        cfg = Config()
        cfg.general.output_dir = temp_dir
        return cfg

    @pytest.fixture
    def run_state(self, mock_config):
        """Create a RunState for testing."""
        return RunState(mock_config, "example.com")

    def test_add_lines_single_line(self, run_state):
        """Adding a single line works."""
        count = run_state.add_lines("subdomains.txt", ["subdomain1.example.com"])
        assert count == 1
        # Check run file was created
        run_file = run_state.run_dir / "subdomains.txt"
        assert run_file.exists()
        lines = run_file.read_text(encoding="utf-8").strip().split("\n")
        assert "subdomain1.example.com" in lines

    def test_add_lines_multiple_lines(self, run_state):
        """Adding multiple lines works."""
        subdomains = ["sub1.example.com", "sub2.example.com", "sub3.example.com"]
        count = run_state.add_lines("subdomains.txt", subdomains)
        assert count == 3
        run_file = run_state.run_dir / "subdomains.txt"
        lines = set(run_file.read_text(encoding="utf-8").strip().split("\n"))
        assert all(s in lines for s in subdomains)

    def test_add_lines_deduplicates_within_run(self, run_state):
        """Duplicate lines within a single call are deduplicated."""
        subdomains = ["sub1.example.com", "sub1.example.com", "sub2.example.com"]
        count = run_state.add_lines("subdomains.txt", subdomains)
        assert count == 2  # Only 2 unique lines
        run_file = run_state.run_dir / "subdomains.txt"
        lines = run_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2

    def test_add_lines_normalizes_whitespace(self, run_state):
        """Leading/trailing whitespace is stripped."""
        subdomains = ["  sub1.example.com  ", "\tsub2.example.com\n"]
        count = run_state.add_lines("subdomains.txt", subdomains)
        assert count == 2
        run_file = run_state.run_dir / "subdomains.txt"
        content = run_file.read_text(encoding="utf-8")
        assert "sub1.example.com" in content
        assert "sub2.example.com" in content

    def test_add_lines_removes_trailing_slashes(self, run_state):
        """Trailing slashes are stripped (normalization)."""
        subdomains = ["sub1.example.com/", "sub2.example.com"]
        count = run_state.add_lines("subdomains.txt", subdomains)
        assert count == 2
        run_file = run_state.run_dir / "subdomains.txt"
        lines = run_file.read_text(encoding="utf-8").strip().split("\n")
        assert "sub1.example.com" in lines
        assert "sub1.example.com/" not in lines

    def test_add_lines_ignores_empty_strings(self, run_state):
        """Empty strings and None are ignored."""
        subdomains = ["sub1.example.com", "", None, "sub2.example.com", "   "]
        count = run_state.add_lines("subdomains.txt", subdomains)
        assert count == 2
        run_file = run_state.run_dir / "subdomains.txt"
        lines = run_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2

    def test_add_lines_accumulates_across_calls(self, run_state):
        """Multiple calls to add_lines accumulate into the run file."""
        run_state.add_lines("subdomains.txt", ["sub1.example.com"])
        run_state.add_lines("subdomains.txt", ["sub2.example.com"])
        run_state.add_lines("subdomains.txt", ["sub3.example.com"])

        run_file = run_state.run_dir / "subdomains.txt"
        lines = set(run_file.read_text(encoding="utf-8").strip().split("\n"))
        assert len(lines) == 3
        assert all(f"sub{i}.example.com" in lines for i in (1, 2, 3))

    def test_add_lines_accumulates_in_base_dir(self, run_state):
        """With accumulate=True, lines are added to base dir accumulator."""
        count = run_state.add_lines("all_subdomains.txt", ["sub1.example.com"], accumulate=True)
        assert count == 1
        # Check accumulator in base dir
        acc_file = run_state.base / "all_subdomains.txt"
        assert acc_file.exists()
        lines = acc_file.read_text(encoding="utf-8").strip().split("\n")
        assert "sub1.example.com" in lines

    def test_add_lines_new_count_excludes_existing_in_accumulator(self, run_state):
        """New lines count excludes lines already in the accumulator."""
        # First run: add to accumulator
        count1 = run_state.add_lines("all_subs.txt", ["sub1.com", "sub2.com"], accumulate=True)
        assert count1 == 2

        # Second run: reuse some of the same lines
        # Create a new RunState to simulate a fresh run
        run_state2 = RunState(run_state.cfg, "example.com")
        count2 = run_state2.add_lines("all_subs.txt", ["sub1.com", "sub3.com"], accumulate=True)
        # Only sub3.com is new relative to accumulator
        assert count2 == 1

    def test_add_lines_no_accumulate_skips_base_dir(self, run_state):
        """With accumulate=False, nothing is written to base dir."""
        run_state.add_lines("temp.txt", ["item1", "item2"], accumulate=False)
        # Only run file should exist
        assert (run_state.run_dir / "temp.txt").exists()
        assert not (run_state.base / "temp.txt").exists()

    def test_add_lines_sorted_output(self, run_state):
        """Lines are written in sorted order."""
        subdomains = ["zebra.com", "alpha.com", "beta.com"]
        run_state.add_lines("subdomains.txt", subdomains)
        run_file = run_state.run_dir / "subdomains.txt"
        lines = run_file.read_text(encoding="utf-8").strip().split("\n")
        assert lines == ["alpha.com", "beta.com", "zebra.com"]


class TestDiffEngine:
    """Test the diff engine - diff_against_previous and write_diff_files."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test artifacts."""
        tmpdir = tempfile.mkdtemp()
        yield tmpdir
        shutil.rmtree(tmpdir)

    @pytest.fixture
    def mock_config(self, temp_dir):
        """Create a mock Config with temp output directory."""
        cfg = Config()
        cfg.general.output_dir = temp_dir
        return cfg

    def test_diff_against_previous_no_history(self, mock_config):
        """Diff against previous with no history."""
        run_state = RunState(mock_config, "example.com")
        run_state.add_lines("subdomains.txt", ["sub1.com", "sub2.com"])

        diff = run_state.diff_against_previous("subdomains.txt")
        assert diff["current_count"] == 2
        assert diff["previous_count"] == 0
        assert len(diff["new"]) == 2
        assert diff["removed"] == []

    def test_diff_against_previous_all_new(self, mock_config):
        """All items are new compared to previous run."""
        # First run
        run_state1 = RunState(mock_config, "example.com")
        run_state1.add_lines("subdomains.txt", ["sub1.com", "sub2.com"], accumulate=False)
        run_state1.archive()

        # Second run with all new items (replacing the previous set)
        # Manually set a different run_id to avoid collision (workaround for bug #53)
        run_state2 = RunState(mock_config, "example.com")
        run_state2.run_id = "20260715_000001"
        run_state2.run_dir = run_state2.base / run_state2.run_id
        run_state2.run_dir.mkdir(parents=True, exist_ok=True)
        run_state2.add_lines("subdomains.txt", ["sub3.com", "sub4.com", "sub5.com"], accumulate=False)

        diff = run_state2.diff_against_previous("subdomains.txt")
        assert diff["current_count"] == 3
        assert diff["previous_count"] == 2
        assert set(diff["new"]) == {"sub3.com", "sub4.com", "sub5.com"}
        assert set(diff["removed"]) == {"sub1.com", "sub2.com"}

    def test_diff_against_previous_all_removed(self, mock_config):
        """All items are removed."""
        # First run
        run_state1 = RunState(mock_config, "example.com")
        run_state1.add_lines("subdomains.txt", ["sub1.com", "sub2.com"])
        run_state1.archive()

        # Second run with no items
        # Manually set a different run_id to avoid collision (workaround for bug #53)
        run_state2 = RunState(mock_config, "example.com")
        run_state2.run_id = "20260715_000002"
        run_state2.run_dir = run_state2.base / run_state2.run_id
        run_state2.run_dir.mkdir(parents=True, exist_ok=True)
        run_state2.add_lines("subdomains.txt", [], accumulate=False)

        diff = run_state2.diff_against_previous("subdomains.txt")
        assert diff["current_count"] == 0
        assert diff["previous_count"] == 2
        assert diff["new"] == []
        assert set(diff["removed"]) == {"sub1.com", "sub2.com"}

    def test_diff_against_previous_overlap(self, mock_config):
        """Mix of new, removed, and unchanged items."""
        # First run
        run_state1 = RunState(mock_config, "example.com")
        run_state1.add_lines("subdomains.txt", ["sub1.com", "sub2.com", "sub3.com"])
        run_state1.archive()

        # Second run with some overlap
        # Manually set a different run_id to avoid collision (workaround for bug #53)
        run_state2 = RunState(mock_config, "example.com")
        run_state2.run_id = "20260715_000003"
        run_state2.run_dir = run_state2.base / run_state2.run_id
        run_state2.run_dir.mkdir(parents=True, exist_ok=True)
        run_state2.add_lines("subdomains.txt", ["sub2.com", "sub3.com", "sub4.com", "sub5.com"], accumulate=False)

        diff = run_state2.diff_against_previous("subdomains.txt")
        assert diff["current_count"] == 4
        assert diff["previous_count"] == 3
        assert set(diff["new"]) == {"sub4.com", "sub5.com"}
        assert set(diff["removed"]) == {"sub1.com"}

    def test_diff_against_previous_finds_latest_history(self, mock_config):
        """Diff finds the most recent history file, not the oldest."""
        # Run 1
        run_state1 = RunState(mock_config, "example.com")
        run_state1.run_id = "20260715_000010"
        run_state1.run_dir = run_state1.base / run_state1.run_id
        run_state1.run_dir.mkdir(parents=True, exist_ok=True)
        run_state1.add_lines("subdomains.txt", ["sub1.com"], accumulate=False)
        run_state1.archive()

        # Run 2
        run_state2 = RunState(mock_config, "example.com")
        run_state2.run_id = "20260715_000020"
        run_state2.run_dir = run_state2.base / run_state2.run_id
        run_state2.run_dir.mkdir(parents=True, exist_ok=True)
        run_state2.add_lines("subdomains.txt", ["sub1.com", "sub2.com"], accumulate=False)
        run_state2.archive()

        # Run 3 - should diff against run 2's history, not run 1's
        run_state3 = RunState(mock_config, "example.com")
        run_state3.run_id = "20260715_000030"
        run_state3.run_dir = run_state3.base / run_state3.run_id
        run_state3.run_dir.mkdir(parents=True, exist_ok=True)
        run_state3.add_lines("subdomains.txt", ["sub1.com", "sub2.com", "sub3.com"], accumulate=False)

        diff = run_state3.diff_against_previous("subdomains.txt")
        assert set(diff["new"]) == {"sub3.com"}
        assert diff["removed"] == []

    def test_write_diff_files_creates_new_file(self, mock_config):
        """write_diff_files creates new_*.txt for new items."""
        # First run
        run_state1 = RunState(mock_config, "example.com")
        run_state1.add_lines("subdomains.txt", ["sub1.com", "sub2.com"])
        run_state1.archive()

        # Second run
        # Manually set a different run_id to avoid collision (workaround for bug #53)
        run_state2 = RunState(mock_config, "example.com")
        run_state2.run_id = "20260715_000040"
        run_state2.run_dir = run_state2.base / run_state2.run_id
        run_state2.run_dir.mkdir(parents=True, exist_ok=True)
        run_state2.add_lines("subdomains.txt", ["sub1.com", "sub3.com"], accumulate=False)

        run_state2.write_diff_files("subdomains.txt")
        new_file = run_state2.run_dir / "new_subdomains.txt"
        assert new_file.exists()
        content = new_file.read_text(encoding="utf-8")
        assert "sub3.com" in content

    def test_write_diff_files_creates_removed_file(self, mock_config):
        """write_diff_files creates removed_*.txt for removed items."""
        # First run
        run_state1 = RunState(mock_config, "example.com")
        run_state1.add_lines("subdomains.txt", ["sub1.com", "sub2.com", "sub3.com"])
        run_state1.archive()

        # Second run with fewer items
        # Manually set a different run_id to avoid collision (workaround for bug #53)
        run_state2 = RunState(mock_config, "example.com")
        run_state2.run_id = "20260715_000050"
        run_state2.run_dir = run_state2.base / run_state2.run_id
        run_state2.run_dir.mkdir(parents=True, exist_ok=True)
        run_state2.add_lines("subdomains.txt", ["sub1.com"], accumulate=False)

        run_state2.write_diff_files("subdomains.txt")
        removed_file = run_state2.run_dir / "removed_subdomains.txt"
        assert removed_file.exists()
        content = removed_file.read_text(encoding="utf-8")
        assert "sub2.com" in content
        assert "sub3.com" in content

    def test_write_diff_files_no_new_no_file(self, mock_config):
        """write_diff_files does not create new_*.txt if no new items."""
        # First run
        run_state1 = RunState(mock_config, "example.com")
        run_state1.add_lines("subdomains.txt", ["sub1.com", "sub2.com"])
        run_state1.archive()

        # Second run with same items
        # Manually set a different run_id to avoid collision (workaround for bug #53)
        run_state2 = RunState(mock_config, "example.com")
        run_state2.run_id = "20260715_000060"
        run_state2.run_dir = run_state2.base / run_state2.run_id
        run_state2.run_dir.mkdir(parents=True, exist_ok=True)
        run_state2.add_lines("subdomains.txt", ["sub1.com", "sub2.com"], accumulate=False)

        run_state2.write_diff_files("subdomains.txt")
        new_file = run_state2.run_dir / "new_subdomains.txt"
        assert not new_file.exists()

    def test_write_diff_files_no_removed_no_file(self, mock_config):
        """write_diff_files does not create removed_*.txt if no removed items."""
        # First run
        run_state1 = RunState(mock_config, "example.com")
        run_state1.add_lines("subdomains.txt", ["sub1.com"])
        run_state1.archive()

        # Second run with more items
        # Manually set a different run_id to avoid collision (workaround for bug #53)
        run_state2 = RunState(mock_config, "example.com")
        run_state2.run_id = "20260715_000070"
        run_state2.run_dir = run_state2.base / run_state2.run_id
        run_state2.run_dir.mkdir(parents=True, exist_ok=True)
        run_state2.add_lines("subdomains.txt", ["sub1.com", "sub2.com"], accumulate=False)

        run_state2.write_diff_files("subdomains.txt")
        removed_file = run_state2.run_dir / "removed_subdomains.txt"
        assert not removed_file.exists()


class TestArtifacts:
    """Test the Artifacts registry."""

    def test_artifacts_constants_exist(self):
        """All artifact constants are defined."""
        assert ARTIFACTS.RESOLVED == "resolved.txt"
        assert ARTIFACTS.LIVE_HTTPX_CSV == "live/httpx.csv"
        assert ARTIFACTS.LIVE_HOSTS == "live_hosts.txt"
        assert ARTIFACTS.ALL_SUBDOMAINS == "all_subdomains.txt"
        assert ARTIFACTS.ALL_URLS == "all_urls.txt"
        assert ARTIFACTS.ALL_LIVE_HOSTS == "all_live_hosts.txt"

    def test_artifacts_singleton(self):
        """ARTIFACTS is a singleton."""
        assert isinstance(ARTIFACTS, Artifacts)
