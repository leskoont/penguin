"""Tests for penguin.runner - subprocess execution and retry logic."""
import pytest

from penguin.runner import is_permanent


class TestIsPermanent:
    """Test is_permanent() error classification logic."""

    def test_curl_couldnt_resolve_host_is_permanent(self):
        """curl exit code 6 (CURLE_COULDNT_RESOLVE_HOST) is permanent."""
        assert is_permanent("curl", 6, "Could not resolve host") is True

    def test_curl_other_error_is_not_permanent(self):
        """curl with other return codes are not permanent."""
        assert is_permanent("curl", 7, "Failed to connect") is False
        assert is_permanent("curl", 28, "Timeout") is False

    def test_flag_provided_but_not_defined_is_permanent(self):
        """Flag mismatch errors are permanent."""
        err = "Error: flag provided but not defined: -foobar"
        assert is_permanent("amass", 1, err) is True

    def test_unknown_flag_is_permanent(self):
        """Unknown flag errors are permanent."""
        err = "Error: unknown shorthand flag '-x' in -xvf"
        assert is_permanent("puredns", 1, err) is True

    def test_unrecognized_arguments_is_permanent(self):
        """Unrecognized argument errors are permanent."""
        err = "error: unrecognized arguments: --foobar"
        assert is_permanent("katana", 1, err) is True

    def test_executable_file_not_found_is_permanent(self):
        """Missing binary in PATH is permanent."""
        err = "executable file not found in $PATH"
        assert is_permanent("nonexistent", 127, err) is True

    def test_modulenotfounderror_is_permanent(self):
        """Missing Python module is permanent."""
        err = "ModuleNotFoundError: No module named 'requests'"
        assert is_permanent("python", 1, err) is True

    def test_traceback_is_permanent(self):
        """Python tracebacks are permanent."""
        err = "Traceback (most recent call last):\n  File ...\nError"
        assert is_permanent("python", 1, err) is True

    def test_no_such_file_or_directory_is_permanent(self):
        """Missing file/wordlist errors are permanent."""
        err = "no such file or directory: /path/to/missing/wordlist.txt"
        assert is_permanent("puredns", 1, err) is True

    def test_does_not_support_reflection_api_is_permanent(self):
        """Missing gRPC reflection is permanent."""
        err = "rpc error: code = Unimplemented desc = the server does not support the reflection api"
        assert is_permanent("grpcurl", 1, err) is True

    def test_case_insensitive_matching(self):
        """Error matching is case-insensitive."""
        err = "MODULENOTFOUNDERROR: No module named 'yaml'"
        assert is_permanent("python", 1, err) is True

        err_mixed = "ExecutaBLE FILE NOT FOUND IN $PATH"
        assert is_permanent("tool", 127, err_mixed) is True

    def test_network_error_not_permanent(self):
        """Generic network errors are not permanent (transient)."""
        err = "connection refused"
        assert is_permanent("curl", 7, err) is False

    def test_timeout_not_permanent(self):
        """Timeouts are not permanent (retry may help)."""
        err = "timeout"
        assert is_permanent("curl", 28, err) is False

    def test_empty_error_not_permanent(self):
        """Empty error string is not permanent."""
        assert is_permanent("tool", 1, "") is False

    def test_random_error_not_permanent(self):
        """Random errors without keywords are not permanent."""
        err = "Something went wrong somewhere"
        assert is_permanent("tool", 1, err) is False
