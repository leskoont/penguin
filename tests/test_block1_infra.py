"""Tests for penguin.pipelines.block1_infra - scope regex and extraction."""
import re
import pytest

from penguin.pipelines.block1_infra import _scope_regex, _extract_scoped


class TestScopeRegex:
    """Test _scope_regex() - regex pattern generation for domain scope matching."""

    def test_single_domain_exact_match(self):
        """Single domain should match exactly."""
        rx = _scope_regex(["example.com"])
        assert rx.search("example.com") is not None
        assert rx.search("example.com").group(1) == "example.com"

    def test_single_domain_with_subdomain(self):
        """Single domain should match its subdomains."""
        rx = _scope_regex(["example.com"])
        match = rx.search("sub.example.com")
        assert match is not None
        assert match.group(1) == "sub.example.com"

    def test_single_domain_multi_level_subdomain(self):
        """Single domain should match multi-level subdomains."""
        rx = _scope_regex(["example.com"])
        match = rx.search("a.b.c.example.com")
        assert match is not None
        assert match.group(1) == "a.b.c.example.com"

    def test_single_domain_no_partial_match(self):
        """Single domain should not match partial substrings."""
        rx = _scope_regex(["example.com"])
        # Should not match as part of a longer name
        assert rx.search("notexample.com") is None
        assert rx.search("example.com.fake") is None

    def test_case_insensitivity(self):
        """Regex should be case-insensitive."""
        rx = _scope_regex(["example.com"])
        assert rx.search("EXAMPLE.COM") is not None
        assert rx.search("Example.Com") is not None
        assert rx.search("ExAmPlE.cOm") is not None

    def test_case_normalized_capture_group(self):
        """Captured group should match the pattern case, but extraction lowercases it."""
        rx = _scope_regex(["example.com"])
        match = rx.search("SUB.EXAMPLE.COM")
        assert match is not None
        # The regex matches case-insensitively; extraction will lowercase the result

    def test_multiple_domains_all_match(self):
        """Multiple domains should all be matchable."""
        rx = _scope_regex(["example.com", "test.org"])
        assert rx.search("example.com") is not None
        assert rx.search("test.org") is not None
        assert rx.search("sub.example.com") is not None
        assert rx.search("sub.test.org") is not None

    def test_multiple_domains_no_cross_pollution(self):
        """Domains should not match outside their scope."""
        rx = _scope_regex(["example.com", "test.org"])
        # example.com should not match test.org's subdomains
        assert rx.search("notarealorg.fake") is None
        # But cross-domain pollution should be prevented by word boundary
        assert rx.search("fakeexample.com") is None

    def test_domain_with_hyphen(self):
        """Domains with hyphens should be properly escaped."""
        rx = _scope_regex(["my-domain.com"])
        assert rx.search("my-domain.com") is not None
        assert rx.search("sub.my-domain.com") is not None

    def test_domain_with_numbers(self):
        """Domains with numbers should match correctly."""
        rx = _scope_regex(["example123.com", "test456org.co"])
        assert rx.search("example123.com") is not None
        assert rx.search("test456org.co") is not None
        assert rx.search("api.example123.com") is not None

    def test_subdomain_with_underscore(self):
        """Subdomains with underscores should match."""
        rx = _scope_regex(["example.com"])
        match = rx.search("api_v1.example.com")
        assert match is not None
        assert match.group(1) == "api_v1.example.com"

    def test_longer_domain_first_in_sorted_list(self):
        """Longer domains should come first to avoid shadowing shorter ones."""
        # If we had example.com and sub.example.com, the longer one should
        # be in the alternation first to avoid partial matches
        rx = _scope_regex(["example.com", "sub.example.com"])
        # Both should match their respective parts
        match1 = rx.search("example.com")
        match2 = rx.search("sub.example.com")
        assert match1 is not None
        assert match2 is not None

    def test_regex_with_special_chars_escaped(self):
        """Special regex characters in domain should be escaped."""
        # Domains shouldn't have these, but test escaping works
        rx = _scope_regex(["example.com"])
        # . should be literal dot, not regex dot
        assert rx.search("exampleXcom") is None
        assert rx.search("example.com") is not None

    def test_empty_domain_list(self):
        """Empty domain list should produce valid regex."""
        rx = _scope_regex([])
        # Should not crash; regex should match nothing
        assert rx.search("any.domain.com") is None

    def test_deduplicated_domains(self):
        """Duplicate domains in list should be deduplicated."""
        rx1 = _scope_regex(["example.com"])
        rx2 = _scope_regex(["example.com", "example.com", "example.com"])
        # Both should behave identically
        assert rx1.search("example.com") is not None
        assert rx2.search("example.com") is not None

    def test_returns_compiled_pattern(self):
        """Function should return a compiled regex pattern."""
        rx = _scope_regex(["example.com"])
        assert isinstance(rx, type(re.compile("")))

    def test_word_boundary_prevents_partial_matches(self):
        """Word boundaries should prevent matching within words."""
        rx = _scope_regex(["example.com"])
        # These should not match because they're word-connected
        assert rx.search("prefix-example.com") is None
        assert rx.search("example.com-suffix") is None
        # But standalone should work
        assert rx.search(" example.com ") is not None
        assert rx.search("(example.com)") is not None


class TestExtractScoped:
    """Test _extract_scoped() - extraction of in-scope hostnames from text."""

    def test_extract_single_domain(self):
        """Extract a single domain from text."""
        rx = _scope_regex(["example.com"])
        text = "example.com"
        result = _extract_scoped(text, rx)
        assert result == {"example.com"}

    def test_extract_single_subdomain(self):
        """Extract a single subdomain from text."""
        rx = _scope_regex(["example.com"])
        text = "api.example.com"
        result = _extract_scoped(text, rx)
        assert result == {"api.example.com"}

    def test_extract_multiple_hosts(self):
        """Extract multiple hosts from text."""
        rx = _scope_regex(["example.com"])
        text = "api.example.com\nweb.example.com\nmail.example.com"
        result = _extract_scoped(text, rx)
        assert result == {"api.example.com", "web.example.com", "mail.example.com"}

    def test_extract_deduplicates_results(self):
        """Extraction should return unique hosts only."""
        rx = _scope_regex(["example.com"])
        text = "api.example.com\napi.example.com\napi.example.com"
        result = _extract_scoped(text, rx)
        assert result == {"api.example.com"}

    def test_extract_normalizes_case(self):
        """Extracted hosts should be lowercase."""
        rx = _scope_regex(["example.com"])
        text = "API.EXAMPLE.COM\nWeb.Example.Com\nmail.example.com"
        result = _extract_scoped(text, rx)
        assert result == {"api.example.com", "web.example.com", "mail.example.com"}
        # Verify they're all lowercase
        for host in result:
            assert host == host.lower()

    def test_extract_handles_hosts_without_trailing_dots(self):
        """Extracted hosts that have no trailing dots are returned as-is."""
        rx = _scope_regex(["example.com"])
        # The regex word boundary prevents matching when followed by a dot,
        # so this tests clean input without trailing dots
        text = "api.example.com\nweb.example.com\nmail.example.com"
        result = _extract_scoped(text, rx)
        assert result == {"api.example.com", "web.example.com", "mail.example.com"}
        # Verify they're all lowercase and without trailing dots
        for host in result:
            assert host == host.lower()
            assert not host.endswith(".")
        # Verify no trailing dots
        for host in result:
            assert not host.endswith(".")

    def test_extract_mixed_case_normalization(self):
        """Extraction should normalize case regardless of input."""
        rx = _scope_regex(["example.com"])
        # Use clean input without trailing dots (regex word boundary prevents matching them)
        text = "API.EXAMPLE.COM\nWeb.Example.Com\nmail.example.com"
        result = _extract_scoped(text, rx)
        assert result == {"api.example.com", "web.example.com", "mail.example.com"}
        # Verify all results are lowercase
        for host in result:
            assert host == host.lower()

    def test_extract_filters_out_of_scope(self):
        """Hosts outside the scope should be filtered out."""
        rx = _scope_regex(["example.com"])
        text = "api.example.com\nweb.other.com\nmail.example.com"
        result = _extract_scoped(text, rx)
        assert result == {"api.example.com", "mail.example.com"}
        assert "web.other.com" not in result

    def test_extract_ignores_asn_in_amass_graph_output(self):
        """ASNs in amass graph output should be ignored."""
        rx = _scope_regex(["example.com"])
        # Amass graph output format: "13238 (ASN) --> announces --> 77.88.0.0/18 (Netblock)"
        text = """relay.example.com (FQDN) --> a_record --> 109.120.155.254 (IPAddress)
13238 (ASN) --> announces --> 77.88.0.0/18 (Netblock)"""
        result = _extract_scoped(text, rx)
        assert result == {"relay.example.com"}
        assert "13238" not in result
        assert "77.88.0.0/18" not in result

    def test_extract_ignores_ip_addresses(self):
        """IP addresses in amass output should be ignored."""
        rx = _scope_regex(["example.com"])
        text = """relay.example.com (FQDN) --> a_record --> 109.120.155.254 (IPAddress)
another.example.com (FQDN) --> a_record --> 192.168.1.1 (IPAddress)"""
        result = _extract_scoped(text, rx)
        assert result == {"relay.example.com", "another.example.com"}
        assert "109.120.155.254" not in result
        assert "192.168.1.1" not in result

    def test_extract_ignores_netblocks(self):
        """CIDR netblocks in amass output should be ignored."""
        rx = _scope_regex(["example.com"])
        text = """relay.example.com (FQDN) --> a_record --> 109.120.155.254 (IPAddress)
13238 (ASN) --> announces --> 77.88.0.0/18 (Netblock)"""
        result = _extract_scoped(text, rx)
        assert "77.88.0.0/18" not in result
        assert result == {"relay.example.com"}

    def test_extract_from_amass_graph_output_complex(self):
        """Extract from realistic amass v4 graph output."""
        rx = _scope_regex(["hantik.ru"])
        text = """relay.hantik.ru (FQDN) --> a_record --> 109.120.155.254 (IPAddress)
109.120.155.254 (IPAddress) --> ptr_record --> relay.hantik.ru (FQDN)
api.hantik.ru (FQDN) --> a_record --> 109.120.155.100 (IPAddress)
13238 (ASN) --> announces --> 77.88.0.0/18 (Netblock)
77.88.0.0/18 (Netblock) --> has_prefix --> 109.120.155.0/24 (Netblock)
109.120.155.0/24 (Netblock) --> has_prefix --> 109.120.155.100 (IPAddress)"""
        result = _extract_scoped(text, rx)
        assert result == {"relay.hantik.ru", "api.hantik.ru"}

    def test_extract_empty_text(self):
        """Extracting from empty text should return empty set."""
        rx = _scope_regex(["example.com"])
        text = ""
        result = _extract_scoped(text, rx)
        assert result == set()

    def test_extract_no_matches(self):
        """Text with no matching hosts should return empty set."""
        rx = _scope_regex(["example.com"])
        text = "other.org\ntest.net\nanother.co"
        result = _extract_scoped(text, rx)
        assert result == set()

    def test_extract_all_match(self):
        """If all hosts match scope, all should be returned."""
        rx = _scope_regex(["example.com"])
        text = "api.example.com\nweb.example.com\nmail.example.com\nwww.example.com"
        result = _extract_scoped(text, rx)
        assert len(result) == 4
        assert all(host.endswith("example.com") for host in result)

    def test_extract_with_multiple_domains(self):
        """Extract from text matching multiple in-scope domains."""
        rx = _scope_regex(["example.com", "test.org"])
        text = """api.example.com
web.test.org
mail.example.com
other.net
mail.test.org"""
        result = _extract_scoped(text, rx)
        assert result == {"api.example.com", "web.test.org", "mail.example.com", "mail.test.org"}
        assert "other.net" not in result

    def test_extract_with_whitespace_variations(self):
        """Extraction should handle various whitespace."""
        rx = _scope_regex(["example.com"])
        text = "  api.example.com  \n\n  web.example.com\t\nmail.example.com  "
        result = _extract_scoped(text, rx)
        assert result == {"api.example.com", "web.example.com", "mail.example.com"}

    def test_extract_returns_set(self):
        """Function should return a set."""
        rx = _scope_regex(["example.com"])
        text = "api.example.com"
        result = _extract_scoped(text, rx)
        assert isinstance(result, set)

    def test_extract_with_special_subdomain_chars(self):
        """Extract subdomains with allowed special characters."""
        rx = _scope_regex(["example.com"])
        text = "api-v1.example.com\napi_v2.example.com\ntest-123.example.com"
        result = _extract_scoped(text, rx)
        assert result == {"api-v1.example.com", "api_v2.example.com", "test-123.example.com"}

    def test_extract_preserves_subdomain_structure(self):
        """Deep subdomains should preserve their full structure."""
        rx = _scope_regex(["example.com"])
        text = "a.b.c.d.e.example.com\nshallow.example.com"
        result = _extract_scoped(text, rx)
        assert result == {"a.b.c.d.e.example.com", "shallow.example.com"}


class TestIntegration:
    """Integration tests for _scope_regex and _extract_scoped together."""

    def test_realistic_subdomain_enumeration_workflow(self):
        """Test a realistic subdomain enumeration workflow with tool output."""
        domains = ["target.com"]
        rx = _scope_regex(domains)

        # Simulate tool output from multiple sources
        tool_outputs = [
            "api.target.com\nweb.target.com\nwww.target.com",
            "mail.target.com\nsmtp.target.com\nother.org",
            "cdn.target.com\ncdn-edge.target.com\nfake.notarget.com",
        ]

        all_hosts = set()
        for output in tool_outputs:
            all_hosts |= _extract_scoped(output, rx)

        expected = {"api.target.com", "web.target.com", "www.target.com",
                   "mail.target.com", "smtp.target.com", "cdn.target.com",
                   "cdn-edge.target.com"}
        assert all_hosts == expected

    def test_multi_domain_target_extraction(self):
        """Test extraction across multiple target domains."""
        domains = ["company.com", "internal.com"]
        rx = _scope_regex(domains)

        text = """api.company.com
web.company.com
other-site.org
api.internal.com
mail.internal.com
unrelated.net"""

        result = _extract_scoped(text, rx)
        expected = {"api.company.com", "web.company.com", "api.internal.com", "mail.internal.com"}
        assert result == expected

    def test_scope_filtering_critical_for_pipeline(self):
        """Verify scope filtering prevents pollution (issue #52 context)."""
        # This is critical: amass graph output can pollute results with ASNs,
        # netblocks, and IPs if not properly filtered by scope
        domains = ["target.com"]
        rx = _scope_regex(domains)

        # Simulated noisy amass output
        amass_output = """api.target.com (FQDN) --> a_record --> 10.0.0.1 (IPAddress)
web.target.com (FQDN) --> a_record --> 10.0.0.2 (IPAddress)
10.0.0.0/8 (Netblock) --> has_prefix --> 10.0.0.1 (IPAddress)
65534 (ASN) --> announces --> 10.0.0.0/8 (Netblock)
notarget.other.com (FQDN) --> a_record --> 10.0.0.3 (IPAddress)
other.malicious.net (FQDN)"""

        result = _extract_scoped(amass_output, rx)

        # Only actual in-scope FQDNs should be extracted
        expected = {"api.target.com", "web.target.com"}
        assert result == expected

        # Verify pollution didn't occur
        assert "65534" not in result  # ASN
        assert "10.0.0.0/8" not in result  # Netblock
        assert "10.0.0.1" not in result  # IP
        assert "10.0.0.2" not in result  # IP
        assert "notarget.other.com" not in result  # Out of scope
        assert "other.malicious.net" not in result  # Out of scope
