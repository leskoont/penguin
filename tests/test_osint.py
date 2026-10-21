"""Tests for penguin.tools.osint - pure parsing of the OSINT aggregator fetches."""
from penguin.tools import osint as O


class TestHostsUnder:
    def test_pulls_in_scope_hosts_from_markup(self):
        html = '<tr><td>api.ex.com</td><td>dev.ex.com</td><td>other.org</td></tr>'
        assert O._hosts_under(html, "ex.com") == {"api.ex.com", "dev.ex.com"}

    def test_apex_not_matched_but_nested_is(self):
        # the regex requires at least one label + dot, so the bare apex is not
        # extracted (RapidDNS lists subdomains only) -- nested hosts are.
        assert O._hosts_under("a.b.ex.com and ex.com", "ex.com") == {"a.b.ex.com"}

    def test_no_partial_suffix_matches(self):
        # "notex.com" must not match domain "ex.com" (the (?i) findall is
        # anchored on ".ex.com" via the dot in the group)
        assert O._hosts_under("notex.com", "ex.com") == set()

    def test_strips_trailing_dot(self):
        assert O._hosts_under("api.ex.com.", "ex.com") == {"api.ex.com"}


class TestParseOtx:
    def test_hostnames(self):
        body = '{"passive_dns": [{"hostname": "API.Ex.com"}, {"hostname": "*.dev.ex.com"}]}'
        assert O.parse_otx(body) == ["api.ex.com", "dev.ex.com"]

    def test_malformed_returns_empty(self):
        assert O.parse_otx("not json") == []
        assert O.parse_otx('{"passive_dns": null}') == []
        assert O.parse_otx('{"passive_dns": [{"nope": 1}]}') == []


class TestParseHackerTarget:
    def test_csv_lines(self):
        body = "www.ex.com,1.2.3.4\napi.ex.com,5.6.7.8\n"
        assert O.parse_hackertarget(body) == ["api.ex.com", "www.ex.com"]

    def test_quota_error_text_yields_nothing(self):
        # the free API answers with a sentence once its daily quota is spent
        assert O.parse_hackertarget("API count exceeded. If you need more queries") == []

    def test_non_host_lines_skipped(self):
        assert O.parse_hackertarget("justtext\nmore\n") == []


class TestParseUrlscan:
    def test_task_and_page_domains(self):
        body = ('{"results": [{"task": {"domain": "api.ex.com"},'
                ' "page": {"domain": "www.ex.com"}},'
                ' {"task": {"domain": "out.com"}, "page": {"domain": "other.org"}}]}')
        assert O.parse_urlscan(body, "ex.com") == ["api.ex.com", "www.ex.com"]

    def test_malformed(self):
        assert O.parse_urlscan("{}", "ex.com") == []
        assert O.parse_urlscan("junk", "ex.com") == []


class TestParseRapiddns:
    def test_html_rows(self):
        html = "<td>sub.ex.com</td><td>IP</td>"
        assert O.parse_rapiddns(html, "ex.com") == ["sub.ex.com"]


class TestParseWaybackCdx:
    def test_only_urls(self):
        body = "https://ex.com/a\nnot a url\nhttp://ex.com/b?q=1\n"
        assert O.parse_wayback_cdx(body) == ["http://ex.com/b?q=1", "https://ex.com/a"]
