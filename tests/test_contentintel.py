"""Tests for penguin.tools.contentintel - classify + robots/sitemap mining."""
from penguin.tools import contentintel as ci


class TestClassify:
    def test_env_true_positive(self):
        assert ci.classify("/.env", 200, "APP_KEY=secret\nDB_PASS=x") == "exposed_config"

    def test_env_soft_404_rejected(self):
        # 200 but body is an HTML login page with no signature -> not exposed
        assert ci.classify("/.env", 200, "<html><body>Not found</body></html>") is None

    def test_non_200_rejected(self):
        assert ci.classify("/.env", 404, "APP_KEY=secret") is None

    def test_git_config(self):
        assert ci.classify("/.git/config", 200, "[core]\nrepositoryformatversion = 0") == "exposed_config"

    def test_server_status_info(self):
        assert ci.classify("/server-status", 200, "Apache Server Status for x") == "info_disclosure"

    def test_actuator_env_config(self):
        assert ci.classify("/actuator/env", 200, '{"propertySources":[]}') == "exposed_config"

    def test_security_txt(self):
        assert ci.classify("/.well-known/security.txt", 200, "Contact: mailto:x@y") == "security_txt"

    def test_unknown_path(self):
        assert ci.classify("/random", 200, "anything") is None


class TestDirectoryListing:
    def test_detects_index_of(self):
        assert ci.is_directory_listing(200, "<title>Index of /uploads</title>") is True

    def test_python_listing(self):
        assert ci.is_directory_listing(200, "Directory listing for /") is True

    def test_normal_page(self):
        assert ci.is_directory_listing(200, "<title>Home</title>") is False

    def test_non_200(self):
        assert ci.is_directory_listing(403, "Index of /") is False


class TestMineRobots:
    def test_extracts_disallow_allow(self):
        txt = "User-agent: *\nDisallow: /admin/\nAllow: /public\nDisallow: /\n"
        got = ci.mine_robots(txt)
        assert "/admin/" in got and "/public" in got
        assert "/" not in got  # root ignored

    def test_dedup(self):
        assert ci.mine_robots("Disallow: /a\nDisallow: /a\n") == ["/a"]

    def test_empty(self):
        assert ci.mine_robots("") == []


class TestMineSitemap:
    def test_extracts_locs(self):
        xml = "<urlset><url><loc>https://x.com/a</loc></url><url><loc>https://x.com/b</loc></url></urlset>"
        assert ci.mine_sitemap(xml) == ["https://x.com/a", "https://x.com/b"]

    def test_dedup_and_empty(self):
        assert ci.mine_sitemap("<loc>u</loc><loc>u</loc>") == ["u"]
        assert ci.mine_sitemap("") == []
