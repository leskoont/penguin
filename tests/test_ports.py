"""Tests for penguin.tools.ports open-port parsers.

masscan and nmap always write their output file even with zero open ports, so
block3 must parse real hits rather than treat the file's existence as an open
database. These lock the parsers in.
"""
from penguin.tools import ports as pt


def test_parse_masscan_open(tmp_path):
    out = tmp_path / "m.txt"
    out.write_text(
        "#masscan\n"
        "open tcp 6379 1.2.3.4 1620000000\n"
        "open tcp 27017 1.2.3.5 1620000000\n"
        "open tcp 6379 1.2.3.4 1620000001\n"   # dup
        "# end\n",
        encoding="utf-8",
    )
    assert pt.parse_masscan_open(out) == ["1.2.3.4:6379", "1.2.3.5:27017"]


def test_parse_masscan_empty_file_is_no_hits(tmp_path):
    out = tmp_path / "m.txt"
    out.write_text("#masscan 1.3.2\n# end\n", encoding="utf-8")   # clean scan
    assert pt.parse_masscan_open(out) == []
    assert pt.parse_masscan_open(tmp_path / "nope.txt") == []


def test_parse_nmap_open(tmp_path):
    out = tmp_path / "n.txt"
    out.write_text(
        "Nmap scan report for db.ex.com (1.2.3.4)\n"
        "PORT      STATE  SERVICE\n"
        "6379/tcp  open   redis\n"
        "3306/tcp  closed mysql\n"
        "Nmap scan report for 5.6.7.8\n"
        "27017/tcp open   mongodb\n"
        "8080/tcp  filtered http\n",
        encoding="utf-8",
    )
    assert pt.parse_nmap_open(out) == ["db.ex.com:6379", "5.6.7.8:27017"]


def test_parse_nmap_no_open_ports(tmp_path):
    out = tmp_path / "n.txt"
    out.write_text(
        "Nmap scan report for safe.ex.com\n"
        "All 23 scanned ports on safe.ex.com are closed\n",
        encoding="utf-8",
    )
    assert pt.parse_nmap_open(out) == []
    assert pt.parse_nmap_open(tmp_path / "nope.txt") == []
