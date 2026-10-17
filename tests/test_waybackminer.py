"""Tests for WaybackMiner. HTTP is mocked - no network access."""
import argparse
import io
import json
import unittest
from unittest import mock

import waybackminer as wm

SAMPLE_CDX = [
    ["timestamp", "original", "statuscode", "mimetype"],
    ["20240101000000", "http://example.com/", "200", "text/html"],
    ["20240102000000", "http://example.com/app.js", "200", "application/javascript"],
    ["20240103000000", "http://example.com/search?q=test", "200", "text/html"],
    ["20240104000000", "http://example.com/backup.sql", "200", "application/sql"],
    ["20240105000000", "http://example.com/app.js", "200", "application/javascript"],  # dup
    ["20240106000000", "http://example.com/old.bak", "404", "text/html"],  # filtered by API
]


def _fake_urlopen(*args, **kwargs):
    payload = json.dumps(SAMPLE_CDX).encode()
    resp = mock.MagicMock()
    resp.read.return_value = payload
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


class TestAnalyze(unittest.TestCase):
    def setUp(self):
        header, *rows = SAMPLE_CDX
        self.entries = [dict(zip(header, r)) for r in rows if r[2] == "200"]

    def test_dedupes_urls(self):
        buckets = wm.analyze(self.entries)
        self.assertEqual(len(buckets["all"]), 4)  # dup app.js counted once

    def test_js_bucket(self):
        buckets = wm.analyze(self.entries)
        self.assertEqual(buckets["js"], ["http://example.com/app.js"])

    def test_params_bucket(self):
        buckets = wm.analyze(self.entries)
        self.assertEqual(buckets["params"], ["http://example.com/search?q=test"])

    def test_interesting_bucket(self):
        buckets = wm.analyze(self.entries)
        self.assertIn("http://example.com/backup.sql", buckets["interesting"])
        self.assertNotIn("http://example.com/", buckets["interesting"])

    def test_sorted(self):
        buckets = wm.analyze(self.entries)
        self.assertEqual(buckets["all"], sorted(buckets["all"]))


class TestFetchCdx(unittest.TestCase):
    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_parses_rows(self, _):
        entries = wm.fetch_cdx("example.com", limit=10)
        self.assertEqual(len(entries), 6)
        self.assertEqual(entries[0]["original"], "http://example.com/")

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_sends_domain_wildcard(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            wm.fetch_cdx("example.com")
            req = m.call_args[0][0]
            self.assertIn("example.com%2F%2A", req.full_url)


class TestCli(unittest.TestCase):
    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_js_only_output(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com", "--js-only"])
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue().strip(), "http://example.com/app.js")

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_params_only_output(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com", "--params-only"])
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue().strip(), "q")

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_params_only_reports_unique_names(self, _):
        entries = [
            {"original": "http://example.com/a?z=1&q=2", "statuscode": "200",
             "mimetype": "text/html"},
            {"original": "http://example.com/b?q=3&a=4", "statuscode": "200",
             "mimetype": "text/html"},
            {"original": "http://example.com/a?z=1&q=2", "statuscode": "200",
             "mimetype": "text/html"},  # dup URL: must not double-count names
        ]
        buckets = wm.analyze(entries)
        self.assertEqual(buckets["param_names"], ["a", "q", "z"])
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets, params_only=True)
        self.assertEqual(buf.getvalue().splitlines(), ["a", "q", "z"])

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_interesting_only_output(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com", "--interesting-only"])
        self.assertEqual(rc, 0)
        # note: the mock skips the API's statuscode filter, so the .bak row
        # with status 404 still shows up here; the real CDX filter removes it
        self.assertEqual(buf.getvalue().splitlines(),
                         ["http://example.com/backup.sql",
                          "http://example.com/old.bak"])

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_interesting_only_is_sorted(self, _):
        entries = [
            {"original": "http://example.com/z.zip", "statuscode": "200",
             "mimetype": "application/zip"},
            {"original": "http://example.com/a.bak", "statuscode": "200",
             "mimetype": "text/plain"},
        ]
        buckets = wm.analyze(entries)
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets, interesting_only=True)
        self.assertEqual(buf.getvalue().splitlines(),
                         ["http://example.com/a.bak", "http://example.com/z.zip"])

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_json_mode_outputs_valid_json(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(set(data), {"all", "js", "params", "param_names",
                                     "interesting", "timeline", "subdomains"})
        self.assertEqual(data["js"], ["http://example.com/app.js"])
        self.assertEqual(data["params"], ["http://example.com/search?q=test"])
        self.assertEqual(data["param_names"], ["q"])
        self.assertIn("http://example.com/backup.sql", data["interesting"])
        self.assertEqual(data["all"], sorted(data["all"]))
        self.assertEqual(data["subdomains"], {"example.com": 5})

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_json_output_flag_writes_json_report(self, _):
        with mock.patch("builtins.open", mock.mock_open()) as m:
            rc = wm.main(["example.com", "--json", "-o", "out.json"])
        self.assertEqual(rc, 0)
        written = "".join(c.args[0] for c in
                          m.return_value.write.call_args_list)
        data = json.loads(written)
        self.assertIn("interesting", data)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_json_conflicts_with_other_modes(self, _):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            with self.assertRaises(SystemExit) as cm:
                wm.main(["example.com", "--json", "--js-only"])
        self.assertEqual(cm.exception.code, 2)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_timeline_first_last_seen(self, _):
        entries = [
            {"original": "http://example.com/app.js", "statuscode": "200",
             "mimetype": "application/javascript", "timestamp": "20240301000000"},
            {"original": "http://example.com/app.js", "statuscode": "200",
             "mimetype": "application/javascript", "timestamp": "20240101000000"},
            {"original": "http://example.com/app.js", "statuscode": "200",
             "mimetype": "application/javascript", "timestamp": "20240601000000"},
        ]
        buckets = wm.analyze(entries)
        self.assertEqual(buckets["timeline"]["http://example.com/app.js"],
                         {"first_seen": "20240101000000",
                          "last_seen": "20240601000000"})
        # dupes must not re-add to the url buckets
        self.assertEqual(buckets["all"], ["http://example.com/app.js"])

    def test_timeline_missing_timestamps(self):
        entries = [
            {"original": "http://example.com/a", "statuscode": "200",
             "mimetype": "text/html"},  # no timestamp key at all
            {"original": "http://example.com/b", "statuscode": "200",
             "mimetype": "text/html", "timestamp": "20240501000000"},
        ]
        buckets = wm.analyze(entries)
        self.assertEqual(buckets["timeline"]["http://example.com/a"],
                         {"first_seen": None, "last_seen": None})
        self.assertIsNone(wm.capture_window({}))
        # mixed: None entries are skipped when computing the window
        self.assertEqual(wm.capture_window(buckets["timeline"]),
                         ("20240501000000", "20240501000000"))

    def test_timeline_sorted_by_url(self):
        entries = [
            {"original": "http://example.com/z", "statuscode": "200",
             "mimetype": "text/html", "timestamp": "20240101000000"},
            {"original": "http://example.com/a", "statuscode": "200",
             "mimetype": "text/html", "timestamp": "20240201000000"},
        ]
        buckets = wm.analyze(entries)
        self.assertEqual(list(buckets["timeline"]),
                         ["http://example.com/a", "http://example.com/z"])

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_summary_shows_capture_window(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com"])
        self.assertEqual(rc, 0)
        self.assertIn("Capture window: 20240101000000 .. 20240106000000",
                      buf.getvalue())

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_summary_counts(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("Archived URLs : 5", out)  # all rows incl. the 404 one
        self.assertIn("JS files      : 1", out)


class TestIncludeStatus(unittest.TestCase):
    def test_parse_single(self):
        self.assertEqual(wm.parse_statuses("200"), [200])

    def test_parse_multiple_sorted_unique(self):
        self.assertEqual(wm.parse_statuses("403, 301,403"), [301, 403])

    def test_parse_rejects_non_numeric(self):
        import argparse
        with self.assertRaises(argparse.ArgumentTypeError):
            wm.parse_statuses("abc")

    def test_parse_rejects_out_of_range(self):
        import argparse
        for bad in ("99", "600", "0", "9999"):
            with self.assertRaises(argparse.ArgumentTypeError):
                wm.parse_statuses(bad)

    def test_parse_rejects_empty(self):
        import argparse
        with self.assertRaises(argparse.ArgumentTypeError):
            wm.parse_statuses("")

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_default_filter_is_status_200(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            wm.fetch_cdx("example.com")
            req = m.call_args[0][0]
            self.assertIn("filter=statuscode%3A200", req.full_url)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_multiple_statuses_or_filter(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            wm.fetch_cdx("example.com", statuses=[301, 403])
            req = m.call_args[0][0]
            self.assertIn("filter=statuscode%3A%28301%7C403%29", req.full_url)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_flag_flows_through(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = wm.main(["example.com", "--include-status", "301,403"])
            self.assertEqual(rc, 0)
            req = m.call_args[0][0]
            self.assertIn("filter=statuscode%3A%28301%7C403%29", req.full_url)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_rejects_bad_status(self, _):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            with self.assertRaises(SystemExit) as cm:
                wm.main(["example.com", "--include-status", "abc"])
        self.assertEqual(cm.exception.code, 2)


class TestSubdomainRollup(unittest.TestCase):
    ENTRIES = [
        {"original": "http://example.com/a", "statuscode": "200",
         "mimetype": "text/html"},
        {"original": "http://blog.example.com/p", "statuscode": "200",
         "mimetype": "text/html"},
        {"original": "http://blog.example.com/q", "statuscode": "200",
         "mimetype": "text/html"},
        {"original": "http://shop.example.com/", "statuscode": "200",
         "mimetype": "text/html"},
        {"original": "http://blog.example.com/p", "statuscode": "200",
         "mimetype": "text/html"},  # dup: counted once
        {"original": "HTTP://EXAMPLE.COM:8080/up", "statuscode": "200",
         "mimetype": "text/html"},  # host normalized: port stripped, lowercased
        {"original": "not a url at all", "statuscode": "200",
         "mimetype": "text/html"},  # no host: skipped from rollup
        {"original": "", "statuscode": "200",
         "mimetype": "text/html"},  # empty: skipped entirely
    ]

    def test_counts_deduped_urls_per_host(self):
        buckets = wm.analyze(self.ENTRIES)
        self.assertEqual(buckets["subdomains"],
                         {"blog.example.com": 2, "example.com": 2,
                          "shop.example.com": 1})

    def test_sorted_by_count_then_host(self):
        buckets = wm.analyze(self.ENTRIES)
        self.assertEqual(list(buckets["subdomains"]),
                         ["blog.example.com", "example.com",
                          "shop.example.com"])

    def test_empty_entries_gives_empty_rollup(self):
        self.assertEqual(wm.analyze([])["subdomains"], {})

    def test_subdomains_only_output(self):
        buckets = wm.analyze(self.ENTRIES)
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets, subdomains_only=True)
        self.assertEqual(buf.getvalue().splitlines(),
                         ["blog.example.com: 2", "example.com: 2",
                          "shop.example.com: 1"])

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_summary_shows_subdomain_count(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com"])
        self.assertEqual(rc, 0)
        self.assertIn("Subdomains    : 1", buf.getvalue())

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_subdomain_section_lists_top_hosts(self, _):
        entries = [
            {"original": f"http://sub{i}.example.com/x", "statuscode": "200",
             "mimetype": "text/html"}
            for i in range(25)
        ] + [
            {"original": "http://example.com/a", "statuscode": "200",
             "mimetype": "text/html"},
            {"original": "http://example.com/b", "statuscode": "200",
             "mimetype": "text/html"},
        ]
        buckets = wm.analyze(entries)
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets)
        out = buf.getvalue()
        self.assertIn("[#] Subdomains (top 20):", out)
        self.assertIn("       2  example.com", out)  # count-desc sorting

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_subdomains_only_conflicts_with_json(self, _):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            with self.assertRaises(SystemExit) as cm:
                wm.main(["example.com", "--subdomains-only", "--json"])
        self.assertEqual(cm.exception.code, 2)




class TestParseExtensions(unittest.TestCase):
    def test_normalizes_bare_and_dotted(self):
        self.assertEqual(wm.parse_extensions("php,.JS"),
                         [".js", ".php"])  # sorted, lowercased, dotted

    def test_dedupes_case_variants(self):
        self.assertEqual(wm.parse_extensions("js,JS,.js"), [".js"])

    def test_empty_token_fails(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            wm.parse_extensions("php,,js")

    def test_empty_value_fails(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            wm.parse_extensions("")

    def test_bad_characters_fail(self):
        for bad in ("..", ".", "p hp", "a/b", ".tar.gz"):
            with self.assertRaises(argparse.ArgumentTypeError, msg=bad):
                wm.parse_extensions(bad)


class TestExtFilter(unittest.TestCase):
    ENTRIES = [
        {"original": "http://example.com/app.js", "statuscode": "200",
         "mimetype": "application/javascript"},
        {"original": "http://example.com/login.php", "statuscode": "200",
         "mimetype": "text/html"},
        {"original": "http://example.com/backup.bak", "statuscode": "200",
         "mimetype": "text/html"},
        {"original": "http://example.com/", "statuscode": "200",
         "mimetype": "text/html"},
        {"original": "http://example.com/mime-js-no-ext", "statuscode": "200",
         "mimetype": "application/javascript"},
    ]

    def test_include_keeps_matching_exts_only(self):
        buckets = wm.analyze(self.ENTRIES, include_exts=[".js"])
        self.assertEqual(buckets["all"], ["http://example.com/app.js"])

    def test_include_drops_extensionless_urls(self):
        buckets = wm.analyze(self.ENTRIES, include_exts=[".js"])
        self.assertNotIn("http://example.com/", buckets["all"])
        self.assertNotIn("http://example.com/mime-js-no-ext", buckets["all"])

    def test_include_matches_case_insensitively(self):
        entries = [{"original": "http://example.com/STYLE.CSS",
                    "statuscode": "200", "mimetype": "text/css"}]
        self.assertEqual(wm.analyze(entries, include_exts=[".css"])["all"],
                         ["http://example.com/STYLE.CSS"])

    def test_exclude_drops_matching_exts(self):
        buckets = wm.analyze(self.ENTRIES, exclude_exts=[".bak"])
        self.assertNotIn("http://example.com/backup.bak", buckets["all"])
        self.assertIn("http://example.com/app.js", buckets["all"])

    def test_exclude_leaves_extensionless_urls(self):
        buckets = wm.analyze(self.ENTRIES, exclude_exts=[".bak"])
        self.assertIn("http://example.com/", buckets["all"])

    def test_include_then_exclude(self):
        buckets = wm.analyze(self.ENTRIES, include_exts=[".js", ".php"],
                             exclude_exts=[".php"])
        self.assertEqual(buckets["all"], ["http://example.com/app.js"])

    def test_no_filters_by_default(self):
        buckets = wm.analyze(self.ENTRIES)
        self.assertEqual(len(buckets["all"]), 5)

    def test_filtered_entries_do_not_pollute_other_buckets(self):
        buckets = wm.analyze(self.ENTRIES, include_exts=[".js"])
        self.assertEqual(buckets["interesting"], [])
        self.assertEqual(buckets["subdomains"], {"example.com": 1})


class TestExtCli(unittest.TestCase):
    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_ext_filters_cli_output(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com", "--ext", "js"])
        self.assertEqual(rc, 0)
        self.assertIn("Archived URLs : 1", buf.getvalue())

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_no_ext_filters_cli_output(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com", "--no-ext", "sql,bak"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("Archived URLs : 3", out)
        self.assertIn("Interesting   : 0", out)

    def test_invalid_ext_exits_2(self):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            with self.assertRaises(SystemExit) as cm:
                wm.main(["example.com", "--ext", ""])
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()


class TestInterestingExtsOverride(unittest.TestCase):
    ENTRIES = [
        {"original": "http://example.com/backup.sql", "statuscode": "200",
         "mimetype": "application/sql"},
        {"original": "http://example.com/app.js", "statuscode": "200",
         "mimetype": "application/javascript"},
        {"original": "http://example.com/key.pem", "statuscode": "200",
         "mimetype": "text/plain"},
    ]

    def test_default_set_unchanged(self):
        buckets = wm.analyze(self.ENTRIES)
        self.assertEqual(buckets["interesting"],
                         ["http://example.com/backup.sql"])

    def test_override_replaces_set(self):
        buckets = wm.analyze(self.ENTRIES, interesting_exts=[".pem"])
        self.assertEqual(buckets["interesting"],
                         ["http://example.com/key.pem"])

    def test_override_composes_with_ext_filter(self):
        buckets = wm.analyze(self.ENTRIES, include_exts=[".js", ".sql"],
                             interesting_exts=[".pem"])
        self.assertEqual(buckets["all"],
                         ["http://example.com/app.js",
                          "http://example.com/backup.sql"])
        self.assertEqual(buckets["interesting"], [])

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_flag(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com", "--interesting-exts", "js"])
        self.assertEqual(rc, 0)
        self.assertIn("Interesting   : 1", buf.getvalue())

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_flag_composes_with_ext(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com", "--ext", "js", "--interesting-exts", "sql"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("Archived URLs : 1", out)
        self.assertIn("Interesting   : 0", out)
