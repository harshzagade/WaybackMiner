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
                                     "interesting", "timeline", "subdomains",
                                     "statuses", "depths", "years", "mimetypes",
                                     "stale", "digest_clusters",
                                     "robots_drift", "url_status"})
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


class TestCsv(unittest.TestCase):
    """Tests for the --csv output mode and render_csv() helper."""

    def _entries(self):
        return [
            {"original": "http://example.com/a", "statuscode": "200",
             "mimetype": "text/html", "timestamp": "20240101000000"},
            {"original": "http://example.com/b", "statuscode": "301",
             "mimetype": "text/html", "timestamp": "20240201000000"},
            {"original": "http://example.com/a", "statuscode": "200",
             "mimetype": "text/html", "timestamp": "20240301000000"},  # dup
        ]

    def test_header_row(self):
        buckets = wm.analyze(self._entries())
        buf = io.StringIO()
        wm.render_csv(buckets, file=buf)
        lines = buf.getvalue().splitlines()
        self.assertEqual(lines[0], "url,first_seen,last_seen,statuscode,depth")

    def test_rows_for_sample_entries(self):
        buckets = wm.analyze(self._entries())
        buf = io.StringIO()
        wm.render_csv(buckets, file=buf)
        lines = buf.getvalue().splitlines()
        # two deduped URLs: /a and /b (sorted)
        self.assertEqual(len(lines), 3)  # header + 2 data rows
        self.assertEqual(lines[1],
                         "http://example.com/a,20240101000000,20240301000000,200,1")
        self.assertEqual(lines[2],
                         "http://example.com/b,20240201000000,20240201000000,301,1")

    def test_unknown_timestamp_is_empty_string(self):
        entries = [
            {"original": "http://example.com/nodate", "statuscode": "200",
             "mimetype": "text/html"},  # no timestamp key
        ]
        buckets = wm.analyze(entries)
        buf = io.StringIO()
        wm.render_csv(buckets, file=buf)
        lines = buf.getvalue().splitlines()
        self.assertEqual(lines[1], "http://example.com/nodate,,,200,1")

    def test_missing_statuscode_is_question_mark(self):
        entries = [
            {"original": "http://example.com/nostatus", "mimetype": "text/html",
             "timestamp": "20240101000000"},  # no statuscode key
        ]
        buckets = wm.analyze(entries)
        buf = io.StringIO()
        wm.render_csv(buckets, file=buf)
        lines = buf.getvalue().splitlines()
        self.assertIn(",?,", lines[1])

    def test_csv_quoting_for_url_containing_comma(self):
        # Synthesise a bucket with a URL that contains a comma (unusual but
        # parseable via the csv module's quoting rules)
        entries = [
            {"original": "http://example.com/path,with,commas", "statuscode": "200",
             "mimetype": "text/html", "timestamp": "20240101000000"},
        ]
        buckets = wm.analyze(entries)
        buf = io.StringIO()
        wm.render_csv(buckets, file=buf)
        lines = buf.getvalue().splitlines()
        # The URL field must be quoted because it contains commas
        self.assertTrue(lines[1].startswith('"http://example.com/path,with,commas"'))

    def test_depth_values_in_csv(self):
        entries = [
            {"original": "http://example.com/", "statuscode": "200",
             "timestamp": "20240101000000"},
            {"original": "http://example.com/a/b/c", "statuscode": "200",
             "timestamp": "20240101000000"},
        ]
        buckets = wm.analyze(entries)
        buf = io.StringIO()
        wm.render_csv(buckets, file=buf)
        lines = buf.getvalue().splitlines()
        # host-only URL: depth 0
        root_row = next(l for l in lines[1:] if "/a/b/c" not in l)
        self.assertTrue(root_row.endswith(",0"))
        # /a/b/c: depth 3
        deep_row = next(l for l in lines[1:] if "/a/b/c" in l)
        self.assertTrue(deep_row.endswith(",3"))

    def test_url_status_bucket_in_analyze(self):
        entries = [
            {"original": "http://example.com/a", "statuscode": "200"},
            {"original": "http://example.com/b"},  # missing statuscode -> "?"
        ]
        buckets = wm.analyze(entries)
        self.assertIn("url_status", buckets)
        self.assertEqual(buckets["url_status"]["http://example.com/a"], "200")
        self.assertEqual(buckets["url_status"]["http://example.com/b"], "?")

    def test_url_status_not_sorted_as_list(self):
        """url_status must not be sorted as a list (it's a dict; sort loop
        must exclude it)."""
        entries = [
            {"original": "http://example.com/z", "statuscode": "301"},
            {"original": "http://example.com/a", "statuscode": "200"},
        ]
        buckets = wm.analyze(entries)
        self.assertIsInstance(buckets["url_status"], dict)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_csv_cli_flag_outputs_csv(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com", "--csv"])
        self.assertEqual(rc, 0)
        lines = buf.getvalue().splitlines()
        self.assertEqual(lines[0], "url,first_seen,last_seen,statuscode,depth")
        # There should be one data row per deduped URL from SAMPLE_CDX (5 rows)
        self.assertEqual(len(lines), 6)  # header + 5 data rows

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_csv_conflicts_with_json(self, _):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            with self.assertRaises(SystemExit) as cm:
                wm.main(["example.com", "--csv", "--json"])
        self.assertEqual(cm.exception.code, 2)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_csv_conflicts_with_js_only(self, _):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            with self.assertRaises(SystemExit) as cm:
                wm.main(["example.com", "--csv", "--js-only"])
        self.assertEqual(cm.exception.code, 2)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_csv_output_flag_writes_csv_file(self, _):
        with mock.patch("builtins.open", mock.mock_open()) as m:
            rc = wm.main(["example.com", "--csv", "-o", "out.csv"])
        self.assertEqual(rc, 0)
        written = "".join(c.args[0] for c in
                          m.return_value.write.call_args_list)
        self.assertIn("url,first_seen,last_seen,statuscode,depth", written)

    def test_json_includes_url_status_bucket(self):
        entries = [
            {"original": "http://example.com/a", "statuscode": "200",
             "timestamp": "20240101000000"},
        ]
        buckets = wm.analyze(entries)
        parsed = json.loads(wm.render_json(buckets))
        self.assertIn("url_status", parsed)
        self.assertEqual(parsed["url_status"]["http://example.com/a"], "200")


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


class TestMimetypeFilter(unittest.TestCase):
    def test_parse_mimetypes_normalizes(self):
        self.assertEqual(wm.parse_mimetypes("TEXT/HTML,image"),
                         ["image", "text/html"])

    def test_parse_mimetypes_rejects_bad(self):
        for bad in ("foo bar", "///", "", "a/b/c", "text/html;level=1"):
            with self.assertRaises(argparse.ArgumentTypeError):
                wm.parse_mimetypes(bad)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_exact_mimetype_filter(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            wm.fetch_cdx("example.com", mimetypes=["text/html"])
            req = m.call_args[0][0]
            self.assertIn("filter=mimetype%3Atext%2Fhtml", req.full_url)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_prefix_mimetype_filter(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            wm.fetch_cdx("example.com", mimetypes=["image/"])
            req = m.call_args[0][0]
            self.assertIn("filter=mimetype%3Aimage%2F.%2A", req.full_url)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_multiple_mimetypes_or_filter(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            wm.fetch_cdx("example.com", mimetypes=["image/", "text/html"])
            req = m.call_args[0][0]
            self.assertIn("filter=mimetype%3A%28image%2F.%2A%7Ctext%2Fhtml%29",
                          req.full_url)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_no_mimetype_filter_by_default(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            wm.fetch_cdx("example.com")
            req = m.call_args[0][0]
            self.assertNotIn("filter=mimetype", req.full_url)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_mimetype_flows_through(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = wm.main(["example.com", "--mimetype", "text/html"])
            self.assertEqual(rc, 0)
            req = m.call_args[0][0]
            self.assertIn("filter=mimetype%3Atext%2Fhtml", req.full_url)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_rejects_bad_mimetype(self, _):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            with self.assertRaises(SystemExit) as cm:
                wm.main(["example.com", "--mimetype", "not a type"])
        self.assertEqual(cm.exception.code, 2)


class TestCollapse(unittest.TestCase):
    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_default_collapse_is_urlkey(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            wm.fetch_cdx("example.com")
            req = m.call_args[0][0]
            self.assertIn("collapse=urlkey", req.full_url)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_digest_collapse(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            wm.fetch_cdx("example.com", collapse="digest")
            req = m.call_args[0][0]
            self.assertIn("collapse=digest", req.full_url)
            self.assertNotIn("collapse=urlkey", req.full_url)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_collapse_flows_through(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = wm.main(["example.com", "--collapse", "digest"])
            self.assertEqual(rc, 0)
            req = m.call_args[0][0]
            self.assertIn("collapse=digest", req.full_url)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_rejects_bad_collapse(self, _):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            with self.assertRaises(SystemExit) as cm:
                wm.main(["example.com", "--collapse", "bogus"])
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


class TestDateBounds(unittest.TestCase):
    def test_parse_accepts_lengths(self):
        for good in ("2020", "202001", "20200115", "2020011503",
                     "202001150330", "20200115033045"):
            self.assertEqual(wm.parse_date_bound(good), good)

    def test_parse_rejects_bad(self):
        for bad in ("", "abc", "202", "2020011", "20213", "20200230X",
                    "202013", "2020-01", "20200132", "2020011524",
                    "202001151260"):
            with self.assertRaises(argparse.ArgumentTypeError, msg=bad):
                wm.parse_date_bound(bad)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_from_to_params_sent(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            wm.fetch_cdx("example.com", since="2020", until="20240115")
            url = m.call_args[0][0].full_url
            self.assertIn("from=2020", url)
            self.assertIn("to=20240115", url)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_no_bounds_by_default(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            wm.fetch_cdx("example.com")
            url = m.call_args[0][0].full_url
            self.assertNotIn("from=", url)
            self.assertNotIn("to=", url)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_flags_flow_through(self, _):
        with mock.patch("urllib.request.urlopen", wraps=_fake_urlopen) as m:
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = wm.main(["example.com", "--since", "202001",
                              "--until", "2024"])
            self.assertEqual(rc, 0)
            url = m.call_args[0][0].full_url
            self.assertIn("from=202001", url)
            self.assertIn("to=2024", url)

    def test_cli_since_after_until_exits_2(self):
        with self.assertRaises(SystemExit) as cm:
            with mock.patch("urllib.request.urlopen",
                            side_effect=_fake_urlopen):
                wm.main(["example.com", "--since", "2024",
                         "--until", "2020"])
        self.assertEqual(cm.exception.code, 2)

    def test_cli_mixed_lengths_ok(self):
        # --since 2024 vs --until 2024 means "all of 2024": valid
        with mock.patch("urllib.request.urlopen",
                        side_effect=_fake_urlopen) as m:
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = wm.main(["example.com", "--since", "2024",
                              "--until", "2024"])
            self.assertEqual(rc, 0)


class TestStatusBreakdown(unittest.TestCase):
    def _entries(self):
        return [
            {"original": "http://example.com/a", "statuscode": "200",
             "timestamp": "20240101000000"},
            {"original": "http://example.com/b", "statuscode": "301",
             "timestamp": "20240102000000"},
            {"original": "http://example.com/c", "statuscode": "403",
             "timestamp": "20240103000000"},
            {"original": "http://example.com/a", "statuscode": "200",
             "timestamp": "20240201000000"},  # dup URL: counted once
            {"original": "http://example.com/d",
             "timestamp": "20240104000000"},  # no statuscode -> "?"
        ]

    def test_counts_deduped_urls_per_code(self):
        buckets = wm.analyze(self._entries())
        self.assertEqual(buckets["statuses"],
                         {"200": 1, "301": 1, "403": 1, "?": 1})

    def test_missing_statuscode_lands_under_question_mark(self):
        buckets = wm.analyze([{"original": "http://example.com/a"}])
        self.assertEqual(buckets["statuses"], {"?": 1})

    def test_summary_shows_section_for_multiple_codes(self):
        buckets = wm.analyze(self._entries())
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets)
        out = buf.getvalue()
        self.assertIn("[=] Status codes", out)
        self.assertIn(" 200", out)
        self.assertIn(" 403", out)

    def test_summary_hides_section_for_single_code(self):
        buckets = wm.analyze([{"original": "http://example.com/a",
                               "statuscode": "200"}])
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets)
        self.assertNotIn("[=] Status codes", buf.getvalue())

    def test_json_includes_statuses(self):
        buckets = wm.analyze(self._entries())
        parsed = json.loads(wm.render_json(buckets))
        self.assertEqual(parsed["statuses"]["301"], 1)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_multi_code_sample_shows_section(self, _):
        # the mock skips the CDX status filter, so the 404 row is analyzed
        # alongside the 200 rows: the breakdown section appears
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com"])
        self.assertEqual(rc, 0)
        self.assertIn("[=] Status codes", buf.getvalue())


class TestUrlDepth(unittest.TestCase):
    def _entries(self):
        return [
            {"original": "http://example.com/", "statuscode": "200"},
            {"original": "http://example.com/a", "statuscode": "200"},
            {"original": "http://example.com/a/b/", "statuscode": "200"},
            {"original": "http://example.com/a/b/c?q=1", "statuscode": "200"},
            {"original": "http://example.com/a/b/c?q=1",  # dup: counted once
             "statuscode": "200"},
        ]

    def test_depth_helper(self):
        self.assertEqual(wm._url_depth("http://example.com/"), 0)
        self.assertEqual(wm._url_depth("http://example.com"), 0)
        self.assertEqual(wm._url_depth("http://example.com/a"), 1)
        self.assertEqual(wm._url_depth("http://example.com/a/b/"), 2)
        self.assertEqual(wm._url_depth("http://example.com/a/b?q=1#x"), 2)
        self.assertEqual(wm._url_depth("http://example.com/a//b"), 2)

    def test_depths_bucket_counts_deduped_urls(self):
        buckets = wm.analyze(self._entries())
        self.assertEqual(buckets["depths"], {0: 1, 1: 1, 2: 1, 3: 1})

    def test_summary_shows_depth_section_and_deepest_urls(self):
        buckets = wm.analyze(self._entries())
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets)
        out = buf.getvalue()
        self.assertIn("[=] Path depths", out)
        self.assertIn("depth 3", out)
        self.assertIn("[#] Deepest URLs (depth 3, first 1):", out)
        self.assertIn("http://example.com/a/b/c", out)

    def test_summary_hides_deepest_list_when_flat(self):
        # all URLs at depth 0: nothing deep to surface
        buckets = wm.analyze([{"original": "http://example.com/"},
                              {"original": "http://example.com/?ref=1"}])
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets)
        out = buf.getvalue()
        self.assertIn("[=] Path depths", out)
        self.assertNotIn("[#] Deepest URLs", out)

    def test_json_includes_depths(self):
        buckets = wm.analyze(self._entries())
        parsed = json.loads(wm.render_json(buckets))
        self.assertEqual(parsed["depths"], {"0": 1, "1": 1, "2": 1, "3": 1})


class TestFirstSeenYears(unittest.TestCase):
    def _entries(self):
        return [
            {"original": "http://example.com/old", "statuscode": "200",
             "timestamp": "20190601000000"},
            {"original": "http://example.com/mid", "statuscode": "200",
             "timestamp": "20230101000000"},
            {"original": "http://example.com/new", "statuscode": "200",
             "timestamp": "20240105000000"},
            {"original": "http://example.com/new", "statuscode": "200",
             "timestamp": "20240201000000"},  # dup: still counts under 2024
            {"original": "http://example.com/nodate", "statuscode": "200"},
            {"original": "http://example.com/also-old", "statuscode": "200",
             "timestamp": "20191231000000"},
        ]

    def test_years_bucket_counts_deduped_urls_by_first_seen_year(self):
        buckets = wm.analyze(self._entries())
        self.assertEqual(buckets["years"],
                         {"2019": 2, "2023": 1, "2024": 1})

    def test_earlier_duplicate_moves_url_to_earlier_year(self):
        entries = [
            {"original": "http://example.com/a", "statuscode": "200",
             "timestamp": "20240101000000"},
            {"original": "http://example.com/a", "statuscode": "200",
             "timestamp": "20180101000000"},  # earlier dup advances first_seen
        ]
        self.assertEqual(wm.analyze(entries)["years"], {"2018": 1})

    def test_summary_shows_year_section(self):
        buckets = wm.analyze(self._entries())
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets)
        out = buf.getvalue()
        self.assertIn("[=] First-seen years", out)
        self.assertIn("2019", out)
        self.assertIn("2024", out)

    def test_json_includes_years(self):
        buckets = wm.analyze(self._entries())
        parsed = json.loads(wm.render_json(buckets))
        self.assertEqual(parsed["years"], {"2019": 2, "2023": 1, "2024": 1})


class TestMimetypeRollup(unittest.TestCase):
    def _entries(self):
        return [
            {"original": "http://example.com/a", "statuscode": "200",
             "mimetype": "text/html"},
            {"original": "http://example.com/b", "statuscode": "200",
             "mimetype": "Text/HTML"},  # case-insensitive: same bucket
            {"original": "http://example.com/c.js", "statuscode": "200",
             "mimetype": "application/javascript"},
            {"original": "http://example.com/a", "statuscode": "200",
             "mimetype": "text/html"},  # dup URL: counted once
            {"original": "http://example.com/d", "statuscode": "200"},
            # no mimetype -> "?"
        ]

    def test_mimetypes_bucket_counts_deduped_urls(self):
        buckets = wm.analyze(self._entries())
        self.assertEqual(buckets["mimetypes"],
                         {"text/html": 2, "application/javascript": 1,
                          "?": 1})

    def test_mimetypes_sorted_by_count_desc_then_name(self):
        buckets = wm.analyze(self._entries())
        self.assertEqual(list(buckets["mimetypes"]),
                         ["text/html", "?", "application/javascript"])

    def test_summary_shows_mimetype_section(self):
        buckets = wm.analyze(self._entries())
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets)
        out = buf.getvalue()
        self.assertIn("[=] Mimetypes", out)
        self.assertIn("text/html", out)

    def test_json_includes_mimetypes(self):
        buckets = wm.analyze(self._entries())
        parsed = json.loads(wm.render_json(buckets))
        self.assertEqual(parsed["mimetypes"]["text/html"], 2)


class TestOldestCaptures(unittest.TestCase):
    def _entries(self):
        return [
            {"original": "http://example.com/new", "statuscode": "200",
             "timestamp": "20240105000000"},
            {"original": "http://example.com/old", "statuscode": "200",
             "timestamp": "20190601000000"},
            {"original": "http://example.com/mid", "statuscode": "200",
             "timestamp": "20230101000000"},
            {"original": "http://example.com/new", "statuscode": "200",
             "timestamp": "20240106000000"},  # dup: advances last_seen
            {"original": "http://example.com/nodate", "statuscode": "200"},
        ]

    def test_orders_oldest_first(self):
        timeline = {u: {"first_seen": f, "last_seen": f} for u, f in [
            ("http://example.com/a", "20240101000000"),
            ("http://example.com/b", "20190101000000"),
            ("http://example.com/c", "20220101000000")]}
        self.assertEqual(wm.oldest_captures(timeline),
                         [("http://example.com/b", "20190101000000"),
                          ("http://example.com/c", "20220101000000"),
                          ("http://example.com/a", "20240101000000")])

    def test_skips_urls_without_last_seen_and_caps_at_n(self):
        timeline = {f"http://example.com/{i}":
                    {"first_seen": "20200101000000",
                     "last_seen": None if i % 2 else f"2020010{i+1}000000"}
                    for i in range(6)}
        got = wm.oldest_captures(timeline, n=2)
        self.assertEqual(len(got), 2)
        self.assertTrue(all(ts is not None for _, ts in got))
        self.assertEqual(got[0][1], "20200101000000")

    def test_analyze_stale_bucket(self):
        buckets = wm.analyze(self._entries())
        self.assertEqual(buckets["stale"],
                         [{"url": "http://example.com/old",
                           "last_seen": "20190601000000"},
                          {"url": "http://example.com/mid",
                           "last_seen": "20230101000000"},
                          {"url": "http://example.com/new",
                           "last_seen": "20240106000000"}])

    def test_summary_shows_stale_section(self):
        buckets = wm.analyze(self._entries())
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets)
        out = buf.getvalue()
        self.assertIn("[~] Stale captures (oldest last_seen, first 3):", out)
        self.assertIn("20190601000000  http://example.com/old", out)
        # the dup's later capture advanced last_seen, so the newer row shows
        self.assertIn("20240106000000  http://example.com/new", out)

    def test_json_includes_stale(self):
        buckets = wm.analyze(self._entries())
        parsed = json.loads(wm.render_json(buckets))
        self.assertEqual(parsed["stale"][0]["url"], "http://example.com/old")
        self.assertEqual(parsed["stale"][0]["last_seen"], "20190601000000")


class TestBucketDumps(unittest.TestCase):
    def _run(self, args, tmp):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            return wm.main(["example.com"] + args)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_dump_js_writes_js_urls(self, _):
        import os, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "js.txt")
            self.assertEqual(self._run(["--dump-js", path], tmp), 0)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "http://example.com/app.js\n")

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_dump_params_writes_param_urls_not_names(self, _):
        import os, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "params.txt")
            self.assertEqual(self._run(["--dump-params", path], tmp), 0)
            with open(path, encoding="utf-8") as fh:
                # the params bucket holds URLs; --params-only names stay out
                self.assertEqual(fh.read(),
                                 "http://example.com/search?q=test\n")

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_dump_works_alongside_json_mode(self, _):
        import os, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "js.txt")
            self.assertEqual(self._run(["--json", "--dump-js", path], tmp), 0)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "http://example.com/app.js\n")

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_dump_empty_bucket_writes_empty_file(self, _):
        import os, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "js.txt")
            # --ext php leaves no JS URLs, so the dump is empty, not an error
            self.assertEqual(self._run(["--ext", "php", "--dump-js", path],
                                       tmp), 0)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "")

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_dump_unwritable_path_returns_2(self, _):
        import os, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "missing-dir", "js.txt")
            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                rc = self._run(["--dump-js", bad], tmp)
            self.assertEqual(rc, 2)
            self.assertIn("could not write", err.getvalue())


class TestExcludeHost(unittest.TestCase):
    def _entries(self):
        return [
            {"original": "http://example.com/a", "statuscode": "200",
             "timestamp": "20240101000000"},
            {"original": "http://blog.example.com/b", "statuscode": "200",
             "timestamp": "20240102000000"},
            {"original": "http://BLOG.example.com:8080/c", "statuscode": "200",
             "timestamp": "20240103000000"},
            {"original": "http://other.example.com/d", "statuscode": "200",
             "timestamp": "20240104000000"},
        ]

    def test_drops_exact_host_only(self):
        buckets = wm.analyze(self._entries(),
                             exclude_hosts=["blog.example.com"])
        self.assertEqual(buckets["all"],
                         ["http://example.com/a",
                          "http://other.example.com/d"])
        # the subdomain rollup drops the excluded host too
        self.assertNotIn("blog.example.com", buckets["subdomains"])

    def test_match_is_case_insensitive_and_port_blind(self):
        buckets = wm.analyze(self._entries(),
                             exclude_hosts=["BLOG.EXAMPLE.COM"])
        self.assertNotIn("http://blog.example.com/b", buckets["all"])
        self.assertNotIn("http://BLOG.example.com:8080/c", buckets["all"])

    def test_parse_normalizes_scheme_port_trailing_dot(self):
        self.assertEqual(wm.parse_exclude_host("https://Blog.Example.COM:8080/"),
                         "blog.example.com")
        self.assertEqual(wm.parse_exclude_host("blog.example.com."),
                         "blog.example.com")

    def test_parse_rejects_garbage(self):
        for bad in ["", "bad host", "a/b", "http://", "exa_mple.com"]:
            with self.assertRaises(argparse.ArgumentTypeError):
                wm.parse_exclude_host(bad)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_flag_flows_through(self, _):
        import os, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "js.txt")
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = wm.main(["example.com", "--exclude-host", "example.com",
                              "--dump-js", path])
            self.assertEqual(rc, 0)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "")  # all SAMPLE hosts excluded

    def test_cli_invalid_host_exits_2(self):
        with self.assertRaises(SystemExit) as cm:
            wm.main(["example.com", "--exclude-host", "bad host"])
        self.assertEqual(cm.exception.code, 2)


class TestDigestClusters(unittest.TestCase):
    def _entries(self):
        return [
            {"original": "http://example.com/a", "statuscode": "200",
             "digest": "AAA"},
            {"original": "http://example.com/b", "statuscode": "200",
             "digest": "AAA"},
            {"original": "http://example.com/c", "statuscode": "200",
             "digest": "BBB"},
            {"original": "http://example.com/d", "statuscode": "200",
             "digest": "AAA"},
            {"original": "http://example.com/e", "statuscode": "200"},
            {"original": "http://example.com/a", "statuscode": "200",
             "digest": "ZZZ"},  # dup URL: first digest wins, no extra cluster
        ]

    def test_groups_same_digest_urls(self):
        buckets = wm.analyze(self._entries())
        self.assertEqual(buckets["digest_clusters"], [
            {"digest": "AAA", "count": 3,
             "urls": ["http://example.com/a", "http://example.com/b",
                      "http://example.com/d"]}])

    def test_singletons_and_missing_digests_are_not_clusters(self):
        buckets = wm.analyze(self._entries())
        digests = [c["digest"] for c in buckets["digest_clusters"]]
        self.assertNotIn("BBB", digests)  # only one URL
        self.assertNotIn("ZZZ", digests)  # dup URL's second digest ignored

    def test_sorted_by_count_desc_then_digest(self):
        entries = [
            {"original": "http://example.com/x1", "digest": "B"},
            {"original": "http://example.com/x2", "digest": "B"},
            {"original": "http://example.com/y1", "digest": "A"},
            {"original": "http://example.com/y2", "digest": "A"},
            {"original": "http://example.com/y3", "digest": "A"},
        ]
        buckets = wm.analyze(entries)
        self.assertEqual([c["digest"] for c in buckets["digest_clusters"]],
                         ["A", "B"])

    def test_summary_shows_cluster_section(self):
        buckets = wm.analyze(self._entries())
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets)
        out = buf.getvalue()
        self.assertIn("Duplicate content", out)
        self.assertIn("AAA", out)
        self.assertIn("http://example.com/b", out)

    def test_no_cluster_section_when_none(self):
        buckets = wm.analyze([{"original": "http://example.com/a",
                               "digest": "ONLY"}])
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets)
        self.assertNotIn("Duplicate content", buf.getvalue())

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_fetch_requests_digest_field(self, _):
        with mock.patch("urllib.request.urlopen",
                        wraps=_fake_urlopen) as m:
            wm.fetch_cdx("example.com")
            req = m.call_args[0][0]
            self.assertIn("digest", req.full_url)


class TestRobotsDrift(unittest.TestCase):
    ROBOTS = """
        # a comment
        User-agent: *
        Disallow: /private/
        Disallow: /tmp/*.bak$
        Allow: /private/public/
        User-agent: googlebot
        Disallow: /google-only/
        """

    def test_parse_keeps_only_wildcard_group(self):
        dis, allow = wm.parse_robots(self.ROBOTS)
        self.assertEqual(dis, ["/private/", "/tmp/*.bak$"])
        self.assertEqual(allow, ["/private/public/"])

    def test_parse_ignores_empty_disallow_and_case(self):
        dis, allow = wm.parse_robots("USER-AGENT: *\nDISALLOW:\n"
                                     "Disallow: /x/\n")
        self.assertEqual(dis, ["/x/"])
        self.assertEqual(allow, [])

    def test_matcher_prefix_wildcard_and_anchor(self):
        self.assertTrue(wm.robots_path_match("/private/secret", "/private/"))
        self.assertFalse(wm.robots_path_match("/private", "/private/"))
        self.assertTrue(wm.robots_path_match("/tmp/a.bak", "/tmp/*.bak$"))
        self.assertFalse(wm.robots_path_match("/tmp/a.bak.txt",
                                              "/tmp/*.bak$"))
        self.assertTrue(wm.robots_path_match("/search?q=x",
                                             "/search?q=x"))

    def test_longest_match_wins_and_allow_wins_ties(self):
        blocked, pattern = wm.robots_disallowed(
            "/private/public/page", ["/private/"], ["/private/public/"])
        self.assertFalse(blocked)  # longer Allow overrides
        blocked, pattern = wm.robots_disallowed(
            "/private/secret", ["/private/"], ["/private/"])
        self.assertFalse(blocked)  # tie goes to Allow
        blocked, pattern = wm.robots_disallowed(
            "/private/secret", ["/private/"], [])
        self.assertTrue(blocked)
        self.assertEqual(pattern, "/private/")

    def test_analyze_drift_bucket(self):
        entries = [
            {"original": "http://example.com/private/secret"},
            {"original": "http://example.com/private/public/page"},
            {"original": "http://example.com/public"},
            {"original": "http://example.com/tmp/a.bak"},
        ]
        buckets = wm.analyze(entries,
                             robots_disallow=["/private/", "/tmp/*.bak$"],
                             robots_allow=["/private/public/"])
        self.assertEqual(buckets["robots_drift"], [
            {"url": "http://example.com/private/secret",
             "pattern": "/private/"},
            {"url": "http://example.com/tmp/a.bak",
             "pattern": "/tmp/*.bak$"}])

    def test_no_patterns_means_no_drift(self):
        buckets = wm.analyze([{"original": "http://example.com/a"}])
        self.assertEqual(buckets["robots_drift"], [])

    def test_summary_shows_drift_section(self):
        buckets = wm.analyze(
            [{"original": "http://example.com/private/secret"}],
            robots_disallow=["/private/"])
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            wm.print_report(buckets)
        self.assertIn("Now disallowed by robots.txt", buf.getvalue())
        self.assertIn("/private/secret", buf.getvalue())

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_flag_flows_through(self, _):
        with mock.patch("waybackminer.fetch_robots_disallow",
                        return_value=(["/private/"], [])):
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = wm.main(["example.com", "--robots-drift"])
        self.assertEqual(rc, 0)
        # SAMPLE rows carry no /private/ path, so only the section
        # absence is asserted here; the analyze test covers the rows
        self.assertNotIn("Now disallowed", buf.getvalue())

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_robots_failure_warns_and_continues(self, _):
        with mock.patch("waybackminer.fetch_robots_disallow",
                        side_effect=RuntimeError("boom")):
            buf, err = io.StringIO(), io.StringIO()
            with mock.patch("sys.stdout", buf), mock.patch("sys.stderr", err):
                rc = wm.main(["example.com", "--robots-drift"])
        self.assertEqual(rc, 0)
        self.assertIn("could not fetch robots.txt", err.getvalue())


class TestExcludePath(unittest.TestCase):
    def _entries(self):
        return [
            {"original": "http://example.com/admin/dashboard",
             "statuscode": "200"},
            {"original": "http://example.com/administrator",
             "statuscode": "200"},
            {"original": "http://example.com/admin/?x=1",
             "statuscode": "200"},
            {"original": "http://example.com/Admin/page",
             "statuscode": "200"},
            {"original": "http://example.com/public/page",
             "statuscode": "200"},
            {"original": "http://example.com/", "statuscode": "200"},
        ]

    def test_drops_prefixed_paths(self):
        buckets = wm.analyze(self._entries(), exclude_paths=["/admin/"])
        self.assertEqual(buckets["all"], [
            "http://example.com/",
            "http://example.com/Admin/page",
            "http://example.com/administrator",
            "http://example.com/public/page"])

    def test_prefix_match_is_literal(self):
        # '/admin' is a literal prefix, so it also matches '/administrator'
        buckets = wm.analyze(self._entries(), exclude_paths=["/admin"])
        self.assertNotIn("http://example.com/administrator",
                         buckets["all"])
        self.assertNotIn("http://example.com/admin/dashboard",
                         buckets["all"])

    def test_query_string_ignored_for_matching(self):
        buckets = wm.analyze(self._entries(), exclude_paths=["/admin/"])
        self.assertNotIn("http://example.com/admin/?x=1", buckets["all"])

    def test_match_is_case_sensitive(self):
        buckets = wm.analyze(self._entries(), exclude_paths=["/admin/"])
        self.assertIn("http://example.com/Admin/page", buckets["all"])

    def test_multiple_prefixes_union(self):
        buckets = wm.analyze(self._entries(),
                             exclude_paths=["/admin/", "/public/"])
        self.assertEqual(buckets["all"], [
            "http://example.com/",
            "http://example.com/Admin/page",
            "http://example.com/administrator"])

    def test_none_changes_nothing(self):
        buckets = wm.analyze(self._entries(), exclude_paths=None)
        self.assertEqual(len(buckets["all"]), 6)

    def test_parse_accepts_path_prefix_unchanged(self):
        self.assertEqual(wm.parse_exclude_path("/admin/"), "/admin/")

    def test_parse_rejects_garbage(self):
        for bad in ("", "   ", "admin", "admin/", "/ad min/"):
            with self.assertRaises(argparse.ArgumentTypeError):
                wm.parse_exclude_path(bad)

    @mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen)
    def test_cli_flag_flows_through(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com", "--exclude-path", "/app.js",
                          "--js-only"])
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue().strip(), "")

    def test_cli_invalid_prefix_exits_2(self):
        with self.assertRaises(SystemExit) as cm:
            wm.main(["example.com", "--exclude-path", "admin"])
        self.assertEqual(cm.exception.code, 2)
