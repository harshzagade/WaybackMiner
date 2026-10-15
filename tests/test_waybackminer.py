"""Tests for WaybackMiner. HTTP is mocked - no network access."""
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
                                     "interesting", "timeline"})
        self.assertEqual(data["js"], ["http://example.com/app.js"])
        self.assertEqual(data["params"], ["http://example.com/search?q=test"])
        self.assertEqual(data["param_names"], ["q"])
        self.assertIn("http://example.com/backup.sql", data["interesting"])
        self.assertEqual(data["all"], sorted(data["all"]))

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


if __name__ == "__main__":
    unittest.main()
