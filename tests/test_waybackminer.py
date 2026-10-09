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
    def test_summary_counts(self, _):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = wm.main(["example.com"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("Archived URLs : 5", out)  # all rows incl. the 404 one
        self.assertIn("JS files      : 1", out)


if __name__ == "__main__":
    unittest.main()
