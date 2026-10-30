# Changelog

All notable changes to WaybackMiner are documented here.

## [Unreleased]
### Added
- `--csv` output mode: prints a CSV report to stdout with header
  `url,first_seen,last_seen,statuscode,depth` and one row per deduped
  archived URL (in sorted order); combined with `--output`, the CSV is
  written to the file instead of stdout. Python's `csv` module handles
  quoting, so URLs containing commas are correctly escaped. The per-URL
  status code is tracked in a new `url_status` bucket (url → statuscode
  string, `?` when missing), also included in the `--json` report.
- Mimetype rollup: the text summary now shows a `Mimetypes` section
  (deduped-URL counts per CDX mimetype, count desc then mimetype asc,
  top 20; mimetypes lowercased, missing ones under `?`); the same counts
  ship in the `--json` report as the `mimetypes` key.
- First-seen year rollup: the text summary now shows a `First-seen years`
  section (deduped-URL counts per year of first capture, derived from the
  timeline so re-captured URLs count under their earliest year); the same
  counts ship in the `--json` report as the `years` key. URLs with no known
  capture timestamp are skipped.
- `--robots-drift` flag: compare archived paths against the domain's live
  robots.txt and report archived URLs that are now Disallow-blocked (the
  `robots_drift` bucket: url/pattern records, also in `--json`; longest
  matching rule wins, Allow wins ties). This is the one request made to
  the target host itself (its public robots.txt); a fetch failure warns
  and continues without drift data. Everything else still goes only to
  web.archive.org.
- Digest dedupe cluster report: the CDX `digest` field is now fetched and
  URLs sharing one digest (the same response body served at many paths)
  are grouped in the `digest_clusters` bucket (digest/count/urls, largest
  groups first; singletons and digest-less entries are not clusters) and
  shown in a `Duplicate content` section of the text summary; the same
  clusters ship in the `--json` report under the `digest_clusters` key.
- `--exclude-host` repeatable flag: drop captures under specific subdomains
  client-side (exact hostname match, case-insensitive, ports ignored;
  sibling subdomains are kept), applied before bucketing so every output
  mode, the subdomain rollup, and `--json` stay consistent. Malformed
  host values fail fast with argparse exit 2.
- Per-bucket dump flags: `--dump-js FILE` writes the JavaScript-file URLs
  bucket and `--dump-params FILE` writes the URLs-with-parameters bucket,
  one URL per line, independent of the printed output mode (so dumps work
  alongside `--json` or the `--js-only`/`--params-only` modes; `--dump-params`
  dumps the URLs themselves, not the parameter names `--params-only` prints).
  An unwritable dump path fails fast with exit 2 instead of a traceback.
- Oldest-captures view: the text summary now shows a `Stale captures`
  section listing the URLs whose `last_seen` is the oldest (top 10) — the
  pages most likely abandoned; the same records ship in the `--json`
  report as the `stale` key (URLs without a known capture timestamp are
  skipped, since staleness is a date claim).
- Path-depth rollup: the text summary now shows a `Path depths` section
  (deduped-URL counts per path depth, depth 0 = the bare host) followed by
  the ten deepest URLs, so deep admin trees stand out; the same counts ship
  in the `--json` report as the `depths` key.
- Status-code breakdown: the text summary now shows a `Status codes` section
  (deduped-URL counts per code, missing codes under `?`) whenever the query
  spans more than one code — the same breakdown ships in the `--json` report
  as the `statuses` key (numeric codes ascending, `?` last).
- `--since` / `--until` capture-date bounds: `--since 2020 --until 2024`
  mines only that era (CDX `from`/`to` params; accepts `2020`, `202001`,
  `20200115`, … up to a full `YYYYMMDDHHMMSS` timestamp; malformed dates and
  `--since` after `--until` fail fast with argparse exit 2).
- `--collapse` option: expose the CDX collapse mode instead of the hard-coded
  `urlkey` — `urlkey` (default, one row per URL; the per-URL
  first_seen/last_seen timeline needs this) or `digest` (one row per unique
  response body, merging URLs that served identical content).
- `--mimetype` option: comma-separated mimetypes to include in the CDX query
  (`--mimetype text/html` exact, `--mimetype image/` or `--mimetype image`
  for any subtype); values are OR-ed with one CDX regex filter
  (`mimetype:(text/.*|image/png)`), so one request covers them all.
  Malformed values fail fast with argparse exit 2. Composes with
  `--include-status` (both filters are sent as separate CDX `filter` params).
- `--ext` / `--no-ext` extension filters: comma-separated extensions to keep
  (`--ext php,js` — bare or dotted, case-insensitive) or drop
  (`--no-ext bak,log`, applied after `--ext`); `--ext` also drops
  extensionless URLs, so the filter is exact. Composes with all output modes.
  Malformed tokens fail fast with argparse exit 2.
- `--interesting-exts` override: replace the built-in interesting-file
  extension set with a custom comma-separated list (same normalization as
  `--ext`), e.g. `--interesting-exts env,key,pem` for a secrets-focused run.
- Subdomain rollup: new `subdomains` bucket counting archived (deduped) URLs
  per host (sorted by count desc, then hostname; also in `--json` output);
  the text summary shows the subdomain count plus a top-20 section, and the
  new `--subdomains-only` mode prints `host: count` lines for piping.
- `--include-status` option: comma-separated HTTP status codes to include in
  the CDX query (default: 200) — e.g. `--include-status 301,403` also mines
  redirect and forbidden captures; codes are OR-ed with one CDX regex filter.
- `--json` output mode: prints the full bucketed report (all URLs, JS files,
  URLs with params, param names, interesting files) as machine-readable JSON;
  `--output` writes the JSON report when combined with `--json`. The four
  output-mode flags are mutually exclusive.
- First-seen / last-seen timestamps per URL (new `timeline` bucket from the
  CDX `timestamp` field; the text summary shows the overall capture window).
- "In simple words" plain-language intro line at the top of the README.
- Real terminal screenshot of a sample run against `example.com`
  (`assets/screenshots/sample-run.png`).
