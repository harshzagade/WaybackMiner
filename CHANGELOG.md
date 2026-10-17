# Changelog

All notable changes to WaybackMiner are documented here.

## [Unreleased]
### Added
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
