# Changelog

All notable changes to WaybackMiner are documented here.

## [Unreleased]
### Added
- `--json` output mode: prints the full bucketed report (all URLs, JS files,
  URLs with params, param names, interesting files) as machine-readable JSON;
  `--output` writes the JSON report when combined with `--json`. The four
  output-mode flags are mutually exclusive.
- First-seen / last-seen timestamps per URL (new `timeline` bucket from the
  CDX `timestamp` field; the text summary shows the overall capture window).
- "In simple words" plain-language intro line at the top of the README.
- Real terminal screenshot of a sample run against `example.com`
  (`assets/screenshots/sample-run.png`).
