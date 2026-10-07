#!/usr/bin/env python3
"""WaybackMiner - mine the Wayback Machine for a domain's forgotten attack surface.

Queries web.archive.org's CDX API and surfaces:
  - all archived URLs (deduped)
  - JavaScript files (prime recon targets)
  - URLs with query parameters (injection surface)
  - interesting files (.php, .bak, .sql, .env, .json, .xml, ...)

Stdlib only. Passive recon - makes requests only to web.archive.org,
never touches the target itself.
"""
import argparse
import json
import sys
import urllib.parse
import urllib.request

CDX_URL = "https://web.archive.org/cdx/search/cdx"

INTERESTING_EXTS = {
    ".php", ".asp", ".aspx", ".jsp", ".do", ".action",
    ".bak", ".old", ".backup", ".sql", ".db", ".env",
    ".json", ".xml", ".yml", ".yaml", ".txt", ".log",
    ".git", ".svn", ".zip", ".tar", ".gz",
}


def fetch_cdx(domain, limit=20000, timeout=120):
    """Fetch archived URLs for domain/* from the CDX API. Returns list of dicts."""
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "limit": str(limit),
    }
    url = CDX_URL + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "WaybackMiner/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
    if not data:
        return []
    header, rows = data[0], data[1:]
    return [dict(zip(header, row)) for row in rows]


def _ext(url):
    path = urllib.parse.urlparse(url).path
    dot = path.rfind(".")
    slash = path.rfind("/")
    return path[dot:].lower() if dot > slash else ""


def analyze(entries):
    """Split entries into js / params / interesting / all buckets (deduped, sorted)."""
    seen = set()
    buckets = {"all": [], "js": [], "params": [], "interesting": []}
    for e in entries:
        url = e.get("original", "")
        if not url or url in seen:
            continue
        seen.add(url)
        buckets["all"].append(url)
        ext = _ext(url)
        if ext == ".js" or e.get("mimetype", "").find("javascript") != -1:
            buckets["js"].append(url)
        if urllib.parse.urlparse(url).query:
            buckets["params"].append(url)
        if ext in INTERESTING_EXTS:
            buckets["interesting"].append(url)
    for k in buckets:
        buckets[k].sort()
    return buckets


def print_report(buckets, js_only=False, params_only=False):
    if js_only:
        for u in buckets["js"]:
            print(u)
        return
    if params_only:
        for u in buckets["params"]:
            print(u)
        return
    print(f"Archived URLs : {len(buckets['all'])}")
    print(f"JS files      : {len(buckets['js'])}")
    print(f"With params   : {len(buckets['params'])}")
    print(f"Interesting   : {len(buckets['interesting'])}")
    if buckets["interesting"]:
        print("\n[!] Interesting files:")
        for u in buckets["interesting"]:
            print(f"  {u}")
    if buckets["params"]:
        print("\n[?] URLs with parameters (first 20):")
        for u in buckets["params"][:20]:
            print(f"  {u}")
    if buckets["js"]:
        print("\n[*] JS files (first 20):")
        for u in buckets["js"][:20]:
            print(f"  {u}")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Mine the Wayback Machine for a domain's archived URLs.")
    ap.add_argument("domain", help="domain to mine, e.g. example.com")
    ap.add_argument("--limit", type=int, default=20000,
                    help="max CDX rows to fetch (default: 20000)")
    ap.add_argument("--js-only", action="store_true",
                    help="print only JavaScript file URLs")
    ap.add_argument("--params-only", action="store_true",
                    help="print only URLs with query parameters")
    ap.add_argument("--output", "-o", help="write full URL list to file")
    args = ap.parse_args(argv)

    try:
        entries = fetch_cdx(args.domain, limit=args.limit)
    except Exception as exc:  # noqa: BLE001 - report cleanly for CLI use
        print(f"error: could not query the CDX API: {exc}", file=sys.stderr)
        return 1
    if not entries:
        print("no archived URLs found for this domain.")
        return 0

    buckets = analyze(entries)
    print_report(buckets, js_only=args.js_only, params_only=args.params_only)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write("\n".join(buckets["all"]) + "\n")
        print(f"\nwrote {len(buckets['all'])} URLs to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
