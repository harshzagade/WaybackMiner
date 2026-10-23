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
import re
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


def parse_statuses(value):
    """Parse '--include-status 301,403' into a sorted list of unique ints.

    Raises argparse.ArgumentTypeError on bad input so argparse exits 2
    with a usage error (fail fast, like the other CLI validations).
    """
    codes = []
    for token in value.split(","):
        token = token.strip()
        if not token.isdigit():
            raise argparse.ArgumentTypeError(
                f"invalid status code {token!r}: expected a number 100-599")
        code = int(token)
        if not 100 <= code <= 599:
            raise argparse.ArgumentTypeError(
                f"invalid status code {code}: expected 100-599")
        codes.append(code)
    if not codes:
        raise argparse.ArgumentTypeError("expected at least one status code")
    return sorted(set(codes))


_DATE_BOUND_LENGTHS = (4, 6, 8, 10, 12, 14)


def parse_date_bound(value):
    """Parse '--since/--until 2020' into a CDX from/to date bound.

    Accepts zero-padded digits in year, year+month, year+month+day, ...
    up to a full YYYYMMDDHHMMSS timestamp (CDX from/to params accept all
    these lengths). Ranges (month 01-12, day 01-31, hour 00-23,
    minute/second 00-59) are sanity-checked; the string is returned as-is
    for the CDX query. Raises argparse.ArgumentTypeError on bad input so
    argparse exits 2 with a usage error (fail fast, like the others).
    """
    value = value.strip()
    if not value.isdigit() or len(value) not in _DATE_BOUND_LENGTHS:
        raise argparse.ArgumentTypeError(
            f"invalid date {value!r}: expected digits like '2020', "
            "'202001', '20200115', or '20200115000000'")
    parts = [(4, 6, 1, 12), (6, 8, 1, 31), (8, 10, 0, 23),
             (10, 12, 0, 59), (12, 14, 0, 59)]
    names = {4: "month", 6: "day", 8: "hour", 10: "minute", 12: "second"}
    for start, end, lo, hi in parts:
        if len(value) >= end:
            num = int(value[start:end])
            if not lo <= num <= hi:
                raise argparse.ArgumentTypeError(
                    f"invalid date {value!r}: {names[start]} out of range")
    return value


def _padded_bound(value, fill):
    """Pad a date bound to full-timestamp length so two bounds of different
    lengths (e.g. '2020' vs '20200115') compare chronologically."""
    return value.ljust(14, fill)


_MIMETYPE_RE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.\-+]*(/[a-z0-9!#$&^_.\-+]+)?/?$")


def parse_mimetypes(value):
    """Parse '--mimetype text/html,image/' into a sorted list of normalized
    mimetype prefixes/types.

    Each token may be a full 'type/subtype' (exact match), a 'type/' prefix,
    or a bare 'type' (equivalent to 'type/'). Normalized to lowercase.
    Raises argparse.ArgumentTypeError on bad input so argparse exits 2
    with a usage error (fail fast, like the other CLI validations).
    """
    mts = []
    for token in value.split(","):
        token = token.strip().lower()
        if not token or not _MIMETYPE_RE.match(token):
            raise argparse.ArgumentTypeError(
                f"invalid mimetype {token!r}: expected e.g. "
                "'text/html', 'image/', or 'image'")
        mts.append(token)
    if not mts:
        raise argparse.ArgumentTypeError("expected at least one mimetype")
    return sorted(set(mts))


def parse_extensions(value):
    """Parse '--ext php,js' into a sorted list of normalized '.ext' strings.

    Bare names gain a leading dot, everything is lowercased. Raises
    argparse.ArgumentTypeError on bad input so argparse exits 2 with a
    usage error (fail fast, like the other CLI validations).
    """
    exts = []
    for token in value.split(","):
        token = token.strip().lower()
        if not token:
            raise argparse.ArgumentTypeError(
                "empty extension in --ext: expected e.g. 'php,js'")
        if not token.startswith("."):
            token = "." + token
        body = token[1:]
        if not body or not all(c.isalnum() or c in "-_" for c in body):
            raise argparse.ArgumentTypeError(
                f"invalid extension {token!r}: expected e.g. 'php' or '.php'")
        exts.append(token)
    if not exts:
        raise argparse.ArgumentTypeError("expected at least one extension")
    return sorted(set(exts))


def fetch_cdx(domain, limit=20000, timeout=120, statuses=(200,),
               mimetypes=None, collapse="urlkey", since=None, until=None):
    """Fetch archived URLs for domain/* from the CDX API. Returns list of dicts.

    statuses: HTTP status codes to include in the CDX filter (default: only
    200). Multiple codes are OR-ed with a single regex-alternation filter
    (e.g. statuscode:(301|403)), so one CDX request covers them all.
    mimetypes: optional list of mimetype prefixes or full types to include
    (e.g. ['text/', 'image/png']) — OR-ed with one regex-alternation filter
    (e.g. mimetype:(text/.*|image/png)). A value without a '/' matches any
    subtype ('image' == 'image/'); a full 'type/subtype' matches exactly.
    collapse: CDX collapse mode — 'urlkey' (default, one row per URL; the
    per-URL first_seen/last_seen timeline needs this) or 'digest' (one row
    per unique response body — merges URLs that served identical content,
    useful for finding how many distinct page variants were served).
    since/until: optional capture-date bounds ('2020', '202001', '20200115',
    ... up to 'YYYYMMDDHHMMSS') sent as the CDX 'from'/'to' params.
    """
    expr = "|".join(str(s) for s in statuses)
    if len(statuses) > 1:
        expr = f"({expr})"
    params = [
        ("url", f"{domain}/*"),
        ("output", "json"),
        ("fl", "timestamp,original,statuscode,mimetype"),
        ("filter", f"statuscode:{expr}"),
        ("collapse", collapse),
        ("limit", str(limit)),
    ]
    if since is not None:
        params.append(("from", since))
    if until is not None:
        params.append(("to", until))
    if mimetypes:
        alts = []
        for mt in mimetypes:
            mt = mt.strip().lower()
            if mt.endswith("/") or "/" not in mt:
                alts.append(re.escape(mt.rstrip("/") + "/") + ".*")
            else:
                alts.append(re.escape(mt))
        expr = "|".join(alts)
        if len(alts) > 1:
            expr = f"({expr})"
        params.insert(-1, ("filter", f"mimetype:{expr}"))
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


def _url_depth(url):
    """Number of path segments in a URL (depth 0 = the bare host).

    Trailing slashes are normalized away and the query string/fragment are
    ignored, so '/a/b/' and '/a/b?x=1' both have depth 2.
    """
    path = urllib.parse.urlparse(url).path.rstrip("/")
    return len([seg for seg in path.split("/") if seg])


def analyze(entries, include_exts=None, exclude_exts=None,
            interesting_exts=None):
    """Split entries into js / params / param_names / interesting / all buckets
    (deduped, sorted), plus a first_seen/last_seen timeline per URL from the
    CDX `timestamp` field (timestamps are zero-padded YYYYMMDDHHMMSS, so
    lexicographic min/max is chronological).

    include_exts: keep only entries whose path extension is in this set
    (extensionless URLs are dropped). exclude_exts: drop entries whose
    extension is in this set, applied after include_exts. interesting_exts:
    override the hard-coded INTERESTING_EXTS set used for the
    interesting-files bucket. All default to None, meaning no filtering and
    the built-in interesting set.

    The `statuses` bucket maps each HTTP status code to the count of deduped
    URLs captured with it (entries with no statuscode field land under "?"),
    so multi-code runs (--include-status 200,301,403) show where the
    archived surface actually lives.

    The `depths` bucket maps each URL path depth to the count of deduped
    URLs at that depth (depth 0 = the bare host), ascending, so deep
    directory trees stand out.
    """
    inc = set(include_exts or ())
    exc = set(exclude_exts or ())
    interesting = (set(interesting_exts) if interesting_exts is not None
                   else INTERESTING_EXTS)
    seen = set()
    param_names = set()
    first_seen, last_seen = {}, {}
    buckets = {"all": [], "js": [], "params": [], "param_names": [], "interesting": []}
    rollup = {}
    status_counts = {}
    depth_counts = {}
    for e in entries:
        url = e.get("original", "")
        if not url:
            continue
        ext = _ext(url)
        if inc and ext not in inc:
            continue
        if ext and ext in exc:
            continue
        ts = e.get("timestamp") or None
        if url in seen:
            # duplicate capture of a known URL: only the timeline advances
            if ts is not None:
                if first_seen[url] is None or ts < first_seen[url]:
                    first_seen[url] = ts
                if last_seen[url] is None or ts > last_seen[url]:
                    last_seen[url] = ts
            continue
        seen.add(url)
        buckets["all"].append(url)
        first_seen[url] = last_seen[url] = ts
        code = str(e.get("statuscode") or "?")
        status_counts[code] = status_counts.get(code, 0) + 1
        depth = _url_depth(url)
        depth_counts[depth] = depth_counts.get(depth, 0) + 1
        host = urllib.parse.urlparse(url).hostname
        if host:
            rollup[host] = rollup.get(host, 0) + 1
        if ext == ".js" or e.get("mimetype", "").find("javascript") != -1:
            buckets["js"].append(url)
        query = urllib.parse.urlparse(url).query
        if query:
            buckets["params"].append(url)
            for name, _value in urllib.parse.parse_qsl(query, keep_blank_values=True):
                param_names.add(name)
        if ext in interesting:
            buckets["interesting"].append(url)
    buckets["param_names"] = sorted(param_names)
    buckets["timeline"] = {u: {"first_seen": first_seen[u], "last_seen": last_seen[u]}
                           for u in sorted(first_seen)}
    # subdomain rollup: host -> count of archived (deduped) URLs,
    # sorted by count desc then hostname asc
    buckets["subdomains"] = {h: rollup[h] for h in
                             sorted(rollup, key=lambda h: (-rollup[h], h))}
    # status breakdown: numeric codes ascending, non-numeric (e.g. "?") last
    buckets["statuses"] = {c: status_counts[c] for c in
                           sorted(status_counts,
                                  key=lambda c: (0, int(c)) if c.isdigit()
                                  else (1, c))}
    # path-depth rollup: depth -> count of archived (deduped) URLs,
    # sorted by depth ascending (depth 0 = the bare host)
    buckets["depths"] = {d: depth_counts[d] for d in sorted(depth_counts)}
    for k in buckets:
        if k not in ("param_names", "timeline", "subdomains", "statuses",
                     "depths"):
            buckets[k].sort()
    return buckets


def capture_window(timeline):
    """Earliest first_seen and latest last_seen across the timeline, or None."""
    firsts = [v["first_seen"] for v in timeline.values() if v["first_seen"]]
    lasts = [v["last_seen"] for v in timeline.values() if v["last_seen"]]
    if not firsts or not lasts:
        return None
    return min(firsts), max(lasts)


def render_json(buckets):
    """Return the full bucketed report as machine-readable JSON."""
    return json.dumps(buckets, indent=2)


def print_report(buckets, js_only=False, params_only=False, interesting_only=False,
               json_only=False, subdomains_only=False):
    if json_only:
        print(render_json(buckets))
        return
    if js_only:
        for u in buckets["js"]:
            print(u)
        return
    if params_only:
        for name in buckets["param_names"]:
            print(name)
        return
    if interesting_only:
        for u in buckets["interesting"]:
            print(u)
        return
    if subdomains_only:
        for host, count in buckets["subdomains"].items():
            print(f"{host}: {count}")
        return
    print(f"Archived URLs : {len(buckets['all'])}")
    print(f"JS files      : {len(buckets['js'])}")
    print(f"With params   : {len(buckets['params'])}")
    print(f"Interesting   : {len(buckets['interesting'])}")
    print(f"Subdomains    : {len(buckets['subdomains'])}")
    window = capture_window(buckets["timeline"])
    if window:
        print(f"Capture window: {window[0]} .. {window[1]}")
    if len(buckets["statuses"]) > 1:
        print("\n[=] Status codes (deduped URLs per code):")
        for code, count in buckets["statuses"].items():
            print(f"  {count:>6}  {code}")
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
    if buckets["subdomains"]:
        print("\n[#] Subdomains (top 20):")
        for host, count in list(buckets["subdomains"].items())[:20]:
            print(f"  {count:>6}  {host}")
    if buckets["depths"]:
        print("\n[=] Path depths (deduped URLs per depth):")
        for depth, count in buckets["depths"].items():
            print(f"  {count:>6}  depth {depth}")
        per_url = {u: _url_depth(u) for u in buckets["all"]}
        deepest = max(per_url.values())
        if deepest:
            shown = [u for u in buckets["all"] if per_url[u] == deepest][:10]
            print(f"\n[#] Deepest URLs (depth {deepest}, first {len(shown)}):")
            for u in shown:
                print(f"  {u}")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Mine the Wayback Machine for a domain's archived URLs.")
    ap.add_argument("domain", help="domain to mine, e.g. example.com")
    ap.add_argument("--limit", type=int, default=20000,
                    help="max CDX rows to fetch (default: 20000)")
    ap.add_argument("--include-status", type=parse_statuses, default=[200],
                    metavar="CODES",
                    help="comma-separated HTTP status codes to include in the "
                         "CDX query (default: 200, e.g. '301,403' to also mine "
                         "redirect and forbidden captures)")
    ap.add_argument("--mimetype", type=parse_mimetypes, default=None,
                    metavar="TYPES",
                    help="comma-separated mimetypes to include in the CDX "
                         "query, e.g. 'text/html' (exact), 'image/' (any "
                         "image), or 'image' (same as 'image/'); OR-ed with "
                         "one CDX regex filter")
    ap.add_argument("--collapse", choices=["urlkey", "digest"],
                    default="urlkey",
                    help="CDX collapse mode: 'urlkey' (default, one row per "
                         "URL — needed for the per-URL first_seen/last_seen "
                         "timeline) or 'digest' (one row per unique response "
                         "body; merges URLs that served identical content)")
    ap.add_argument("--since", type=parse_date_bound, default=None,
                    metavar="DATE",
                    help="only include captures from this date on (e.g. "
                         "'2020', '202001', '20200115', or a full "
                         "'YYYYMMDDHHMMSS' timestamp; CDX 'from' param)")
    ap.add_argument("--until", type=parse_date_bound, default=None,
                    metavar="DATE",
                    help="only include captures up to this date (same format "
                         "as --since; CDX 'to' param)")
    modes = ap.add_mutually_exclusive_group()
    modes.add_argument("--js-only", action="store_true",
                       help="print only JavaScript file URLs")
    modes.add_argument("--params-only", action="store_true",
                       help="print only unique query-parameter names (sorted)")
    modes.add_argument("--interesting-only", action="store_true",
                       help="print only interesting-file URLs (one per line)")
    modes.add_argument("--json", action="store_true",
                       help="print the full report as machine-readable JSON")
    modes.add_argument("--subdomains-only", action="store_true",
                       help="print per-subdomain archived-URL counts "
                            "(sorted by count, one per line)")
    ap.add_argument("--output", "-o", help="write full URL list to file")
    ap.add_argument("--ext", type=parse_extensions, default=None,
                    metavar="EXTS",
                    help="comma-separated file extensions to keep, e.g. "
                         "'php,js' (bare or dotted); URLs with other "
                         "extensions (and extensionless URLs) are dropped")
    ap.add_argument("--no-ext", dest="no_ext", type=parse_extensions,
                    default=None, metavar="EXTS",
                    help="comma-separated file extensions to drop, e.g. "
                         "'bak,log'; applied after --ext")
    ap.add_argument("--interesting-exts", dest="interesting_exts",
                    type=parse_extensions, default=None, metavar="EXTS",
                    help="override the built-in interesting-file extension set, "
                         "e.g. '--interesting-exts env,key,pem' for a "
                         "secrets-focused run")
    args = ap.parse_args(argv)

    if (args.since is not None and args.until is not None
            and _padded_bound(args.since, "0") > _padded_bound(args.until, "9")):
        ap.error("--since must not be after --until")

    try:
        entries = fetch_cdx(args.domain, limit=args.limit,
                            statuses=args.include_status,
                            mimetypes=args.mimetype,
                            collapse=args.collapse,
                            since=args.since, until=args.until)
    except Exception as exc:  # noqa: BLE001 - report cleanly for CLI use
        print(f"error: could not query the CDX API: {exc}", file=sys.stderr)
        return 1
    if not entries:
        print("no archived URLs found for this domain.")
        return 0

    buckets = analyze(entries, include_exts=args.ext,
                      exclude_exts=args.no_ext,
                      interesting_exts=args.interesting_exts)
    print_report(buckets, js_only=args.js_only, params_only=args.params_only,
                 interesting_only=args.interesting_only, json_only=args.json,
                 subdomains_only=args.subdomains_only)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            if args.json:
                fh.write(render_json(buckets) + "\n")
            else:
                fh.write("\n".join(buckets["all"]) + "\n")
        print(f"\nwrote {len(buckets['all'])} URLs to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
