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
import csv
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


_HOST_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)*$")


def parse_exclude_host(value):
    """Parse '--exclude-host blog.example.com' into a normalized hostname.

    Case-insensitive, a trailing dot is stripped, and a port or scheme in
    the value is ignored (matching is by hostname only). Raises
    argparse.ArgumentTypeError on bad input so argparse exits 2 with a
    usage error (fail fast, like the other CLI validations).
    """
    raw = value.strip().lower()
    if not raw or any(c.isspace() for c in raw):
        raise argparse.ArgumentTypeError(
            f"invalid host {value!r}: expected e.g. 'blog.example.com'")
    if "://" in raw:
        host = urllib.parse.urlparse(raw).hostname
    elif "/" in raw:
        raise argparse.ArgumentTypeError(
            f"invalid host {value!r}: expected a bare hostname, not a path")
    else:
        host = urllib.parse.urlparse("//" + raw).hostname
    if not host:
        raise argparse.ArgumentTypeError(
            f"invalid host {value!r}: expected e.g. 'blog.example.com'")
    host = host.rstrip(".")
    if not _HOST_RE.match(host):
        raise argparse.ArgumentTypeError(
            f"invalid host {value!r}: expected e.g. 'blog.example.com'")
    return host


def parse_exclude_path(value):
    """Parse '--exclude-path /admin/' into a path prefix to drop.

    Paths are case-sensitive, so the value is returned exactly as given
    (no lowercasing, no trailing-slash stripping). Raises
    argparse.ArgumentTypeError on bad input so argparse exits 2 with a
    usage error (fail fast, like the other CLI validations).
    """
    prefix = value.strip()
    if not prefix:
        raise argparse.ArgumentTypeError(
            "invalid path prefix: expected e.g. '/admin/'")
    if any(c.isspace() for c in prefix):
        raise argparse.ArgumentTypeError(
            f"invalid path prefix {value!r}: must not contain whitespace")
    if not prefix.startswith("/"):
        raise argparse.ArgumentTypeError(
            f"invalid path prefix {value!r}: expected a path starting "
            "with '/', e.g. '/admin/'")
    return prefix


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
    The CDX `digest` field is also fetched: identical digests across
    different URLs mean the same response body was served at many paths
    (see the `digest_clusters` bucket in analyze()).
    """
    expr = "|".join(str(s) for s in statuses)
    if len(statuses) > 1:
        expr = f"({expr})"
    params = [
        ("url", f"{domain}/*"),
        ("output", "json"),
        ("fl", "timestamp,original,statuscode,mimetype,digest"),
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
            interesting_exts=None, exclude_hosts=None,
            exclude_paths=None,
            robots_disallow=None, robots_allow=None):
    """Split entries into js / params / param_names / interesting / all buckets
    (deduped, sorted), plus a first_seen/last_seen timeline per URL from the
    CDX `timestamp` field (timestamps are zero-padded YYYYMMDDHHMMSS, so
    lexicographic min/max is chronological).

    include_exts: keep only entries whose path extension is in this set
    (extensionless URLs are dropped). exclude_exts: drop entries whose
    extension is in this set, applied after include_exts. interesting_exts:
    override the hard-coded INTERESTING_EXTS set used for the
    interesting-files bucket. exclude_hosts: drop entries whose hostname
    (exact match, case-insensitive, ports ignored) is in this set, before
    bucketing, so every mode, the subdomain rollup, and --json stay
    consistent. exclude_paths: drop entries whose URL path starts with
    any of these prefixes (literal prefix match, case-sensitive, query
    strings ignored), also before bucketing. All default to None, meaning
    no filtering and the built-in interesting set.

    The `statuses` bucket maps each HTTP status code to the count of deduped
    URLs captured with it (entries with no statuscode field land under "?"),
    so multi-code runs (--include-status 200,301,403) show where the
    archived surface actually lives.

    The `depths` bucket maps each URL path depth to the count of deduped
    URLs at that depth (depth 0 = the bare host), ascending, so deep
    directory trees stand out.

    The `years` bucket maps each first-capture year to the count of deduped
    URLs first seen in that year (from the timeline's `first_seen`, so a
    URL re-captured later still counts under its earliest year), ascending,
    so the years the archived surface grew stand out. URLs with no known
    capture timestamp are skipped — a year is a date claim, not a
    data-absence claim.

    The `mimetypes` bucket maps each CDX mimetype to the count of deduped
    URLs captured with it (normalized to lowercase, entries with no
    mimetype land under "?"), sorted by count desc then mimetype asc, so
    the makeup of the archived surface (how much is HTML vs JS vs images)
    is visible at a glance.

    The `stale` bucket lists the URLs whose `last_seen` is the oldest (top
    10, as url/last_seen records) — the pages most likely abandoned.

    The `digest_clusters` bucket lists groups of two or more deduped URLs
    that share one CDX `digest` (the same response body served at many
    paths), as digest/count/urls records sorted by group size desc then
    digest asc. Entries with no digest (or a duplicate URL seen again)
    contribute nothing: a URL's digest is the one from its first entry,
    and a group of one is not a cluster.

    robots_disallow/robots_allow: the current robots.txt patterns (from
    parse_robots, only consulted when disallows are given). The
    `robots_drift` bucket lists deduped archived URLs whose path (plus
    query) is now disallowed — paths that were crawlable when archived
    but are blocked today — as url/pattern records sorted by URL.
    Without patterns the bucket is empty.
    """
    inc = set(include_exts or ())
    exc = set(exclude_exts or ())
    exc_hosts = {h.lower().rstrip(".") for h in (exclude_hosts or ())}
    exc_paths = list(exclude_paths or ())
    interesting = (set(interesting_exts) if interesting_exts is not None
                   else INTERESTING_EXTS)
    seen = set()
    param_names = set()
    first_seen, last_seen = {}, {}
    buckets = {"all": [], "js": [], "params": [], "param_names": [], "interesting": []}
    rollup = {}
    status_counts = {}
    url_status = {}
    depth_counts = {}
    mimetype_counts = {}
    digest_groups = {}
    robots_drift = []
    disallow_patterns = list(robots_disallow or ())
    allow_patterns = list(robots_allow or ())
    for e in entries:
        url = e.get("original", "")
        if not url:
            continue
        entry_host = urllib.parse.urlparse(url).hostname
        if (entry_host and entry_host.lower().rstrip(".") in exc_hosts):
            continue
        entry_path = urllib.parse.urlparse(url).path
        if any(entry_path.startswith(p) for p in exc_paths):
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
        url_status[url] = code
        digest = e.get("digest") or None
        if digest:
            digest_groups.setdefault(digest, []).append(url)
        if disallow_patterns:
            parsed = urllib.parse.urlparse(url)
            path_q = parsed.path + ("?" + parsed.query if parsed.query else "")
            blocked, pattern = robots_disallowed(path_q, disallow_patterns,
                                                 allow_patterns)
            if blocked:
                robots_drift.append({"url": url, "pattern": pattern})
        status_counts[code] = status_counts.get(code, 0) + 1
        mt = (e.get("mimetype") or "").strip().lower() or "?"
        mimetype_counts[mt] = mimetype_counts.get(mt, 0) + 1
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
    # per-URL status code: url -> statuscode string ('?' when missing),
    # ordered by URL (same ordering as timeline) for deterministic JSON output
    buckets["url_status"] = {u: url_status[u] for u in sorted(url_status)}
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
    # first-seen year rollup: year -> count of deduped URLs first captured
    # in that year, sorted by year ascending; derived from the timeline so
    # a re-captured URL still counts under its earliest year, and URLs
    # with no known timestamp are skipped
    year_counts = {}
    for ts in first_seen.values():
        if ts and len(ts) >= 4 and ts[:4].isdigit():
            year = ts[:4]
            year_counts[year] = year_counts.get(year, 0) + 1
    buckets["years"] = {y: year_counts[y] for y in sorted(year_counts)}
    # mimetype rollup: mimetype -> count of deduped URLs, sorted by count
    # desc then mimetype asc (same ordering as the subdomain rollup)
    buckets["mimetypes"] = {m: mimetype_counts[m] for m in
                            sorted(mimetype_counts,
                                   key=lambda m: (-mimetype_counts[m], m))}
    # stale captures: the URLs whose last capture is the oldest (top 10),
    # i.e. the pages most likely abandoned — carried as url/last_seen records
    buckets["stale"] = [{"url": u, "last_seen": ts}
                        for u, ts in oldest_captures(buckets["timeline"])]
    # digest clusters: same response body at two or more deduped URLs,
    # largest groups first, digest asc as the tiebreak
    buckets["digest_clusters"] = [
        {"digest": d, "count": len(urls), "urls": sorted(urls)}
        for d, urls in sorted(digest_groups.items(),
                              key=lambda kv: (-len(kv[1]), kv[0]))
        if len(urls) >= 2]
    # robots drift: archived URLs now blocked by the live robots.txt,
    # sorted by URL (drift is computed per deduped URL, so already unique)
    buckets["robots_drift"] = sorted(robots_drift, key=lambda r: r["url"])
    for k in buckets:
        if k not in ("param_names", "timeline", "url_status", "subdomains",
                     "statuses", "depths", "years", "mimetypes", "stale",
                     "digest_clusters", "robots_drift"):
            buckets[k].sort()
    return buckets


def capture_window(timeline):
    """Earliest first_seen and latest last_seen across the timeline, or None."""
    firsts = [v["first_seen"] for v in timeline.values() if v["first_seen"]]
    lasts = [v["last_seen"] for v in timeline.values() if v["last_seen"]]
    if not firsts or not lasts:
        return None
    return min(firsts), max(lasts)


def oldest_captures(timeline, n=10):
    """Return the (url, last_seen) pairs with the oldest last_seen, oldest
    first, capped at n. Timestamps are zero-padded YYYYMMDDHHMMSS, so
    lexicographic order is chronological. URLs whose last capture timestamp
    is unknown are skipped — staleness is a date claim, not a data-absence
    one. Abandoned pages (oldest last_seen) are the most likely forgotten.
    """
    dated = [(u, v["last_seen"]) for u, v in timeline.items()
             if v.get("last_seen")]
    dated.sort(key=lambda pair: pair[1])
    return dated[:n]


def _robots_pattern_regex(pattern):
    """Compile one robots.txt Disallow/Allow pattern to a regex.

    `*` matches any sequence, a trailing `$` anchors the end of the path;
    otherwise the pattern is a prefix match (the robots.txt rule). The
    path tested includes the query string, per the robots spec.
    """
    anchored = pattern.endswith("$")
    body = pattern[:-1] if anchored else pattern
    out = []
    for ch in body:
        out.append(".*" if ch == "*" else re.escape(ch))
    suffix = r"\Z" if anchored else ""
    return re.compile("^" + "".join(out) + suffix)


def robots_path_match(path, pattern):
    """True if a robots.txt pattern matches this path (path + query)."""
    return _robots_pattern_regex(pattern).match(path) is not None


def parse_robots(text):
    """Parse robots.txt into (disallows, allows) from `User-agent: *` groups.

    Only wildcard groups apply to every crawler, so agent-specific groups
    are ignored. Comments are stripped, keys are case-insensitive, and an
    empty Disallow (allow-all) contributes nothing. Returns two lists of
    raw patterns, in file order.
    """
    disallows, allows = [], []
    agents, seen_rule = [], False
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent":
            if seen_rule:
                agents, seen_rule = [], False
            agents.append(value.lower())
        elif key in ("disallow", "allow"):
            seen_rule = True
            if "*" in agents and value:
                (disallows if key == "disallow" else allows).append(value)
    return disallows, allows


def robots_disallowed(path, disallows, allows):
    """Longest-match robots decision for a path: (disallowed, pattern).

    The longest matching pattern wins; on a tie Allow wins (RFC 9309).
    Returns (False, None) when no Disallow pattern matches the path.
    """
    best_dis = max((len(p) for p in disallows
                    if robots_path_match(path, p)), default=None)
    if best_dis is None:
        return False, None
    best_allow = max((len(p) for p in allows
                      if robots_path_match(path, p)), default=-1)
    if best_allow >= best_dis:
        return False, None
    pattern = next(p for p in disallows
                   if len(p) == best_dis and robots_path_match(path, p))
    return True, pattern


def fetch_robots_disallow(domain, timeout=30):
    """Fetch a domain's public robots.txt and return (disallows, allows).

    This is the one request WaybackMiner makes to the target host itself
    (everything else goes to web.archive.org); callers treat it as
    opt-in. Raises on network/HTTP failure so the caller can warn and
    continue without drift data.
    """
    url = f"https://{domain}/robots.txt"
    req = urllib.request.Request(url, headers={"User-Agent": "WaybackMiner/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", "replace")
    return parse_robots(text)


def render_json(buckets):
    """Return the full bucketed report as machine-readable JSON."""
    return json.dumps(buckets, indent=2)


def render_csv(buckets, file=None):
    """Write a CSV report to *file* (default: sys.stdout).

    Header: url,first_seen,last_seen,statuscode,depth
    One row per deduped archived URL, in buckets['all'] order (sorted).
    first_seen/last_seen come from buckets['timeline'] (empty string when
    unknown). statuscode comes from buckets['url_status']. depth is
    computed via _url_depth(). Uses Python's csv module so commas/quotes
    in any field are handled correctly.
    """
    if file is None:
        file = sys.stdout
    writer = csv.writer(file, lineterminator="\n")
    writer.writerow(["url", "first_seen", "last_seen", "statuscode", "depth"])
    timeline = buckets.get("timeline", {})
    url_status = buckets.get("url_status", {})
    for url in buckets["all"]:
        tl = timeline.get(url, {})
        first = tl.get("first_seen") or ""
        last = tl.get("last_seen") or ""
        code = url_status.get(url, "?")
        depth = _url_depth(url)
        writer.writerow([url, first, last, code, depth])


def print_report(buckets, js_only=False, params_only=False, interesting_only=False,
               json_only=False, subdomains_only=False, csv_only=False):
    if json_only:
        print(render_json(buckets))
        return
    if csv_only:
        render_csv(buckets)
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
    if buckets["stale"]:
        print(f"\n[~] Stale captures (oldest last_seen, "
              f"first {len(buckets['stale'])}):")
        for row in buckets["stale"]:
            print(f"  {row['last_seen']}  {row['url']}")
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
    if buckets["years"]:
        print("\n[=] First-seen years (deduped URLs per first-capture year):")
        for year, count in buckets["years"].items():
            print(f"  {count:>6}  {year}")
    if buckets["mimetypes"]:
        print("\n[=] Mimetypes (deduped URLs per CDX mimetype, top 20):")
        for mt, count in list(buckets["mimetypes"].items())[:20]:
            print(f"  {count:>6}  {mt}")
        if len(buckets["mimetypes"]) > 20:
            print(f"  ... and {len(buckets['mimetypes']) - 20} more")
    if buckets["digest_clusters"]:
        print("\n[=] Duplicate content (same CDX digest, multiple URLs):")
        for cluster in buckets["digest_clusters"][:10]:
            print(f"  {cluster['count']:>6}  {cluster['digest']}")
            for u in cluster["urls"][:5]:
                print(f"           {u}")
            if len(cluster["urls"]) > 5:
                print(f"           ... and {len(cluster['urls']) - 5} more")
    if buckets["robots_drift"]:
        print("\n[!] Now disallowed by robots.txt "
              f"(archived but blocked today, first 20):")
        for row in buckets["robots_drift"][:20]:
            print(f"  {row['pattern']}  {row['url']}")
        if len(buckets["robots_drift"]) > 20:
            print(f"  ... and {len(buckets['robots_drift']) - 20} more")


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
    modes.add_argument("--csv", action="store_true",
                       help="print a CSV report to stdout with header "
                            "'url,first_seen,last_seen,statuscode,depth' "
                            "and one row per deduped archived URL (sorted); "
                            "combined with --output the CSV is written to "
                            "the file instead")
    ap.add_argument("--output", "-o", help="write full URL list to file")
    ap.add_argument("--dump-js", dest="dump_js", metavar="FILE",
                    help="write the JavaScript-file URLs bucket to FILE, one "
                         "per line, for piping into other tools (independent "
                         "of the printed output mode)")
    ap.add_argument("--dump-params", dest="dump_params", metavar="FILE",
                    help="write the URLs-with-parameters bucket to FILE, one "
                         "per line (the URLs themselves, not the parameter "
                         "names that --params-only prints)")
    ap.add_argument("--ext", type=parse_extensions, default=None,
                    metavar="EXTS",
                    help="comma-separated file extensions to keep, e.g. "
                         "'php,js' (bare or dotted); URLs with other "
                         "extensions (and extensionless URLs) are dropped")
    ap.add_argument("--no-ext", dest="no_ext", type=parse_extensions,
                    default=None, metavar="EXTS",
                    help="comma-separated file extensions to drop, e.g. "
                         "'bak,log'; applied after --ext")
    ap.add_argument("--exclude-host", dest="exclude_host",
                    action="append", type=parse_exclude_host,
                    default=None, metavar="HOST",
                    help="repeatable: drop captures under this host, e.g. "
                         "'--exclude-host blog.example.com' (exact hostname "
                         "match, case-insensitive, ports ignored; sibling "
                         "subdomains are kept); applied before bucketing so "
                         "all modes and --json stay consistent")
    ap.add_argument("--exclude-path", dest="exclude_path",
                    action="append", type=parse_exclude_path,
                    default=None, metavar="PREFIX",
                    help="repeatable: drop archived URLs whose path starts "
                         "with this prefix, e.g. '--exclude-path /admin/' "
                         "(literal prefix match, case-sensitive, query "
                         "strings ignored); applied before bucketing so "
                         "all modes and --json/--csv stay consistent")
    ap.add_argument("--interesting-exts", dest="interesting_exts",
                    type=parse_extensions, default=None, metavar="EXTS",
                    help="override the built-in interesting-file extension set, "
                         "e.g. '--interesting-exts env,key,pem' for a "
                         "secrets-focused run")
    ap.add_argument("--robots-drift", dest="robots_drift",
                    action="store_true",
                    help="compare archived paths against the domain's live "
                         "robots.txt and report archived URLs that are now "
                         "Disallow-blocked; this is the one request made to "
                         "the target host itself (its public robots.txt) — "
                         "everything else still goes only to web.archive.org; "
                         "a robots.txt fetch failure warns and continues "
                         "without drift data")
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

    disallows, allows = [], []
    if args.robots_drift:
        try:
            disallows, allows = fetch_robots_disallow(args.domain)
        except Exception as exc:  # noqa: BLE001 - drift is auxiliary
            print(f"warning: could not fetch robots.txt: {exc}; "
                  f"continuing without robots drift", file=sys.stderr)
    buckets = analyze(entries, include_exts=args.ext,
                      exclude_exts=args.no_ext,
                      interesting_exts=args.interesting_exts,
                      exclude_hosts=args.exclude_host,
                      exclude_paths=args.exclude_path,
                      robots_disallow=disallows, robots_allow=allows)
    print_report(buckets, js_only=args.js_only, params_only=args.params_only,
                 interesting_only=args.interesting_only, json_only=args.json,
                 subdomains_only=args.subdomains_only, csv_only=args.csv)
    for path, items in ((args.dump_js, buckets["js"]),
                        (args.dump_params, buckets["params"])):
        if path is None:
            continue
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("".join(u + "\n" for u in items))
        except OSError as exc:
            print(f"error: could not write {path}: {exc}", file=sys.stderr)
            return 2
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            if args.json:
                fh.write(render_json(buckets) + "\n")
            elif args.csv:
                render_csv(buckets, file=fh)
            else:
                fh.write("\n".join(buckets["all"]) + "\n")
        print(f"\nwrote {len(buckets['all'])} URLs to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
