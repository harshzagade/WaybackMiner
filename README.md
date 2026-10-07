# WaybackMiner

Mine the [Wayback Machine](https://web.archive.org) for a domain's forgotten
attack surface. Passive recon — it only talks to `web.archive.org`, never
touches the target itself.

## What it finds

- **All archived URLs** for a domain (deduped, sorted)
- **JavaScript files** — prime recon targets
- **URLs with query parameters** — injection surface
- **Interesting files** — `.php`, `.bak`, `.sql`, `.env`, `.json`, `.git`, …

## Install

```bash
git clone https://github.com/harshzagade/WaybackMiner.git
cd WaybackMiner
```

Stdlib only. Python 3.8+.

## Usage

```bash
python3 waybackminer.py example.com
python3 waybackminer.py example.com --js-only
python3 waybackminer.py example.com --params-only
python3 waybackminer.py example.com --limit 5000 -o urls.txt
```

## Sample output

```
Archived URLs : 50
JS files      : 3
With params   : 39
Interesting   : 2

[!] Interesting files:
  http://example.com/backup.sql
  http://example.com/config.json

[?] URLs with parameters (first 20):
  http://example.com/search?q=test
  ...

[*] JS files (first 20):
  http://example.com/app.js
  ...
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## License

MIT
