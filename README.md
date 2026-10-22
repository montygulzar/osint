# osint.py

single-file osint toolkit. no paid API keys, no signup. uses only public free sources that actually respond.

## install

```bash
pip install -r requirements.txt
chmod +x osint.py
```

## usage

```bash
./osint.py username rac0
./osint.py email target@example.com
./osint.py domain example.com
./osint.py ip 1.1.1.1
./osint.py phone +15551234567
./osint.py github torvalds
./osint.py wayback example.com --limit 20
./osint.py all 1.1.1.1               # auto-dispatch
./osint.py --json domain example.com # machine-readable
```

## sources

| module    | sources |
|-----------|---------|
| username  | 40+ sites, direct HTTP probes (status + body heuristics) |
| email     | gravatar JSON, github email search, md5/sha256, MX |
| domain    | crt.sh (subdomains), dnspython (A/AAAA/MX/NS/TXT/CAA/SOA), python-whois, wayback first-seen |
| ip        | ip-api.com (geo/asn/isp/proxy/hosting), shodan InternetDB (ports/cves/hostnames), reverse DNS |
| phone     | google's libphonenumber via `phonenumbers` (region/carrier/timezones/type) |
| github    | public api — profile, repos, ssh keys, gists, commit-email harvest |
| wayback   | web.archive.org CDX API |

all free, all no-auth. the only soft rate limits are github (60/hr unauth) and ip-api (45/min).

## notes

- parallel username enum uses 20 workers; drops to serial on request error.
- commit-email harvest skips `noreply` addresses.
- shodan InternetDB returns `404` when no record exists; treated as a clean miss, not an error.
- crt.sh sometimes returns HTML under load — handled, printed as a warning.
