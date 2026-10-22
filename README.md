# osint.py

single-file osint toolkit. no paid API keys, no signup. uses only public free sources that actually respond.

## install (one-liner)

```bash
git clone https://github.com/montygulzar/osint.git && cd osint && pip install -r requirements.txt && chmod +x osint.py
```

or into a venv:

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && chmod +x osint.py
```

## usage

```bash
./osint.py username rac0
./osint.py email target@example.com
./osint.py domain example.com
./osint.py ip 1.1.1.1
./osint.py phone +15551234567
./osint.py github torvalds
./osint.py discord 80351110224678912          # discord user id lookup (swatted-style)
./osint.py discord-invite discord-developers  # or paste full discord.gg/<code> url
./osint.py wayback example.com --limit 20
./osint.py all 80351110224678912              # auto-dispatch by target shape
./osint.py --json domain example.com          # machine-readable
```

## sources

| module         | sources |
|----------------|---------|
| username       | 40+ sites, direct HTTP probes (status + body heuristics) |
| email          | gravatar JSON, github email search, md5/sha256, MX |
| domain         | crt.sh (subdomains), dnspython (A/AAAA/MX/NS/TXT/CAA/SOA), python-whois, wayback first-seen |
| ip             | ip-api.com (geo/asn/isp/proxy/hosting), shodan InternetDB (ports/cves/hostnames), reverse DNS |
| phone          | libphonenumber (`phonenumbers`) — region/carrier/timezones/type |
| github         | public api — profile, repos, ssh keys, gists, commit-email harvest |
| discord        | snowflake decode (created_at, worker, process, increment), discordlookup.mesalytic.moe (username, global_name, avatar, banner, badges, public flags), lanyard presence |
| discord-invite | discord.com/api/v10/invites — guild id/name/features/boost tier/member count, channel, inviter, decoded guild snowflake |
| wayback        | web.archive.org CDX API |

all free, all no-auth. soft rate limits: github 60/hr unauth, ip-api 45/min.

## auto-dispatch rules

- `17-20 digit numeric` → discord user id
- `discord.gg/<code>` or `discord-<name>` → discord invite
- `name@host.tld` → email
- `v4/v6 ip` → ip
- `+digits...` → phone
- `name.tld...` → domain
- anything else → username enum

## notes

- parallel username enum uses 20 workers.
- commit-email harvest skips `noreply` addresses.
- shodan InternetDB `404` is a clean miss, not an error.
- crt.sh sometimes returns HTML under load — handled, warning printed.
- discord endpoints used are public and unauthenticated — nothing scraped, nothing bypassed.
