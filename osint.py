#!/usr/bin/env python3
"""
osint.py — free osint toolkit, no paid keys.

sources (all free, no auth unless noted):
  crt.sh                  certificate transparency -> subdomains
  shodan internetdb       open ports / cves / hostnames per ip
  ip-api.com              geolocation, asn, isp
  web.archive.org (cdx)   historical snapshots
  api.github.com          public user / repo / commit data (unauth: 60 req/hr)
  gravatar                md5-hashed email -> profile
  phonenumbers lib        parse / region / carrier / timezone
  dns (dnspython)         A/AAAA/MX/NS/TXT/CAA/SOA
  python-whois            whois records
  http probes             username enumeration across ~40 sites

usage:
  ./osint.py username rac0
  ./osint.py email target@example.com
  ./osint.py domain example.com
  ./osint.py ip 1.1.1.1
  ./osint.py phone +15551234567
  ./osint.py github torvalds
  ./osint.py wayback example.com --limit 20
  ./osint.py all target@example.com      # auto-dispatch by shape

output: human-readable by default, add --json for machine-readable.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import re
import socket
import sys
from dataclasses import dataclass, field
from typing import Any

try:
    import requests
except ImportError:
    sys.stderr.write("missing dep: pip install requests\n")
    sys.exit(1)

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 osint.py/1.0"
HEADERS = {"User-Agent": UA, "Accept": "*/*"}
TIMEOUT = 10
S = requests.Session()
S.headers.update(HEADERS)


# ---------- output helpers ----------

class C:
    R = "\033[0m"
    B = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GRN = "\033[32m"
    YEL = "\033[33m"
    BLU = "\033[34m"
    MAG = "\033[35m"
    CYN = "\033[36m"


def banner(title: str) -> None:
    print(f"\n{C.B}{C.CYN}── {title} ──{C.R}")


def kv(key: str, val: Any) -> None:
    if val in (None, "", [], {}):
        return
    print(f"  {C.DIM}{key:<14}{C.R} {val}")


def hit(line: str) -> None:
    print(f"  {C.GRN}+{C.R} {line}")


def miss(line: str) -> None:
    print(f"  {C.DIM}- {line}{C.R}")


def warn(line: str) -> None:
    print(f"  {C.YEL}!{C.R} {line}", file=sys.stderr)


# ---------- username enumeration ----------
# curated list: direct HTTP checks, status-based or body-based.
# format: name -> (url_template, method, success_rule)
#   success_rule: ("status", code) or ("not_in_body", "text") or ("in_body", "text")

USERNAME_SITES: dict[str, tuple[str, str, tuple]] = {
    "GitHub":       ("https://github.com/{u}",                   "GET", ("status", 200)),
    "GitLab":       ("https://gitlab.com/{u}",                   "GET", ("status", 200)),
    "Bitbucket":    ("https://bitbucket.org/{u}/",               "GET", ("status", 200)),
    "Twitter/X":    ("https://x.com/{u}",                        "GET", ("status", 200)),
    "Reddit":       ("https://www.reddit.com/user/{u}/about.json","GET", ("not_in_body", '"error"')),
    "Instagram":    ("https://www.instagram.com/{u}/",           "GET", ("status", 200)),
    "TikTok":       ("https://www.tiktok.com/@{u}",              "GET", ("not_in_body", "Couldn't find this account")),
    "YouTube":      ("https://www.youtube.com/@{u}",             "GET", ("status", 200)),
    "Twitch":       ("https://www.twitch.tv/{u}",                "GET", ("status", 200)),
    "Steam":        ("https://steamcommunity.com/id/{u}",        "GET", ("not_in_body", "The specified profile could not be found")),
    "HackerNews":   ("https://news.ycombinator.com/user?id={u}", "GET", ("not_in_body", "No such user.")),
    "Medium":       ("https://medium.com/@{u}",                  "GET", ("status", 200)),
    "DEV.to":       ("https://dev.to/{u}",                       "GET", ("status", 200)),
    "Keybase":      ("https://keybase.io/{u}",                   "GET", ("status", 200)),
    "Pastebin":     ("https://pastebin.com/u/{u}",               "GET", ("not_in_body", "Not Found")),
    "SoundCloud":   ("https://soundcloud.com/{u}",               "GET", ("status", 200)),
    "Vimeo":        ("https://vimeo.com/{u}",                    "GET", ("status", 200)),
    "Flickr":       ("https://www.flickr.com/people/{u}",        "GET", ("status", 200)),
    "Pinterest":    ("https://www.pinterest.com/{u}/",           "GET", ("status", 200)),
    "Linktree":     ("https://linktr.ee/{u}",                    "GET", ("status", 200)),
    "Patreon":      ("https://www.patreon.com/{u}",              "GET", ("status", 200)),
    "ProductHunt":  ("https://www.producthunt.com/@{u}",         "GET", ("status", 200)),
    "Mastodon.social": ("https://mastodon.social/@{u}",          "GET", ("status", 200)),
    "Fosstodon":    ("https://fosstodon.org/@{u}",               "GET", ("status", 200)),
    "Codeberg":     ("https://codeberg.org/{u}",                 "GET", ("status", 200)),
    "Replit":       ("https://replit.com/@{u}",                  "GET", ("status", 200)),
    "CodePen":      ("https://codepen.io/{u}",                   "GET", ("status", 200)),
    "StackOverflow":("https://stackoverflow.com/users/filter?search={u}", "GET", ("in_body", "{u}")),
    "AboutMe":      ("https://about.me/{u}",                     "GET", ("status", 200)),
    "Gravatar":     ("https://en.gravatar.com/{u}",              "GET", ("status", 200)),
    "Imgur":        ("https://imgur.com/user/{u}",               "GET", ("status", 200)),
    "DeviantArt":   ("https://www.deviantart.com/{u}",           "GET", ("status", 200)),
    "ArtStation":   ("https://www.artstation.com/{u}",           "GET", ("status", 200)),
    "Behance":      ("https://www.behance.net/{u}",              "GET", ("status", 200)),
    "500px":        ("https://500px.com/p/{u}",                  "GET", ("status", 200)),
    "Dribbble":     ("https://dribbble.com/{u}",                 "GET", ("status", 200)),
    "Giphy":        ("https://giphy.com/{u}",                    "GET", ("status", 200)),
    "Last.fm":      ("https://www.last.fm/user/{u}",             "GET", ("status", 200)),
    "Chess.com":    ("https://www.chess.com/member/{u}",         "GET", ("status", 200)),
    "Lichess":      ("https://lichess.org/@/{u}",                "GET", ("status", 200)),
    "Trello":       ("https://trello.com/{u}",                   "GET", ("status", 200)),
}


def _check_site(name: str, tpl: tuple, user: str) -> tuple[str, bool, str]:
    url_t, method, rule = tpl
    url = url_t.format(u=user)
    try:
        r = S.request(method, url, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        return name, False, f"err: {type(e).__name__}"
    kind = rule[0]
    if kind == "status":
        ok = r.status_code == rule[1]
    elif kind == "not_in_body":
        ok = r.status_code == 200 and rule[1] not in r.text
    elif kind == "in_body":
        needle = rule[1].format(u=user)
        ok = r.status_code == 200 and needle.lower() in r.text.lower()
    else:
        ok = False
    return name, ok, url


def username_scan(user: str, workers: int = 20) -> dict[str, Any]:
    found: list[dict] = []
    missing: list[str] = []
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_check_site, n, t, user): n for n, t in USERNAME_SITES.items()}
        for f in cf.as_completed(futs):
            name, ok, url = f.result()
            if ok:
                found.append({"site": name, "url": url})
            else:
                missing.append(name)
    found.sort(key=lambda x: x["site"].lower())
    return {"username": user, "found": found, "checked": len(USERNAME_SITES)}


# ---------- email ----------

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def email_scan(email: str) -> dict[str, Any]:
    out: dict[str, Any] = {"email": email, "valid_format": bool(EMAIL_RE.match(email))}
    if not out["valid_format"]:
        return out
    local, domain = email.split("@", 1)
    out["local"] = local
    out["domain"] = domain

    norm = email.strip().lower()
    md5 = hashlib.md5(norm.encode()).hexdigest()
    sha256 = hashlib.sha256(norm.encode()).hexdigest()
    out["md5"] = md5
    out["sha256"] = sha256

    # gravatar
    try:
        r = S.get(f"https://www.gravatar.com/{md5}.json", timeout=TIMEOUT)
        if r.status_code == 200:
            out["gravatar"] = r.json()
            out["gravatar_url"] = f"https://www.gravatar.com/avatar/{md5}?s=400"
        else:
            out["gravatar"] = None
    except Exception as e:
        out["gravatar_error"] = str(e)

    # github commit search by email (unauth, limited)
    try:
        r = S.get(
            "https://api.github.com/search/users",
            params={"q": f"{email} in:email"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            out["github_matches"] = r.json().get("items", [])[:5]
    except Exception:
        pass

    # mx check (deliverability signal)
    out["mx"] = _resolve(domain, "MX")

    return out


# ---------- domain ----------

def _resolve(name: str, rtype: str) -> list[str]:
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        try:
            # fallback: only A via socket
            if rtype == "A":
                return [socket.gethostbyname(name)]
        except Exception:
            pass
        return []
    try:
        answers = dns.resolver.resolve(name, rtype, lifetime=TIMEOUT)
        return [r.to_text() for r in answers]
    except Exception:
        return []


def domain_scan(domain: str) -> dict[str, Any]:
    domain = domain.lower().strip().lstrip(".")
    out: dict[str, Any] = {"domain": domain}

    out["dns"] = {
        rt: _resolve(domain, rt)
        for rt in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA")
    }

    # subdomains via crt.sh
    try:
        r = S.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20,
        )
        if r.status_code == 200 and r.text.strip():
            try:
                data = r.json()
                subs = set()
                for row in data:
                    for n in str(row.get("name_value", "")).split("\n"):
                        n = n.strip().lower().lstrip("*.")
                        if n.endswith(domain):
                            subs.add(n)
                out["subdomains"] = sorted(subs)
            except json.JSONDecodeError:
                out["subdomains"] = []
                warn("crt.sh returned non-JSON (rate-limited?)")
    except Exception as e:
        warn(f"crt.sh: {e}")

    # whois
    try:
        import whois  # type: ignore
        w = whois.whois(domain)
        out["whois"] = {
            "registrar": getattr(w, "registrar", None),
            "creation_date": str(getattr(w, "creation_date", "") or ""),
            "expiration_date": str(getattr(w, "expiration_date", "") or ""),
            "name_servers": getattr(w, "name_servers", None),
            "emails": getattr(w, "emails", None),
            "org": getattr(w, "org", None),
            "country": getattr(w, "country", None),
        }
    except ImportError:
        warn("whois lib not installed (pip install python-whois)")
    except Exception as e:
        warn(f"whois: {e}")

    # wayback summary
    try:
        r = S.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": domain, "output": "json", "limit": 1, "fastLatest": "true"},
            timeout=15,
        )
        if r.ok and r.json():
            out["wayback_first_seen"] = r.json()[1][1] if len(r.json()) > 1 else None
    except Exception:
        pass

    return out


# ---------- ip ----------

def ip_scan(ip: str) -> dict[str, Any]:
    out: dict[str, Any] = {"ip": ip}

    # reverse dns
    try:
        out["ptr"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        out["ptr"] = None

    # ip-api.com (free, no key, 45 req/min)
    try:
        r = S.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,region,regionName,"
                              "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"},
            timeout=TIMEOUT,
        )
        if r.ok:
            out["ip_api"] = r.json()
    except Exception as e:
        warn(f"ip-api: {e}")

    # shodan internetdb (free, no key)
    try:
        r = S.get(f"https://internetdb.shodan.io/{ip}", timeout=TIMEOUT)
        if r.status_code == 200:
            out["shodan_internetdb"] = r.json()
        elif r.status_code == 404:
            out["shodan_internetdb"] = {"note": "no record"}
    except Exception as e:
        warn(f"shodan internetdb: {e}")

    return out


# ---------- phone ----------

def phone_scan(number: str) -> dict[str, Any]:
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone as pntz
    except ImportError:
        warn("missing dep: pip install phonenumbers")
        return {"phone": number, "error": "install phonenumbers"}
    out: dict[str, Any] = {"phone": number}
    try:
        p = phonenumbers.parse(number, None)
    except phonenumbers.NumberParseException as e:
        return {"phone": number, "error": str(e)}
    out["valid"] = phonenumbers.is_valid_number(p)
    out["possible"] = phonenumbers.is_possible_number(p)
    out["country_code"] = p.country_code
    out["national"] = p.national_number
    out["e164"] = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164)
    out["international"] = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    out["region"] = phonenumbers.region_code_for_number(p)
    out["location"] = geocoder.description_for_number(p, "en")
    out["carrier"] = carrier.name_for_number(p, "en")
    out["timezones"] = list(pntz.time_zones_for_number(p))
    out["type"] = str(phonenumbers.number_type(p))
    return out


# ---------- github ----------

def github_scan(user: str) -> dict[str, Any]:
    out: dict[str, Any] = {"user": user}
    try:
        r = S.get(f"https://api.github.com/users/{user}", timeout=TIMEOUT)
        if r.status_code != 200:
            out["error"] = f"status {r.status_code}"
            return out
        prof = r.json()
    except Exception as e:
        out["error"] = str(e)
        return out
    out["profile"] = {k: prof.get(k) for k in (
        "login", "id", "name", "company", "blog", "location",
        "email", "bio", "twitter_username", "public_repos",
        "followers", "following", "created_at", "updated_at", "html_url",
    )}

    # repos
    try:
        r = S.get(
            f"https://api.github.com/users/{user}/repos",
            params={"per_page": 100, "sort": "updated"},
            timeout=TIMEOUT,
        )
        if r.ok:
            repos = r.json()
            out["repos"] = [
                {
                    "name": x["name"],
                    "lang": x.get("language"),
                    "stars": x.get("stargazers_count"),
                    "fork": x.get("fork"),
                    "updated": x.get("updated_at"),
                    "url": x.get("html_url"),
                }
                for x in repos
            ]
            # harvest emails from recent commits of non-fork repos
            emails: dict[str, int] = {}
            for repo in [x for x in repos if not x.get("fork")][:5]:
                try:
                    cr = S.get(
                        f"https://api.github.com/repos/{user}/{repo['name']}/commits",
                        params={"author": user, "per_page": 30},
                        timeout=TIMEOUT,
                    )
                    if cr.ok:
                        for c in cr.json():
                            a = (c.get("commit") or {}).get("author") or {}
                            e = a.get("email")
                            if e and "noreply" not in e:
                                emails[e] = emails.get(e, 0) + 1
                except Exception:
                    continue
            out["emails_from_commits"] = sorted(emails.items(), key=lambda x: -x[1])
    except Exception as e:
        warn(f"github repos: {e}")

    # keys
    try:
        r = S.get(f"https://api.github.com/users/{user}/keys", timeout=TIMEOUT)
        if r.ok:
            out["ssh_keys"] = r.json()
    except Exception:
        pass

    # gists
    try:
        r = S.get(f"https://api.github.com/users/{user}/gists", timeout=TIMEOUT)
        if r.ok:
            out["gists"] = [{"id": g["id"], "desc": g.get("description"), "url": g["html_url"]}
                            for g in r.json()[:20]]
    except Exception:
        pass

    return out


# ---------- wayback ----------

def wayback_scan(target: str, limit: int = 50) -> dict[str, Any]:
    out: dict[str, Any] = {"target": target}
    try:
        r = S.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": target,
                "output": "json",
                "limit": limit,
                "collapse": "timestamp:8",
                "fl": "timestamp,original,statuscode,mimetype,digest",
            },
            timeout=20,
        )
        if r.ok and r.text.strip():
            data = r.json()
            if data:
                hdr = data[0]
                rows = [dict(zip(hdr, row)) for row in data[1:]]
                out["snapshots"] = rows
                out["count"] = len(rows)
    except Exception as e:
        warn(f"wayback: {e}")
    return out


# ---------- auto-dispatch ----------

IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")
PHONE_RE = re.compile(r"^\+?[\d\s\-().]{7,}$")
DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$", re.I)


def auto(target: str) -> dict[str, Any]:
    t = target.strip()
    if "@" in t and EMAIL_RE.match(t):
        return {"type": "email", **email_scan(t)}
    if IP_RE.match(t) or (":" in t and IPV6_RE.match(t) and t.count(":") >= 2):
        return {"type": "ip", **ip_scan(t)}
    if t.startswith("+") and PHONE_RE.match(t):
        return {"type": "phone", **phone_scan(t)}
    if DOMAIN_RE.match(t):
        return {"type": "domain", **domain_scan(t)}
    return {"type": "username", **username_scan(t)}


# ---------- pretty print per module ----------

def print_username(d: dict) -> None:
    banner(f"username: {d['username']}  ({len(d['found'])}/{d['checked']})")
    for f in d["found"]:
        hit(f"{f['site']:<18} {f['url']}")
    if not d["found"]:
        miss("no hits")


def print_email(d: dict) -> None:
    banner(f"email: {d['email']}")
    kv("format", "ok" if d.get("valid_format") else "invalid")
    kv("local", d.get("local"))
    kv("domain", d.get("domain"))
    kv("md5", d.get("md5"))
    kv("sha256", d.get("sha256"))
    kv("mx", ", ".join(d.get("mx", [])))
    g = d.get("gravatar")
    if g:
        hit(f"gravatar: {d.get('gravatar_url')}")
        if isinstance(g, dict) and g.get("entry"):
            e = g["entry"][0]
            kv("name", e.get("displayName"))
            kv("profile", e.get("profileUrl"))
            for a in e.get("accounts", []) or []:
                hit(f"linked: {a.get('shortname')}  {a.get('url')}")
    elif g is None:
        miss("no gravatar")
    for u in d.get("github_matches", []) or []:
        hit(f"github: {u.get('login')}  {u.get('html_url')}")


def print_domain(d: dict) -> None:
    banner(f"domain: {d['domain']}")
    for rt, vals in (d.get("dns") or {}).items():
        if vals:
            kv(rt, ", ".join(vals))
    w = d.get("whois") or {}
    for k in ("registrar", "org", "country", "creation_date", "expiration_date"):
        kv(k, w.get(k))
    for e in w.get("emails") or []:
        hit(f"whois email: {e}")
    subs = d.get("subdomains") or []
    if subs:
        print(f"\n  {C.B}subdomains ({len(subs)}){C.R}")
        for s in subs:
            hit(s)
    kv("wayback_first", d.get("wayback_first_seen"))


def print_ip(d: dict) -> None:
    banner(f"ip: {d['ip']}")
    kv("ptr", d.get("ptr"))
    a = d.get("ip_api") or {}
    for k in ("country", "regionName", "city", "zip", "lat", "lon",
              "timezone", "isp", "org", "as", "mobile", "proxy", "hosting"):
        kv(k, a.get(k))
    s = d.get("shodan_internetdb") or {}
    if s and "note" not in s:
        for h in s.get("hostnames", []) or []:
            hit(f"hostname: {h}")
        for p in s.get("ports", []) or []:
            hit(f"port: {p}")
        for v in s.get("vulns", []) or []:
            print(f"  {C.RED}cve{C.R} {v}")
        for t in s.get("tags", []) or []:
            kv("tag", t)
    elif s:
        miss("shodan: no record")


def print_phone(d: dict) -> None:
    banner(f"phone: {d['phone']}")
    if "error" in d:
        warn(d["error"])
        return
    kv("valid", d.get("valid"))
    kv("e164", d.get("e164"))
    kv("intl", d.get("international"))
    kv("region", d.get("region"))
    kv("location", d.get("location"))
    kv("carrier", d.get("carrier"))
    kv("timezones", ", ".join(d.get("timezones") or []))
    kv("type", d.get("type"))


def print_github(d: dict) -> None:
    banner(f"github: {d['user']}")
    if "error" in d:
        warn(d["error"])
        return
    p = d.get("profile") or {}
    for k in ("name", "company", "blog", "location", "email",
              "twitter_username", "public_repos", "followers",
              "created_at", "html_url", "bio"):
        kv(k, p.get(k))
    for e, n in d.get("emails_from_commits") or []:
        hit(f"commit email: {e}  ({n})")
    for k in d.get("ssh_keys") or []:
        hit(f"ssh key id={k.get('id')}  {k.get('key', '')[:40]}...")
    repos = d.get("repos") or []
    if repos:
        print(f"\n  {C.B}top repos{C.R}")
        for r in repos[:15]:
            star = f"★{r['stars']}" if r.get("stars") else ""
            lang = f"[{r['lang']}]" if r.get("lang") else ""
            print(f"  {C.GRN}+{C.R} {r['name']:<30} {lang:<14} {star:<6} {r['url']}")


def print_wayback(d: dict) -> None:
    banner(f"wayback: {d['target']}  ({d.get('count', 0)} snapshots)")
    for s in (d.get("snapshots") or [])[:40]:
        ts = s.get("timestamp", "")
        pretty = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
        print(f"  {C.GRN}+{C.R} {pretty}  {s.get('statuscode'):<4} "
              f"https://web.archive.org/web/{ts}/{s.get('original')}")


PRINTERS = {
    "username": print_username,
    "email":    print_email,
    "domain":   print_domain,
    "ip":       print_ip,
    "phone":    print_phone,
    "github":   print_github,
    "wayback":  print_wayback,
}


# ---------- cli ----------

def main() -> int:
    ap = argparse.ArgumentParser(prog="osint",
        description="free osint toolkit — no paid keys")
    ap.add_argument("--json", action="store_true", help="json output")
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name in ("username", "email", "domain", "ip", "phone", "github"):
        sp = sub.add_parser(name)
        sp.add_argument("target")

    wb = sub.add_parser("wayback")
    wb.add_argument("target")
    wb.add_argument("--limit", type=int, default=50)

    al = sub.add_parser("all", help="auto-dispatch by target shape")
    al.add_argument("target")

    args = ap.parse_args()

    dispatch = {
        "username": lambda: ("username", username_scan(args.target)),
        "email":    lambda: ("email",    email_scan(args.target)),
        "domain":   lambda: ("domain",   domain_scan(args.target)),
        "ip":       lambda: ("ip",       ip_scan(args.target)),
        "phone":    lambda: ("phone",    phone_scan(args.target)),
        "github":   lambda: ("github",   github_scan(args.target)),
        "wayback":  lambda: ("wayback",  wayback_scan(args.target, args.limit)),
        "all":      lambda: (auto(args.target).get("type", "username"), auto(args.target)),
    }
    kind, data = dispatch[args.cmd]()

    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        PRINTERS[kind](data)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
