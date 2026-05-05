# Security Header Analysis: Missing Headers = Missing Defenses. Find the Gaps.

**Severity:** MEDIUM | **Category:** Fingerprinting | **Series:** #300DaysWithAppSec

---

## Headers Are Browser-Side Security — Controlled by the Server

HTTP security headers tell the browser how to behave when displaying your site. When these headers are missing, browsers use their default (permissive) behavior — which is exactly what attackers need.

A missing `Content-Security-Policy` means your XSS payload executes freely. A missing `Strict-Transport-Security` means HTTPS can be downgraded. A misconfigured `Access-Control-Allow-Origin` means any site can read your API responses.

Checking security headers takes 30 seconds. Every missing one is a finding.

---

## The 6 Critical Security Headers

### 1. Content-Security-Policy (CSP)

```
What it does: Defines which scripts, styles, and resources the browser is allowed to load

Missing means: XSS payloads execute without any browser-level restriction
Weak means:    CSP with unsafe-inline or unsafe-eval = effectively no CSP

Check:
curl -sI https://target.com | grep -i content-security-policy

Good:   Content-Security-Policy: default-src 'self'; script-src 'self'
Bad:    (not present) OR Content-Security-Policy: default-src * 'unsafe-inline'
```

### 2. Strict-Transport-Security (HSTS)

```
What it does: Forces browser to always use HTTPS for this domain

Missing means: SSL stripping attacks → attacker downgrades to HTTP → intercept traffic
Weak means:    max-age too short, no includeSubDomains

Check:
curl -sI https://target.com | grep -i strict-transport

Good:   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Bad:    (not present) OR Strict-Transport-Security: max-age=0
```

### 3. X-Frame-Options

```
What it does: Controls whether the page can be embedded in an iframe

Missing means: Clickjacking attacks → victim clicks on invisible iframe overlay
Weak means:    ALLOWALL (deprecated but still used)

Check:
curl -sI https://target.com | grep -i x-frame

Good:   X-Frame-Options: DENY  OR  X-Frame-Options: SAMEORIGIN
Bad:    (not present)
```

### 4. X-Content-Type-Options

```
What it does: Prevents browser MIME type sniffing

Missing means: Attacker uploads image with HTML/JS content → browser executes it as script
Only value:   X-Content-Type-Options: nosniff

Check:
curl -sI https://target.com | grep -i x-content-type
```

### 5. Referrer-Policy

```
What it does: Controls what URL is sent in the Referer header

Missing means: Full URL (including tokens, IDs) sent to third parties on every link click
Good value:   Referrer-Policy: strict-origin-when-cross-origin

Check:
curl -sI https://target.com | grep -i referrer-policy
```

### 6. Permissions-Policy (formerly Feature-Policy)

```
What it does: Controls which browser APIs (camera, mic, geolocation) the page can use

Missing means: Injected scripts can silently access camera, microphone, geolocation
Good value:   Permissions-Policy: camera=(), microphone=(), geolocation=()

Check:
curl -sI https://target.com | grep -i permissions-policy
```

---

## CORS Misconfiguration — A Separate High-Impact Issue

```bash
# Test if CORS reflects arbitrary origins
curl -H "Origin: https://evil.com" -sI https://target.com/api/users | \
    grep -i "access-control"

# Vulnerable response:
# Access-Control-Allow-Origin: https://evil.com  ← reflected!
# Access-Control-Allow-Credentials: true         ← auth cookies included!

# This means: any attacker site can make authenticated requests to the API

# Null origin bypass (sandbox iframe trick)
curl -H "Origin: null" -sI https://target.com/api/users | \
    grep -i "access-control-allow-origin"
# If: Access-Control-Allow-Origin: null → sandboxed iframe bypass works
```

---

## Automated Header Analysis

```bash
# Quick grep from a single site
curl -sI https://target.com | grep -iE \
    "content-security|strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy"

# securityheaders.com — paste URL → instant A-F grade report

# nuclei — scan entire subdomain list
nuclei -t misconfiguration/http-missing-security-headers.yaml \
    -l subs.txt -silent -o header_findings.txt

# httpx — check which subdomains have CSP
cat subs.txt | httpx -silent \
    -include-response-header Content-Security-Policy \
    -include-response-header Strict-Transport-Security | \
    grep -v "Content-Security-Policy" | head -20
# Lines without CSP = targets to report

# Bulk check all headers across all subdomains
cat subs.txt | httpx -silent -include-response-header "" | \
    grep -v "strict-transport\|content-security\|x-frame" | \
    awk '{print $1}' | sort -u > missing_headers_subdomains.txt
```

---

## The Bug Report

```
Title: Missing Security Headers — CSP, HSTS, X-Frame-Options

Severity: MEDIUM

Description:
The application is missing several critical HTTP security headers that
protect against common client-side attacks.

Missing Headers:
1. Content-Security-Policy → enables XSS execution in victim's browser
2. Strict-Transport-Security → enables SSL stripping / HTTP downgrade
3. X-Frame-Options → enables clickjacking attacks
4. X-Content-Type-Options → enables MIME sniffing attacks

Evidence:
curl -sI https://target.com
[Attach header dump showing absence of security headers]

Impact:
Each missing header enables a specific attack vector. Most critically,
absence of CSP means any XSS vulnerability found will execute with full
impact — no browser-level mitigation will stop it.

Remediation (nginx):
add_header Content-Security-Policy "default-src 'self'";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
add_header X-Frame-Options "DENY";
add_header X-Content-Type-Options "nosniff";
add_header Referrer-Policy "strict-origin-when-cross-origin";
```

---

## Key Takeaways

```
1. Security headers = browser-side defenses controlled by server config
2. Missing CSP → XSS executes freely → escalate any XSS to HIGH
3. Missing HSTS → SSL stripping → intercept HTTPS traffic as HTTP
4. Missing X-Frame-Options → clickjacking on login pages → credential theft
5. CORS * + credentials:true = any site reads your authenticated API = CRITICAL
6. Check: curl -sI + grep, or securityheaders.com for instant A-F grade
7. nuclei http-missing-security-headers template covers bulk subdomain scan
8. Fix: 6 add_header lines in nginx.conf → immediate A grade
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
