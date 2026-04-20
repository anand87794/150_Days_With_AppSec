# JS File Endpoint Extraction: Reading the API Map Devs Left in the Frontend

**Severity:** MEDIUM | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The Biggest Mistake Modern Developers Make

When developers build React, Vue, or Angular applications, all the application logic — including every API endpoint the app calls — gets bundled into JavaScript files and shipped to every user's browser.

The backend API routes are defined in the frontend code. And since the frontend runs in your browser, you can read every line of it.

This means that for every modern web app you test, there's a complete map of every API endpoint sitting in the JavaScript files — waiting to be extracted.

---

## What Gets Bundled Into JavaScript

### Single Page Applications (SPAs)

```javascript
// React code (developer writes this):
const API_BASE = "https://api.target.com";

function getUsers() {
    return fetch(`${API_BASE}/v2/admin/users/export`);
}

function deleteUser(id) {
    return fetch(`${API_BASE}/v2/admin/users/${id}`, { method: 'DELETE' });
}

// After bundling, this becomes (minified but still readable):
// fetch("https://api.target.com/v2/admin/users/export")
// fetch("https://api.target.com/v2/admin/users/"+id, {method:"DELETE"})
```

Every API call, every route, every parameter name — all in the bundle.

### What Hunters Actually Find

```javascript
// Real patterns found in production JS files:

// API keys (Critical finding!)
const STRIPE_KEY = "XxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxX";
const GOOGLE_API_KEY = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

// Internal endpoints (not in any documentation)
"/api/v1/internal/admin/users"
"/api/v2/debug/system-logs"
"/internal/health-check?verbose=true"

// S3 buckets (may be misconfigured)
"https://target-internal-uploads.s3.amazonaws.com"
"https://target-backup-data.s3.us-east-1.amazonaws.com"

// GraphQL queries with sensitive field names
query { adminUsers { id email role password_hash apiKey } }

// JWT secrets in config objects
const config = { jwtSecret: "hardcoded_secret_123" };
```

---

## Step 1: Find the JavaScript Files

### Method A: Browser DevTools (Manual)

```
1. Open target.com in Chrome
2. Press F12 → Network tab
3. Filter by "JS" type
4. Reload the page
5. See all JS files loaded — look for bundle.js, app.js, main.js, chunk.js files
6. Click each to view source or copy URL
```

### Method B: Automated Collection

```bash
# Get all JS file URLs from a target using gau
gau target.com --ft js --o js_urls.txt
echo "JS files found: $(wc -l < js_urls.txt)"

# Or use waybackurls (also finds historical JS files)
echo "target.com" | waybackurls | grep -E "\.js(\?|$)" | sort -u > js_urls.txt

# Or use gospider to crawl and find JS files
go install github.com/jaeles-project/gospider@latest
gospider -s https://target.com -d 2 -c 10 --js -o js_crawl/

# Or use hakrawler
echo "https://target.com" | hakrawler -js -subs
```

### Method C: From Subdomains at Scale

```bash
# Get JS files from ALL discovered subdomains
cat all_subdomains.txt | \
    httpx -silent | \                        # Only live ones
    gau --ft js | \                          # Get their JS files
    sort -u > all_js_files.txt
echo "Total JS files: $(wc -l < all_js_files.txt)"
```

---

## Step 2: Extract Endpoints from JS Files

### Manual Grep (Quick and Dirty)

```bash
# Download a JS file and grep it
curl -sk https://target.com/static/js/main.chunk.js -o main.js

# Extract API paths
grep -oE "(\"|\')(/api/[a-zA-Z0-9/_{}?=-]+)(\"|\' )" main.js | tr -d "'\"" | sort -u

# Extract full URLs
grep -oE "https?://[a-zA-Z0-9./_?=-]+" main.js | sort -u

# Extract anything that looks like an endpoint
grep -oE "['\"][/a-zA-Z0-9._?={}-]{5,}['\"]" main.js | \
    grep -v "\.png\|\.jpg\|\.css\|\.svg\|\.woff" | \
    tr -d "'\"" | sort -u
```

### LinkFinder (Best for Endpoint Extraction)

```bash
# Install
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
pip3 install -r requirements.txt --break-system-packages

# Analyze a single JS file URL
python3 linkfinder.py -i https://target.com/static/js/app.bundle.js -o cli

# Analyze an entire website (crawls and finds all JS)
python3 linkfinder.py -i https://target.com -d -o cli

# Output to HTML report
python3 linkfinder.py -i https://target.com -d -o linkfinder_report.html

# Bulk analysis from a list of JS URLs
while read url; do
    python3 linkfinder.py -i "$url" -o cli 2>/dev/null
done < js_urls.txt | sort -u > all_endpoints.txt
```

### SecretFinder (For Secrets in JS)

```bash
# Install
git clone https://github.com/m4ll0k/SecretFinder.git
cd SecretFinder
pip3 install -r requirements.txt --break-system-packages

# Scan a JS file for secrets
python3 SecretFinder.py -i https://target.com/static/js/app.js -o cli

# Scan from a list of JS URLs
while read url; do
    python3 SecretFinder.py -i "$url" -o cli 2>/dev/null
done < js_urls.txt

# What SecretFinder detects:
# - AWS Access Keys (AKIA...)
# - Stripe API keys (sk_live_, pk_live_)
# - Google API keys (AIzaSy...)
# - JWT tokens
# - Private keys
# - Slack webhooks
# - GitHub tokens
# - Generic API keys and secrets
```

### JSScanner / xnLinkFinder (Faster at Scale)

```bash
# Install xnLinkFinder (faster alternative to LinkFinder)
pip3 install xnLinkFinder --break-system-packages

# Single URL
xnLinkFinder -i https://target.com -sp https://target.com -sf target.com

# From a file of URLs
xnLinkFinder -i js_urls.txt -sf target.com -o endpoints.txt
```

---

## Step 3: Full Automated Pipeline

```bash
#!/bin/bash
TARGET="${1:-target.com}"
DIR="js_recon_${TARGET//./_}"
mkdir -p "$DIR"

echo "=== JS Endpoint Extraction: $TARGET ==="

# Step 1: Collect all JS file URLs
echo "[1] Collecting JS file URLs..."
gau "$TARGET" --ft js --o "$DIR/js_raw.txt" 2>/dev/null
echo "target.com" | waybackurls 2>/dev/null | \
    grep -E "\.js(\?|$)" >> "$DIR/js_raw.txt"
sort -u "$DIR/js_raw.txt" -o "$DIR/js_urls.txt"
echo "    JS files found: $(wc -l < $DIR/js_urls.txt)"

# Step 2: Filter to only live JS files
echo "[2] Checking which JS files are live..."
cat "$DIR/js_urls.txt" | httpx -silent -status-code | \
    grep " 200 " | awk '{print $1}' > "$DIR/js_live.txt"
echo "    Live JS files: $(wc -l < $DIR/js_live.txt)"

# Step 3: Extract endpoints with LinkFinder
echo "[3] Extracting endpoints with LinkFinder..."
while read js_url; do
    python3 ~/tools/LinkFinder/linkfinder.py -i "$js_url" -o cli 2>/dev/null
done < "$DIR/js_live.txt" | sort -u > "$DIR/raw_endpoints.txt"
echo "    Raw endpoints: $(wc -l < $DIR/raw_endpoints.txt)"

# Step 4: Scan for secrets
echo "[4] Scanning for hardcoded secrets..."
while read js_url; do
    python3 ~/tools/SecretFinder/SecretFinder.py -i "$js_url" -o cli 2>/dev/null
done < "$DIR/js_live.txt" > "$DIR/secrets.txt"
SECRET_COUNT=$(wc -l < "$DIR/secrets.txt")
echo "    Potential secrets: $SECRET_COUNT"
[ "$SECRET_COUNT" -gt 0 ] && echo "    !!! REVIEW SECRETS FILE IMMEDIATELY !!!"

# Step 5: Filter endpoints by interest level
echo "[5] Filtering interesting endpoints..."
grep -iE "admin|export|delete|internal|debug|secret|token|key|password" \
    "$DIR/raw_endpoints.txt" > "$DIR/high_priority.txt"
grep -E "/api/" "$DIR/raw_endpoints.txt" | sort -u > "$DIR/api_endpoints.txt"

echo ""
echo "=== RESULTS SUMMARY ==="
echo "JS files analyzed: $(wc -l < $DIR/js_live.txt)"
echo "Total endpoints:   $(wc -l < $DIR/raw_endpoints.txt)"
echo "API endpoints:     $(wc -l < $DIR/api_endpoints.txt)"
echo "High priority:     $(wc -l < $DIR/high_priority.txt)"
echo "Secrets found:     $(wc -l < $DIR/secrets.txt)"
echo ""
echo "High priority endpoints:"
cat "$DIR/high_priority.txt"
```

---

## React Native Apps — JS Bundle Is Even Richer

React Native apps ship a single massive JS bundle (`index.android.bundle` or `index.ios.bundle`) that contains the ENTIRE app logic. You can extract this directly from an APK:

```bash
# Extract APK
unzip target.apk -d apk_extracted/

# Find the bundle
find apk_extracted/ -name "*.bundle" -o -name "index.js" | head -5

# It's usually at:
# apk_extracted/assets/index.android.bundle

# Grep for API endpoints
grep -oE "['\"]https?://[a-zA-Z0-9./_?=-]+['\"]" \
    apk_extracted/assets/index.android.bundle | \
    tr -d "'\"" | sort -u

# Find all /api/ paths
grep -oE "['\"][/a-zA-Z0-9/_?={}-]{5,}['\"]" \
    apk_extracted/assets/index.android.bundle | \
    grep "/api/" | tr -d "'\"" | sort -u
```

---

## Reporting JS Endpoint Findings

### Hardcoded Secret (Critical)

```
Title: Hardcoded Stripe Secret Key Exposed in Client-Side JavaScript

Severity: Critical

Description:
The file https://target.com/static/js/main.chunk.js contains a 
hardcoded Stripe secret key (sk_live_) which provides full access 
to the company's Stripe payment account.

Evidence:
Line 1847: const STRIPE_KEY = "sk_live_51NxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxV";

Impact:
An attacker can use this key to:
- List all customer payment methods
- Create unauthorized charges
- Issue refunds
- Access complete payment history

Remediation:
Immediately rotate the Stripe secret key.
API keys must never be included in client-side code.
Use environment variables on the server side only.
```

### Undocumented Admin Endpoint

```
Title: Undocumented Admin Export Endpoint Found in JavaScript Bundle

Severity: High (escalates to Critical if accessible)

Description:
Analysis of https://target.com/static/js/app.bundle.js reveals an 
undocumented API endpoint: /api/v1/admin/users/export

This endpoint is not mentioned in any documentation and was found 
only by analyzing the client-side JavaScript bundle.

Testing:
curl -H "Authorization: Bearer USER_TOKEN" https://api.target.com/api/v1/admin/users/export

Result: HTTP 200 — returns complete user database export as CSV
(Attach: screenshot of response)

Severity: Critical — authenticated regular users can access admin export
```

---

## Key Takeaways

```
1. Every SPA (React/Vue/Angular) bundles ALL API routes into JS files
2. These routes are shipped to every user's browser — readable by anyone
3. Tools: LinkFinder (endpoints), SecretFinder (keys), gau (JS URLs)
4. React Native: extract APK → read index.android.bundle → goldmine
5. Priority finds: hardcoded API keys, undocumented admin routes, GraphQL queries
6. Always test extracted endpoints — many are unauthenticated or weakly protected
7. Old bundled JS from Wayback Machine reveals legacy routes still running
8. Hardcoded secret = immediate Critical — report and get rotated ASAP
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
