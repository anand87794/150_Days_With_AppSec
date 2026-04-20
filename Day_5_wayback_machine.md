# Wayback Machine Endpoint Harvest: Mining the Internet's Memory for Hidden URLs

**Severity:** MEDIUM | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The Archive That Never Forgets

Every time a developer pushes an update, removes a feature, or migrates to a new backend — the old URLs still exist somewhere. The Wayback Machine at `web.archive.org` has been crawling and archiving the web since 1996. It has saved **over 800 billion web pages**, including the old APIs, admin panels, debug endpoints, and backup files that developers thought were deleted.

For a penetration tester or bug bounty hunter, this archive is a direct window into a target's past — and the past often has much weaker security than the present.

---

## Why Old Endpoints Are High Value

When a development team removes a feature from the current version of their app, they often:

1. Remove the frontend UI element (button, menu link)
2. Remove the documentation
3. **Forget to remove the actual backend endpoint**

The server still handles requests to `/api/v1/admin/export` — it just doesn't advertise it anymore. And that endpoint was built before the current security standards were enforced. It might have:

- No authentication check
- No rate limiting
- Verbose error messages revealing internal structure
- IDOR vulnerabilities that the new version fixed but the old route didn't

---

## What the Wayback Machine Actually Stores

The archive stores the full HTML of pages as they appeared at different points in time. For endpoint harvesting, the valuable data is in:

```
URLs that were crawled:
  https://target.com/api/v1/users?id=1
  https://target.com/admin/export.php
  https://target.com/config.php.bak    ← backup file!
  https://target.com/api/v2/debug/logs

JavaScript files from the past:
  https://target.com/static/app.js (2021 version with old routes)

Form action endpoints:
  <form action="/api/internal/submit"> ← now hidden from current HTML
```

---

## Tools for Wayback Endpoint Harvesting

### waybackurls (Fastest, Simplest)

```bash
# Install
go install github.com/tomnomnom/waybackurls@latest

# Basic usage — pipe domain, get all archived URLs
echo "target.com" | waybackurls

# With subdomains
echo "target.com" | waybackurls | grep "target.com"

# Save output
echo "target.com" | waybackurls > wayback_urls.txt
wc -l wayback_urls.txt
```

### gau — Get All URLs (Multi-Source)

```bash
# Install
go install github.com/lc/gau/v2/cmd/gau@latest

# gau queries Wayback + OTX + CommmonCrawl + URLScan
gau target.com

# With thread control (faster)
gau target.com --threads 5 --o gau_urls.txt

# Include subdomains
gau --subs target.com --o all_urls.txt
```

### waymore (Even More Sources)

```bash
# Install
pip3 install waymore --break-system-packages

# Run
waymore -i target.com -mode U -oU waymore_urls.txt
```

---

## Filtering for High-Value Endpoints

Raw output can be millions of URLs. Filter ruthlessly:

```bash
# Store all URLs
echo "target.com" | gau --threads 5 > all_urls.txt

# === FILTER 1: Backup and config files (immediate Critical/High) ===
grep -iE "\.(bak|backup|old|orig|copy|txt|sql|db|env|config|cfg|ini|log)$" \
    all_urls.txt > backup_files.txt
echo "Backup files: $(wc -l < backup_files.txt)"
cat backup_files.txt

# === FILTER 2: Old API versions ===
grep -iE "/api/v[0-9]+|/api/[0-9]+\." all_urls.txt | sort -u

# === FILTER 3: Sensitive path patterns ===
grep -iE "admin|debug|test|dev|internal|staging|manage|dashboard|secret|token" \
    all_urls.txt | sort -u

# === FILTER 4: URLs with parameters (IDOR, injection surface) ===
grep -E "\?.*=" all_urls.txt | sort -u > parameterized_urls.txt
echo "URLs with params: $(wc -l < parameterized_urls.txt)"

# === FILTER 5: PHP endpoints (often older security) ===
grep -E "\.php" all_urls.txt | sort -u

# === FILTER 6: JavaScript files (mine these separately) ===
grep -E "\.js$|\.js\?" all_urls.txt | sort -u > js_files.txt
```

---

## Testing Harvested Endpoints

After filtering, test which ones still respond:

```bash
# Check which old endpoints are still alive (return 200)
cat interesting_urls.txt | httpx -silent -status-code -content-length | \
    grep -v " 404 "

# Specifically look for non-404 responses on sensitive paths
cat backup_files.txt | httpx -silent -status-code | grep -vE "404|301|302"

# Download files that respond with 200
cat backup_files.txt | httpx -silent -status-code | grep " 200 " | \
    awk '{print $1}' | xargs -I{} wget -q {} -P ./downloaded_files/

# Check what was downloaded
ls -la downloaded_files/
```

---

## Real Findings from Wayback Harvesting

Here's what hunters actually find using this technique:

### Finding 1: Exposed .env Backup

```bash
# Wayback shows: https://target.com/.env.backup (archived 2022-03-14)
curl https://target.com/.env.backup

# Response:
DB_HOST=10.0.0.5
DB_USER=admin
DB_PASS=SuperSecret123!
STRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxx
AWS_ACCESS_KEY=AKIAXXXXXXXXXXXXXXXX
AWS_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
JWT_SECRET=my-secret-key
# CRITICAL finding — direct credential exposure
```

### Finding 2: Old Admin Endpoint Without Auth

```bash
# Wayback shows: https://target.com/api/v1/admin/users (archived 2021)
# Current API is /api/v3/admin/users (has auth)
# Old v1 endpoint still live:

curl https://target.com/api/v1/admin/users
# Returns full user list without any authentication!
# CRITICAL — unauthenticated admin access
```

### Finding 3: Old Debug Endpoint

```bash
# Wayback shows: https://target.com/debug/phpinfo.php (archived 2020)
curl https://target.com/debug/phpinfo.php
# Returns full phpinfo() output:
# - PHP version (find CVEs)
# - Server configuration
# - Enabled extensions
# - Environment variables (sometimes includes secrets!)
```

---

## Complete Automated Wayback Workflow

```bash
#!/bin/bash
TARGET="${1:-target.com}"
DIR="wayback_${TARGET//./_}"
mkdir -p "$DIR"

echo "=== Wayback Endpoint Harvest: $TARGET ==="

# Harvest from multiple sources
echo "[1] Harvesting URLs from Wayback + Common Crawl..."
gau "$TARGET" --subs --threads 10 --o "$DIR/raw_urls.txt" 2>/dev/null
echo "    Raw URLs: $(wc -l < $DIR/raw_urls.txt)"

# Sort and deduplicate
sort -u "$DIR/raw_urls.txt" -o "$DIR/raw_urls.txt"

# Filter categories
echo "[2] Filtering categories..."
grep -iE "\.(bak|env|sql|config|log|backup|old)$" "$DIR/raw_urls.txt" \
    > "$DIR/backup_files.txt"
grep -iE "/api/v[0-9]" "$DIR/raw_urls.txt" | sort -u \
    > "$DIR/api_versions.txt"
grep -iE "admin|debug|internal|secret" "$DIR/raw_urls.txt" | sort -u \
    > "$DIR/sensitive_paths.txt"
grep -E "\?.*=" "$DIR/raw_urls.txt" | sort -u \
    > "$DIR/params.txt"

echo "    Backups: $(wc -l < $DIR/backup_files.txt)"
echo "    API versions: $(wc -l < $DIR/api_versions.txt)"
echo "    Sensitive paths: $(wc -l < $DIR/sensitive_paths.txt)"
echo "    Parameterized: $(wc -l < $DIR/params.txt)"

# Test live status
echo "[3] Testing which are still alive..."
for category in backup_files api_versions sensitive_paths; do
    cat "$DIR/$category.txt" | httpx -silent -status-code -o "$DIR/${category}_live.txt"
    LIVE=$(grep -v "404" "$DIR/${category}_live.txt" | wc -l)
    echo "    $category: $LIVE live (non-404)"
done

echo "[4] High-priority findings:"
grep -v "404" "$DIR/backup_files_live.txt"
```

---

## Key Takeaways

```
1. Wayback Machine archives URLs forever — even after pages are deleted
2. Deleted endpoints often still respond — they're just hidden from the UI
3. gau + waybackurls = best combo for maximum URL coverage
4. Filter first: .env, .bak, .sql, /api/v1/, /admin/, ?debug= are priorities
5. Test live status with httpx — only test what's still responding
6. Old endpoints = old code = old security = more bugs
7. Historical JS files contain old API routes no longer documented
8. Finding a live .env or config backup = immediate Critical report
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
