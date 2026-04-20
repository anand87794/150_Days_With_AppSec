# Directory & File Bruteforce: Knocking on Every Door Until One Opens

**Severity:** MEDIUM | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## Not Linked Does Not Mean Not Accessible

When a developer removes a page from the navigation menu, they assume users can no longer access it. They're right about legitimate users. They're completely wrong about attackers.

Unless the page is explicitly blocked at the server level, removing the link means nothing. The URL still works. The file still exists on the server. And with directory bruteforcing, you'll find it in seconds.

This technique sends HTTP requests for thousands of common file and directory names — `/admin`, `/.env`, `/backup.zip`, `/.git/` — and watches which ones the server responds to. Every 200 OK is a potential finding.

---

## Why This Is Always in the Methodology

Directory bruteforcing is one of the most consistently productive techniques in pentesting because:

1. **Developers forget files** — backup files, old configs, test pages sit on servers for years
2. **Default paths are common** — almost every framework puts admin panels at predictable paths
3. **Deployment mistakes** — `.git` directories, `.env` files, `phpinfo.php` accidentally pushed to production
4. **Legacy code** — old PHP pages from 2015 still running on the same server as the new React app

The combination of large wordlists and fast tools means you cover thousands of paths in minutes.

---

## What You're Looking For

### Immediate Critical Findings

```
/.git/              → Git repository exposed
                      Exploit: git clone https://target.com/.git → full source code
                      
/.env               → Environment variables
                      Contains: DB_PASSWORD, API_KEY, JWT_SECRET, STRIPE_KEY
                      
/.env.backup        → Backup of environment file
/config.php.bak     → Backup config with credentials
/database.sql       → Database dump with all user data
/backup.zip         → Full application backup
```

### High-Value Findings

```
/admin              → Admin panel — try default: admin/admin, admin/password
/administrator      → Joomla, other CMSes
/wp-admin           → WordPress admin
/phpMyAdmin         → Direct database access
/adminer.php        → Adminer database manager
/server-status      → Apache real-time request info
/server-info        → Apache configuration details
/api/swagger        → Hidden API documentation
/api/swagger.json   → Swagger spec with all endpoints
/api-docs           → OpenAPI documentation
/actuator           → Spring Boot actuator (health, env, beans)
/metrics            → Application metrics
```

### Source Code Exposure

```
/.git/config        → Git configuration
/.git/HEAD          → Current branch
/.git/COMMIT_EDITMSG → Last commit message
/.svn/              → SVN repository
/WEB-INF/web.xml    → Java web app configuration
```

---

## Tool 1: ffuf — The Swiss Army Knife

```bash
# Install
go install github.com/ffuf/ffuf/v2@latest

# Basic directory scan
ffuf -u https://target.com/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -mc 200,204,301,302,307,401,403

# With authentication
ffuf -u https://target.com/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -H "Authorization: Bearer TOKEN" \
    -mc 200,301,302,403

# File extension fuzzing (find backup files)
ffuf -u https://target.com/indexFUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt \
    -mc 200

# Recursive scan (go deeper into found directories)
ffuf -u https://target.com/FUZZ \
    -w common.txt \
    -recursion -recursion-depth 3 \
    -mc 200,301,302

# Save output
ffuf -u https://target.com/FUZZ \
    -w common.txt \
    -mc 200,301,302,403 \
    -o ffuf_results.json -of json

# Filter by response size (remove false positives)
ffuf -u https://target.com/FUZZ \
    -w common.txt \
    -mc 200 \
    -fs 1234   # filter responses exactly 1234 bytes (usually the 404 page)
```

### Calibrating ffuf to Avoid False Positives

```bash
# Step 1: Find what the 404 page looks like
curl -s https://target.com/thispageclearlyDoesNotExist123 | wc -c
# Output: 1842 bytes → this is your false positive size

# Step 2: Filter that size out
ffuf -u https://target.com/FUZZ \
    -w common.txt \
    -mc 200,301,302 \
    -fs 1842   # ignore responses this size

# Or filter by word count
ffuf -u https://target.com/FUZZ \
    -w common.txt \
    -fw 42     # filter 42-word responses (the 404 page word count)
```

---

## Tool 2: gobuster — Fast and Reliable

```bash
# Install
go install github.com/OJ/gobuster/v3@latest

# Directory mode
gobuster dir \
    -u https://target.com \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -t 50 \
    -b 404,400 \
    -x php,html,txt,bak,zip

# With auth
gobuster dir \
    -u https://target.com \
    -w common.txt \
    -H "Authorization: Bearer TOKEN" \
    -t 50

# DNS subdomain mode (bonus use of gobuster)
gobuster dns \
    -d target.com \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Save output
gobuster dir \
    -u https://target.com \
    -w common.txt \
    -o gobuster_results.txt
```

---

## Tool 3: feroxbuster — Recursive by Default

```bash
# Install
cargo install feroxbuster
# Or: curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash

# Basic scan
feroxbuster -u https://target.com \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Auto-tune (automatically adjusts speed based on errors)
feroxbuster -u https://target.com \
    -w common.txt \
    --auto-tune

# Scan multiple URLs
feroxbuster --stdin \
    -w common.txt \
    --auto-tune
# Then pipe: cat urls.txt | feroxbuster --stdin -w common.txt

# Limit depth of recursion
feroxbuster -u https://target.com \
    -w common.txt \
    --depth 3

# Skip certain extensions
feroxbuster -u https://target.com \
    -w common.txt \
    --filter-extensions png,jpg,gif,css,ico
```

---

## Wordlists — The Most Important Decision

Your results are only as good as your wordlist. Here are the ones that matter:

```bash
# Download SecLists (essential — do this once)
git clone https://github.com/danielmiessler/SecLists.git /opt/seclists

# Directory structure:
# /opt/seclists/Discovery/Web-Content/
#   common.txt            → 4,713 words, general purpose, fast
#   big.txt               → 20,476 words, more thorough
#   raft-medium-files.txt → 17,182 words, file-focused
#   raft-large-files.txt  → 37,042 words, most comprehensive
#   api/objects.txt       → 3,132 words, API-specific paths
#   burp-parameter-names.txt → 6,453 names, for param discovery

# When to use which:
# Quick sweep:   common.txt
# Standard test: big.txt
# File hunting:  raft-medium-files.txt
# Full test:     raft-large-files.txt
# API testing:   api/objects.txt
```

---

## Exploiting .git Directory Exposure

When you find `/.git/` responding with 200 or 403, the source code may be downloadable:

```bash
# Check if .git is accessible
curl -s https://target.com/.git/config
# If it returns the git config → repository is exposed!

# Download the full repository
# Tool: git-dumper
pip3 install git-dumper --break-system-packages
git-dumper https://target.com/.git ./dumped_repo

# Now explore the source code
ls -la dumped_repo/
cat dumped_repo/.env  # often finds credentials
grep -r "password\|secret\|key\|token" dumped_repo/ | head -20

# Check git log for interesting commits
cd dumped_repo
git log --oneline
git show HEAD
git diff HEAD~1 HEAD  # what changed in last commit
```

---

## Complete Bruteforce Workflow

```bash
#!/bin/bash
TARGET="${1:-https://target.com}"
DIR="dirbrute_$(echo $TARGET | sed 's/https\?:\/\///g' | tr '/' '_')"
mkdir -p "$DIR"

echo "=== Directory & File Bruteforce: $TARGET ==="

# Phase 1: Quick common scan
echo "[1] Quick scan with common.txt..."
ffuf -u "$TARGET/FUZZ" \
    -w /opt/seclists/Discovery/Web-Content/common.txt \
    -mc 200,204,301,302,307,401,403 \
    -o "$DIR/quick_scan.json" -of json -silent

# Parse and display results
python3 -c "
import json
with open('$DIR/quick_scan.json') as f:
    data = json.load(f)
for r in data.get('results',[]):
    print(f\"{r['status']} | {r['length']:6d} | {r['url']}\")
" | sort -k1 | tee "$DIR/quick_results.txt"

# Phase 2: Sensitive file scan
echo "[2] Scanning for sensitive files..."
ffuf -u "$TARGET/FUZZ" \
    -w /opt/seclists/Discovery/Web-Content/raft-medium-files.txt \
    -mc 200 \
    -o "$DIR/files_scan.json" -of json -silent

# Phase 3: Specifically check for critical files
echo "[3] Checking critical file paths..."
CRITICAL=(
    "/.env" "/.env.backup" "/.env.local"
    "/.git/config" "/.git/HEAD"
    "/config.php" "/config.php.bak" "/wp-config.php"
    "/phpinfo.php" "/info.php"
    "/admin" "/administrator" "/wp-admin" "/adminer.php"
    "/api/swagger.json" "/api/swagger" "/openapi.json"
    "/actuator" "/actuator/env" "/actuator/health"
    "/server-status" "/server-info"
    "/backup.zip" "/backup.tar.gz" "/www.zip"
)
for path in "${CRITICAL[@]}"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$path")
    [ "$code" != "404" ] && echo "  [$code] $TARGET$path"
done

echo "[4] Results in $DIR/"
```

---

## Key Takeaways

```
1. Directory bruteforce finds files/paths not linked from the UI
2. Critical finds: .git, .env, phpinfo.php, /admin, backup files
3. Tool choice: ffuf (most flexible), gobuster (reliable), feroxbuster (recursive)
4. Wordlist choice: SecLists common.txt → big.txt → raft-large-files.txt
5. Calibrate first: check 404 response size → filter it with -fs
6. .git exposure = full source code → git-dumper → credentials in commits
7. Always test with extensions: .php .bak .old .zip .sql .env
8. Check 403 responses too — some need auth but path exists (still a finding)
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
