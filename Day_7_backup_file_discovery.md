# Backup File Discovery: The Files Developers Forgot to Delete

**Severity:** LOW | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The Most Embarrassing Finding in Web Security

Imagine a developer edits `config.php` on a production server using nano. Nano auto-creates a backup: `config.php~`. Or they use vim — it creates `config.php.swp`. Or they manually type `cp config.php config.php.bak` before making changes.

The backup file sits in the same web-accessible directory as the original. The web server serves it without question. Anyone who requests `https://target.com/config.php.bak` gets the raw PHP source code — including every database password, API key, and secret it contains.

This happens constantly. It's one of the most consistently rewarding recon techniques because developers are human, deployment processes are imperfect, and nobody audits for forgotten backup files.

---

## Why LOW Severity Can Become Critical Instantly

Backup file discovery is rated LOW because finding a `.bak` extension of a static HTML file is genuinely low impact. But the moment that backup file contains a password, API key, or database credentials — the severity jumps to Critical immediately.

The discovery technique is LOW. The impact of what you find can be anything.

```
Backup file found:        LOW severity
config.php.bak with DB_PASS inside:    CRITICAL severity
.env.backup with AWS_SECRET_KEY:       CRITICAL severity  
database.sql with user records:        HIGH/CRITICAL severity
app.zip with full source code:         HIGH severity
```

---

## How Backup Files End Up on Production Servers

### Scenario 1: Editor Auto-Backup

```bash
# Developer SSHs into production server and edits config
nano /var/www/html/config.php
# nano creates: config.php~ (auto-backup, same directory)

vim /var/www/html/wp-config.php
# vim creates: .wp-config.php.swp (swap file)

# Developer forgets these exist → they're web-accessible
curl https://target.com/config.php~
# Returns: full PHP source with database credentials
```

### Scenario 2: Manual Developer Backup

```bash
# Developer makes a manual backup before dangerous change
cp config.php config.php.bak
cp .env .env.backup
cp database.php database.php.old

# Makes the change, it works
# Forgets the backup files exist
# Deployment script doesn't clean them
# They sit on server indefinitely
```

### Scenario 3: Deployment Pipeline Artifact

```bash
# CI/CD system creates archives during deployment
# build/app_2024_01_15.zip left in web root
# Old version: app.v1.2.tar.gz never cleaned up
# Database migration: 20240115_schema.sql left accessible
```

### Scenario 4: Version Control Artifacts

```bash
# Developer initializes git in web root (huge mistake)
# .git/ directory becomes web-accessible
# All commit history, deleted files, credentials visible

# SVN checkout in web root:
# .svn/ directory exposes repository structure

# Mercurial:
# .hg/ directory
```

---

## The Complete Extension List

Every extension represents a different tool or workflow. Test all of them:

```bash
# Text editor backups
.bak          # Generic backup
.backup       # Explicit backup
.old          # "old version"
.orig         # Version control conflict original
~             # nano/emacs auto-backup
.swp          # vim swap file (binary but readable with strings)
.swo          # vim alternate swap
.bk           # Short backup

# Source control
.save         # Notepad++ auto-save

# Archive backups  
.zip          # Application archive
.tar          # tar archive
.tar.gz       # Compressed tar
.tar.bz2      # Bzip2 compressed
.tgz          # Compressed tar shorthand
.7z           # 7-zip archive
.rar          # RAR archive

# Database dumps
.sql          # SQL dump
.sql.gz       # Compressed SQL dump
.sqlite       # SQLite database file
.db           # Generic database

# Configuration duplicates
.conf         # Alternative config extension
.config       # Windows-style config
.properties   # Java properties file
.yml.bak      # YAML backup

# Log files left accessible
.log          # Application logs
access.log    # Web server access logs (reveals all URLs!)
error.log     # Error messages with stack traces
```

---

## Target Files That Matter Most

When you know the target's technology stack, you know exactly which files to check:

### PHP Applications (WordPress, Laravel, etc.)

```bash
# Check these on every PHP site:
wp-config.php.bak
wp-config.php.old
config.php.bak
configuration.php.bak   # Joomla
LocalSettings.php.bak   # MediaWiki
settings.php.bak        # Drupal
.htaccess.bak
```

### Python/Django/Flask

```bash
settings.py.bak
local_settings.py.bak
config.py.bak
.env.backup
requirements.txt.bak    # reveals all dependencies + versions
manage.py.bak
```

### Node.js Applications

```bash
.env.bak
.env.backup
.env.old
config.js.bak
database.js.bak
app.js.bak
package.json.bak        # reveals all dependencies
```

### Java / Spring Boot

```bash
application.properties.bak
application.yml.bak
hibernate.cfg.xml.bak
web.xml.bak
```

### Generic (Any Stack)

```bash
.env.bak
.env.backup
.env.local.bak
database.sql
backup.zip
backup.tar.gz
www.zip
htdocs.zip
public_html.zip
```

---

## How to Find Them — Tools and Techniques

### Method 1: Targeted Manual Testing

```bash
# Test known filenames with backup extensions
TARGET="https://target.com"

# Core files to check
CORE_FILES=(
    "config.php" "wp-config.php" ".env" "settings.py"
    "app.js" "config.js" "database.php" "connection.php"
)

EXTENSIONS=(".bak" ".old" ".orig" ".backup" "~" ".swp" ".zip")

for file in "${CORE_FILES[@]}"; do
    for ext in "${EXTENSIONS[@]}"; do
        url="${TARGET}/${file}${ext}"
        code=$(curl -sk -o /dev/null -w "%{http_code}" "$url")
        [ "$code" = "200" ] && echo "FOUND [$code]: $url"
    done
done
```

### Method 2: ffuf Extension Fuzzing

```bash
# Create backup extensions wordlist
cat > /tmp/backup_extensions.txt << 'EOF'
.bak
.backup
.old
.orig
~
.swp
.swo
.save
.copy
.cp
.bk
.1
.2
.tmp
EOF

# Fuzz known filename + backup extension
ffuf -u "https://target.com/config.phpFUZZ" \
    -w /tmp/backup_extensions.txt \
    -mc 200 -silent

# Fuzz directory for any backup files
ffuf -u "https://target.com/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
    -mc 200 \
    -t 50
```

### Method 3: nuclei Backup Templates

```bash
# nuclei has dedicated backup file detection templates
nuclei -u https://target.com -t exposures/files/backup-files.yaml -silent
nuclei -u https://target.com -t exposures/backups/ -silent

# Or scan a list of URLs
nuclei -l urls.txt -t exposures/backups/ -silent -o backup_findings.txt
```

### Method 4: Wayback Machine + CT Logs

```bash
# Old backup files may be indexed in Wayback
echo "target.com" | waybackurls | grep -iE "\.(bak|old|backup|sql|zip|tar)"

# Some CT logs capture backup file paths too
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    python3 -c "
import json,sys
for e in json.load(sys.stdin):
    n=e.get('name_value','')
    if any(x in n for x in ['.bak','.old','.sql','.zip']):
        print(n)
"
```

---

## Full Automated Workflow

```bash
#!/bin/bash
TARGET="${1:-https://target.com}"

echo "=== Backup File Discovery: $TARGET ==="

# Phase 1: Quick critical checks
echo "[1] Critical file checks..."
CRITICAL=(
    ".env" ".env.bak" ".env.backup" ".env.old" ".env.local"
    ".git/config" ".git/HEAD"
    "config.php.bak" "wp-config.php.bak" "wp-config.php.old"
    "database.sql" "backup.sql" "dump.sql"
    "backup.zip" "www.zip" "site.zip" "app.zip" "htdocs.zip"
    "config.js.bak" "settings.py.bak" "application.yml.bak"
)

for path in "${CRITICAL[@]}"; do
    code=$(curl -sk -o /tmp/resp.txt -w "%{http_code}" "$TARGET/$path")
    size=$(wc -c < /tmp/resp.txt)
    if [ "$code" = "200" ] && [ "$size" -gt 50 ]; then
        echo "  [CRITICAL CHECK] $TARGET/$path → $code ($size bytes)"
        head -3 /tmp/resp.txt | strings
        echo "---"
    fi
done

# Phase 2: ffuf comprehensive scan
echo "[2] Running ffuf backup scan..."
ffuf -u "$TARGET/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
    -mc 200 -fs 0 -silent | tee /tmp/backup_ffuf.txt
echo "  ffuf finds: $(wc -l < /tmp/backup_ffuf.txt)"

# Phase 3: nuclei templates
echo "[3] Running nuclei backup templates..."
nuclei -u "$TARGET" -t exposures/backups/ -silent -o /tmp/nuclei_backup.txt 2>/dev/null
cat /tmp/nuclei_backup.txt
```

---

## Exploiting a Found Backup File

### 1. Download and Read

```bash
# Download the backup
curl -sk https://target.com/config.php.bak -o config_backup.php

# Read it — even if it's PHP, the backup is served as raw text
cat config_backup.php

# Look for credentials
grep -iE "password|passwd|pass|secret|key|token|api" config_backup.php
```

### 2. Download .git and Extract Full Source

```bash
# .git directory means full source code
pip3 install git-dumper
git-dumper https://target.com/.git ./source_code/

# Search for secrets in the entire codebase
grep -rE "password|secret|api_key|token" source_code/ | grep -v ".git"

# Check git history for removed credentials
cd source_code
git log --oneline
git show --stat HEAD
git grep "password" $(git log --format="%H")
```

---

## Key Takeaways

```
1. Backup files are created by editors, developers, and deployment tools
2. Same directory as original = same web-accessible URL, just different extension
3. LOW severity for the technique — Critical for what's inside
4. Test: .bak .old .orig .backup ~ .swp .zip .sql on every known file
5. Priority files: .env, config.php, wp-config.php, settings.py, app.js
6. Tools: ffuf extension fuzzing, nuclei backup templates, manual curl
7. .git/ exposure → git-dumper → full source code + commit history
8. Always check Wayback Machine for historically accessible backup files
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
