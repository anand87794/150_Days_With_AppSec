# GitHub Dork: Hardcoded Credentials in Git History

**Severity:** MEDIUM | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## Deleted From Code. Not From Git. Never.

This is the one that gets developers every time. They write a database password directly into the code, push it, realize the mistake, delete it, push again — and think they're safe.

They're not. Git stores every version of every file that was ever committed. The password is still there in commit history. Anyone with read access to the repo — or anyone on the internet if it was ever public even briefly — can see it.

Hardcoded credentials in git history are one of the most common Critical findings in bug bounties because the fix looks obvious (delete it) but doesn't actually work.

---

## Why Developers Hardcode Credentials

### The "I'll Fix It Later" Pattern
```python
# config.py (committed Friday at 6pm)
DB_HOST = "db.target.com"
DB_USER = "admin"
DB_PASS = "P@ssw0rd2024!"  # TODO: move to env before production

# Monday morning: push to prod
# Tuesday: security audit finds it
# "I deleted it!" — but git log shows the commit
```

### The Accidental .env Commit
```bash
# Developer runs:
git add .
git commit -m "add new feature"
# .env was not in .gitignore → committed with all credentials
# Developer realizes, adds .env to .gitignore, commits again
# But .env content is already in commit a3f9d2c FOREVER
```

### The CI/CD Auto-Config Mistake
```yaml
# ci-config.yml committed to repo
deploy:
  env:
    DATABASE_URL: postgresql://admin:LivePassword123@prod-db.internal:5432/mydb
    REDIS_URL: redis://:RedisPass456@cache.internal:6379
```

---

## What Gets Hardcoded Most Often

### Database Connection Strings
```python
# Python/Django
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'mydb',
        'USER': 'admin',
        'PASSWORD': 'SuperSecret123!',  # ← hardcoded
        'HOST': 'db.target.com',
    }
}

# Node.js
const db = mysql.createConnection({
    host: 'db.target.com',
    user: 'root',
    password: 'rootpass2024',  # ← hardcoded
    database: 'production'
});

# Direct connection string
mongodb://admin:MongoPass!@mongo.target.internal:27017/mydb
postgresql://dbuser:DbPassword@10.0.0.5:5432/app
```

### Email / SMTP Credentials
```python
SMTP_HOST = 'smtp.gmail.com'
SMTP_USER = 'noreply@target.com'
SMTP_PASS = 'EmailPassword123!'   # ← email account access

EMAIL_HOST_PASSWORD = 'app_specific_password'
```

### Admin / Service Account Passwords
```javascript
const ADMIN_CREDENTIALS = {
    username: 'admin',
    password: 'Admin@2024',  // TODO: change before prod
    secret: 'mySecretKey123'
};
```

### Internal Service Tokens
```python
INTERNAL_API_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
REDIS_AUTH = "redis_password_prod_2024"
RABBITMQ_PASS = "rabbit_mq_admin_pass"
```

---

## GitHub Dorks for Credentials

### Database Passwords
```
org:target "DB_PASSWORD" OR "db_pass" OR "database_password"
org:target "MYSQL_PASS" OR "POSTGRES_PASS"
org:target "mongodb://" OR "postgresql://" OR "mysql://"
org:target filename:database.yml "password:"
org:target filename:settings.py "PASSWORD"
```

### SMTP / Email
```
org:target "SMTP_PASS" OR "smtp_password" OR "email_password"
org:target "EMAIL_HOST_PASSWORD"
org:target "sendgrid_api_key" OR "mailgun_api_key"
```

### Django / Rails Secrets
```
org:target "SECRET_KEY" filename:settings.py
org:target "secret_key_base" filename:secrets.yml
org:target "DJANGO_SECRET_KEY"
```

### CI/CD Config Files
```
org:target filename:.travis.yml "password"
org:target filename:Jenkinsfile "credentials"
org:target filename:.gitlab-ci.yml "password"
org:target filename:docker-compose.yml "PASS"
```

### Connection Strings
```
org:target "Server=" "Password=" filename:.config
org:target "connectionString" "password"
org:target "Data Source=" "Password="
```

---

## Hunting in Git History

Current code clean? Check every commit:

```bash
# Clone the repo
git clone https://github.com/target/repo
cd repo

# Search entire history for password patterns
git log --all -p | grep -iE "(password|passwd|DB_PASS|secret|api_key)\s*[=:]\s*['\"]" | head -30

# More targeted — find the actual value
git log --all -p | grep -E "password\s*=\s*['\"][^'\"]{6,}['\"]" | head -20

# Search for connection strings in history
git log --all -p | grep -E "(mongodb|postgresql|mysql|redis)://" | head -20

# Find commits that touched .env files
git log --all --follow --diff-filter=A -- "*.env" "**/.env"
git show $(git log --all --format="%H" -- .env | head -1)

# Check if .env was ever committed (even if now in .gitignore)
git log --all -- .env
# If this shows commits → .env was committed → check those commits
```

### Automated with truffleHog (Scans All History)

```bash
# truffleHog checks entropy + regex across ALL commits
trufflehog git https://github.com/target/repo --only-verified

# Org-wide scan
trufflehog github --org=target --only-verified

# Output example:
# ✅ Verified True Positive
# Detector: Postgres
# File: config/database.yml  
# Line: 8
# Commit: 3f9a2d1
# Branch: main
# Author: dev@target.com
# Secret: postgresql://admin:LiveProdPass@db.internal/app
```

### Automated with gitleaks

```bash
# Scan cloned repo
gitleaks detect --source=./repo --report-format json -v

# gitleaks.toml — add custom rules
[[rules]]
id = "custom-internal-token"
description = "Internal API Token"
regex = '''INTERNAL_[A-Z_]+\s*=\s*['"][a-zA-Z0-9+/]{20,}['"]'''
```

---

## Complete Recon Workflow

```bash
#!/bin/bash
ORG="${1:-target-company}"
TOKEN="${GITHUB_TOKEN}"

echo "=== GitHub Cred Hunt: $ORG ==="

# Step 1: List all public repos
curl -s -H "Authorization: token $TOKEN" \
    "https://api.github.com/orgs/$ORG/repos?per_page=100" | \
    python3 -c "import json,sys; [print(r['clone_url']) for r in json.load(sys.stdin)]" \
    > /tmp/repos.txt
echo "Repos: $(wc -l < /tmp/repos.txt)"

# Step 2: Run truffleHog on each repo
mkdir -p /tmp/findings
while read url; do
    repo_name=$(basename "$url" .git)
    echo "Scanning: $repo_name"
    trufflehog git "$url" --only-verified --json \
        > "/tmp/findings/${repo_name}.json" 2>/dev/null
done < /tmp/repos.txt

# Step 3: Aggregate findings
echo ""
echo "=== FINDINGS ==="
cat /tmp/findings/*.json 2>/dev/null | \
    python3 -c "
import json, sys
for line in sys.stdin:
    try:
        d = json.loads(line)
        print(f\"[{d.get('DetectorType','?')}] {d.get('SourceMetadata',{}).get('Data',{})}\")
    except: pass
"
```

---

## Key Takeaways

```
1. Hardcoded creds = credentials written directly into source files
2. Deleting doesn't help — git history preserves every commit
3. CI/CD config files (travis, Jenkinsfile, docker-compose) are goldmines
4. Check git log --all -p BEFORE concluding no secrets in repo
5. truffleHog --only-verified = verified live secrets only (high confidence)
6. gitleaks covers 150+ patterns including custom rules
7. DB connection strings expose host, port, user AND password together
8. Report with the commit hash, file path, and rotate key immediately
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:**
| Platform | Link |
|----------|------|
| 💼 LinkedIn | [linkedin.com/in/anand-prajapati-7a265a369](https://linkedin.com/in/anand-prajapati-7a265a369) |
| 🐙 GitHub | [github.com/anand87794](https://github.com/anand87794) |
| 🌐 Portfolio | [anandprajapati.lovable.app](https://anandprajapati.lovable.app) |
| 🐦 X | [@anand87794](https://x.com/anand87794) |

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
