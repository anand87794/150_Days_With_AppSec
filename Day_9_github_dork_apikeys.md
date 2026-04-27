# GitHub Dorking: Finding API Keys & Secrets in Public Code

**Severity:** MEDIUM | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The Goldmine Nobody Locks

GitHub indexes billions of lines of code written by developers around the world. Every commit, every config file, every accidentally pushed `.env` — all searchable. GitHub's search operators let you write precise queries to find exactly what you're looking for across all public repos.

For bug bounty hunters and pentesters, this is one of the highest-ROI recon techniques: completely passive, zero requests to the target, and the payoff is often a Critical finding in minutes.

---

## Why Secrets End Up on GitHub

The commit cycle is the culprit:

```
Developer adds API key to code for local testing
     ↓
"git add ."  ← key is now staged
     ↓
"git commit -m 'fix auth'"  ← key is in history FOREVER
     ↓
"git push"  ← key is on GitHub
     ↓
Developer notices, deletes key from code
     ↓
"git commit -m 'remove key'"  ← but it's still in commit history
```

**The critical mistake:** Deleting a file from the current code doesn't remove it from git history. `git log --all -p` shows every change ever made, including the line where the key was added.

---

## GitHub Search Operators — The Building Blocks

```bash
# Search scope operators
org:company_name          # only this organisation's repos
repo:user/repo-name       # one specific repo
user:username             # one specific user's repos

# File-level operators
filename:.env             # files with this exact name
filename:config.js        # files named config.js
extension:py              # all Python files
path:/config/             # files inside /config/ directory
path:/src/api/            # files inside /src/api/

# Content operators
"api_key"                 # exact string match
"secret" "password"       # both strings present in same file
"AKIA" NOT "example"      # contains AKIA but not 'example'

# Combine them
org:target filename:.env "SECRET"
org:target "api_key" extension:js
```

---

## The Dork Playbook — API Keys

Paste these directly into GitHub search (`github.com/search?q=...&type=code`):

### AWS Keys
```
org:target "AKIA"
org:target "aws_access_key_id"
org:target "aws_secret_access_key"
```

### Stripe Keys
```
org:target "sk_live_"
org:target "pk_live_"
org:target "sk_test_" OR "pk_test_"
```

### Generic API Keys
```
org:target "api_key" OR "API_KEY" OR "apiKey"
org:target "secret_key" OR "SECRET_KEY"
org:target filename:.env "KEY"
org:target filename:config.json "key"
```

### Google / Firebase
```
org:target "AIzaSy"
org:target "google_api_key"
org:target ".firebaseio.com"
```

### JWT / Auth Tokens
```
org:target "jwt_secret" OR "JWT_SECRET"
org:target "signing_secret"
org:target "token" filename:.env
```

### Slack / Webhooks
```
org:target "hooks.slack.com"
org:target "xoxb-" OR "xoxp-"
```

---

## Automating with truffleHog

truffleHog is the gold standard for secret scanning — it detects secrets using regex and entropy analysis, and crucially, scans the **entire git history**, not just the current code.

```bash
# Install
pip3 install trufflehog --break-system-packages

# Scan a specific repo (all commits)
trufflehog git https://github.com/target/repo-name

# Only show verified live secrets (reduces false positives massively)
trufflehog git https://github.com/target/repo-name --only-verified

# Scan entire GitHub org
trufflehog github --org=target-company --only-verified

# Output as JSON for piping
trufflehog git https://github.com/target/repo --json | python3 -m json.tool
```

### What truffleHog Finds

```
[HIGH] AWS Access Key (verified live)
  Detector: AWS
  File: src/config/prod.js
  Commit: a3f9d2c (2023-04-12)
  Secret: AKIAXXXXXXXXXXXXXXXX
  
[HIGH] Stripe Secret Key (verified live)
  Detector: Stripe
  File: .env
  Commit: b8e1f44 (2023-01-08)
  Secret: sk_live_51Nxxxxxxxxx
```

---

## Automating with gitleaks

```bash
# Install
go install github.com/zricethezav/gitleaks/v8@latest

# Scan a local cloned repo
git clone https://github.com/target/repo
gitleaks detect --source=./repo -v

# JSON output
gitleaks detect --source=./repo --report-format json --report-path leaks.json

# Scan with a custom config (add your own patterns)
gitleaks detect --source=./repo --config=custom.toml
```

---

## The Git History Trick

Even after a dev deletes a secret from the codebase, it lives in commits:

```bash
# Clone the repo
git clone https://github.com/target/repo
cd repo

# Search ALL commits for secrets (including deleted)
git log --all -p | grep -i "password\|secret\|api_key\|token" | head -50

# More targeted
git log --all -p | grep -E "AKIA[A-Z0-9]{16}" | head -20

# See what changed in specific commit
git show <commit_hash>

# List all commits that touched a specific file
git log --all --follow -- .env
git show $(git log --all --follow --format="%H" -- .env | head -1)
```

---

## Key Takeaways

```
1. GitHub indexes ALL public code — including historical commits
2. org: operator is the most important — scope to your target
3. Dork for: API keys, DB passwords, JWT secrets, OAuth tokens
4. truffleHog with --only-verified = fewer false positives
5. Always check git history — deletion doesn't erase commits
6. gitleaks checks 150+ secret patterns automatically
7. Report immediately with evidence — rotate the key first
8. Severity: MEDIUM discovery, CRITICAL impact when key is live
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
