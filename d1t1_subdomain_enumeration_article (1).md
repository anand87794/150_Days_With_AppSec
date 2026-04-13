# Subdomain Enumeration: Finding Every Entry Point Before the Attacker Does

**Severity:** LOW | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The First Thing Every Hacker Does

Before a penetration tester or bug bounty hunter sends a single exploit payload, before they touch a login form or look at an API — they do recon. And the very first step of recon is almost always **subdomain enumeration**.

Here's the simple truth: every company has one main website, but usually dozens or hundreds of subdomains. Things like `api.company.com`, `dev.company.com`, `admin.company.com`, `staging.company.com`. Each one is a completely separate web application, often built by a different team, running different software, with different security controls.

The main site might be perfectly secured. But that forgotten staging server from three years ago? That's where your P1 bug is hiding.

---

## What Is a Subdomain?

Let's start from the very beginning.

A domain looks like this: `target.com`

A subdomain is anything that comes before the main domain with a dot:
```
api.target.com         → API service
admin.target.com       → Admin panel
dev.target.com         → Development environment
staging.target.com     → Pre-production testing server
mail.target.com        → Email server
vpn.target.com         → VPN portal
app.target.com         → Main web application
beta.target.com        → Beta version of the app
```

Every single one of these is potentially a separate attack surface — different server, different code, different vulnerabilities.

---

## Why Subdomain Enumeration Matters in Pentesting

### The Developer Mindset Problem

When developers build new features or services, they often spin up new subdomains for testing:

```
dev.target.com      → "Just for internal testing, no one knows this URL"
staging.target.com  → "This is only for QA, not exposed to public"
old.target.com      → "We migrated, but left the old server running"
```

They never announce these URLs publicly. They assume "security through obscurity" — if no one knows the URL, no one can attack it. But here's the problem: **DNS records are public**. Anyone can look up what subdomains exist.

### Real Impact of Subdomain Enumeration Findings

Subdomain enumeration itself isn't a bug — it's a recon technique. But what you find on those subdomains often leads to critical bugs:

```
dev.target.com         → Debug mode ON → full error messages with DB credentials
staging.target.com     → Admin portal with default password admin:admin
old.target.com         → WordPress 4.x → dozens of known CVEs → RCE
api-test.target.com    → No authentication on API endpoints → data breach
jenkins.target.com     → Jenkins with no login → CI/CD pipeline access
```

---

## Two Types of Subdomain Enumeration

### Type 1: Passive Recon (Silent, No Touch)

You never send a single packet to the target. You gather information from third-party sources that have already indexed the target's DNS data.

**Why passive first?** Many companies have bug bounty rules that prohibit aggressive scanning. Passive recon is completely undetectable.

**Source 1: Certificate Transparency Logs (crt.sh)**

When a company gets an SSL/TLS certificate, it's publicly logged in "Certificate Transparency Logs." These logs contain the domain names the certificate covers — including subdomains.

```bash
# Visit crt.sh in browser:
# https://crt.sh/?q=%.target.com

# Or use the API via curl:
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
domains = set()
for entry in data:
    name = entry.get('name_value', '')
    for d in name.split('\n'):
        domains.add(d.strip().lstrip('*.'))
for d in sorted(domains):
    print(d)
" | grep "target.com"
```

This often returns 50-200 subdomains in seconds, completely passively.

**Source 2: SecurityTrails (free tier available)**

SecurityTrails maintains historical DNS data. Go to `securitytrails.com`, search your target, and see all subdomains they've ever seen.

**Source 3: VirusTotal Passive DNS**

```bash
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=YOUR_KEY&domain=target.com" | \
    python3 -c "import json,sys; data=json.load(sys.stdin); [print(s) for s in data.get('subdomains',[])]"
```

**Source 4: Shodan**

```bash
# Shodan CLI (pip install shodan)
shodan search --fields hostnames "hostname:target.com" | tr ',' '\n' | grep target.com | sort -u
```

### Type 2: Active Recon (DNS Brute Force)

You send DNS queries to public DNS resolvers, asking "does this subdomain exist?" for thousands of common names.

```
Does "mail.target.com" exist?   → YES → found!
Does "admin.target.com" exist?  → YES → found!
Does "purple.target.com" exist? → NO  → skip
Does "api.target.com" exist?    → YES → found!
```

---

## Tools — The Full Arsenal

### subfinder (Best Starting Point)

```bash
# Install
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Basic usage
subfinder -d target.com

# With all sources enabled (slower but more complete)
subfinder -d target.com -all

# Save output
subfinder -d target.com -all -o subdomains_raw.txt

# Multiple targets
subfinder -dL targets.txt -o subdomains_raw.txt
```

subfinder queries 50+ passive sources (crt.sh, SecurityTrails, Shodan, etc.) simultaneously. It's fast, quiet, and usually the first tool you run.

### amass (Most Comprehensive)

```bash
# Install
go install -v github.com/owasp-amass/amass/v4/...@master

# Passive only (quiet mode)
amass enum -passive -d target.com -o amass_results.txt

# Active + Passive (more aggressive, more results)
amass enum -d target.com -o amass_results.txt

# Visualize the results
amass viz -d3 -dir ~/.config/amass -o graph.html
```

amass is slower but finds subdomains that subfinder misses. Run it in parallel.

### dnsx (Resolve and Verify Live Subdomains)

```bash
# Install
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Resolve subdomains — find which ones are actually live
cat subdomains_raw.txt | dnsx -resp -a

# Output format:
# api.target.com [10.20.30.40]
# admin.target.com [10.20.30.41]
# staging.target.com [NXDOMAIN]  ← this one is dead, skip it
```

### httpx (Find Which Have Web Servers)

```bash
# Install
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Check which live subdomains have HTTP/HTTPS running
cat live_subdomains.txt | httpx -title -tech-detect -status-code

# Output:
# https://admin.target.com [200] [Admin Panel] [WordPress 5.8]
# https://api.target.com [401] [API Gateway] [Express]
# https://dev.target.com [200] [Development Build] [Django 3.1]
```

---

## The Complete Workflow (Run This on Every Target)

```bash
#!/bin/bash
TARGET="${1:-target.com}"

echo "[1] Passive recon with subfinder..."
subfinder -d $TARGET -all -silent -o 01_subfinder.txt

echo "[2] Certificate transparency with crt.sh..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
    python3 -c "
import json,sys
d=json.load(sys.stdin)
s=set()
for e in d:
    for n in e.get('name_value','').split('\n'):
        n=n.strip().lstrip('*.')
        if '$TARGET' in n: s.add(n)
for x in sorted(s): print(x)
" > 02_crtsh.txt

echo "[3] Merging all sources..."
cat 01_subfinder.txt 02_crtsh.txt | sort -u > 03_all_subs.txt
echo "Total unique subdomains: $(wc -l < 03_all_subs.txt)"

echo "[4] Resolving live subdomains..."
cat 03_all_subs.txt | dnsx -resp -a -silent -o 04_live_subs.txt
echo "Live subdomains: $(wc -l < 04_live_subs.txt)"

echo "[5] Finding web services..."
cat 04_live_subs.txt | httpx -title -tech-detect -status-code -silent -o 05_web_alive.txt
echo "Web services found: $(wc -l < 05_web_alive.txt)"

echo "[6] Done! Check 05_web_alive.txt for interesting targets."
cat 05_web_alive.txt
```

---

## What to Look For in Results

After running the workflow, look for these high-value patterns:

```bash
# Status code 200 with interesting titles
grep "200" 05_web_alive.txt | grep -iE "admin|panel|dashboard|login|internal|dev|test|staging"

# Old/vulnerable tech versions
grep -iE "wordpress [0-4]\.|drupal [0-8]\.|joomla [0-3]\." 05_web_alive.txt

# Exposed services (shouldn't be public)
grep -iE "jenkins|grafana|kibana|sonarqube|jira|confluence" 05_web_alive.txt

# Development/staging environments
grep -iE "dev\.|staging\.|test\.|qa\.|uat\." 05_web_alive.txt
```

---

## Reporting Subdomain Enumeration Findings

Subdomain enumeration itself isn't reportable. But the bugs you find ON those subdomains are.

**If you find a sensitive subdomain that shouldn't be public:**

```
Title: Staging Environment Exposed Publicly — dev.target.com

Severity: MEDIUM (information disclosure) to CRITICAL (depending on content)

Description:
The subdomain dev.target.com is publicly accessible and appears to be a 
development/staging environment. The server is running in debug mode, 
exposing full stack traces and internal configuration details in error messages.

Steps to Reproduce:
1. Browse to https://dev.target.com
2. Visit https://dev.target.com/nonexistent-page
3. Observe: full Django debug page with database credentials and SECRET_KEY

Impact:
[Describe what you found — credentials, source code, internal data, etc.]
```

---

## Key Takeaways

```
1. Always do subdomain enumeration FIRST — before any other testing
2. Passive recon first (crt.sh, subfinder) — quiet, undetectable
3. Active recon second (amass) — more complete, some noise
4. Resolve with dnsx → only test live subdomains
5. httpx → prioritize by tech stack and title
6. The best bugs hide on forgotten, unmonitored subdomains
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:**
- LinkedIn: [linkedin.com/in/anand-prajapati-7a265a369](https://linkedin.com/in/anand-prajapati-7a265a369)
- GitHub: [github.com/anand87794](https://github.com/anand87794)
- Portfolio: [anandprajapati.lovable.app](https://anandprajapati.lovable.app)
- X (Twitter): [@anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, 300 posts, real security education.*
