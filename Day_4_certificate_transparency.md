# Certificate Transparency Log Mining: Every SSL Cert Is a Recon Gift

**Severity:** MEDIUM | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The Law That Made Hackers Happy

In 2013, Google proposed — and the CA/Browser Forum adopted — a requirement that changed recon forever: every SSL/TLS certificate issued by any trusted Certificate Authority must be **publicly logged** in Certificate Transparency (CT) logs before it can be trusted by browsers.

The intention was to catch rogue or misissued certificates. The side effect was that every company's subdomain infrastructure became publicly searchable — forever.

When a developer creates a new subdomain and gets an SSL certificate for it (which is nearly always), that subdomain name is written to a public log. You can query that log right now, for free, and see every subdomain that company has ever issued a certificate for.

---

## Understanding Certificate Transparency

### What Is a CT Log?

A CT log is essentially an append-only public database run by organisations like Google, Cloudflare, and DigiCert. Before a Certificate Authority can issue a certificate, they must submit it to at least two CT logs. The logs then provide a "Signed Certificate Timestamp" (SCT) that gets embedded in the certificate — proving it was logged.

```
Developer creates: staging.target.com
Gets SSL cert from: Let's Encrypt
Let's Encrypt submits to: Google's "Argon" CT log
Log records:        {
                      domain: "staging.target.com",
                      issuer: "Let's Encrypt",
                      issued: "2024-01-15",
                      expires: "2024-04-15"
                    }
You search crt.sh:  staging.target.com ← visible immediately
```

### Why It's MEDIUM Severity

CT log mining itself is not a vulnerability — it's a technique. We rate it MEDIUM because:
- It actively aids discovery of sensitive or hidden subdomains
- Those discoveries often lead to HIGH/CRITICAL bugs
- The data is passive (no noise), comprehensive, and permanent

---

## How to Query CT Logs

### Method 1: crt.sh Browser Interface (Fastest)

Go to `https://crt.sh` and search:

```
%25.target.com        → All subdomains (% is SQL wildcard)
staging.target.com    → Specific subdomain
target.com            → Exact domain only
```

The `%25` in the URL represents `%` which is the SQL LIKE wildcard — it matches any prefix.

You'll see a table with:
- **crt.sh ID** — unique certificate ID
- **Logged At** — when the cert was submitted
- **Not Before/After** — validity period (expired certs still useful!)
- **Common Name** — the main domain
- **Matching Identities** — ALL domains in the cert (this is gold)

### Method 2: crt.sh JSON API (Automatable)

```bash
# Basic query — returns JSON
curl -s "https://crt.sh/?q=%.target.com&output=json"

# Parse and extract unique subdomains
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    python3 -c "
import json, sys

try:
    data = json.load(sys.stdin)
except json.JSONDecodeError:
    print('No results or rate limited')
    sys.exit(1)

domains = set()
for cert in data:
    # name_value can contain multiple domains separated by newlines
    for name in cert.get('name_value', '').split('\n'):
        name = name.strip().lower()
        if name and not name.startswith('*'):  # Skip wildcard entries
            domains.add(name)
        elif name.startswith('*.'):
            # Add the root of wildcard too
            domains.add(name[2:])

for domain in sorted(domains):
    if 'target.com' in domain:
        print(domain)
" | sort -u > ct_subdomains.txt

wc -l ct_subdomains.txt
cat ct_subdomains.txt
```

### Method 3: CTFR Tool (Best Automated Option)

```bash
# Clone and install CTFR
git clone https://github.com/UnaPibaGeek/ctfr.git
cd ctfr
pip3 install -r requirements.txt

# Run against target
python3 ctfr.py -d target.com -o ct_results.txt

# Output:
# [*] ---- TARGET: target.com ----
# api.target.com
# dev.target.com
# staging.target.com
# internal-api.target.com
# ...
```

### Method 4: subfinder with CT Source

```bash
# subfinder uses crt.sh as one of its sources
# Run with CT as primary source
subfinder -d target.com -s certspotter,crtsh -silent

# Or enable all sources (includes CT logs)
subfinder -d target.com -all -silent
```

### Method 5: Multiple CT Log Aggregators

Different aggregators index different CT logs. Use multiple for maximum coverage:

```bash
# Certspotter (also very comprehensive)
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
domains = set()
for cert in data:
    for name in cert.get('dns_names', []):
        domains.add(name.lower())
for d in sorted(domains):
    print(d)
"
```

---

## The Hidden Gold: Historical and Expired Certificates

One thing most beginners don't realise: **expired certificates are just as valuable as current ones.**

When a company decommissions a subdomain, they stop renewing the certificate. But the certificate entry stays in CT logs forever. That subdomain might still be running — just without a valid cert.

```bash
# crt.sh shows ALL certificates including expired
# Filter by date to find old subdomains
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    python3 -c "
import json, sys
from datetime import datetime

data = json.load(sys.stdin)
now = datetime.now()
old_domains = set()

for cert in data:
    not_after = cert.get('not_after', '')
    if not_after:
        try:
            expiry = datetime.strptime(not_after, '%Y-%m-%dT%H:%M:%S')
            if expiry < now:  # Certificate has expired
                for name in cert.get('name_value', '').split('\n'):
                    name = name.strip().lstrip('*.')
                    if 'target.com' in name:
                        old_domains.add(name)
        except ValueError:
            pass

print('=== Subdomains from EXPIRED certificates ===')
for d in sorted(old_domains):
    print(d)
"
```

These old subdomains deserve specific attention:
- They may still be running on old, unpatched software
- The team that built them may no longer work there
- Security controls are likely minimal

---

## What to Look for in CT Log Results

### High-Value Subdomain Patterns

```bash
# After getting CT results, filter for interesting patterns
cat ct_subdomains.txt | grep -E \
    "dev|staging|test|qa|uat|beta|alpha|old|legacy|admin|dashboard|panel|manage|internal|api-v[0-9]|api-old|jenkins|gitlab|grafana|kibana|sonar|vault|secret"

# Development/staging environments
grep -E "^(dev|stg|staging|test|qa|uat|preprod)\." ct_subdomains.txt

# API versioning — old versions often have weaker auth
grep -E "api-v[0-9]|api/v[0-9]|api-old|api-legacy" ct_subdomains.txt

# Infrastructure tools (these should NOT be public)
grep -E "jenkins|grafana|kibana|sonarqube|jira|confluence|nexus|artifactory" ct_subdomains.txt

# Wildcard certs (tells you about subdomain patterns used)
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
wildcards = set()
for cert in data:
    for name in cert.get('name_value','').split('\n'):
        if name.startswith('*.'): wildcards.add(name)
for w in sorted(wildcards): print(w)
"
# *.internal.target.com → tells you there's an internal subdomain pattern
# *.api.target.com → tells you about API subdomain structure
```

---

## Full Automated CT Recon Pipeline

```bash
#!/bin/bash
TARGET="${1:-target.com}"
OUTPUT_DIR="ct_recon_${TARGET}"
mkdir -p "$OUTPUT_DIR"

echo "=== CT Log Mining for $TARGET ==="

# Step 1: crt.sh query
echo "[1] Querying crt.sh..."
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | \
    python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    domains = set()
    for cert in data:
        for name in cert.get('name_value','').split('\n'):
            name = name.strip().lstrip('*.')
            if '${TARGET}' in name and name:
                domains.add(name.lower())
    for d in sorted(domains): print(d)
except: pass
" > "$OUTPUT_DIR/crt_sh.txt"
echo "   crt.sh: $(wc -l < $OUTPUT_DIR/crt_sh.txt) subdomains"

# Step 2: certspotter query
echo "[2] Querying certspotter..."
curl -s "https://api.certspotter.com/v1/issuances?domain=${TARGET}&include_subdomains=true&expand=dns_names" | \
    python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    domains = set()
    for cert in data:
        for name in cert.get('dns_names', []):
            if '${TARGET}' in name:
                domains.add(name.lower().lstrip('*.'))
    for d in sorted(domains): print(d)
except: pass
" > "$OUTPUT_DIR/certspotter.txt"
echo "   certspotter: $(wc -l < $OUTPUT_DIR/certspotter.txt) subdomains"

# Step 3: Merge and deduplicate
cat "$OUTPUT_DIR"/*.txt | sort -u > "$OUTPUT_DIR/all_ct_subs.txt"
echo "[3] Total unique (merged): $(wc -l < $OUTPUT_DIR/all_ct_subs.txt)"

# Step 4: Resolve live subdomains
echo "[4] Resolving live subdomains..."
cat "$OUTPUT_DIR/all_ct_subs.txt" | dnsx -silent -resp -a \
    -o "$OUTPUT_DIR/live_subs.txt"
echo "   Live: $(wc -l < $OUTPUT_DIR/live_subs.txt)"

# Step 5: Find web servers
echo "[5] Probing for web services..."
cat "$OUTPUT_DIR/live_subs.txt" | httpx -silent -status-code -title \
    -o "$OUTPUT_DIR/web_services.txt"
echo "   Web services: $(wc -l < $OUTPUT_DIR/web_services.txt)"

# Step 6: Flag interesting findings
echo "[6] Interesting subdomains:"
grep -E "dev|staging|admin|internal|api-v|jenkins|grafana" \
    "$OUTPUT_DIR/all_ct_subs.txt"
```

---

## Reporting CT Log Findings

CT log mining is a technique, not a vulnerability. You report what you find ON the discovered subdomains. However, there are two edge cases worth noting:

### Finding 1: Sensitive Subdomain Names Publicly Visible

```
Title: Sensitive Infrastructure Subdomains Visible in Certificate 
       Transparency Logs

Severity: LOW (informational)

Description:
Certificate Transparency logs reveal internal infrastructure subdomain
naming conventions including:
- db-primary.target.com (database server)  
- vault.internal.target.com (secrets management)
- jenkins.target.com (CI/CD pipeline)

These names provide detailed infrastructure intelligence to attackers.

Remediation: 
Cannot be removed from CT logs (permanent). Prevent by using 
private PKI for internal services that should not be publicly known.
```

### Finding 2: Forgotten Subdomain Still Running

```
Title: Decommissioned Subdomain Still Active — Found via CT Logs

Severity: Depends on what's running there (LOW to CRITICAL)

Description:
CT log mining revealed old.target.com issued a certificate in 2022.
The certificate has expired. The subdomain still resolves and serves
an outdated application with [specific finding].
```

---

## Key Takeaways

```
1. CT logs record every SSL cert issued — mandatory by law since 2013
2. crt.sh is the most popular search interface — free, instant, JSON API
3. Zero noise — you read a public database, target never knows
4. Historical certs reveal old/decommissioned subdomains still worth testing
5. Wildcard cert entries reveal naming patterns used internally
6. Best finds: dev.*, staging.*, admin.*, api-v1.*, jenkins.*, grafana.*
7. Always combine CT results with reverse DNS for maximum coverage
8. Use CTFR tool or subfinder for automation at scale
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
