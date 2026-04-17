# Subdomain Takeover: How Hackers Claim Your Subdomain and Serve Malware From It

**Severity:** HIGH | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The Setup: A Real Scenario

A company launches a careers page at `careers.target.com`. They set up a Netlify site to host it, add a CNAME record in their DNS pointing `careers.target.com` → `target-careers.netlify.app`, and everything works fine.

Six months later, the product team migrates to a new job board platform. Someone deletes the Netlify site. But nobody tells the DNS team. The CNAME record stays in DNS — pointing to a Netlify address that no longer exists.

Now any attacker can create a FREE Netlify account, register `target-careers.netlify.app`, and immediately take full control of `careers.target.com`.

**That's subdomain takeover. And it's completely avoidable.**

---

## What Exactly Is a CNAME Record?

Before we go deeper, you need to understand what a CNAME record does.

DNS has different record types. An **A record** maps a domain directly to an IP address:
```
target.com  →  A  →  93.184.216.34
```

A **CNAME record** (Canonical Name) maps a domain to another domain name instead of an IP:
```
careers.target.com  →  CNAME  →  target-careers.netlify.app
```

When your browser visits `careers.target.com`, DNS says "go ask Netlify where this is" and Netlify serves the content.

**The vulnerability appears when:**
1. The CNAME record exists in DNS (`careers.target.com` → `target-careers.netlify.app`)
2. But the destination (`target-careers.netlify.app`) no longer exists
3. The external service (Netlify) is willing to let anyone claim that site name

---

## Why This Is HIGH Severity

Most bugs give you read access to data or the ability to inject content somewhere obscure. Subdomain takeover is different — it gives you full control of an **official company subdomain**.

Think about what that means:

### 1. Phishing on Steroids
```
Attacker controls careers.target.com
Attacker creates a fake login page that looks identical to the real one
Sends phishing email: "Please log in to apply for this position"
Email link points to careers.target.com — a REAL company domain
Victims have no reason to suspect it — it's the actual company's domain
```

### 2. Cookie Theft via Subdomain Scope
When a company sets a cookie with `domain=.target.com`, that cookie is sent to ALL subdomains — including `careers.target.com`. 

If an attacker controls `careers.target.com`, they can run JavaScript that reads those cookies and sends them to their server. This can lead to **account takeover** for any user who visits the attacker's subdomain while logged into the main site.

### 3. CSP and CORS Bypass
Many apps add subdomains to their **Content Security Policy** and **CORS allowlist**:
```
Content-Security-Policy: script-src 'self' *.target.com
Access-Control-Allow-Origin: careers.target.com
```

If an attacker controls `careers.target.com`, they can serve malicious scripts or make cross-origin API calls that bypass these security controls.

---

## The Attack Flow — Step by Step

### Step 1: Detect the Dangling CNAME

The attacker (or you, as a hunter) runs subdomain enumeration and finds `careers.target.com`. They check the DNS:

```bash
dig CNAME careers.target.com

# Output:
# careers.target.com.   3600   IN   CNAME   target-careers.netlify.app.
```

So `careers.target.com` points to `target-careers.netlify.app`. Now check if that Netlify site exists:

```bash
dig A target-careers.netlify.app

# Output:
# NXDOMAIN  (Non-Existent Domain — the site is gone!)
```

Or visit it in a browser and get a Netlify 404 page with a specific error message. Different services show different messages when the site is unclaimed:

```
Netlify:      "Not Found - Request ID: ..."
GitHub Pages: "There isn't a GitHub Pages site here."
Heroku:       "No such app"
AWS S3:       "NoSuchBucket"
Shopify:      "Sorry, this shop is currently unavailable."
Zendesk:      "Help Center Closed"
```

These specific error messages are the fingerprints that tools use to detect takeover opportunities.

### Step 2: Verify It's Claimable

Just because the destination doesn't exist doesn't mean you can claim it. Different services have different claim mechanisms:

```
Netlify:      Create an account → add custom domain OR create new site with that name
GitHub Pages: Create a repo named "[username].github.io" and configure the custom domain
Heroku:       heroku create target-careers → heroku domains:add careers.target.com
AWS S3:       aws s3 mb s3://target-careers → set up static hosting
Shopify:      Create a store → point domain to your store
```

Some services (like GitHub Pages) require you to verify domain ownership, which makes them harder to take over. Others (like old Netlify setups) have no verification — first come, first serve.

### Step 3: Claim and Control

Once you've registered the service with the matching name, your content is served from the company's real subdomain.

---

## How to Find These Vulnerabilities

### Manual Method

```bash
# Step 1: Get all subdomains (from subfinder, amass, crt.sh, etc.)
subfinder -d target.com -all -o subs.txt

# Step 2: Check CNAME records for each subdomain
cat subs.txt | while read sub; do
    cname=$(dig CNAME "$sub" +short)
    if [ -n "$cname" ]; then
        echo "$sub -> $cname"
    fi
done

# Step 3: For each CNAME, check if destination exists
dig A "$cname" | grep -q "NXDOMAIN" && echo "POTENTIAL TAKEOVER: $sub -> $cname"
```

### Tool: subjack (Most Popular)

```bash
# Install
go install github.com/haccer/subjack@latest

# Fingerprints file (maps services to their 404 messages)
# Download from: https://github.com/haccer/subjack/blob/master/fingerprints.json

# Run against subdomain list
subjack -w subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -o takeover_results.txt

# Check results
cat takeover_results.txt
# [VULNERABLE] careers.target.com - Netlify
# [Not Vulnerable] api.target.com - AWS
```

### Tool: nuclei (Template-Based)

```bash
# Install
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates (includes takeover templates)
nuclei -update-templates

# Run takeover templates
nuclei -l subs.txt -t takeovers/ -silent

# Output:
# [subdomain-takeover] [high] careers.target.com [netlify]
```

### Tool: subzy (Checks 90+ Services)

```bash
# Install
go install github.com/PentestPad/subzy@latest

# Run
subzy run --targets subs.txt

# Output shows vulnerable subdomains with service name
```

### Complete Automated Workflow

```bash
#!/bin/bash
TARGET="${1:-target.com}"

echo "[1] Enumerating subdomains..."
subfinder -d $TARGET -all -silent -o /tmp/subs_raw.txt
wc -l /tmp/subs_raw.txt

echo "[2] Resolving live subdomains..."
cat /tmp/subs_raw.txt | dnsx -silent -a -resp -o /tmp/subs_live.txt

echo "[3] Checking for subdomain takeover..."
subjack -w /tmp/subs_raw.txt -t 50 -timeout 30 \
    -c fingerprints.json -ssl -o /tmp/takeover_results.txt

echo "[4] Running nuclei takeover templates..."
nuclei -l /tmp/subs_raw.txt -t takeovers/ -silent \
    -o /tmp/nuclei_takeover.txt

echo "[5] Done! Results:"
cat /tmp/takeover_results.txt
cat /tmp/nuclei_takeover.txt
```

---

## What to Do When You Find One

### Verify It Thoroughly

Before reporting, confirm that you can actually take it over (or that a clear fingerprint confirms it):

1. Check the error message matches a known vulnerable service fingerprint
2. Confirm the CNAME points to an external service (not internal)
3. Try to access the unclaimed resource (e.g., the Netlify URL directly)
4. **Do NOT actually claim it** unless the bug bounty program explicitly allows it

### Document Your Evidence

```bash
# Capture DNS state
dig CNAME careers.target.com > evidence_cname.txt
dig A target-careers.netlify.app >> evidence_cname.txt

# Screenshot the error page from the provider
# e.g., visiting target-careers.netlify.app in browser → "Not Found"

# Screenshot the CNAME pointing to that URL
```

### The Bug Report

```
Title: Subdomain Takeover — careers.target.com via Netlify

Severity: HIGH

Description:
The subdomain careers.target.com has a CNAME record pointing to 
target-careers.netlify.app. This Netlify site no longer exists and 
is available for registration by anyone. An attacker can create a 
free Netlify account, register "target-careers" as a site name, and 
immediately serve arbitrary content from the legitimate company subdomain 
careers.target.com.

Steps to Reproduce:
1. Enumerate subdomains: subfinder -d target.com
2. Check CNAME: dig CNAME careers.target.com
   Result: careers.target.com → target-careers.netlify.app
3. Verify Netlify site is unclaimed: dig A target-careers.netlify.app
   Result: NXDOMAIN (site does not exist)
4. Visit https://target-careers.netlify.app → Netlify "Not Found" page
   (This confirms the site name is available to register)

Proof of Concept:
[Screenshot of dig CNAME output]
[Screenshot of Netlify Not Found page]

Impact:
- An attacker can serve a phishing page from careers.target.com
- Session cookies scoped to .target.com are accessible from this subdomain
- This subdomain may be on the CSP allowlist, enabling script injection

Remediation:
Remove the CNAME record for careers.target.com from DNS, or point it 
to a controlled server. Implement a process to audit DNS records when 
external services are decommissioned.

CVSS: 8.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)
```

---

## Prevention — What Developers Should Do

1. **Audit DNS on service decommission** — when you delete a Netlify/Heroku/S3 resource, also delete the DNS record
2. **Use dangling DNS scanners in CI/CD** — tools like `dnscontrol` or `octodns` can alert on dangling records
3. **Domain ownership verification** — use services that require domain verification (not all do)
4. **Monitor with cloud providers** — AWS Route 53 and Cloudflare have built-in dangling record alerts

---

## Key Takeaways

```
1. Subdomain takeover = dangling CNAME pointing to unclaimed external resource
2. Attacker claims the resource → controls the company's subdomain
3. Impact: phishing, cookie theft, CSP bypass — all using trusted domain
4. Detection: subjack, nuclei takeover templates, subzy
5. Always check CNAME records during recon — not just A records
6. Report with CNAME evidence + provider fingerprint, don't actually claim
7. Severity escalates if cookies are scoped to .target.com (parent domain)
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
