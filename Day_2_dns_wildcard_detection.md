# DNS Wildcard Detection: Why Your Recon Results Are Lying to You

**Severity:** LOW | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The Problem With "Everything Exists"

You're running subdomain brute-force on a target. Your tool is flying through a wordlist, testing thousands of names. Then you see this:

```
test.target.com           → 93.184.216.34
admin.target.com          → 93.184.216.34
api.target.com            → 93.184.216.34
thisiscompletelyfake.target.com → 93.184.216.34
xyzabc999notreal.target.com    → 93.184.216.34
```

Every single subdomain resolves to the same IP. Even completely nonsense ones. **You've hit a wildcard DNS configuration** — and if you don't detect it, your entire recon is garbage.

---

## What Is a DNS Wildcard?

A DNS wildcard is a special record that matches **any subdomain** that isn't explicitly defined. It's written with an asterisk (*):

```
*.target.com  →  A  →  93.184.216.34
```

This tells DNS servers: "If someone asks for ANY subdomain of target.com that doesn't have its own specific record, return this IP address."

### Why Companies Use Wildcards

Wildcards aren't always malicious or misconfigured. Companies use them for legitimate reasons:

```
SaaS platforms:    customer1.saas.com → main server (customer is identified by hostname)
Error handling:    Catch all unknown subdomains → redirect to homepage
CDN setups:        Route all subdomains through a CDN entry point
Multi-tenant apps: Each tenant gets a subdomain, all point to same load balancer
```

The problem isn't that wildcards exist. The problem is **when recon tools don't detect them** and treat every fabricated subdomain as real.

---

## How Wildcards Break Subdomain Brute-Force

Let's walk through exactly what happens when a wildcard is active.

### Without Wildcard (Normal Behavior)

```bash
# Testing: does "fakename.target.com" exist?
dig A fakename.target.com

# Output (no wildcard):
# ;; ANSWER SECTION: (empty)
# ;; AUTHORITY SECTION:
# target.com.   3600   IN   SOA   ns1.target.com. ...
# Status: NXDOMAIN

# Tool correctly marks "fakename.target.com" as non-existent → skip it
```

### With Wildcard (Broken Behavior)

```bash
# Testing: does "fakename.target.com" exist?
dig A fakename.target.com

# Output (wildcard active):
# ;; ANSWER SECTION:
# fakename.target.com.   300   IN   A   93.184.216.34
# Status: NOERROR

# Tool thinks "fakename.target.com" is a real, live server
# It adds it to results along with 10,000 other fake subdomains
# Your results are now completely useless noise
```

If you're brute-forcing with a 10,000-word wordlist and the target has a wildcard, you'll get **10,000 "discoveries"** — all pointing to the same IP, all fake. You have to filter these out before your recon means anything.

---

## Detecting a Wildcard — The Simple Test

The detection method is elegant: **generate a subdomain name so random that it could never actually exist, and check if it resolves.**

```bash
# Generate a random test subdomain
RANDOM_SUB="zjqx9k2m7p$(date +%s)random"
TARGET="target.com"

echo "Testing: ${RANDOM_SUB}.${TARGET}"
dig A "${RANDOM_SUB}.${TARGET}"

# If this returns an IP address → WILDCARD IS ACTIVE
# If this returns NXDOMAIN → No wildcard (normal behavior)
```

The logic: if a completely random, never-registered subdomain resolves, it's not because it actually exists — it's because the wildcard is catching all queries.

### One-Liner Detection Script

```bash
#!/bin/bash
TARGET="${1:-target.com}"

# Generate three random test subdomains
for i in 1 2 3; do
    RAND="wildcard-test-$(openssl rand -hex 8)"
    RESULT=$(dig A "$RAND.$TARGET" +short)
    if [ -n "$RESULT" ]; then
        echo "[WILDCARD DETECTED] $TARGET → All subdomains resolve to: $RESULT"
        echo "Wildcard IP: $RESULT"
        break
    fi
done

if [ -z "$RESULT" ]; then
    echo "[NO WILDCARD] $TARGET behaves normally"
fi
```

---

## The Wildcard IP — Your New Filter

Once you detect a wildcard, you now know the **wildcard IP address**. Every subdomain that resolves to this IP is a false positive. You filter it out:

```bash
# You detected: wildcard IP = 93.184.216.34

# Run normal subdomain resolution
cat all_subdomains.txt | dnsx -resp -a -silent > all_resolved.txt

# Filter OUT the wildcard IP → keep only real subdomains
grep -v "93.184.216.34" all_resolved.txt > real_subdomains.txt

# Now real_subdomains.txt contains only genuine subdomains
# that have their own specific DNS records
```

---

## Tools That Handle Wildcards Automatically

Modern recon tools detect and filter wildcards without you needing to do it manually. Here's how each one handles it:

### dnsx — The Most Direct Approach

```bash
# dnsx with wildcard detection enabled
dnsx -l subdomains.txt -wd target.com -resp -a -silent

# -wd flag: wildcard domain → dnsx detects wildcard IP first,
#           then filters all results matching that IP
# Output: only real, unique subdomains
```

### puredns — Purpose-Built for This Problem

```bash
# Install
go install github.com/d3mondev/puredns/v2@latest

# puredns is specifically designed to handle wildcard DNS
# It resolves at scale while accurately detecting wildcards
puredns resolve subdomains.txt -r resolvers.txt

# Also works for brute-force:
puredns bruteforce wordlist.txt target.com -r resolvers.txt
```

puredns works by:
1. Sending random test queries to detect wildcard IPs
2. During resolution, filtering any result matching wildcard IPs
3. Re-checking ambiguous results with multiple DNS resolvers

### amass — Automatic Wildcard Handling

```bash
# amass detects wildcards automatically during enumeration
amass enum -d target.com -o results.txt

# It internally tests for wildcards and excludes matching results
# No extra flags needed
```

### massdns — Manual Filtering Required

```bash
# massdns doesn't filter wildcards natively
# Use it with a filter step
massdns -r resolvers.txt -t A subdomains.txt > raw_results.txt

# Detect wildcard IP first
WILDCARD_IP=$(dig A "zzzfake99999.target.com" +short)

# Filter it out
grep -v "$WILDCARD_IP" raw_results.txt > clean_results.txt
```

---

## Multiple Wildcard IPs — The Harder Case

Some companies use load balancers or CDNs that return **different IPs for the same wildcard query** (round-robin DNS). This makes filtering by IP unreliable:

```bash
dig A fakename1.target.com  →  93.184.216.34
dig A fakename2.target.com  →  93.184.216.35   ← different IP!
dig A fakename3.target.com  →  93.184.216.36   ← different IP!
```

### How to Handle This

```bash
# Strategy: collect multiple wildcard IPs
WILDCARD_IPS=()
for i in $(seq 1 10); do
    RAND="test$(openssl rand -hex 6)"
    IP=$(dig A "$RAND.target.com" +short | head -1)
    [ -n "$IP" ] && WILDCARD_IPS+=("$IP")
done

# Deduplicate wildcard IPs
UNIQUE_WC_IPS=($(echo "${WILDCARD_IPS[@]}" | tr ' ' '\n' | sort -u))
echo "Wildcard IPs detected: ${UNIQUE_WC_IPS[@]}"

# Build grep filter
FILTER=$(IFS='|'; echo "${UNIQUE_WC_IPS[*]}")
grep -vE "$FILTER" all_resolved.txt > clean_subdomains.txt
```

Better approach: use **puredns** or **dnsx -wd** which handle this internally.

---

## Wildcard + HTTP Response Validation

Even after DNS filtering, some wildcard setups return NXDOMAIN at DNS level but serve a real page at HTTP level (or vice versa). Always validate with HTTP probing:

```bash
# After DNS filtering, probe HTTP responses
cat clean_subdomains.txt | httpx -silent -status-code -title -content-length

# Look for different status codes or content lengths
# Real subdomains usually have unique content
# Wildcard catch-all pages usually have identical content/length

# Filter by unique content length
cat clean_subdomains.txt | httpx -silent -status-code -content-length | \
    awk '{print $3}' | sort | uniq -c | sort -rn
# Most common content-length = probably wildcard catch-all
# Less common content-lengths = real, unique subdomains
```

---

## When Wildcards Create Their Own Bug

In most cases, wildcard DNS is not a vulnerability — it's just a configuration that affects your recon. But in some scenarios, it IS a finding:

### Scenario 1: Wildcard + Subdomain Takeover Risk
```
*.target.com → CloudFront distribution
CloudFront distribution is misconfigured → accepts any hostname
Any attacker can point their domain to this CloudFront → subdomain confusion
```

### Scenario 2: Wildcard Exposing Internal Functionality
```
*.internal.target.com → 10.0.0.1 (internal server)
Wildcard is publicly DNS-accessible
Attacker can enumerate internal service names
```

### Scenario 3: Cookie Scope Issues
```
If *.target.com all resolve to same server
And cookies are set with domain=.target.com
Any subdomain (including attacker-controlled via takeover) can read those cookies
```

**Severity for wildcard itself:** LOW to INFORMATIONAL  
**Severity when chained:** Escalates based on what the chain enables

---

## The Complete Wildcard-Aware Recon Flow

```bash
#!/bin/bash
TARGET="${1:-target.com}"
WORDLIST="${2:-/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt}"

echo "[1] Checking for wildcard DNS..."
WILDCARD_IP=$(dig A "$(openssl rand -hex 12).$TARGET" +short | head -1)

if [ -n "$WILDCARD_IP" ]; then
    echo "  WILDCARD DETECTED: All unknown subdomains resolve to $WILDCARD_IP"
    echo "  Activating wildcard filtering..."
    WILDCARD_ACTIVE=true
else
    echo "  No wildcard detected. Normal enumeration."
    WILDCARD_ACTIVE=false
fi

echo "[2] Running subdomain enumeration..."
subfinder -d $TARGET -all -silent -o /tmp/subs_passive.txt
echo "  Passive: $(wc -l < /tmp/subs_passive.txt) found"

echo "[3] Resolving with wildcard filtering..."
if [ "$WILDCARD_ACTIVE" = true ]; then
    dnsx -l /tmp/subs_passive.txt -wd $TARGET -resp -a -silent -o /tmp/subs_live.txt
else
    dnsx -l /tmp/subs_passive.txt -resp -a -silent -o /tmp/subs_live.txt
fi
echo "  Live (filtered): $(wc -l < /tmp/subs_live.txt) found"

echo "[4] HTTP probing..."
cat /tmp/subs_live.txt | httpx -silent -status-code -title -o /tmp/web_final.txt
echo "  Web services: $(wc -l < /tmp/web_final.txt)"

echo "[5] Results:"
cat /tmp/web_final.txt
```

---

## Key Takeaways

```
1. Wildcard DNS = *.target.com resolves ALL subdomains to same IP
2. It breaks brute-force recon → every guess looks like a real subdomain
3. Detect it: query a random impossible subdomain → if it resolves → wildcard active
4. The wildcard IP is your filter → remove all subdomains matching that IP
5. Use dnsx -wd, puredns, or amass — all handle wildcards automatically
6. Multiple wildcard IPs (round-robin CDN) need multiple test queries
7. Wildcard itself = LOW/INFO, but it can mask takeover candidates
8. Always validate final results with httpx — DNS resolution ≠ real web service
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
