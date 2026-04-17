# Reverse DNS Lookup: Turning IP Addresses Into Attack Surface

**Severity:** LOW | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## You Have an IP. But What Is It?

You're doing recon on a target. You find an IP address — maybe in a JavaScript file, maybe from a leaked server header, maybe from a misconfigured API response. The IP is `185.220.101.45`. 

Normal DNS tells you nothing — that's not a domain, it's a number. But what if you could ask DNS: "hey, what domain lives at this address?" That's exactly what **Reverse DNS Lookup** does, and it's one of the most underused techniques in beginner recon toolkits.

---

## Normal DNS vs Reverse DNS

Before we dive in, let's get the direction right.

**Forward DNS** (what everyone knows):
```
Question: What is the IP of google.com?
DNS:      google.com → A record → 142.250.195.46
```

**Reverse DNS** (what we're learning today):
```
Question: What domain lives at 142.250.195.46?
DNS:      142.250.195.46 → PTR record → google.com
```

The PTR record (Pointer record) is the DNS record type that makes reverse lookup work. Not every IP has a PTR record — it's optional — but when one exists, it can tell you exactly what lives at that address.

---

## The Technical Mechanism — How PTR Records Work

Reverse DNS uses a special domain called `in-addr.arpa` (for IPv4) or `ip6.arpa` (for IPv6).

For the IP `93.184.216.34`, the PTR lookup works like this:

```
Step 1: Reverse the IP address: 34.216.184.93
Step 2: Append .in-addr.arpa: 34.216.184.93.in-addr.arpa
Step 3: Look up the PTR record for that domain
Step 4: Get back the hostname: example.com
```

You don't need to do this manually — `dig -x` handles it:

```bash
dig -x 93.184.216.34
# Returns: 93.184.216.34.in-addr.arpa → PTR → example.com
```

---

## Why Recon Hunters Use Reverse DNS

### Use Case 1: Discovering Hidden Subdomains

Sometimes a subdomain doesn't appear in certificate logs, doesn't come up in passive recon, and isn't brute-forceable with wordlists — but its IP has a PTR record.

```bash
# You found IP 185.220.101.45 in a JS file
dig -x 185.220.101.45
# Returns: internal-api-v2.target.com

# "internal-api-v2" was NEVER in subfinder results
# It's a completely undiscovered subdomain — test it immediately!
```

### Use Case 2: Scanning an Entire IP Range

Companies often own entire IP blocks (like `10.20.0.0/24`). By running reverse DNS across the whole range, you can map every server they're running — including forgotten ones that no scanner would find.

```bash
# Scan the entire /24 range for hostnames
nmap -sn --script rdns-query 185.220.101.0/24

# Or with dnsx (much faster):
# Generate all IPs in range:
for i in $(seq 1 254); do echo "185.220.101.$i"; done > ip_range.txt
dnsx -ptr -l ip_range.txt -resp -silent

# Output:
# 185.220.101.14 → api.target.com
# 185.220.101.22 → db-replica.target.com  ← database server!
# 185.220.101.45 → internal-api-v2.target.com  ← hidden endpoint!
# 185.220.101.100 → staging.target.com  ← staging server!
```

### Use Case 3: Bypassing Cloudflare / CDN to Find Origin IP

One of the most powerful uses of reverse DNS. Many companies hide their origin server behind Cloudflare. The "real" IP is what you need for direct attacks that bypass Cloudflare's WAF.

```bash
# target.com resolves to Cloudflare IPs (not useful)
dig A target.com
# 104.21.34.18 → Cloudflare (useless)

# BUT: if the company has other infrastructure on the same /24...
# Find their ASN first:
whois 185.220.101.45 | grep -i "ORG\|AS\|netrange"
# ASN: AS12345, NetRange: 185.220.101.0 - 185.220.101.255

# Reverse DNS the entire range
for i in $(seq 1 254); do echo "185.220.101.$i"; done | dnsx -ptr -resp -silent
# 185.220.101.14 → api.target.com  ← THIS might be the origin!

# Test if origin accepts direct connection
curl -H "Host: target.com" https://185.220.101.14 --insecure
# If it responds = origin server found → can bypass Cloudflare!
```

### Use Case 4: Shared Hosting Discovery

Many servers host hundreds of websites on a single IP. If you find a vulnerability on one of those sites, the server configuration is often shared — meaning your finding might affect multiple tenants.

```bash
# One IP → many domains
dig -x 23.227.38.65
# Returns: shops.myshopify.com

# But reverse DNS might reveal OTHER domains on the same IP:
# (Use VirusTotal passive DNS or SecurityTrails for this)
curl "https://api.securitytrails.com/v1/ips/neighbors/23.227.38.65" \
    -H "APIKEY: YOUR_KEY" | python3 -m json.tool

# Multiple companies on same server → misconfiguration in one affects all
```

---

## Commands and Tools — From Beginner to Scale

### dig (Built-In, No Install)

```bash
# Single IP reverse lookup
dig -x 93.184.216.34

# Get just the PTR record (cleaner output)
dig -x 93.184.216.34 +short
# example.com.

# Specify a custom DNS resolver
dig -x 93.184.216.34 @8.8.8.8 +short
```

### host (Simple, Human-Friendly)

```bash
# Even simpler output than dig
host 93.184.216.34
# 34.216.184.93.in-addr.arpa domain name pointer example.com.

# Also shows forward lookup in one command
host example.com
# example.com has address 93.184.216.34
```

### nmap (Network Scan + Reverse DNS)

```bash
# Scan subnet and show hostnames
nmap -sn --script rdns-query 93.184.216.0/24 -oN rdns_results.txt

# Just ping sweep + DNS (no port scan)
nmap -sn 93.184.216.0/24

# Output includes hostname if PTR exists:
# Nmap scan report for example.com (93.184.216.34)
# Host is up (0.012s latency).
```

### dnsx (Fastest — Designed for Scale)

```bash
# Install
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Reverse DNS on a list of IPs
dnsx -ptr -l ip_list.txt -resp -silent

# Combined: forward + reverse in one pass
dnsx -l subdomains.txt -ptr -a -resp -silent -o full_dns.txt

# Filter for PTR records only
dnsx -ptr -l ip_list.txt -resp -silent | grep "PTR"
# 93.184.216.34 [example.com]
```

### hakrevdns (Bulk Reverse DNS Via Pipe)

```bash
# Install
go install github.com/hakluke/hakrevdns@latest

# Pipe IPs directly
cat ip_list.txt | hakrevdns -d

# Generate entire subnet and pipe
for i in $(seq 1 254); do echo "93.184.216.$i"; done | hakrevdns -d
# 93.184.216.34 → example.com
# 93.184.216.1  → (no PTR)
```

---

## The Full Workflow — Chaining Reverse DNS Into Your Recon

```bash
#!/bin/bash
TARGET="${1:-target.com}"

echo "[1] Finding live IP addresses for all subdomains..."
subfinder -d $TARGET -all -silent | \
    dnsx -resp -a -silent | \
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
    sort -u > /tmp/target_ips.txt
echo "  Found: $(wc -l < /tmp/target_ips.txt) unique IPs"

echo "[2] Running reverse DNS on all discovered IPs..."
dnsx -ptr -l /tmp/target_ips.txt -resp -silent > /tmp/rdns_results.txt
echo "  PTR records found: $(wc -l < /tmp/rdns_results.txt)"

echo "[3] Extracting new hostnames (not in original subdomain list)..."
# Get all PTR-discovered hostnames
grep -oE '[a-zA-Z0-9._-]+\.'"$TARGET" /tmp/rdns_results.txt | \
    sort -u > /tmp/rdns_hostnames.txt

echo "  New hostnames via reverse DNS: $(wc -l < /tmp/rdns_hostnames.txt)"
cat /tmp/rdns_hostnames.txt

echo "[4] Testing these new hostnames for web services..."
cat /tmp/rdns_hostnames.txt | \
    httpx -silent -status-code -title -o /tmp/rdns_web.txt
cat /tmp/rdns_web.txt
```

---

## Finding the ASN and Scanning the Full IP Range

```bash
# Step 1: Find what IP block (ASN) the target owns
# Use one of their known IPs
TARGET_IP=$(dig A target.com +short | head -1)
echo "Using IP: $TARGET_IP"

# Query BGP data
curl -s "https://api.bgpview.io/ip/$TARGET_IP" | \
    python3 -c "
import json, sys
d = json.load(sys.stdin)
for pfx in d.get('data', {}).get('prefixes', []):
    print(f\"ASN: {pfx.get('asn',{}).get('asn')} | Prefix: {pfx.get('prefix')} | {pfx.get('asn',{}).get('description')}\")
"

# Step 2: Get all IP ranges for that ASN
ASN="AS12345"  # Replace with actual ASN
curl -s "https://api.bgpview.io/asn/$ASN/prefixes" | \
    python3 -c "
import json, sys
d = json.load(sys.stdin)
for pfx in d.get('data', {}).get('ipv4_prefixes', []):
    print(pfx.get('prefix'))
" > /tmp/asn_ranges.txt

# Step 3: Generate all IPs in those ranges and reverse DNS
# (Be careful: large ranges can generate millions of IPs)
# Use masscan for speed, dnsx for DNS
```

---

## What the Results Tell You

After running reverse DNS on a target's IP range, here's what different findings mean:

```
Hostname found            → What it means
─────────────────────────────────────────────────
api-internal.target.com   → Internal API not in public docs → test it!
db-primary.target.com     → Database server → never should be public
jenkins.target.com        → CI/CD server → often has weak auth
staging.target.com        → Staging environment → different security posture
mail.target.com           → Email server → test for SMTP vulns
vpn.target.com            → VPN gateway → test login page
legacy-app.target.com     → Old application → likely running outdated software
```

---

## Reporting Reverse DNS Findings

Reverse DNS itself is informational — it's a technique, not a vulnerability. You report what you find ON those discovered hostnames, not the reverse DNS itself.

**Exception:** If reverse DNS reveals internal/private information that shouldn't be in PTR records:

```
Title: Internal Server Hostnames Exposed via PTR/Reverse DNS Records

Severity: LOW / INFORMATIONAL

Description:
Reverse DNS lookup on the target's IP range reveals internal 
server naming conventions and infrastructure details including:
- db-primary.target.com (185.220.101.22) — database server
- vpn.target.com (185.220.101.50) — VPN gateway
- jenkins.target.com (185.220.101.75) — CI/CD server

This information aids attackers in targeted attacks against 
specific infrastructure components.

Remediation:
Remove PTR records for internal/sensitive server names, or 
use generic names (e.g., "server01.target.com" instead of 
"db-primary.target.com") for infrastructure servers.
```

---

## Key Takeaways

```
1. Reverse DNS turns an IP into a domain name using PTR records
2. Not every IP has a PTR record — but when it does, it's gold
3. Discovers subdomains that passive/brute-force recon completely misses
4. Scan entire ASN ranges → map all company servers including hidden ones
5. Use to find real origin IP behind Cloudflare/CDN
6. Shared hosting: one IP → 100 domains → one vuln affects all tenants
7. Tools: dig -x (basic), dnsx -ptr (fast + scalable), hakrevdns (pipeline)
8. Chain into workflow: subdomains → IPs → reverse DNS → more subdomains
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
