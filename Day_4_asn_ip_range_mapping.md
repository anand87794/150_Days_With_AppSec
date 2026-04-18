# ASN & IP Range Mapping: Find Every Server a Company Owns Before You Scan

**Severity:** LOW | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## Why Most Beginners Miss Half the Attack Surface

When a beginner starts recon on a target, they usually do this:

```
1. subfinder -d target.com → get subdomains
2. httpx → find live web servers
3. Start testing
```

This approach misses a massive slice of the attack surface. Companies don't just own their main domain — they own entire **IP ranges** with dozens or hundreds of servers that may never appear in any domain enumeration tool. Some of these servers have no public DNS records at all. The only way to find them is through **ASN and IP range mapping**.

---

## What Is an ASN?

**ASN stands for Autonomous System Number.** It's a unique identifier assigned to every organisation that manages its own IP routing on the internet.

Think of the internet as a network of cities. Each city has its own internal road system and manages its own traffic. An ASN is like the city's official registration number. Every company that owns a block of IP addresses has one (or more) ASNs.

```
Company: Google LLC
ASN:     AS15169
IP ranges owned under this ASN:
  8.8.0.0/24      → Google's DNS servers
  34.0.0.0/9      → Google Cloud
  142.250.0.0/15  → Google services
  ... (hundreds more)
```

When you find the ASN, you find the entire IP portfolio.

---

## Why This Matters for Penetration Testing

### 1. The Bug Bounty Scope Loophole

Most bug bounty programs define scope as `*.target.com` — all subdomains. But if target.com owns `185.220.0.0/16` and that entire range is their infrastructure, servers on `185.220.101.55` are almost certainly in scope even if they have no DNS record at all.

```bash
# This server has no DNS record
# It won't appear in subfinder, amass, or any other tool
# But it's on the company's ASN → it's fair game
185.220.101.55 → runs on target's infrastructure → potentially in scope
```

### 2. Forgotten Servers With No WAF

Servers added to the DNS get Cloudflare attached by default. Servers that exist only as IPs often:
- Have no WAF protecting them
- Run older software (nobody's monitoring)  
- Have weak or no authentication
- Have development/admin tools exposed

### 3. True Network Understanding

Before a professional pentest, mapping the ASN gives you a complete picture of what you're dealing with — not just what the DNS tells you.

---

## Step 1: Find the Company's ASN

### Method A: whois (Built-In)

```bash
# Query whois for a known IP of the target
TARGET_IP=$(dig A target.com +short | head -1)
echo "Target IP: $TARGET_IP"

whois $TARGET_IP | grep -iE "OriginAS|org-name|OrgName|netname|AS[0-9]"

# Output:
# OrgName:        Target Company Inc.
# OriginAS:       AS12345
# NetRange:       185.220.100.0 - 185.220.101.255
# CIDR:           185.220.100.0/23
```

### Method B: bgp.he.net (Browser — Easiest)

1. Go to `https://bgp.he.net`
2. Search for the company name: `"Target Inc"`
3. See all ASNs registered to that company
4. Click any ASN to see all IP prefixes (ranges) they announce

This is the most visual and beginner-friendly method. No terminal needed.

### Method C: bgpview.io API (Programmable)

```bash
# Get ASN for an IP address
curl -s "https://api.bgpview.io/ip/$TARGET_IP" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for pfx in data.get('data', {}).get('prefixes', []):
    asn  = pfx.get('asn', {})
    print(f\"ASN: AS{asn.get('asn')}  |  Org: {asn.get('description')}  |  Prefix: {pfx.get('prefix')}\")
"

# Get all prefixes for an ASN
ASN_NUM="12345"
curl -s "https://api.bgpview.io/asn/$ASN_NUM/prefixes" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for pfx in data.get('data', {}).get('ipv4_prefixes', []):
    print(pfx.get('prefix'))
" > all_ip_ranges.txt

cat all_ip_ranges.txt
# 185.220.100.0/23
# 185.220.102.0/24
# 93.184.216.0/24
```

### Method D: amass intel (All-In-One CLI)

```bash
# amass can find ASNs by organisation name directly
amass intel -org "Target Company" -asn

# Output:
# ASN: 12345, Target Company (US)
# ASN: 67890, Target Company EU (DE)

# Then get all CIDRs for those ASNs
amass intel -asn 12345 -cidr

# Outputs all IP ranges in CIDR notation
```

---

## Step 2: Get All IP Ranges for the ASN

```bash
#!/bin/bash
ASN="${1:-AS12345}"
ASN_NUM="${ASN#AS}"  # Strip "AS" prefix

echo "[*] Fetching all IP ranges for $ASN..."

# Method 1: bgpview API
curl -s "https://api.bgpview.io/asn/$ASN_NUM/prefixes" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
for pfx in data.get('data', {}).get('ipv4_prefixes', []):
    print(pfx.get('prefix'))
" > /tmp/ipv4_ranges.txt

echo "IPv4 ranges found: $(wc -l < /tmp/ipv4_ranges.txt)"
cat /tmp/ipv4_ranges.txt

# Method 2: whois route objects (RIPE NCC / ARIN)
echo ""
echo "[*] Cross-checking with whois..."
whois -h whois.radb.net "!gAS$ASN_NUM" 2>/dev/null | head -30
```

---

## Step 3: Enumerate Live Hosts in Each Range

Once you have the IP ranges, find which IPs are actually running services.

### Ping Sweep (Find Live Hosts)

```bash
# nmap ping sweep — no port scan, just discover live hosts
nmap -sn 185.220.100.0/24 -oG - | grep "Up" | awk '{print $2}' > live_hosts.txt
echo "Live hosts: $(wc -l < live_hosts.txt)"

# For large ranges, masscan is much faster
masscan 185.220.100.0/23 -p0 --rate 1000 --open -oG masscan_live.txt
```

### Reverse DNS All Live IPs

```bash
# Get hostnames for all live hosts
cat live_hosts.txt | dnsx -ptr -resp -silent > rdns_results.txt

# Find any that resolve to target's domain
grep "target.com" rdns_results.txt
```

### Port Scan Live Hosts

```bash
# Fast scan of common web ports
nmap -p 80,443,8080,8443,8888,3000,4000,5000,9000 \
    -iL live_hosts.txt --open -T4 \
    -oN port_scan.txt

# Check for web servers on all live hosts
cat live_hosts.txt | httpx -silent -status-code -title \
    -ports 80,443,8080,8443 -o web_servers.txt
cat web_servers.txt
```

---

## Complete Automated Workflow

```bash
#!/bin/bash
TARGET="${1:-target.com}"

echo "=== ASN & IP Range Mapping for $TARGET ==="

# Step 1: Get target IP
TARGET_IP=$(dig A $TARGET +short | head -1)
echo "[1] Target IP: $TARGET_IP"

# Step 2: Find ASN
ASN_INFO=$(curl -s "https://api.bgpview.io/ip/$TARGET_IP")
ASN_NUM=$(echo "$ASN_INFO" | python3 -c "
import json, sys
d=json.load(sys.stdin)
pfxs=d.get('data',{}).get('prefixes',[])
if pfxs: print(pfxs[0].get('asn',{}).get('asn',''))
" 2>/dev/null)

echo "[2] ASN: AS$ASN_NUM"

# Step 3: Get all IP ranges
curl -s "https://api.bgpview.io/asn/$ASN_NUM/prefixes" | python3 -c "
import json, sys
d=json.load(sys.stdin)
[print(p.get('prefix')) for p in d.get('data',{}).get('ipv4_prefixes',[])]
" > /tmp/ranges.txt
echo "[3] IP ranges: $(wc -l < /tmp/ranges.txt)"

# Step 4: Scan for live hosts (careful with large ranges!)
echo "[4] Scanning live hosts (this takes time for large ranges)..."
while read range; do
    nmap -sn "$range" -oG - 2>/dev/null | grep "Up" | awk '{print $2}'
done < /tmp/ranges.txt > /tmp/live_hosts.txt
echo "    Live hosts found: $(wc -l < /tmp/live_hosts.txt)"

# Step 5: Reverse DNS
echo "[5] Reverse DNS lookup on all live hosts..."
cat /tmp/live_hosts.txt | dnsx -ptr -resp -silent > /tmp/rdns.txt

# Step 6: Find hosts belonging to target
echo "[6] Hosts resolving to $TARGET domain:"
grep "$TARGET" /tmp/rdns.txt

echo "[7] Web servers on discovered IPs:"
cat /tmp/live_hosts.txt | httpx -silent -status-code -title \
    -ports 80,443,8080,8443 -o /tmp/web.txt
cat /tmp/web.txt
```

---

## What to Look For in Results

After scanning the IP ranges, these findings are gold:

```bash
# Admin panels on raw IPs (no domain)
grep -E "admin|dashboard|panel|manage" /tmp/web.txt

# Dev/staging tools
grep -E "jenkins|gitlab|grafana|kibana|sonar|jira" /tmp/web.txt

# Old/forgotten web apps
grep -E "200" /tmp/web.txt | grep -v "target.com"
# These are servers with no domain pointing to them

# Unusual ports running web servers
httpx -l /tmp/live_hosts.txt -ports 3000,4000,5000,8000,8888,9200,9300
```

---

## Key Takeaways

```
1. ASN = unique identifier grouping all IPs owned by a company
2. Find ASN → get every IP range → scan all → find hidden servers
3. Best tools: bgp.he.net (browser), bgpview.io API, amass intel
4. Many IP-only servers have no WAF — direct access, less security
5. Reverse DNS on IP ranges finds subdomains impossible to brute-force
6. Chain: ASN ranges → live hosts → web servers → test everything
7. Always verify scope — some IP ranges may be cloud/shared hosting
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
