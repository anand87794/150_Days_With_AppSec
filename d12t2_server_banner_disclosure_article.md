# Server Banner Disclosure: Your Server Just Told Me Exactly What Version It Runs

**Severity:** LOW | **Category:** Fingerprinting | **Series:** #300DaysWithAppSec

---

## The Smallest Leak With the Biggest Chains

Server banner disclosure is rated LOW in isolation — it's just information. But in practice, it's the first step in nearly every targeted attack chain. Finding `Server: Apache/2.4.49` in a response header takes 10 seconds. Looking up CVE-2021-41773 (path traversal to RCE on that exact version) takes another 10 seconds. Exploiting it takes one curl command.

The banner didn't cause the vulnerability. But without the banner, the attacker would have had to try multiple exploits blindly. With it, they go straight to the known exploit.

---

## What Information Gets Leaked

### HTTP Response Headers

Every HTTP response includes headers. Most web servers add an identity header by default:

```bash
curl -sI https://target.com

# Response headers:
HTTP/2 200
Server: Apache/2.4.49 (Ubuntu)         ← web server + version + OS
X-Powered-By: PHP/7.4.3                ← language and version
X-AspNet-Version: 4.0.30319            ← .NET version
X-Generator: Drupal 9 (https://drupal.org)  ← CMS name and version
X-Drupal-Cache: HIT
X-Frame-Options: SAMEORIGIN
```

### What Each Header Tells an Attacker

```
Server: Apache/2.4.49         → exact Apache version → check NVD for CVEs
Server: nginx/1.18.0          → nginx version → known misconfig patterns
X-Powered-By: PHP/7.4.3      → PHP version → deserialization, type juggling
X-Powered-By: Express         → Node.js with Express → prototype pollution
X-AspNet-Version: 4.0.30319  → .NET framework → deserialization gadget chains
X-Generator: WordPress 5.8    → WP version → xmlrpc attacks, plugin CVEs
X-Generator: Drupal 9         → check Drupal security advisories
Via: 1.1 Squid/4.11           → proxy version → SSRF/bypass opportunities
```

---

## How to Check Banners Systematically

### Single Target

```bash
# Get all response headers
curl -sI https://target.com

# Get headers + follow redirects
curl -sIL https://target.com | grep -iE "server|powered|generator|framework|version"

# Check specific ports
for port in 80 443 8080 8443 8888 3000; do
    echo "=== Port $port ==="
    curl -skI "https://target.com:$port" 2>/dev/null | \
        grep -iE "server|powered|version|generator"
done
```

### All Subdomains at Scale

```bash
# httpx — bulk header check with tech detection
cat subdomains.txt | httpx -silent -title -tech-detect -server -status-code \
    -o fingerprints.txt

# Extract just server headers
cat subdomains.txt | httpx -silent -server | grep -v "^$"

# whatweb — comprehensive fingerprinting
whatweb https://target.com
whatweb -i subdomains.txt --log-json=whatweb_results.json
```

### nmap Service Version Detection

```bash
# Version detection on web ports
nmap -sV -p 80,443,8080,8443 target.com

# Output:
# 80/tcp  open  http    Apache httpd 2.4.49 ((Ubuntu))
# 443/tcp open  https   nginx 1.18.0

# More aggressive version detection
nmap -sV --version-intensity 9 -p 80,443 target.com
```

---

## Version to CVE Mapping — Why This Matters

Once you have a version, check these resources:

```bash
# NVD (National Vulnerability Database)
# https://nvd.nist.gov/vuln/search?query=Apache+2.4.49

# Exploit-DB
searchsploit apache 2.4.49
# --------------------------------------------------------------------------
# Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)
# --------------------------------------------------------------------------

# Example chain: Banner → CVE → Exploit
# Server: Apache/2.4.49
# → CVE-2021-41773 (CVSS 9.8)
# → curl -s --path-as-is "https://target.com/cgi-bin/.%2e/.%2e/.%2e/etc/passwd"
# → /etc/passwd contents returned → RCE via POST to /cgi-bin/
```

### High-Impact Version Chains

| Banner | Version | CVE | Impact |
|--------|---------|-----|--------|
| Apache | 2.4.49 | CVE-2021-41773 | Path traversal + RCE |
| Apache | 2.4.50 | CVE-2021-42013 | Same but harder bypass |
| PHP | 8.1.0-dev | CVE-2021-38931 | Backdoor RCE via User-Agentt header |
| WordPress | < 5.8.3 | Multiple | SQLi, XSS, CSRF |
| Drupal | 7.x | CVE-2018-7600 | Drupalgeddon2 RCE |
| Log4j via | any Java | CVE-2021-44228 | Log4Shell RCE |

---

## What to Look for Beyond Server Headers

### Error Pages

```bash
# 404 pages often reveal framework
curl -s https://target.com/nonexistent-page-xyz

# Django 404: "Page not found (404)" + "Django" in HTML
# Laravel 404: "Whoops! There was an error." or debug page
# Spring Boot: WhitelabelErrorPage
# Express: "Cannot GET /nonexistent"
```

### Response Timing and Quirks

```bash
# Check if server is behind a reverse proxy
curl -sI https://target.com | grep -i "via\|x-cache\|x-varnish\|cf-ray"

# Via: 1.1 vegur (Heroku)     → Heroku hosting
# CF-Ray: xxx → Cloudflare
# X-Served-By: cache-xxx → Fastly/Varnish
```

---

## Reporting Server Banner Disclosure

```
Title: Server Version Disclosure — Apache/2.4.49 in HTTP Response Header

Severity: LOW (standalone) / HIGH (if vulnerable version)

Description:
The web server discloses its exact version in the HTTP response header:
Server: Apache/2.4.49 (Ubuntu)

This information enables targeted attacks using known vulnerabilities
for this specific version. Apache 2.4.49 is affected by CVE-2021-41773
(CVSS 9.8) — a path traversal and RCE vulnerability.

Evidence:
$ curl -sI https://target.com | grep Server
Server: Apache/2.4.49 (Ubuntu)

CVE Reference: CVE-2021-41773 — Path traversal to RCE on Apache 2.4.49
Exploit: https://www.exploit-db.com/exploits/50383

Remediation:
Update Apache to latest version OR suppress the banner:
In httpd.conf: ServerTokens Prod   (shows only "Apache")
In httpd.conf: ServerSignature Off (removes from error pages)

For PHP: In php.ini: expose_php = Off
For nginx: In nginx.conf: server_tokens off;
```

---

## Key Takeaways

```
1. Server banners = exact software version in HTTP response headers
2. Check: Server, X-Powered-By, X-Generator, X-AspNet-Version
3. Tools: curl -I, httpx -server, whatweb, nmap -sV
4. Version → NVD → CVE → known exploit = targeted attack ready
5. Always check 404 pages — framework leaks in error messages
6. LOW severity standalone → HIGH/CRITICAL if version has known CVE
7. Fix: ServerTokens Prod (Apache), server_tokens off (nginx), expose_php=Off
8. Bulk check all subdomains with httpx -tech-detect for maximum coverage
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
