# Shodan Open Ports on ASN: Every Port Is a Question. Some Have Dangerous Answers.

**Severity:** HIGH | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## An Open Port Is an Open Invitation

When a server has port 27017 (MongoDB) open to the internet, it's not automatically a vulnerability. But when that MongoDB instance has no authentication — which is the default — it's a Critical finding. Anyone on the internet can connect and read, write, or delete the entire database.

Shodan makes finding these in seconds. You search for a company's ASN or IP range, filter by dangerous ports, and get a list of every exposed service with their banners confirming exactly what's running and whether auth is required.

---

## The Port Dictionary — What Each Port Means

### Databases (No Auth = Critical)

| Port | Service | Default Auth | If No Auth |
|------|---------|--------------|------------|
| 27017 | MongoDB | None | Full DB read/write |
| 9200 | Elasticsearch | None | Full index search/delete |
| 6379 | Redis | None | Read all data + RCE via config |
| 5432 | PostgreSQL | Password | Brute force target |
| 3306 | MySQL | Password | Brute force target |
| 5984 | CouchDB | None | Full DB access |
| 9042 | Cassandra | None | Full cluster access |

### Remote Access (High Risk)

| Port | Service | Risk |
|------|---------|------|
| 22 | SSH | Brute force, old cipher attacks |
| 3389 | RDP | Brute force, BlueKeep (CVE-2019-0708) |
| 5900 | VNC | Often no auth, full desktop |
| 23 | Telnet | Plaintext credentials |

### Admin & Dev Tools (Often No Auth)

| Port | Service | Risk |
|------|---------|------|
| 8080 | Jenkins | No auth = CI/CD control, code access |
| 9090 | Prometheus | Metrics + internal network map |
| 3000 | Grafana | Dashboard with sensitive metrics |
| 5601 | Kibana | Elasticsearch frontend |
| 4848 | GlassFish | Admin console |
| 8161 | ActiveMQ | Admin panel |

---

## Finding Open Ports on ASN with Shodan

### Step 1: Get the Company's ASN

```bash
# From ASN lookup
curl -s "https://api.bgpview.io/ip/185.220.101.45" | \
    python3 -c "import json,sys; d=json.load(sys.stdin); \
    [print(f\"AS{p['asn']['asn']}  {p['asn']['description']}\") \
    for p in d['data']['prefixes']]"

# Output:
# AS12345  Target Company Inc.
```

### Step 2: Search Shodan for All Open Ports

```bash
# All services for the org
shodan search --fields ip_str,port,product,banner \
    'org:"Target Company"' > company_ports.txt

# Specific dangerous ports
shodan search --fields ip_str,port,product \
    'org:"Target" port:27017,6379,9200,3389,5900' > risky_ports.txt

# By IP range (if you know their CIDR)
shodan search --fields ip_str,port,product \
    'net:185.220.101.0/24'

# Sorted by port
cat company_ports.txt | sort -t' ' -k2 -n
```

### Step 3: Banner Analysis — Confirm Auth Status

```bash
# MongoDB banner tells you immediately:
# "MongoDB 4.2.1" — need to connect to check auth
# Banner containing "ismaster" — MongoDB is running

# Test MongoDB auth status
mongo --host 185.220.101.45 --eval "db.adminCommand('listDatabases')"
# If it returns data without auth prompt → no auth → CRITICAL

# Elasticsearch — check with curl
curl http://185.220.101.22:9200
# Returns cluster info → accessible → check for auth
curl http://185.220.101.22:9200/_cat/indices
# Returns all indices → no auth → CRITICAL

# Redis
redis-cli -h 185.220.101.10 ping
# PONG → connected. Check auth:
redis-cli -h 185.220.101.10 CONFIG GET requirepass
# "" (empty) → no password → CRITICAL

# Jenkins
curl http://185.220.101.80:8080/api/json
# Returns JSON → no auth → HIGH/CRITICAL
```

---

## Port Scan the ASN Yourself

When Shodan data is old, use nmap to verify:

```bash
# Get all IPs in the ASN
curl -s "https://api.bgpview.io/asn/12345/prefixes" | \
    python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d['data']['ipv4_prefixes']:
    print(p['prefix'])
" > asn_ranges.txt

# nmap scan for dangerous ports across all ranges
while read range; do
    nmap -sV -p 22,3389,5900,6379,9200,27017,8080,9090 \
        --open -T4 "$range" -oG - | grep "open"
done < asn_ranges.txt | tee open_ports.txt

# Filter critical services
grep -E "27017|9200|6379|5900|5984" open_ports.txt
```

---

## Complete ASN Port Audit Script

```bash
#!/bin/bash
TARGET_ORG="${1:-Target Company}"
SHODAN_KEY="${SHODAN_API_KEY}"

echo "=== Open Port Audit: $TARGET_ORG ==="

# Dangerous ports to check
CRITICAL_PORTS="27017,9200,6379,5984,9042"
HIGH_PORTS="3389,5900,23,8080,9090,5601,3000"

echo "[1] Searching Shodan for critical database ports..."
shodan search --fields ip_str,port,product \
    "org:\"$TARGET_ORG\" port:$CRITICAL_PORTS" | \
    tee critical_services.txt

echo "[2] Searching for admin/dev tool ports..."
shodan search --fields ip_str,port,product,http.title \
    "org:\"$TARGET_ORG\" port:$HIGH_PORTS" | \
    tee admin_services.txt

echo "[3] Verifying MongoDB instances..."
while read line; do
    IP=$(echo $line | awk '{print $1}')
    PORT=$(echo $line | awk '{print $2}')
    if echo $line | grep -q "27017"; then
        result=$(timeout 3 mongo --host $IP --eval \
            "db.adminCommand('listDatabases')" 2>/dev/null | head -3)
        [ -n "$result" ] && echo "CRITICAL: Unauthenticated MongoDB at $IP:$PORT"
    fi
done < critical_services.txt

echo "[4] Verifying Elasticsearch..."
while read line; do
    IP=$(echo $line | awk '{print $1}')
    if echo $line | grep -q "9200"; then
        result=$(curl -sk "http://$IP:9200/_cat/indices" 2>/dev/null | head -3)
        [ -n "$result" ] && echo "CRITICAL: Unauthenticated Elasticsearch at $IP:9200"
    fi
done < critical_services.txt

echo "Done. Review: critical_services.txt + admin_services.txt"
```

---

## Reporting Open Port Findings

```
Title: Unauthenticated MongoDB Instance Exposed — 185.220.101.45:27017

Severity: CRITICAL

Description:
A MongoDB database instance is publicly accessible on port 27017 without
any authentication requirement. The instance was discovered via Shodan
and confirmed to allow unauthenticated connections.

Evidence:
Shodan result: https://www.shodan.io/host/185.220.101.45
Banner: MongoDB 4.2.1

Verification:
$ mongo --host 185.220.101.45
> show databases;
admin   0.000GB
users   2.340GB    ← user database accessible!
orders  8.120GB    ← order/payment data accessible!

Impact:
Full unauthenticated read and write access to all databases including
user PII, order history, and authentication data.

Remediation:
1. Enable MongoDB authentication immediately
2. Restrict network access via firewall to known IP ranges only
3. Audit all data accessed during exposure window
```

---

## Key Takeaways

```
1. Shodan stores port scan results for every public IP — use it
2. Filter by ASN/org + dangerous ports for instant triage
3. MongoDB, Redis, Elasticsearch: no auth by default = Critical if exposed
4. Always verify live — Shodan data can be weeks old
5. Banner grabbing confirms: service + version + auth status
6. Port 6379 Redis: no auth + write access = RCE via cron config
7. Report with: Shodan link + banner + live verification + data sample
8. Severity = service type: DB no auth = Critical, dev tool = High
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
