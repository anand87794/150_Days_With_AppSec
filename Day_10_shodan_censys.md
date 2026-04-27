# Shodan / Censys: Finding Exposed Services Without Touching the Target

**Severity:** HIGH | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The Search Engine for Hackers

Shodan is often called "the scariest search engine on the internet" — and for good reason. While Google indexes websites, Shodan indexes **devices and services**. It continuously scans the entire IPv4 address space, grabbing banners from every open port it finds, and makes all of that searchable.

For a bug bounty hunter or pentester, this means you can find every server a company has exposed to the internet — databases, admin panels, dev tools, cameras — without sending a single packet to the target. Shodan already did the scanning weeks ago.

---

## What Shodan Actually Stores

For every open port on every public IP, Shodan stores:

```
IP Address:     185.220.101.45
Port:           27017
Protocol:       TCP
Service:        MongoDB
Banner:         MongoDB 4.2.1 (no authentication required)
Organization:   Target Company Inc.
ASN:            AS12345
Hostnames:      db.target.com
SSL Cert:       Issued for: *.target.com, api.target.com
Country:        US
Last Updated:   2024-01-15
```

This is the information that makes it dangerous. The "no authentication required" in a MongoDB banner means anyone on the internet can connect and read the database.

---

## How to Search on Shodan

### Basic Search — Web UI

Go to `shodan.io`, log in (free account gives 2 pages of results), and search:

```
org:"Target Company"              → all servers for this org
hostname:target.com               → servers with this hostname
ssl:"target.com"                  → servers with SSL cert mentioning target.com
net:185.220.101.0/24              → all devices in this IP range
```

### Shodan CLI — Automated

```bash
# Install and authenticate
pip3 install shodan --break-system-packages
shodan init YOUR_API_KEY   # get key from shodan.io/api

# Search by org name
shodan search --fields ip_str,port,org 'org:"Target Inc"'

# All IPs + hostnames for a domain
shodan domain target.com

# Search SSL certificates mentioning the target
shodan search --fields ip_str,port 'ssl.cert.subject.cn:target.com'

# Download all results for analysis
shodan download results 'org:"Target Inc"' --limit 1000
shodan parse --fields ip_str,port,org results.json.gz
```

### Power Dorks — Find Specific Services

```
org:"Target" http.title:"Jenkins"              → Jenkins CI servers
org:"Target" product:"Elasticsearch"          → Elasticsearch clusters
org:"Target" port:27017                       → MongoDB instances
org:"Target" port:6379                        → Redis instances
org:"Target" port:9200 product:"Elastic"      → Elasticsearch on 9200
org:"Target" port:5601 product:"Kibana"       → Kibana dashboards
org:"Target" http.title:"Grafana"             → Grafana monitoring
org:"Target" port:3306 product:"MySQL"        → MySQL databases
net:185.220.101.0/24 port:22 "OpenSSH 6"     → old SSH versions
ssl:"target.com" port:443,8443,4443           → HTTPS on non-standard ports
```

---

## Censys — The Alternative

Censys (censys.io) does the same thing as Shodan but with different scanning infrastructure. Use both — they find different assets.

```bash
# Censys CLI
pip3 install censys --break-system-packages
censys config   # enter your API ID and secret

# Search hosts
censys search 'autonomous_system.name:"Target Company"' --index hosts

# Search certificates
censys search 'parsed.names:target.com' --index certificates

# View specific host
censys view 185.220.101.45 --index hosts
```

---

## What to Do With Results

### Step 1: List Everything

```bash
shodan search --fields ip_str,port,product,org 'org:"Target Inc"' > all_services.txt
cat all_services.txt

# Output:
# 185.220.101.45  27017  MongoDB     Target Inc
# 185.220.101.22  9200   Elastic     Target Inc
# 185.220.101.10  6379               Target Inc
# 185.220.101.80  8080   Jetty       Target Inc
```

### Step 2: Triage by Risk

```bash
# CRITICAL — databases with no auth
grep -E "27017|9200|6379|5432|3306" all_services.txt

# HIGH — admin tools
grep -E "8080|8443|4848|9090" all_services.txt

# Check each one manually
curl http://185.220.101.22:9200           # Elasticsearch
redis-cli -h 185.220.101.10 ping          # Redis
nc -zv 185.220.101.45 27017              # MongoDB
```

---

## Key Takeaways

```
1. Shodan = internet-wide scanner — all results without touching target
2. Search by: org name, hostname, ASN, IP range, port, product
3. Censys = alternative — use both for complete coverage
4. High-value finds: MongoDB, Redis, Elasticsearch, Jenkins, RDP
5. Banner = service name + version + often "no authentication"
6. shodan domain target.com = fastest way to see all exposure
7. Always verify manually before reporting — Shodan data can be old
8. Severity = what's running: unauthenticated DB = Critical
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
