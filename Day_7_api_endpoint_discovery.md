# API Endpoint Discovery via JS & OpenAPI Spec: Reading the Map Devs Left in Public

**Severity:** MEDIUM | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The API Map Is Already Public — You Just Have to Look

Most developers don't intentionally hide their API endpoints. They document them (Swagger/OpenAPI), expose them to frontend teams (published API docs), or bundle the routes directly into JavaScript files that go to every user's browser.

The difference between a web app's public API and its hidden attack surface is often just knowing where to look. This is API endpoint discovery — systematically finding every route, method, parameter, and auth requirement that the API exposes.

---

## Source 1: Swagger / OpenAPI Specification

OpenAPI (formerly Swagger) is the industry standard for documenting REST APIs. A Swagger spec is a JSON or YAML file that lists every:
- Endpoint path (`/api/v1/users/{id}`)
- HTTP method (GET, POST, PUT, DELETE)
- Required parameters and their types
- Authentication requirements
- Response schemas (tells you what data you'll get back)

This is pure gold for a pentester. When you find it, you have a complete attack surface map.

### Where to Find It

```bash
# Paste this list into ffuf — one will hit
SWAGGER_PATHS=(
    "/swagger.json"
    "/swagger.yaml"
    "/swagger.html"
    "/api-docs"
    "/api-docs.json"
    "/api/api-docs"
    "/openapi.json"
    "/openapi.yaml"
    "/v1/api-docs"
    "/v2/api-docs"
    "/v3/api-docs"
    "/api/v1/swagger.json"
    "/api/v2/swagger.json"
    "/.well-known/openapi"
    "/redoc.html"
    "/api/swagger"
    "/api/swagger.json"
    "/swagger/v1/swagger.json"     # .NET
    "/swagger/v2/swagger.json"
    "/v1/swagger.json"
)

TARGET="https://target.com"
for path in "${SWAGGER_PATHS[@]}"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$path")
    [ "$code" = "200" ] && echo "FOUND [$code]: $TARGET$path"
done
```

### Automated with ffuf

```bash
# Create swagger paths wordlist (or use SecLists)
# SecLists: /Discovery/Web-Content/swagger.txt

ffuf -u https://target.com/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/swagger.txt \
    -mc 200,401,403 -silent

# Also check behind authentication
ffuf -u https://target.com/FUZZ \
    -w swagger-paths.txt \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -mc 200 -silent
```

### Parsing the Swagger Spec

```bash
# Download the spec
curl -sk https://target.com/swagger.json -o swagger.json

# Extract all endpoint paths
python3 -c "
import json
with open('swagger.json') as f:
    spec = json.load(f)

# OpenAPI 3.0
paths = spec.get('paths', {})
for path, methods in paths.items():
    for method in methods:
        if method.upper() in ['GET','POST','PUT','PATCH','DELETE','HEAD']:
            print(f'{method.upper():8} {path}')
" | sort

# Output:
# GET      /api/v1/users
# GET      /api/v1/users/{id}
# POST     /api/v1/users
# PUT      /api/v1/users/{id}
# DELETE   /api/v1/users/{id}
# GET      /api/v1/admin/users          ← admin route!
# POST     /api/v1/admin/export         ← admin action!
# DELETE   /api/v1/admin/users/{id}     ← admin delete!
```

### Extract All Unique Endpoints with Parameters

```python
#!/usr/bin/env python3
import json, sys, requests

TARGET = "https://target.com"
SWAGGER_URL = f"{TARGET}/swagger.json"

resp = requests.get(SWAGGER_URL, verify=False)
spec = resp.json()

endpoints = []
base_path = spec.get('basePath', '')
paths = spec.get('paths', {})

for path, methods in paths.items():
    full_path = base_path + path
    for method, details in methods.items():
        if method.upper() not in ['GET','POST','PUT','PATCH','DELETE']: continue
        
        params = details.get('parameters', [])
        auth = 'security' in details or 'security' in spec
        
        param_str = ", ".join([p['name'] for p in params])
        
        print(f"{method.upper():8} {full_path}")
        print(f"         Params: {param_str or 'none'}")
        print(f"         Auth required: {auth}")
        print()
        
        endpoints.append({
            'method': method.upper(),
            'path': full_path,
            'params': params,
            'auth': auth
        })

# Find unauthenticated endpoints
print("\n=== ENDPOINTS WITHOUT AUTH (test first!) ===")
for ep in endpoints:
    if not ep['auth']:
        print(f"  {ep['method']:8} {ep['path']}")
```

---

## Source 2: JavaScript Bundle Mining

When Swagger isn't available, the frontend JavaScript code is your next best source. Every `fetch()`, `axios.get()`, `$.ajax()` call in the JS bundle reveals an API endpoint.

### Extract from JS Files

```bash
# Get all JS files
gau target.com --ft js | sort -u > js_files.txt

# Pattern 1: fetch() and axios calls
while read url; do
    curl -sk "$url" | grep -oE "(fetch|axios\.(get|post|put|delete|patch))\(['\"][/a-zA-Z0-9/_{}?=-]+['\"]" | \
    grep -oE "['\"][/a-zA-Z0-9/_{}?=-]+['\"]" | tr -d "'\""
done < js_files.txt | sort -u | tee api_routes_from_js.txt

# Pattern 2: Direct path strings
while read url; do
    curl -sk "$url" | grep -oE "['\"][/api/[a-zA-Z0-9/_{}?=-]+['\"]" | \
    tr -d "'\"" | grep "^/api/"
done < js_files.txt | sort -u | tee -a api_routes_from_js.txt

# Pattern 3: baseURL + relative paths
while read url; do
    curl -sk "$url" | grep -oE "baseURL['\": ]+['\"]https?://[^'\"]+['\"]"
done < js_files.txt | sort -u
```

### React Native / Mobile Apps

```bash
# Extract APK, find JS bundle
unzip target.apk -d apk_extracted/
find apk_extracted/ -name "*.bundle" -o -name "index.android.bundle" | head -3

# Grep the bundle for API paths
grep -oE "['\"][/a-zA-Z0-9/_{}?=-]{8,}['\"]" \
    apk_extracted/assets/index.android.bundle | \
    tr -d "'\"" | grep "^/api/" | sort -u
```

### Using LinkFinder for Automation

```bash
# LinkFinder handles JS parsing intelligently
python3 linkfinder.py -i https://target.com -d -o cli | \
    grep -E "^/api/|^https?://.*(/api/|/v[0-9]+/)" | sort -u
```

---

## Source 3: GraphQL Introspection

If the target uses GraphQL, introspection gives you the complete schema:

```bash
# Test if GraphQL endpoint exists
curl -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' 2>/dev/null | python3 -m json.tool

# If it responds → run full introspection
curl -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d '{
        "query": "{
            __schema {
                types { name kind fields { name type { name kind } } }
                queryType { name fields { name } }
                mutationType { name fields { name } }
            }
        }"
    }' | python3 -m json.tool > graphql_schema.json

# Extract query names
python3 -c "
import json
with open('graphql_schema.json') as f:
    data = json.load(f)
schema = data.get('data',{}).get('__schema',{})
qt = schema.get('queryType',{}).get('fields',[])
mt = schema.get('mutationType',{}).get('fields',[]) or []
print('=== QUERIES ===')
for q in qt: print(f'  {q[\"name\"]}')
print('=== MUTATIONS ===')
for m in mt: print(f'  {m[\"name\"]}')
"
```

---

## Source 4: Postman Collections and API Portals

```bash
# Postman public collections are searchable
# Visit: https://www.postman.com/explore
# Search: "target.com" or the company name

# Some companies publish their collections:
curl -s "https://www.postman.com/collections/[COLLECTION_ID]" | python3 -m json.tool

# Also check:
# developer.target.com
# api.target.com/docs
# docs.target.com
# dev.target.com/api
```

---

## Source 5: robots.txt and sitemap.xml

```bash
# These sometimes list API paths
curl -sk https://target.com/robots.txt
# Disallow: /api/internal/   ← tells you exactly where to look

curl -sk https://target.com/sitemap.xml | grep -oE "https?://[^<]+" | sort -u

# Also check for API-specific sitemaps
curl -sk https://target.com/api/sitemap.xml
curl -sk https://api.target.com/sitemap.xml
```

---

## Complete API Discovery Workflow

```bash
#!/bin/bash
TARGET="${1:-https://target.com}"
TOKEN="${2:-}"

echo "=== API Endpoint Discovery: $TARGET ==="
HEADERS="-H 'Authorization: Bearer $TOKEN'"

# Phase 1: Swagger hunt
echo "[1] Searching for Swagger/OpenAPI spec..."
for path in /swagger.json /api-docs /openapi.json /v1/api-docs /v2/api-docs /swagger.yaml; do
    code=$(curl -sk -o /tmp/swagger_resp.txt -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" "$TARGET$path")
    if [ "$code" = "200" ]; then
        echo "  FOUND: $TARGET$path"
        # Parse endpoints
        python3 -c "
import json, sys
try:
    s=json.load(open('/tmp/swagger_resp.txt'))
    for p,m in s.get('paths',{}).items():
        for method in m:
            if method.upper() in ['GET','POST','PUT','DELETE','PATCH']:
                print(f'  {method.upper():8} {p}')
except: pass
" 2>/dev/null
    fi
done

# Phase 2: JS endpoint extraction
echo "[2] Mining JS files for API routes..."
gau "$TARGET" --ft js 2>/dev/null | head -20 | while read url; do
    curl -sk "$url" | grep -oE "['\"][/a-zA-Z0-9/_{}?=-]{8,}['\"]" | \
    tr -d "'\"" | grep "^/api/" | sort -u
done | sort -u | tee /tmp/js_endpoints.txt
echo "  JS endpoints: $(wc -l < /tmp/js_endpoints.txt)"

# Phase 3: GraphQL check
echo "[3] Checking for GraphQL..."
gql_resp=$(curl -sk -X POST "$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' 2>/dev/null)
echo "$gql_resp" | grep -q "__typename" && echo "  GraphQL endpoint found at $TARGET/graphql"

# Phase 4: robots.txt
echo "[4] Checking robots.txt..."
curl -sk "$TARGET/robots.txt" | grep -i "disallow\|api\|endpoint"
```

---

## Key Takeaways

```
1. Swagger/OpenAPI = complete API map — check 15+ path variations
2. Parse the spec: extract all paths, methods, auth requirements
3. Unauthenticated endpoints in Swagger = test immediately
4. JS bundle = every fetch() call = every API route
5. GraphQL introspection = full schema = query and mutation names
6. robots.txt Disallow entries = developers telling you what not to look at
7. Postman public collections sometimes published by target
8. Chain discovery: find hidden admin routes → test with user token → BFLA
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
