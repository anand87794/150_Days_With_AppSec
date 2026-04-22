# robots.txt & sitemap.xml Leak: The Hidden Intelligence Nobody Thinks About

**Severity:** HIGH | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## You Told the Crawler to Stay Away. The Attacker Listened.

The entire purpose of `robots.txt` is to tell search engine crawlers which pages they should NOT index. It's a polite request — crawlers don't have to obey it. But here's the irony that makes this a HIGH severity finding:

**Every path listed in `Disallow:` is a gift to the attacker.**

When a developer writes `Disallow: /admin/`, they've just published the location of their admin panel to anyone who visits `https://target.com/robots.txt`. Google's crawler stays away. An attacker goes directly there.

This is passive intelligence gathering at its finest — zero requests to anything sensitive, all the information served up voluntarily.

---

## robots.txt — The Complete Guide

### What robots.txt Is

robots.txt is a plain text file at the root of every domain. It follows the Robots Exclusion Protocol — a standard from 1994 that has no enforcement mechanism. It's entirely honor-based.

```
# Structure:
User-agent: *          → applies to all crawlers
Disallow: /path/       → crawlers should not index this
Allow: /path/          → explicitly allow this (overrides Disallow)
Crawl-delay: 10        → wait 10 seconds between requests

User-agent: Googlebot  → specific to Google's crawler only
Disallow: /secret/
```

### What a Vulnerable robots.txt Looks Like

```
User-agent: *
Disallow: /admin/                    ← admin panel location
Disallow: /api/internal/             ← internal API endpoints
Disallow: /api/v1/debug/             ← debug API
Disallow: /backup/                   ← backup directory
Disallow: /staging/                  ← staging environment
Disallow: /wp-admin/                 ← WordPress admin (confirms CMS)
Disallow: /phpmyadmin/               ← database management tool
Disallow: /jenkins/                  ← CI/CD pipeline
Disallow: /grafana/                  ← monitoring dashboard
Disallow: /.env                      ← environment file (check if accessible!)
Disallow: /config/                   ← configuration directory
Disallow: /private/                  ← private files
Disallow: /uploads/2024/             ← upload directory structure
Allow: /                             
Sitemap: https://target.com/sitemap.xml   ← follow this too!
```

Every `Disallow` entry is a URL worth investigating. The developer considered these important enough to hide from search engines — which usually means they're sensitive.

### Automated Extraction

```bash
# Download and read robots.txt
curl -s https://target.com/robots.txt

# Extract all Disallow paths
curl -s https://target.com/robots.txt | \
    grep "Disallow" | awk '{print $2}' | sort -u

# Test each disallowed path for accessibility
curl -s https://target.com/robots.txt | \
    grep "Disallow" | awk '{print $2}' | \
    while read path; do
        code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com$path")
        echo "[$code] https://target.com$path"
    done

# Look for the Sitemap directive
curl -s https://target.com/robots.txt | grep -i "Sitemap"
# → Follow those URLs next!
```

### Variations to Check

```bash
TARGET="https://target.com"

# Standard locations
curl -sk "$TARGET/robots.txt"
curl -sk "$TARGET/Robots.txt"        # case variation
curl -sk "$TARGET/ROBOTS.TXT"

# Subdomain variations
for sub in www api dev staging app; do
    curl -sk "https://$sub.target.com/robots.txt" 2>/dev/null | \
        grep -i "disallow\|sitemap" | head -10
done
```

---

## sitemap.xml — Complete URL Intelligence

### What sitemap.xml Is

A sitemap is an XML file that tells search engines "here are all the pages on my website." It's the opposite of robots.txt — instead of hiding paths, it lists everything the developer wants indexed.

```xml
<!-- Standard sitemap format -->
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://target.com/</loc>
    <lastmod>2024-01-15</lastmod>    ← recently added!
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://target.com/api/v2/users</loc>   ← API route in sitemap!
    <lastmod>2024-01-10</lastmod>
  </url>
  <url>
    <loc>https://target.com/admin/dashboard</loc>  ← admin in sitemap!
    <lastmod>2023-12-01</lastmod>
  </url>
</urlset>
```

### The Sitemap Index — Multiple Sitemaps

Large websites use a sitemap index that links to multiple sub-sitemaps:

```xml
<!-- sitemap_index.xml — follow all these! -->
<sitemapindex>
  <sitemap>
    <loc>https://target.com/sitemap-products.xml</loc>
  </sitemap>
  <sitemap>
    <loc>https://target.com/sitemap-api.xml</loc>      ← API sitemap!
  </sitemap>
  <sitemap>
    <loc>https://target.com/sitemap-admin.xml</loc>    ← admin sitemap!
  </sitemap>
</sitemapindex>
```

### Extracting All URLs from sitemap.xml

```bash
#!/bin/bash
TARGET="${1:-https://target.com}"

# Step 1: Download main sitemap
curl -sk "$TARGET/sitemap.xml" -o /tmp/sitemap.xml

# Step 2: Check if it's a sitemap index (links to more sitemaps)
if grep -q "sitemapindex" /tmp/sitemap.xml; then
    echo "Sitemap INDEX found — fetching sub-sitemaps..."
    
    # Extract all sub-sitemap URLs
    grep -oE "https?://[^<]+" /tmp/sitemap.xml | \
        grep -i "sitemap" | sort -u | while read sub_url; do
        echo "Fetching: $sub_url"
        curl -sk "$sub_url"
    done
fi

# Step 3: Extract all URLs
python3 -c "
import xml.etree.ElementTree as ET
import sys

try:
    tree = ET.parse('/tmp/sitemap.xml')
    root = tree.getroot()
    ns = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
    
    for url_el in root.findall('.//sm:url', ns):
        loc = url_el.find('sm:loc', ns)
        lastmod = url_el.find('sm:lastmod', ns)
        if loc is not None:
            mod = lastmod.text if lastmod is not None else 'unknown'
            print(f'{mod}  {loc.text}')
except ET.ParseError:
    # Fallback: regex
    import re
    content = open('/tmp/sitemap.xml').read()
    urls = re.findall(r'<loc>([^<]+)</loc>', content)
    for u in urls: print(u)
" | sort -r  # Sort by date — newest first!

# Step 4: Filter for interesting patterns
grep -iE "admin|api|debug|internal|test|private" /tmp/sitemap.xml | \
    grep -oE "https?://[^<]+" | sort -u
```

---

## The lastmod Intelligence — What Was Changed Recently?

The `<lastmod>` field in sitemap.xml shows when a page was last modified. This is valuable for two reasons:

1. **Recently added pages** = new features = potentially missed security review
2. **Date correlations** = "this admin page was added 3 days ago" = probably the new feature you heard about

```bash
# Extract URLs sorted by modification date (newest = most interesting)
python3 << 'EOF'
import xml.etree.ElementTree as ET
from datetime import datetime

tree = ET.parse('/tmp/sitemap.xml')
root = tree.getroot()
ns = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}

entries = []
for url_el in root.findall('.//sm:url', ns):
    loc = url_el.find('sm:loc', ns)
    lastmod = url_el.find('sm:lastmod', ns)
    if loc is not None:
        date = lastmod.text if lastmod is not None else '1970-01-01'
        entries.append((date, loc.text))

# Sort newest first
for date, url in sorted(entries, reverse=True)[:20]:
    print(f"{date}  {url}")
EOF
```

---

## Complete Passive Recon Workflow

```bash
#!/bin/bash
TARGET="${1:-https://target.com}"

echo "=== robots.txt + sitemap.xml Recon: $TARGET ==="

# ── robots.txt ────────────────────────────────────────────────────────
echo ""
echo "[1] Fetching robots.txt..."
ROBOTS=$(curl -sk "$TARGET/robots.txt")
echo "$ROBOTS"

echo ""
echo "[2] Extracting Disallow paths..."
DISALLOW_PATHS=$(echo "$ROBOTS" | grep -i "Disallow" | awk '{print $2}' | sort -u)
echo "$DISALLOW_PATHS"

echo ""
echo "[3] Testing each disallowed path..."
echo "$DISALLOW_PATHS" | while read path; do
    [ -z "$path" ] && continue
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$path")
    size=$(curl -sk -o /dev/null -w "%{size_download}" "$TARGET$path")
    echo "  [$code] [$size bytes] $TARGET$path"
done

# ── sitemap.xml ───────────────────────────────────────────────────────
echo ""
echo "[4] Fetching sitemap.xml..."
SITEMAP_URLS=(
    "$TARGET/sitemap.xml"
    "$TARGET/sitemap_index.xml"
    "$TARGET/sitemap1.xml"
    "$TARGET/news-sitemap.xml"
    "$TARGET/product-sitemap.xml"
)
for url in "${SITEMAP_URLS[@]}"; do
    code=$(curl -sk -o /tmp/sitemap_check.txt -w "%{http_code}" "$url")
    if [ "$code" = "200" ]; then
        echo "  FOUND: $url"
        # Extract URLs
        grep -oE "https?://[^<]+" /tmp/sitemap_check.txt | sort -u | wc -l
        echo "    URLs extracted"
        # Flag interesting ones
        grep -iE "admin|api|debug|internal|private|secret" /tmp/sitemap_check.txt | \
            grep -oE "https?://[^<]+" | head -10
    fi
done

# Also check sitemap URL from robots.txt
SITEMAP_FROM_ROBOTS=$(echo "$ROBOTS" | grep -i "Sitemap:" | awk '{print $2}')
if [ -n "$SITEMAP_FROM_ROBOTS" ]; then
    echo ""
    echo "[5] Fetching sitemap from robots.txt directive: $SITEMAP_FROM_ROBOTS"
    curl -sk "$SITEMAP_FROM_ROBOTS" | grep -oE "https?://[^<]+" | sort -u | head -30
fi
```

---

## Reporting

```
Title: robots.txt Exposes Internal Path Structure — /admin/, /api/internal/, /backup/

Severity: HIGH

Description:
The file https://target.com/robots.txt contains Disallow directives 
that expose the complete internal URL structure of the application, 
including admin panels, internal APIs, and backup directories.

Exposed Paths:
- /admin/ → HTTP 200 (accessible admin panel)
- /api/internal/ → HTTP 200 (internal API, no auth required)
- /backup/ → HTTP 403 (backup directory exists, access restricted)
- /api/v1/debug/ → HTTP 200 (debug endpoint, returns verbose data)

Steps to Reproduce:
1. GET https://target.com/robots.txt
2. Note all Disallow entries
3. Test each: GET https://target.com/admin/ → 200 OK

Impact:
robots.txt entries provide a roadmap to sensitive application areas.
The /admin/ and /api/internal/ paths are accessible without authentication,
enabling direct unauthorized access to administrative functionality.

Remediation:
- Remove specific internal paths from robots.txt
- Use a generic catch-all: Disallow: / for truly sensitive sections
- Ensure admin paths require authentication regardless of robots.txt
```

---

## Key Takeaways

```
1. robots.txt Disallow = "here are our sensitive paths" — test all of them
2. sitemap.xml = complete URL inventory — extract + test everything
3. sitemap lastmod shows recently added pages → new features → test first
4. sitemap_index.xml links to sub-sitemaps — follow all of them
5. Both files are passive — zero noise, completely undetectable
6. Sitemap entries often include API paths devs forgot to exclude
7. Disallow does NOT block access — it just requests crawlers to skip
8. Find sitemap URL in robots.txt → two birds, one stone
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
