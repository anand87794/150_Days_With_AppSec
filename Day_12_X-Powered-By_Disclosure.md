# X-Powered-By Disclosure: One Header, Full Tech Stack Revealed

**Severity:** LOW | **Category:** Fingerprinting | **Series:** #300DaysWithAppSec

---

## The Header Nobody Thought to Remove

PHP sets `X-Powered-By: PHP/8.1.2` in every response by default. Express.js sets `X-Powered-By: Express`. ASP.NET sets `X-Powered-By: ASP.NET`. These headers were added during development to help developers and browser vendors understand the web ecosystem — and most production servers never had them removed.

A single curl command reveals the backend language, version, and sometimes the operating system. That version maps directly to CVEs with working exploits. This is why fingerprinting matters — even LOW severity findings become starting points for Critical chains.

---

## What X-Powered-By Values Mean

```bash
curl -sI https://target.com | grep -i x-powered

# Common values and their implications:
X-Powered-By: PHP/7.4.3        → old PHP, CVE-2021-21707, type juggling bugs
X-Powered-By: PHP/5.6.40       → EOL since 2018, dozens of unpatched vulns
X-Powered-By: PHP/8.1.2        → current, check for known type juggling issues
X-Powered-By: ASP.NET          → .NET stack → ViewState attacks, deserialization
X-Powered-By: ASP.NET 4.0      → .NET 4.0 → specific serialization gadgets
X-Powered-By: Express          → Node.js → prototype pollution patterns
X-Powered-By: Next.js          → Next.js → check for misconfigured rewrites
X-Powered-By: Servlet/4.0      → Java servlet → check for Struts, Spring issues
```

---

## How to Check at Scale

```bash
# Single target
curl -sI https://target.com | grep -iE "x-powered|server|x-generator"

# All subdomains
cat subdomains.txt | httpx -silent -header "X-Powered-By" -title \
    -status-code -o tech_fingerprints.txt

# whatweb — comprehensive tech detection
whatweb https://target.com -v
whatweb -i subdomains.txt --log-json=whatweb.json

# Grep for old PHP versions (high priority)
cat tech_fingerprints.txt | grep -E "PHP/[45]\." | head -20
```

---

## Version to Attack Mapping

```
PHP/7.4.3  → CVE-2021-21707 (XML parsing), type juggling (loose comparisons)
PHP/5.x    → EOL → buffer overflows, arbitrary code execution patterns
Express    → prototype pollution → RCE if merge/clone used on user input
ASP.NET    → check __VIEWSTATE MAC disabled → deserialization → RCE
Servlet    → check for Spring4Shell (CVE-2022-22965) if Spring in stack
```

---

## Fix — Two Lines

```ini
# PHP — php.ini
expose_php = Off

# Apache — httpd.conf
Header unset X-Powered-By

# nginx — nginx.conf (proxy)
proxy_hide_header X-Powered-By;

# Express — app.js
app.disable('x-powered-by');

# Next.js — next.config.js
module.exports = { poweredByHeader: false }
```

---

## Key Takeaways

```
1. X-Powered-By = language/version in every HTTP response header
2. PHP, Express, ASP.NET set it by default — never removed in prod
3. Version → NVD search → known CVE → targeted exploit
4. PHP 5.x/7.x still running = old = unpatched = high-value target
5. Check all subdomains: httpx -tech-detect covers this automatically
6. LOW standalone → chain with CVE for MEDIUM/HIGH report
7. Fix is 1 line: expose_php=Off or app.disable('x-powered-by')
8. Always grep error pages and 404s too — version in error messages
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
