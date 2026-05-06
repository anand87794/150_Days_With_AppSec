# Error Message Stack Trace Leak: Every Crash Is a Confession

**Severity:** HIGH | **Category:** Fingerprinting | **Series:** #300DaysWithAppSec

---

## The Error Page That Hands You Everything

When a developer forgets to configure proper error handling, a single bad request turns the server into an informant. Stack traces reveal file paths, class names, SQL queries, database credentials, internal IPs, and framework versions — all in one response.

This isn't theoretical. It happens constantly on production servers.

---

## How to Trigger Error Messages

```bash
# Method 1: Send wrong data type
GET /api/users/abc          # expects integer, gets string
GET /api/orders/null        # null where object expected

# Method 2: SQL injection character
GET /api/user?id=1'         # triggers DB error with query exposed

# Method 3: Nonexistent resource
GET /api/users/999999999    # object not found → stack trace

# Method 4: Malformed JSON body
curl -X POST https://target.com/api \
    -H "Content-Type: application/json" \
    -d "{'broken json"       # triggers parse error

# Method 5: Invalid file extension
GET /dashboard.phpX          # unknown extension → error
GET /api/users.xml           # XML not supported → trace
```

---

## What Each Framework Leaks

### Django (Python)
```
# triggers: any error with DEBUG=True
# leaks: full settings.py — including:
SECRET_KEY = 'django-insecure-abc123xyz...'
DATABASES = {'default': {'PASSWORD': 'db_password_prod'}}
INSTALLED_APPS = ['myapp', ...]
# also: full request/response, local variables at each frame
```

### Laravel (PHP)
```
# triggers: any unhandled exception  
# Ignition debug page leaks:
.env file contents: DB_PASSWORD=prod_password
APP_KEY=base64:xxx  → forge encrypted cookies
Stack trace with: /var/www/html/app/... file paths
SQL query that failed with bind parameters
```

### Node.js / Express
```
Error: ECONNREFUSED connect ECONNREFUSED 10.0.0.5:5432
    at TCPConnectWrap.afterConnect (/app/node_modules/pg-pool/lib/index.js:53)
# leaks: internal DB host IP, path to node_modules, db client version
```

### Java Spring
```
org.springframework.dao.DataAccessException: 
Failed to execute SQL: SELECT * FROM users WHERE id=? 
  at com.target.app.UserService.findById(UserService.java:47)
  at com.target.app.UserController.getUser(UserController.java:23)
# leaks: package structure, class names, method names, SQL
```

---

## The Attack Chain

```
Error reveals: /var/www/html/config/database.php:142
     ↓
Path traversal attempt: GET /api/files?path=../../config/database.php
     ↓
If vulnerable: full DB credentials exposed → CRITICAL

Error reveals: DB host = db.internal.target.com at 10.0.0.5
     ↓
SSRF attempt: GET /api/fetch?url=http://10.0.0.5:5432
     ↓
Internal DB access via SSRF → CRITICAL

Error reveals: Framework version = Spring 5.3.1
     ↓
Check CVE database → Spring4Shell CVE-2022-22965 → RCE
```

---

## Key Takeaways

```
1. Stack traces leak: file paths, DB creds, internal IPs, framework versions
2. Trigger with: wrong types, SQL chars, nonexistent IDs, malformed JSON
3. Django DEBUG=True: full settings.py on every 404 page
4. Laravel Ignition: .env contents + DB password on debug page
5. Flask debug: interactive shell → direct RCE
6. Chain: file path → path traversal; DB host → SSRF; version → CVE
7. HIGH finding standalone → escalates to CRITICAL when chained
8. Fix: set debug=false + configure generic error pages in production
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
