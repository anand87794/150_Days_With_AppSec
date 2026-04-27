# Pastebin / Gist Leaks: Secrets Shared for Help, Indexed by Everyone

**Severity:** MEDIUM | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The "Quick Share" Problem

A developer hits a bug at 11pm. They paste their config file to Pastebin to share with a colleague on Slack. The config has a real database password. They forget about the paste. Six months later, Google has indexed it. A bug bounty hunter finds it with a two-word dork.

This happens constantly. Pastebin alone processes millions of new pastes per day. A meaningful percentage of them contain credentials, API keys, internal URLs, and employee data — shared carelessly for "quick help."

---

## Where Leaks Happen

**Pastebin.com** — Most common. Public by default. Google indexed.

**GitHub Gist** — Code snippets. Public gists are searchable. Even "secret" gists are accessible to anyone with the URL.

**GitLab Snippets** — Same as Gist but on GitLab instances.

**Hastebin / Ghostbin / dpaste** — Alternative paste sites, less monitored.

**Discord / Slack public channels** — Messages with paste links get archived.

---

## Google Dorks — Find Company Pastes Passively

```bash
# Basic pattern — company domain + sensitive keyword
site:pastebin.com "target.com" "password"
site:pastebin.com "target.com" "api_key"
site:pastebin.com "target.com" "SECRET"
site:pastebin.com "target.com" "token"

# GitHub Gist
site:gist.github.com "target.com" "api_key"
site:gist.github.com "target.com" "password"
site:gist.github.com org:target

# Email-based search
"@target.com" site:pastebin.com
"@target.com" site:gist.github.com

# GitLab snippets
site:gitlab.com/snippets "target.com"

# Specific credential patterns
site:pastebin.com "target.com" "DB_PASSWORD"
site:pastebin.com "target.com" "mongodb://"
site:pastebin.com "AKIA" "target"         # AWS keys mentioning target
```

---

## Automated Tools

```bash
# pwnedOrNot — checks if email appears in paste leaks
pip3 install pwnedornot --break-system-packages
pwnedornot -e employee@target.com

# IntelligenceX (intelligence.io) — best commercial coverage
# Search: target.com → filters paste sites, breach data, dark web

# pastehunter — monitor paste sites in real-time
git clone https://github.com/kevthehermit/PasteHunter
# Add keyword: target.com → get alerts when it appears in new pastes

# Custom Google search via SerpAPI
python3 -c "
import requests
API_KEY = 'YOUR_SERPAPI_KEY'
results = requests.get('https://serpapi.com/search', params={
    'api_key': API_KEY,
    'q': 'site:pastebin.com target.com password',
    'num': 100
}).json()
for r in results.get('organic_results', []):
    print(r['link'], r.get('snippet','')[:80])
"
```

---

## What to Do When You Find a Paste

```bash
# Step 1: Archive it immediately
curl -s "https://pastebin.com/raw/PASTE_ID" > found_paste.txt
# Take a screenshot of the paste URL with content visible

# Step 2: Extract sensitive data
grep -iE "password|secret|api_key|token|AKIA" found_paste.txt

# Step 3: Verify if credentials are live (minimal testing)
# API key → make a single API call to check validity
# DB password → attempt connection (only if in scope)

# Step 4: Report with:
# - Paste URL (may be deleted — your screenshot is evidence)
# - Excerpt of what was found (mask the actual secret in report)
# - Whether credential was verified live
# - Timestamp of paste creation
```

---

## Key Takeaways

```
1. Pastebin, Gist, GitLab Snippets = searchable public paste sites
2. Google indexes them — dorks find pastes years after creation
3. Even deleted pastes: may be in Google cache or archive.org
4. site:pastebin.com "target.com" "password" = first dork to run
5. Tools: pwnedOrNot (emails), IntelX (comprehensive), pastehunter (monitoring)
6. Archive immediately — pastes get deleted when reported
7. Verify if live (minimal test) before reporting
8. MEDIUM discovery → CRITICAL if live credentials found
```

---

*Written by Anand Prajapati — Penetration Tester & Security Researcher*

🔗 **Connect:** [LinkedIn](https://linkedin.com/in/anand-prajapati-7a265a369) · [GitHub](https://github.com/anand87794) · [Portfolio](https://anandprajapati.lovable.app) · [X @anand87794](https://x.com/anand87794)

*Part of the #300DaysWithAppSec series — 300 vulnerabilities, real security education.*
