# CNAME Pointing to Unclaimed Service: When Your DNS Outlives Your Subscription

**Severity:** HIGH | **Category:** Recon | **Series:** #300DaysWithAppSec

---

## The Setup Nobody Notices Until It's Too Late

Picture this: a startup uses Shopify for their online store. They set up `shop.startup.com` with a CNAME record pointing to `startup.myshopify.com`. Business is good, they migrate to a custom backend, cancel the Shopify subscription — but no one touches the DNS.

Six months later, `shop.startup.com` still has that CNAME in DNS. The Shopify store is gone. The name `startup.myshopify.com` is now available for anyone to register for free.

This exact scenario happens hundreds of times a day across the internet. It's one of the most common recon findings — and depending on the service, it can escalate from informational all the way to Critical.

---

## Understanding the DNS Chain That Creates This Vulnerability

To exploit this, you first need to understand what a CNAME record does and why removing the account without removing the DNS record causes the problem.

### Normal CNAME Flow (Working)

```
User visits: shop.startup.com
     ↓
DNS lookup: shop.startup.com → CNAME → startup.myshopify.com
     ↓
DNS lookup: startup.myshopify.com → A → 23.227.38.65 (Shopify's server)
     ↓
Shopify's server checks: "do I know startup.myshopify.com?" → YES → serve the store
```

### Broken CNAME Flow (After Account Deletion)

```
User visits: shop.startup.com
     ↓
DNS lookup: shop.startup.com → CNAME → startup.myshopify.com  ← still in DNS!
     ↓
DNS lookup: startup.myshopify.com → A → 23.227.38.65 (still Shopify's server)
     ↓
Shopify's server checks: "do I know startup.myshopify.com?" → NO RECORD FOUND
     ↓
Shopify returns: "store not found" page or HTTP 404
```

The domain still resolves. DNS still works. But the destination account is gone — leaving the door open for anyone who registers `startup.myshopify.com`.

---

## How Severity Is Determined

Not all dangling CNAMEs are equal. The severity depends entirely on **what the external service allows**:

### HIGH — Service Is Claimable (Full Subdomain Takeover)

```
Scenario: shop.startup.com → startup.myshopify.com
Action:   Attacker creates free Shopify store → names it "startup"
Result:   Attacker now controls shop.startup.com
Severity: HIGH → effectively a full subdomain takeover
```

### MEDIUM — Service Exists But Account Is Inactive

```
Scenario: help.startup.com → startup.zendesk.com
Action:   Zendesk account exists but is suspended/inactive
Result:   Shows "Help Center Closed" — not claimable yet
Severity: MEDIUM → monitor for when account expires fully
```

### LOW — Service Is Permanently Gone With No Claim Path

```
Scenario: old.startup.com → startup.oldplatform.io (platform shut down entirely)
Action:   Platform no longer exists — nobody can register on it
Result:   DNS dangling but no exploitation path
Severity: LOW → still worth reporting for DNS hygiene
```

---

## How to Find These Vulnerabilities

### Step 1: Get All Subdomains With CNAME Records

```bash
# Start with full subdomain enumeration
subfinder -d target.com -all -silent -o all_subs.txt

# Filter only subdomains with CNAME records (not A records)
cat all_subs.txt | while read sub; do
    cname=$(dig CNAME "$sub" +short 2>/dev/null)
    [ -n "$cname" ] && echo "$sub → $cname"
done > cname_subs.txt

cat cname_subs.txt
# Output:
# shop.target.com → target.myshopify.com.
# help.target.com → target.zendesk.com.
# blog.target.com → target.ghost.io.
# careers.target.com → target-careers.netlify.app.
```

### Step 2: Check If the CNAME Destination Is Claimed

```bash
# For each CNAME, hit the destination and check the response
cat cname_subs.txt | while IFS=' → ' read sub cname; do
    # Clean trailing dot from dig output
    cname_clean="${cname%.}"
    
    # Get HTTP response from the CNAME destination directly
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 5 "https://$cname_clean" 2>/dev/null)
    
    # Also check the original subdomain
    sub_status=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 5 "https://$sub" 2>/dev/null)
    
    echo "$sub → $cname_clean | CNAME_STATUS:$status | SUB_STATUS:$sub_status"
done
```

### Step 3: Identify the Service and Check Its Fingerprint

Different services show different error messages when a name isn't claimed:

```bash
# Fingerprint check for common services
check_fingerprint() {
    local url="$1"
    local body=$(curl -s --connect-timeout 5 "$url" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    
    # Shopify
    echo "$body" | grep -q "there is no store called" && echo "SHOPIFY - CLAIMABLE"
    # Netlify
    echo "$body" | grep -q "not found" && echo "NETLIFY - CHECK MANUALLY"
    # GitHub Pages
    echo "$body" | grep -q "there isn't a github pages site here" && echo "GITHUB PAGES - CLAIMABLE"
    # Heroku
    echo "$body" | grep -q "no such app" && echo "HEROKU - CLAIMABLE"
    # Zendesk
    echo "$body" | grep -q "help center closed" && echo "ZENDESK - MONITOR"
    # HubSpot
    echo "$body" | grep -q "does not exist" && echo "HUBSPOT - CHECK"
    # Cargo
    echo "$body" | grep -q "if you're moving your cargo site" && echo "CARGO - CLAIMABLE"
}

check_fingerprint "https://target.myshopify.com"
```

### Automated: nuclei Templates

```bash
# Install/update nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# Run takeover templates (covers 50+ services)
nuclei -l all_subs.txt -t takeovers/ -silent -o takeover_findings.txt

# Results:
# [subdomain-takeover:shopify] [high] shop.target.com [shopify]
# [subdomain-takeover:netlify] [medium] blog.target.com [netlify]
```

### Automated: subzy

```bash
# Install
go install github.com/PentestPad/subzy@latest

# Run against all subdomains
subzy run --targets all_subs.txt

# Output:
# [VULNERABLE] shop.target.com - Shopify
# [NOT VULNERABLE] api.target.com
```

---

## Commonly Affected Services

These are the most common services found in dangling CNAME vulnerabilities:

| Service | Unclaimed Pattern | Claimable? |
|---------|------------------|------------|
| **Shopify** | "There is no store called X" | ✅ Yes — free plan available |
| **Netlify** | "Not Found" page | ✅ Yes — register the site name |
| **GitHub Pages** | "There isn't a GitHub Pages site here" | ✅ Yes — create matching repo |
| **Heroku** | "No such app" | ✅ Yes — free tier |
| **Zendesk** | "Help Center Closed" | ⚠️ Sometimes — check availability |
| **HubSpot** | Custom page/redirect | ⚠️ Sometimes |
| **AWS S3** | "NoSuchBucket" | ✅ Yes — create the bucket |
| **Azure** | "Web App not found" | ✅ Yes — create matching app |
| **Ghost (Pro)** | "The thing you were looking for" | ⚠️ Sometimes |
| **Webflow** | Site removed message | ✅ Yes — register the name |

---

## Proof of Concept — What to Show in Your Report

### Step 1: Document the DNS State

```bash
# Capture and screenshot this output
dig CNAME shop.target.com

# Output:
# ;; ANSWER SECTION:
# shop.target.com.    3600    IN    CNAME    target.myshopify.com.

# Confirm the Shopify site is unclaimed
curl -sI https://target.myshopify.com | head -5
# HTTP/1.1 404 Not Found
# ...

# Check the page body
curl -s https://target.myshopify.com | grep "no store"
# "There is no store called 'target'"  ← confirmed unclaimed
```

### Step 2: Confirm You COULD Take It Over (Without Actually Doing It)

For the bug report, you show that:
1. The CNAME record exists (dig output)
2. The destination is unclaimed (404 + service-specific fingerprint)
3. The service allows free registration with that name

You **do not** actually register the service unless the program explicitly allows it (some do, some don't — always check).

---

## The Bug Report

```
Title: CNAME Pointing to Unclaimed Shopify Store — shop.target.com

Severity: HIGH

Description:
The subdomain shop.target.com has a CNAME record pointing to 
target.myshopify.com. This Shopify store has been deleted but the 
DNS record was not removed. The store name "target" on Shopify is 
currently available for registration, allowing any attacker to create 
a free Shopify account and register this name, gaining full control 
of shop.target.com.

Steps to Reproduce:
1. Query DNS: dig CNAME shop.target.com
   Result: shop.target.com → target.myshopify.com

2. Check Shopify store: curl -s https://target.myshopify.com
   Result: "There is no store called 'target'" (store is gone)

3. Visit https://www.shopify.com → Create store → Enter "target" as store name
   Result: Name is available (not claiming, proving availability)

Proof:
[Screenshot: dig CNAME output]
[Screenshot: Shopify "no store" page at target.myshopify.com]
[Screenshot: Shopify registration page showing "target" is available]

Impact:
An attacker can serve phishing content from shop.target.com — a domain
that appears fully legitimate to visitors. Session cookies scoped to 
.target.com are accessible from this subdomain, potentially enabling 
account takeover for any user who visits the subdomain.

Remediation:
Remove the CNAME record for shop.target.com from DNS.
Implement a process to audit and clean up DNS records when 
external services are decommissioned.

CVSS: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
```

---

## Key Takeaways

```
1. CNAME to unclaimed = DNS points to a service account that no longer exists
2. Severity: HIGH if claimable, MEDIUM if service exists, LOW if gone entirely
3. Find it: check CNAME records → verify destination returns service error page
4. Tools: nuclei takeovers/ templates, subzy — both handle 50+ services
5. Always document without claiming (unless program allows it)
6. Chain it: unclaimed CNAME → actual takeover → cookie theft → ATO
7. Prevention: DNS audit checklist whenever canceling external service subscriptions
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
