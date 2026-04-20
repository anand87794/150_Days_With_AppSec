<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=28&pause=1000&color=3B82F6&center=true&vCenter=true&width=700&lines=%23300DaysWithAppSec;300+Vulnerabilities.+Real+Education.;Web+%7C+API+%7C+Mobile+%7C+Cloud+%7C+AI%2FLLM" alt="Typing SVG" />



> **300 vulnerabilities. 300 infographics. 300 in-depth articles.**  
> *The most visual, beginner-friendly application security series on the internet.*

<br/>

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Anand%20Prajapati-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/anand-prajapati-7a265a369)
[![GitHub](https://img.shields.io/badge/GitHub-anand87794-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/anand87794)
[![Portfolio](https://img.shields.io/badge/Portfolio-anandprajapati.lovable.app-FF6B6B?style=for-the-badge&logo=firefox&logoColor=white)](https://anandprajapati.lovable.app)
[![X](https://img.shields.io/badge/X%20(Twitter)-@anand114bug-000000?style=for-the-badge&logo=x&logoColor=white)](https://x.com/anand87794)

</div>

---

## 📌 What Is This Repository?

This is the official GitHub home of **#300DaysWithAppSec** — a long-form application security education series covering **300 real-world vulnerabilities, misconfigurations, and attack techniques** across the entire modern attack surface.

Every entry in this series includes:

| Deliverable | Description |
|-------------|-------------|
| 🖼️ **Infographic** | Visual cheatsheet (1080×1940px HD) — understand the bug at a glance |
| 📝 **Article** | Deep-dive written guide — from zero to exploit, beginner-friendly |

Each article is structured to answer **4 core questions:**
1. What is this vulnerability? *(explained in plain English)*
2. Why does it exist? *(the root cause)*
3. How do you find and exploit it? *(step-by-step with real commands)*
4. How do you report it? *(severity, impact, remediation)*

**No fluff. No theory without practice. Every topic has real commands you can run today.**

---

## 🗂️ Categories Covered

This series spans the **complete application security landscape** — from the very first step of recon all the way to AI/LLM-specific attacks:

<table>
<tr>
<td valign="top" width="50%">

### 🔍 Recon & Fingerprinting
Subdomain enumeration, DNS attacks, certificate transparency, GitHub dorking, Shodan hunting, source map exposure, admin panel discovery, version disclosure, and more.

### 🔑 Authentication & Session
Brute force, credential stuffing, OTP bypass, MFA bypass, session fixation, cookie security flags, JWT attacks (alg:none, RS256→HS256, weak secrets, kid injection), OAuth flows, SAML attacks, SSO misconfigurations.

### 🛡️ Access Control
IDOR (numeric, UUID, encoded, second-order), BOLA, BFLA, vertical and horizontal privilege escalation, mass assignment, CSRF in all variants, forced browsing, method override attacks.

### 💉 Injection
SQL injection (error-based, union, blind, time-based, out-of-band), NoSQL injection, ORM injection, OS command injection, SSTI across all major template engines (Jinja2, Twig, Freemarker, Velocity, OGNL), LDAP, XPath, email header, log injection, CSV injection.

### 🕸️ XSS & Client-Side
Reflected, stored, DOM-based, blind XSS, mXSS, XSS via file uploads, CSP bypass techniques (JSONP, unsafe-inline, trusted CDN), XSS-to-ATO chains.

</td>
<td valign="top" width="50%">

### 🌐 SSRF / XXE
Basic and blind SSRF, SSRF to cloud metadata (AWS/GCP/Azure), SSRF filter bypasses, SSRF to RCE chains, XXE in-band and OOB, XXE via file uploads, billion laughs DoS.

### 📁 File Upload & Path Traversal
Unrestricted upload, extension bypass, content-type bypass, magic bytes bypass, null byte injection, path traversal via filename, LFI (including log poisoning and PHP wrappers), RFI, ZIP slip.

### 💼 Business Logic & Race Conditions
Price manipulation, workflow step bypass, coupon stacking, race conditions (coupon reuse, double spend, account verification bypass), payment manipulation, refund abuse.

### 🔌 API Security
OWASP API Top 10, GraphQL attacks, WebSocket security, gRPC/Protobuf, API versioning bypass, shadow APIs, mass assignment via API, rate limiting bypass.

### ☁️ Cloud & Infrastructure
AWS (S3, IAM, Lambda, ECR), GCP, Azure, Kubernetes, Docker, CI/CD pipelines (GitHub Actions, Jenkins), Terraform state exposure, exposed databases (Elasticsearch, MongoDB, Redis).

### 📱 Mobile Security
Android deep link hijacking, insecure data storage, SSL pinning bypass, hardcoded secrets in APK, logcat leaks, WebView vulnerabilities, root detection bypass.

### 🤖 AI / LLM Security
Prompt injection (direct and indirect), insecure plugin execution, LLM agent manipulation.

</td>
</tr>
</table>

---

## 📊 Series Statistics

<div align="center">

| Metric | Count |
|--------|-------|
| 🐛 Total Vulnerabilities | **300** |
| 🖼️ Infographics | **300** |
| 📝 Articles | **300** |
| ⚠️ Critical Severity | **80** |
| 🔴 High Severity | **135** |
| 🟡 Medium Severity | **70** |
| 🟢 Low Severity | **15** |

</div>

---

## 🔥 Severity Distribution

```
CRITICAL  ████████████████░░░░░░░░░░░░░░  80  bugs  (27%)
HIGH      ██████████████████████████░░░░  135 bugs  (45%)
MEDIUM    █████████████░░░░░░░░░░░░░░░░░  70  bugs  (23%)
LOW       ███░░░░░░░░░░░░░░░░░░░░░░░░░░░  15  bugs  (5%)
```

---

## 📖 How to Use This Repository

### For Beginners
Start with the **Recon** section. Every article is written assuming zero prior knowledge — if you can read English and run a terminal, you can follow along. Concepts are explained with real-world analogies before commands are introduced.

### For Intermediate/Advanced Learners
Jump directly to any category that interests you. Articles include full exploitation scripts, chained attack scenarios, and detailed bug report templates you can use directly in your bug bounty reports.

### For Bug Bounty Hunters
Every article ends with:
- ✅ Exact steps to reproduce
- ✅ CVSS score guidance
- ✅ Severity justification
- ✅ Complete bug report template
- ✅ Remediation advice (to understand what you're looking for)

### For Pentesters & Security Teams
The articles are structured to be used as **testing checklists**. Each vulnerability includes detection methods, tool commands, and evidence collection guidance suitable for professional pentest reports.

---

## 🛠️ Tools Referenced in This Series

This series uses **only free and open-source tools** (unless otherwise noted):

```
Recon:          subfinder, amass, dnsx, httpx, ffuf, gau, waybackurls
Scanning:       nmap, masscan, nuclei
Web Testing:    Burp Suite Community, OWASP ZAP, curl, httpx
API Testing:    Postman, grpcurl, wscat, Burp WebSocket
Mobile:         jadx, apktool, frida, objection, adb
Cloud:          aws-cli, gcloud, az, pacu, cloudsploit
Exploitation:   sqlmap, ysoserial, jwt_tool, pwncat
```

---

## 📂 Repository Structure

```
300DaysWithAppSec/
│
├── recon/
│   ├── infographics/          → HD visual cheatsheets
│   └── articles/              → In-depth written guides
│
├── fingerprinting/
│   ├── infographics/
│   └── articles/
│
├── authentication-session/
│   ├── infographics/
│   └── articles/
│
├── access-control/
│   ├── infographics/
│   └── articles/
│
├── injection/
│   ├── infographics/
│   └── articles/
│
├── xss/
│   ├── infographics/
│   └── articles/
│
├── ssrf-xxe/
│   ├── infographics/
│   └── articles/
│
├── file-upload/
│   ├── infographics/
│   └── articles/
│
├── business-logic/
│   ├── infographics/
│   └── articles/
│
├── api-security/
│   ├── infographics/
│   └── articles/
│
├── cryptography/
│   ├── infographics/
│   └── articles/
│
├── deserialization/
│   ├── infographics/
│   └── articles/
│
├── cache-smuggling/
│   ├── infographics/
│   └── articles/
│
├── cloud-infrastructure/
│   ├── infographics/
│   └── articles/
│
├── mobile/
│   ├── infographics/
│   └── articles/
│
└── ai-llm/
    ├── infographics/
    └── articles/
```

---

## ⭐ If This Helped You

If this series helped you understand a concept, find a bug, or level up your skills — **star this repository**. It helps other security learners discover this content.

And if you're actively hunting bugs or studying for certifications — bookmark this. Every topic in this series maps directly to real-world targets.

---

## 👤 About the Author

<div align="center">

**Anand Prajapati**  
*Penetration Tester · Bug Bounty Hunter · Security Researcher*

Hands-on experience in web application pentesting, API security, and red teaming.  
Completed **500+ PortSwigger Web Security Academy labs**.  
Active on HackerOne and Bugcrowd.

| Platform | Link |
|----------|------|
| 🔗 LinkedIn | [linkedin.com/in/anand-prajapati-7a265a369](https://linkedin.com/in/anand-prajapati-7a265a369) |
| 🐙 GitHub | [github.com/anand87794](https://github.com/anand87794) |
| 🌐 Portfolio | [anandprajapati.lovable.app](https://anandprajapati.lovable.app) |
| 🐦 X (Twitter) | [@anand114bug](https://x.com/anand114bug) |
| 📧 Email | available on portfolio |

</div>

---

## 📜 License

This repository and all its contents are licensed under the **MIT License** — free to read, share, and learn from. If you use content from this series, a credit/mention is appreciated but not required.

---

<div align="center">

*Security is not a product. It's a mindset.*  
*Build it one vulnerability at a time.*

**#300DaysWithAppSec · #BugBounty · #AppSec · #PenTest · #WebSecurity**

</div>
