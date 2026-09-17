🛡️ VulnHunter

<img width="1505" height="726" alt="image" src="https://github.com/user-attachments/assets/e7a09093-a1f7-41b4-bd72-d39013ae338f" />


VulnHunter is a modular Python-based vulnerability assessment tool for security research, authorized penetration testing, and educational labs.

VulnHunter هي أداة مرنة مبنية بلغة Python لتقييم الثغرات الأمنية، واكتشاف الخدمات وتطبيقات الويب، وتحليل الثغرات، وربط النتائج بمعلومات CVE وExploitDB.

---

📖 About | عن المشروع

VulnHunter is designed to automate different stages of a security assessment, starting from target discovery and web enumeration, then detecting potential vulnerabilities and correlating the results with vulnerability intelligence.

تم تصميم VulnHunter لأتمتة عدة مراحل من عملية التقييم الأمني، بدايةً من اكتشاف الهدف والخدمات والمسارات، ثم فحص تطبيقات الويب، واكتشاف مؤشرات الثغرات، وربط النتائج بمعلومات الثغرات الأمنية.

The project is modular, making it easier to add new scanners, vulnerability detectors, and intelligence sources.

المشروع مبني بطريقة Modular، مما يسهل إضافة أدوات فحص جديدة، وكواشف ثغرات جديدة، ومصادر معلومات أمنية جديدة.

---

✨ Features | المميزات

Feature| Description| الوصف
🔎 Port Discovery| Discover open ports and services| اكتشاف المنافذ والخدمات
🌐 Web Discovery| Discover web applications and endpoints| اكتشاف تطبيقات ومسارات الويب
📁 Directory Discovery| Discover accessible directories and files| اكتشاف المجلدات والملفات
🕷️ Vulnerability Detection| Detect potential web vulnerabilities| اكتشاف مؤشرات الثغرات
💉 SQL Injection| Check for SQL injection indicators| فحص مؤشرات SQL Injection
⚡ XSS| Check for Cross-Site Scripting indicators| فحص مؤشرات XSS
🔄 SSRF| Check for SSRF indicators| فحص مؤشرات SSRF
📄 XXE| Check for XXE-related issues| فحص مؤشرات XXE
📂 Path Traversal| Check for path traversal issues| فحص Path Traversal
↪️ Open Redirect| Check for open redirect issues| فحص Open Redirect
🔐 Security Checks| Check common security misconfigurations| فحص الإعدادات الأمنية
🧩 CVE Correlation| Correlate software with CVEs| ربط الخدمات مع CVEs
💥 ExploitDB| Retrieve related ExploitDB information| البحث عن ExploitDB
📊 Reporting| Generate structured reports| إنشاء التقارير

---

🚀 Installation | التثبيت

1. Clone the repository | تحميل المشروع

git clone https://github.com/abdullah-cyb/VulnHunter.git

cd VulnHunter

---

2. Create a virtual environment | إنشاء بيئة افتراضية

Linux / Parrot OS:

python3 -m venv .venv

Activate the environment:

source .venv/bin/activate

Windows:

python -m venv .venv

.venv\Scripts\activate

---

3. Install VulnHunter | تثبيت الأداة

pip install -e .

After installation, verify that the command works:

vulnhunter --help

---

▶️ Usage | الاستخدام

Basic Scan | فحص أساسي

vulnhunter --target 192.168.1.50

---

Scan an Authorized Web Application | فحص تطبيق ويب مصرح به

vulnhunter --target https://authorized-lab.example --authorize

---

Standard Scan | الفحص القياسي

vulnhunter --target 192.168.1.50 --mode STANDARD

---

Deep Scan | الفحص المتقدم

vulnhunter --target https://authorized-lab.example --authorize --mode DEEP

---

Save Results | حفظ النتائج

vulnhunter --target https://authorized-lab.example --authorize -o ./reports

---

🌐 Web Discovery | اكتشاف الويب

VulnHunter can discover web applications, endpoints, directories, and other accessible paths.

يمكن لـ VulnHunter اكتشاف تطبيقات الويب والـEndpoints والمجلدات والمسارات المتاحة.

Example:

vulnhunter --target https://authorized-lab.example --authorize

Possible discovery results:

/
├── login
├── admin
├── api
├── uploads
├── assets
└── discovered endpoints

Directory discovery helps identify paths that may not be directly linked from the main web page.

يساعد اكتشاف المجلدات في العثور على مسارات قد لا تكون مرتبطة بشكل مباشر بالصفحة الرئيسية.

---

🐛 Vulnerability Detection | اكتشاف الثغرات

VulnHunter uses modular vulnerability detectors.

يستخدم VulnHunter وحدات منفصلة لاكتشاف أنواع مختلفة من الثغرات.

Current detector categories include:

SQL Injection
Cross-Site Scripting (XSS)
Server-Side Request Forgery (SSRF)
XML External Entity (XXE)
Path Traversal
Open Redirect
CORS Misconfiguration
GraphQL Security Checks
TLS Security Checks
Security Misconfiguration
Weak Credentials Checks

The tool analyzes the target and reports potential findings with supporting information.

تقوم الأداة بتحليل الهدف وعرض النتائج المحتملة مع المعلومات المرتبطة بها.

---

💉 SQL Injection | حقن SQL

VulnHunter can check web parameters for indicators of SQL injection vulnerabilities.

يمكن لـ VulnHunter فحص معاملات تطبيقات الويب بحثًا عن مؤشرات SQL Injection.

Example:

vulnhunter --target https://authorized-lab.example --authorize

Possible result:

Vulnerability: SQL Injection
Severity: High
Endpoint: /product
Parameter: id
Confidence: High

---

⚡ XSS | Cross-Site Scripting

The XSS detector checks web inputs and responses for potential Cross-Site Scripting indicators.

يقوم كاشف XSS بفحص المدخلات والاستجابات بحثًا عن مؤشرات Cross-Site Scripting.

Possible result:

Vulnerability: Cross-Site Scripting
Type: Reflected
Endpoint: /search
Parameter: q
Confidence: Medium

---

🔄 SSRF | Server-Side Request Forgery

VulnHunter can identify parameters and endpoints that may be vulnerable to SSRF.

يمكن للأداة اكتشاف الـEndpoints والمعاملات التي قد تكون مرتبطة بثغرات SSRF.

Possible result:

Vulnerability: SSRF
Endpoint: /fetch
Parameter: url
Confidence: Medium

---

📂 Path Traversal | تجاوز المسارات

The Path Traversal detector checks for potential unsafe file path handling.

يقوم الكاشف بفحص التعامل مع مسارات الملفات بحثًا عن مؤشرات Path Traversal.

Possible result:

Vulnerability: Path Traversal
Endpoint: /download
Parameter: file
Confidence: High

---

🧩 CVE Intelligence | معلومات CVE

VulnHunter can correlate discovered software and versions with known CVEs.

يمكن للأداة ربط البرامج والإصدارات المكتشفة مع الثغرات المعروفة في CVE.

Example:

Service: Apache HTTP Server
Version: X.X.X

CVE:
CVE-XXXX-XXXXX

CWE:
CWE-XXX

Severity:
High

Confidence:
High

The purpose of this feature is to help researchers investigate known vulnerabilities related to discovered software.

الهدف من هذه الميزة هو مساعدة الباحث الأمني على معرفة الثغرات المعروفة المرتبطة بالبرامج والإصدارات المكتشفة.

---

💥 ExploitDB Intelligence | معلومات ExploitDB

VulnHunter can associate relevant findings with ExploitDB information when available.

يمكن للأداة ربط النتائج بمعلومات ExploitDB عند توفرها.

Example:

CVE: CVE-XXXX-XXXXX
ExploitDB: Available
Reference: ExploitDB Entry

This information is provided for vulnerability research and verification.

هذه المعلومات مخصصة للبحث الأمني والتحقق من الثغرات.

---

📊 Reports | التقارير

VulnHunter can generate structured security assessment reports.

يمكن لـ VulnHunter إنشاء تقارير منظمة لنتائج التقييم الأمني.

Example:

vulnhunter --target https://authorized-lab.example --authorize -o ./reports

Reports can contain:

Target Information
Scan Information
Open Ports
Detected Services
Web Applications
Directories
Endpoints
Vulnerabilities
Severity
Evidence
Confidence
CVE Information
ExploitDB References
Recommendations

---

🧪 Testing | الاختبارات

Run the complete test suite:

pytest

Run tests with detailed output:

pytest -v

Run a specific test directory:

pytest tests/

---

📁 Project Structure | هيكل المشروع

VulnHunter/
│
├── src/
│   └── vulnhunter/
│       │
│       ├── core/
│       │   ├── engine.py
│       │   ├── models.py
│       │   ├── config.py
│       │   ├── audit.py
│       │   └── scope.py
│       │
│       ├── discovery/
│       │   ├── port_scanner.py
│       │   ├── web_crawler.py
│       │   ├── web_directory.py
│       │   ├── endpoint_discovery.py
│       │   └── importer.py
│       │
│       ├── correlation/
│       │   ├── cve_correlator.py
│       │   ├── version_matcher.py
│       │   └── confidence_calculator.py
│       │
│       ├── intel/
│       │   ├── db.py
│       │   ├── nvd_cache.py
│       │   ├── exploitdb.py
│       │   └── cwe_map.py
│       │
│       ├── plugins/
│       │   ├── sqli.py
│       │   ├── xss.py
│       │   ├── ssrf.py
│       │   ├── xxe.py
│       │   ├── path_traversal.py
│       │   ├── open_redirect.py
│       │   ├── cors_checker.py
│       │   ├── graphql_checker.py
│       │   ├── tls_checker.py
│       │   └── misconfig.py
│       │
│       ├── reporting/
│       │   ├── html_reporter.py
│       │   └── json_reporter.py
│       │
│       └── ui/
│           └── console.py
│
├── tests/
├── examples/
├── docs/
├── pyproject.toml
└── README.md

---

⚙️ Architecture | البنية

The general workflow of VulnHunter is:

مسار عمل VulnHunter بشكل عام:

Target
   │
   ▼
Discovery
   │
   ├── Ports
   ├── Services
   ├── Web Applications
   ├── Endpoints
   └── Directories
   │
   ▼
Vulnerability Detection
   │
   ├── SQL Injection
   ├── XSS
   ├── SSRF
   ├── XXE
   ├── Path Traversal
   └── Other Checks
   │
   ▼
CVE / ExploitDB Correlation
   │
   ▼
Confidence & Analysis
   │
   ▼
Security Report

---

🔐 Authorization | التصريح

VulnHunter is intended for authorized security testing only.

Use the tool only against:

- Systems you own
- Authorized penetration-testing targets
- CTF environments
- Educational labs
- Systems where you have explicit permission

استخدم الأداة فقط على الأنظمة التي تملكها أو لديك تصريح واضح لاختبارها.

Do not scan or test systems without authorization.

---

🛠️ Development | التطوير

To install the project for development:

git clone https://github.com/abdullah-cyb/VulnHunter.git
cd VulnHunter
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

Run the tests:

pytest -v

---

👨‍💻 Author | المطور

Abdullah Nasser

Cybersecurity Student & Developer

GitHub:

https://github.com/abdullah-cyb

Project:

https://github.com/abdullah-cyb/VulnHunter

---

📄 License | الترخيص

VulnHunter is developed for educational purposes, security research, and authorized security assessments.

تم تطوير VulnHunter للأغراض التعليمية والبحث الأمني وعمليات التقييم الأمني المصرح بها.
