🛡️ VulnHunter

VulnHunter is a modular Python-based vulnerability assessment tool designed to help security researchers and students discover security weaknesses, analyze services, identify web vulnerabilities, correlate findings with CVEs, and generate security reports.

VulnHunter هي أداة لتقييم الثغرات الأمنية مبنية بلغة Python، تساعد الباحثين والطلاب في الأمن السيبراني على اكتشاف نقاط الضعف، تحليل الخدمات، فحص تطبيقات الويب، ربط النتائج مع CVEs، وإنشاء تقارير أمنية.

---

📌 Features | المميزات

- 🔎 Service & Port Discovery — اكتشاف المنافذ والخدمات
- 🌐 Web Discovery — اكتشاف صفحات ومسارات الويب
- 📁 Directory Discovery — اكتشاف المجلدات والمسارات المخفية
- 🕷️ Web Vulnerability Detection — اكتشاف ثغرات تطبيقات الويب
- 💉 SQL Injection Detection — فحص مؤشرات SQL Injection
- ⚡ XSS Detection — فحص مؤشرات Cross-Site Scripting
- 🔄 SSRF Detection — فحص مؤشرات SSRF
- 📂 Path Traversal Detection — فحص Path Traversal
- ↪️ Open Redirect Detection — فحص Open Redirect
- 🔐 Security Misconfiguration Checks — فحص الإعدادات الأمنية الخاطئة
- 🧩 CVE Correlation — ربط الخدمات والإصدارات مع CVEs
- 💥 ExploitDB Intelligence — البحث عن معلومات ExploitDB المرتبطة بالنتائج
- 📊 Security Reports — إنشاء تقارير JSON وHTML

---

🚀 Installation | التثبيت

Clone the repository:

استنسخ المشروع:

git clone https://github.com/abdullah-cyb/VulnHunter.git
cd VulnHunter

Create a virtual environment:

python3 -m venv .venv
source .venv/bin/activate

Install the project:

pip install -e .

---

▶️ Usage | الاستخدام

Basic scan:

فحص أساسي:

vulnhunter --target 192.168.1.50

Scan an authorized web application:

vulnhunter --target https://authorized-lab.example --authorize

Specify the scan mode:

vulnhunter --target 192.168.1.50 --mode STANDARD

Deep assessment:

vulnhunter --target https://authorized-lab.example --authorize --mode DEEP

Save the results:

vulnhunter --target https://authorized-lab.example --authorize -o ./reports

---

🌐 Web Discovery | اكتشاف الويب

VulnHunter can discover web endpoints and directories that may not be directly visible from the main page.

يمكن للأداة اكتشاف صفحات ومسارات ومجلدات الويب التي قد لا تكون ظاهرة بشكل مباشر.

Example:

vulnhunter --target https://authorized-lab.example --authorize

The results may include:

Web Application
├── /
├── /login
├── /admin
├── /api
├── /uploads
└── discovered endpoints

---

🐛 Vulnerability Detection | اكتشاف الثغرات

VulnHunter includes modular detectors for different vulnerability classes.

تحتوي الأداة على وحدات منفصلة لفحص أنواع مختلفة من الثغرات.

Examples:

SQL Injection
XSS
SSRF
XXE
Path Traversal
Open Redirect
CORS Misconfiguration
GraphQL Issues
TLS Issues
Security Misconfiguration

The tool reports findings with information such as:

Vulnerability
Severity
Target
Endpoint
Parameter
Evidence
Confidence
CVE
CWE
ExploitDB Reference

---

🧩 CVE & Exploit Intelligence | معلومات الثغرات

VulnHunter can correlate discovered software and versions with vulnerability intelligence.

يمكن للأداة مقارنة الخدمات والإصدارات المكتشفة مع قواعد بيانات الثغرات.

Example result:

Service: Apache HTTP Server
Version: X.X.X

Potential CVE:
CVE-XXXX-XXXXX

CWE:
CWE-XXX

ExploitDB:
Available / Not Available

Confidence:
High / Medium / Low

The results are intended to help the security researcher investigate the vulnerability further.

---

📊 Reports | التقارير

VulnHunter can generate structured reports for security assessments.

يمكن للأداة إنشاء تقارير منظمة لعمليات التقييم الأمني.

Example:

vulnhunter --target https://authorized-lab.example --authorize -o ./reports

Reports can contain:

Target Information
Scan Information
Discovered Services
Web Endpoints
Directories
Vulnerabilities
Severity
Evidence
CVE Information
ExploitDB References
Recommendations

---

🧪 Testing | الاختبارات

Run the project tests:

pytest

Run with verbose output:

pytest -v

---

📁 Project Structure | هيكل المشروع

VulnHunter/
├── src/
│   └── vulnhunter/
│       ├── core/
│       ├── discovery/
│       ├── correlation/
│       ├── intel/
│       ├── plugins/
│       ├── reporting/
│       └── ui/
│
├── tests/
├── examples/
├── docs/
├── pyproject.toml
└── README.md

---

⚙️ Architecture | البنية

The project is organized into separate modules so that new scanners and vulnerability detectors can be added easily.

تم تقسيم المشروع إلى وحدات منفصلة لتسهيل إضافة فحوصات واكتشافات جديدة.

Target
   │
   ▼
Discovery
   │
   ├── Ports
   ├── Services
   ├── Web
   └── Directories
   │
   ▼
Vulnerability Detection
   │
   ▼
CVE / ExploitDB Correlation
   │
   ▼
Risk & Confidence
   │
   ▼
Reports

---

⚠️ Responsible Use | الاستخدام المسؤول

VulnHunter is intended for:

- Authorized penetration testing
- Security research
- CTFs and training labs
- Systems you own
- Systems where you have explicit permission to test

Only scan systems you are authorized to assess.

الأداة مخصصة للاختبارات الأمنية المصرح بها، والـ CTFs، والمختبرات التعليمية، والأنظمة التي تملكها أو لديك تصريح واضح لاختبارها.

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

This project is intended for educational and authorized security testing purposes.

هذا المشروع مخصص للأغراض التعليمية والاختبارات الأمنية المصرح بها.
