🛡️ ABDULLAH.CYB VulnHunter

«DISCOVER. CORRELATE. VERIFY. REPORT.
اكتشف. اربط المعلومات. تحقّق. أصدِر التقرير.»

VulnHunter is a modular cybersecurity vulnerability assessment and intelligence platform designed for authorized security testing, penetration testing labs, security analysts, and defensive research.

VulnHunter هي منصة معيارية لتقييم الثغرات الأمنية وربط المعلومات الأمنية، صُممت للاختبارات الأمنية المصرح بها، ومختبرات اختبار الاختراق، ومحللي الأمن السيبراني، والبحث الدفاعي.

---

🌐 Overview | نبذة عن المشروع

🇬🇧 English

VulnHunter combines reconnaissance, service discovery, web application analysis, vulnerability intelligence, evidence correlation, controlled verification, and professional reporting into a structured assessment workflow.

Instead of treating every detected version or technology as a vulnerability, VulnHunter attempts to correlate multiple sources of evidence before assigning a confidence level to a finding.

The platform is built around a modular architecture so that discovery modules, vulnerability intelligence sources, verification plugins, and reporting components can evolve independently.

🇸🇦 العربية

يجمع VulnHunter بين الاستطلاع، واكتشاف الخدمات، وتحليل تطبيقات الويب، ومعلومات الثغرات الأمنية، وربط الأدلة، والتحقق المنضبط، وإنشاء التقارير الاحترافية ضمن سير عمل منظم.

وبدلًا من اعتبار كل إصدار أو تقنية مكتشفة ثغرة بشكل مباشر، يحاول VulnHunter ربط عدة مصادر من الأدلة قبل تحديد مستوى الثقة في النتيجة.

تم تصميم المشروع بهندسة معيارية تسمح بتطوير وحدات الاكتشاف، ومصادر معلومات الثغرات، ووحدات التحقق، ومكونات التقارير بشكل مستقل.

---

✨ Key Features | أهم المميزات

Feature| الميزة
🔎 Attack Surface Discovery| اكتشاف سطح الهجوم
🌐 Web Discovery & Crawling| اكتشاف مسارات وروابط تطبيقات الويب
🧩 Technology Fingerprinting| تحديد التقنيات والأطر المستخدمة
🔗 CVE Correlation| ربط الإصدارات بمعلومات CVE
🛡️ CISA KEV Intelligence| الاستفادة من بيانات CISA KEV
🧠 Evidence Correlation| ربط الأدلة قبل تقييم النتيجة
🎯 Controlled Verification| اختبارات تحقق منضبطة للمختبرات المصرح بها
🧪 Modular Detection Plugins| نظام Plugins لاكتشاف أنواع مختلفة من المشكلات الأمنية
📊 Confidence Rating| تصنيف مستوى الثقة في النتائج
📄 HTML Reports| تقارير HTML تفاعلية
📦 JSON Reports| تقارير JSON قابلة للمعالجة آليًا
💾 Local Intelligence Database| قاعدة بيانات معلومات أمنية محلية

---

🔬 Investigation Pipeline | مراحل الفحص

VulnHunter organizes the assessment process into a structured 15-stage investigation pipeline.

ينظم VulnHunter عملية التقييم الأمني ضمن 15 مرحلة مترابطة:

#| Stage| المرحلة| Purpose / الهدف
01| Target Analysis| تحليل الهدف| Validate and normalize the target
02| DNS Resolution| تحليل DNS| Resolve relevant DNS records
03| Attack Surface Discovery| اكتشاف سطح الهجوم| Identify reachable hosts and protocols
04| Port Discovery| اكتشاف المنافذ| Discover accessible TCP services
05| Service Identification| تحديد الخدمات| Identify services and banners
06| Technology Fingerprinting| تحديد التقنيات| Detect frameworks, CMS and technologies
07| Version Analysis| تحليل الإصدارات| Extract versions and map products
08| CVE Intelligence| معلومات CVE| Correlate products and versions with vulnerability intelligence
09| Web Crawling| زحف الويب| Discover routes, links and web resources
10| Endpoint Discovery| اكتشاف نقاط النهاية| Identify forms, parameters and endpoints
11| Passive Security Analysis| التحليل السلبي| Analyze headers, CORS and TLS configuration
12| Controlled Verification| التحقق المنضبط| Perform authorized security checks
13| Evidence Validation| التحقق من الأدلة| Calculate finding confidence
14| Risk Analysis| تحليل المخاطر| Prioritize findings using available risk intelligence
15| Report Generation| إنشاء التقارير| Generate structured HTML and JSON reports

---

🧠 Vulnerability Intelligence | معلومات الثغرات

🇬🇧 English

VulnHunter is designed to correlate vulnerability intelligence from multiple sources rather than relying on a single database.

The architecture can work with:

- CVE / NVD information
- CISA Known Exploited Vulnerabilities (KEV)
- OSV vulnerability information
- CWE mappings
- ExploitDB references
- Local SQLite vulnerability intelligence
- Product and version correlation

This allows the engine to distinguish between:

Detected Technology
        ↓
Product Identification
        ↓
Version Analysis
        ↓
Vulnerability Correlation
        ↓
Evidence Validation
        ↓
Confidence Rating
        ↓
Report

🇸🇦 العربية

تم تصميم VulnHunter لربط معلومات الثغرات من عدة مصادر بدل الاعتماد على قاعدة بيانات واحدة.

ومن المصادر التي يدعمها التصميم:

- معلومات CVE / NVD
- بيانات CISA KEV
- معلومات الثغرات من OSV
- خرائط CWE
- مراجع ExploitDB
- قاعدة معلومات محلية باستخدام SQLite
- ربط المنتجات بالإصدارات

والهدف هو الانتقال من:

اكتشاف التقنية
      ↓
تحديد المنتج
      ↓
تحليل الإصدار
      ↓
ربط الثغرات
      ↓
التحقق من الأدلة
      ↓
تحديد مستوى الثقة
      ↓
إصدار التقرير

---

🎯 Detection & Verification | الاكتشاف والتحقق

VulnHunter uses a modular plugin architecture for security analysis.

The project currently provides detection modules for areas such as:

- SQL Injection indicators
- Cross-Site Scripting (XSS) indicators
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Path Traversal
- Open Redirect
- CORS configuration issues
- GraphQL security checks
- TLS configuration
- Weak credential indicators
- Security misconfigurations

«⚠️ Active verification is intended for authorized targets and controlled security labs only.»

«⚠️ عمليات التحقق النشطة مخصصة فقط للأهداف المصرح باختبارها والمختبرات الأمنية.»

---

📊 Sample Report | نموذج التقرير

The following image shows an example of the HTML reporting interface generated by VulnHunter.

الصورة التالية توضح مثالًا على واجهة التقرير HTML التي يقوم VulnHunter بإنشائها.

🖼️ Report Preview

«ضع صورة التقرير هنا»

[ REPORT SCREENSHOT ]

Suggested file path:

docs/images/sample-report.png

Then add it to this README using:

![VulnHunter Report](docs/images/sample-report.png)

---

🚀 Installation | التثبيت

Linux

VulnHunter is primarily designed for Linux security environments such as Kali Linux, Parrot OS, Ubuntu, and Debian.

تم تصميم VulnHunter بشكل أساسي لبيئات Linux الأمنية مثل Kali Linux وParrot OS وUbuntu وDebian.

git clone https://github.com/abdullah-cyb/VulnHunter.git
cd VulnHunter

Create a virtual environment:

python3 -m venv .venv
source .venv/bin/activate

Install the project:

pip install -e .

Verify the installation:

vulnhunter --version

---

💻 Usage | الاستخدام

1. Basic Assessment

vulnhunter --target 192.168.1.50

العربية: تشغيل تقييم أساسي للهدف.

---

2. Authorized Deep Assessment

vulnhunter --target https://authorized-lab.example:8443 --authorize --mode DEEP -o ./reports

العربية: تشغيل فحص أعمق على هدف مصرح باختباره مع إنشاء التقارير داخل مجلد "reports".

---

3. Subnet Discovery

vulnhunter --target 10.0.0.0/24 --mode STANDARD

العربية: تحليل نطاق شبكي لاكتشاف سطح الهجوم والخدمات المتاحة.

---

4. Synchronize Vulnerability Intelligence

vulnhunter --sync-intel

العربية: مزامنة معلومات الثغرات مع قاعدة البيانات المحلية.

---

🧪 Testing | الاختبارات

Run the complete automated test suite:

pytest -v

تشغيل جميع الاختبارات الآلية:

pytest -v

The test suite covers core functionality, discovery components, correlation logic, plugins, and reporting-related components.

---

🏗️ Architecture | البنية البرمجية

VulnHunter follows a modular Python architecture.

VulnHunter
│
├── core/
│   ├── engine
│   ├── models
│   ├── config
│   └── audit
│
├── discovery/
│   ├── port scanning
│   ├── web crawling
│   ├── directory discovery
│   ├── endpoint discovery
│   └── technology detection
│
├── correlation/
│   ├── CVE correlation
│   ├── version matching
│   └── confidence calculation
│
├── intel/
│   ├── NVD
│   ├── CISA KEV
│   ├── CWE
│   ├── OSV
│   └── ExploitDB
│
├── plugins/
│   └── vulnerability detectors
│
├── reporting/
│   ├── HTML
│   └── JSON
│
└── tests/

---

🛡️ Safety & Responsible Use | الاستخدام الآمن والمسؤول

🇬🇧 English

VulnHunter is intended for:

- Authorized penetration testing
- Security research
- CTF environments
- Vulnerable laboratory environments
- Defensive security assessments
- Systems owned or explicitly authorized for testing

Users are responsible for obtaining appropriate authorization before testing systems they do not own.

VulnHunter is not designed to perform destructive exploitation, denial-of-service attacks, or uncontrolled weaponized activity.

🇸🇦 العربية

تم تصميم VulnHunter للاستخدام في:

- اختبارات الاختراق المصرح بها
- البحث الأمني
- بيئات CTF
- المختبرات الأمنية الضعيفة والمخصصة للتدريب
- التقييمات الدفاعية
- الأنظمة التي يملكها المستخدم أو لديه تصريح صريح لاختبارها

يتحمل المستخدم مسؤولية الحصول على التصريح المناسب قبل اختبار أي نظام لا يملكه.

ولا يهدف VulnHunter إلى تنفيذ استغلال تخريبي أو هجمات حجب الخدمة أو أنشطة هجومية غير منضبطة.

---

📋 Project Status | حالة المشروع

Current focus:

- Modular vulnerability detection
- Web attack-surface discovery
- CVE intelligence correlation
- Evidence-based vulnerability validation
- Automated reporting
- Security testing in authorized environments

The project is actively evolving, and individual modules may change as development continues.

المشروع قيد التطوير المستمر، وقد تتغير بعض الوحدات والواجهات البرمجية مع استمرار التطوير.

---

🤝 Contributing | المساهمة

Contributions, bug reports, feature ideas, and security improvements are welcome.

If you would like to contribute:

git clone https://github.com/abdullah-cyb/VulnHunter.git
cd VulnHunter

Create a feature branch:

git checkout -b feature/my-feature

Make your changes, test them, and submit a pull request.

---

📜 License | الترخيص

VulnHunter is distributed under the MIT License.

See ""LICENSE"" (LICENSE) for the complete license text.

VulnHunter يتم توزيعه بموجب رخصة MIT.

راجع ملف ""LICENSE"" (LICENSE) للحصول على النص الكامل للترخيص.

---

👨‍💻 Author | المطور

ABDULLAH.CYB

Cybersecurity Student • Security Researcher • Developer

GitHub:

https://github.com/abdullah-cyb

---

⭐ Support the Project

If you find VulnHunter useful for learning, research, or authorized security testing:

⭐ Star the repository on GitHub

🐛 Report bugs

💡 Suggest improvements

🤝 Contribute to the project

---

«ABDULLAH.CYB VulnHunter
Discover. Correlate. Verify. Report.

اكتشف. اربط المعلومات. تحقّق. أصدِر التقرير.»
