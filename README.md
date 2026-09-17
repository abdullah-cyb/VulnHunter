🛡️ VulnHunter

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

vulnhunter --target https://a
