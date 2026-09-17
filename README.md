# ABDULLAH.CYB VULNHUNTER

> **اكتشاف. ربط البيانات. تحقق. إعداد تقارير.**
> **DISCOVER. CORRELATE. VERIFY. REPORT.**
>
> محرك احترافي لاكتشاف الثغرات الأمنية، ربط الاستخبارات، والتحقق منها.
> Professional Cybersecurity Vulnerability Discovery, Intelligence Correlation, and Verification Engine.

![صورة التقرير - Report Screenshot](link-to-your-image-here.png)

---

## 🔒 نظرة عامة | Executive Overview

أداة `ABDULLAH.CYB VulnHunter` هي تطبيق متقدم يعمل عبر واجهة سطر الأوامر (CLI) مصمم خصيصاً لمختبري الاختراق، ومحللي الأمن السيبراني، وفرق الهجوم (Red Teams). تنفذ الأداة مسار فحص منهجي مكون من 15 مرحلة لاستهداف الشبكات، تطبيقات الويب، والشبكات الفرعية.
`ABDULLAH.CYB VulnHunter` is an autonomous senior security engineering CLI application designed for penetration testers, security analysts, and red teams. It executes a 15-stage structured investigation pipeline against network targets, web applications, and subnets.

على عكس أدوات الفحص البدائية التي تولد نتائج مزعجة أو تعتمد على افتراضات ثابتة، تعتمد الأداة على ربط الأدلة متعددة العوامل، مطابقة الإصدارات الدقيقة، التحقق من ثغرات CISA KEV، وإجراء اختبارات نشطة آمنة ومدروسة.
Unlike primitive scanners that generate noise or hardcoded CVE assumptions, VulnHunter performs multi-factor evidence correlation, semantic version matching, CISA KEV (Known Exploited Vulnerabilities) verification, and safe controlled active probing.

---

## ⚡ الميزات الرئيسية | Key Features

* **محرك استخبارات الثغرات الحقيقي:** يعتمد على قاعدة بيانات SQLite محلية مدمجة مع بيانات CISA KEV، ومراجع NVD، وواجهات برمجة OSV. يعمل بكفاءة تامة دون اتصال بالإنترنت.
  **Real Vulnerability Intelligence Engine:** Local SQLite database populated with CISA KEV catalog data, NVD references, and OSV API integrations. Operates seamlessly offline.

* **مسار فحص من 15 مرحلة:** يعرض تقدم العمل في الوقت الفعلي بدءاً من تحليل الهدف، استعلامات DNS، اكتشاف المنافذ، تحديد التقنيات، ربط الإصدارات، التحقق النشط، وحتى إصدار التقارير.
  **15-Stage Investigation Pipeline:** Exposes real-time progress across target analysis, DNS, port discovery, technology fingerprinting, version correlation, active verification, and report generation.

* **حماية التفويض الصارمة:** تمنع الأداة تنفيذ أي اختبارات نشطة تداخلية ضد الأهداف غير المصرح بها ما لم يتم تفعيل ذلك صراحةً عبر الأمر (`--authorize`).
  **Strict Authorization Guard:** Prevents intrusive active probing against unauthorized targets unless explicitly enabled (`--authorize`).

* **تقييم موثوقية الأدلة:** تُصنف النتائج منطقياً إلى `مؤكدة` (CONFIRMED)، `مرجحة` (PROBABLE)، `محتملة` (POTENTIAL)، أو `غير مؤكدة` (NOT VERIFIED) بناءً على المورد، المنتج، الإصدار، والتحقق من إثبات المفهوم.
  **Evidence Confidence Rating:** Findings are classified as `CONFIRMED`, `PROBABLE`, `POTENTIAL`, or `NOT VERIFIED` based on vendor, product, version, and PoC verification.

* **تقارير احترافية:** توليد تقارير HTML تفاعلية بالوضع المظلم، بالإضافة إلى تصدير النتائج بصيغة JSON لسهولة دمجها مع أدوات أخرى.
  **Executive Reporting:** Generates interactive HTML reports with dark mode visuals and structured JSON exports.

---

## 🚀 التثبيت | Installation

مخصص لأنظمة لينكس (Kali Linux, Parrot OS, Ubuntu, Debian):
Linux First (Kali Linux, Parrot OS, Ubuntu, Debian):

```bash
# استنساخ المستودع | Clone repository
git clone [https://github.com/abdullah-cyb/vulnhunter.git](https://github.com/abdullah-cyb/vulnhunter.git)
cd vulnhunter

# تثبيت الحزمة بشكل عام أو داخل بيئة افتراضية | Install package globally or in virtualenv
pip install -e .

للتحقق من نجاح التثبيت | Verify installation:
vulnhunter --version

📖 أمثلة الاستخدام | Usage Examples
1. استطلاع سلبي غير تداخلي وربط ثغرات CVE
1. Non-Intrusive Passive Reconnaissance & CVE Correlation
vulnhunter --target 192.168.1.50

2. فحص شامل ومصرح (يتضمن اختبارات تحقق نشطة وآمنة)
2. Full Authorized Assessment (Includes Safe Active Verification)
vulnhunter --target [https://authorized-lab.example:8443](https://authorized-lab.example:8443) --authorize --mode DEEP -o ./reports

3. اكتشاف سطح الهجوم لشبكة فرعية
3. Subnet Attack Surface Discovery
vulnhunter --target 10.0.0.0/24 --mode STANDARD

4. مزامنة قاعدة بيانات استخبارات الثغرات
4. Synchronize Vulnerability Intelligence Database
vulnhunter --sync-intel

🔬 مسار التحقيق المكون من 15 مرحلة | 15-Stage Investigation Pipeline
 * [01] تحليل الهدف | Target Analysis: التحقق من صحة الهدف، استخراج الـ IP، والتحقق من التفويض.
   Target validation, IP resolution, and authorization verification.
 * [02] استعلامات DNS | DNS Resolution: جلب سجلات A, AAAA, MX, PTR, و TXT.
   A, AAAA, MX, PTR, and TXT record resolution.
 * [03] اكتشاف سطح الهجوم | Attack Surface: التحقق من استجابة المضيف والبروتوكولات الأساسية.
   Host reachability & protocol verification.
 * [04] اكتشاف المنافذ | Port Discovery: فحص منافذ TCP بشكل غير متزامن.
   Asynchronous TCP port scanning.
 * [05] تحديد الخدمات | Service Identification: قراءة لافتات الشبكة (Banner grabbing) وتحليل الترويسات.
   Banner grabbing & service header parsing.
 * [06] البصمة التقنية | Fingerprinting: استخراج بصمات أطر عمل الويب وأنظمة إدارة المحتوى.
   Deep web framework, CMS, & language fingerprinting.
 * [07] تحليل الإصدارات | Version Analysis: استخراج دقيق للإصدارات ومطابقتها مع نظام CPE.
   Semantic version extraction & CPE mapping.
 * [08] استخبارات CVE | CVE Intelligence: المطابقة مع قاعدة بيانات SQLite وقائمة CISA KEV.
   Local SQLite database cross-correlation against CISA KEV.
 * [09] الزحف على الويب | Web Crawling: استخراج الروابط والمسارات بشكل غير متزامن.
   Asynchronous web route and link crawling.
 * [10] اكتشاف النقاط الطرفية | Endpoint Discovery: استخراج النماذج (Forms) ومعلمات الإدخال.
   Form action and parameter vector discovery.
 * [11] التحليل الأمني السلبي | Passive Audit: مراجعة الترويسات الأمنية، إعدادات CORS، و TLS.
   Security headers, CORS, and TLS configuration audit.
 * [12] الاختبارات النشطة | Active Tests: فحص نشط وآمن (SQLi, XSS, LFI) [لأهداف مصرحة فقط].
   Safe active probes (SQLi heuristics, XSS, LFI) [Authorized Only].
 * [13] التحقق من الأدلة | Evidence Validation: حساب نسبة الموثوقية بناءً على عوامل متعددة.
   Multi-vector confidence calculation.
 * [14] تحليل المخاطر | Risk Analysis: حساب وزن CVSS وترتيب الأولويات.
   Aggregated CVSS weighting & CISA KEV prioritization.
 * [15] إنشاء التقارير | Report Generation: استخراج تقارير نهائية بصيغتي JSON و HTML.
   JSON & HTML executive report rendering.
🛡️ الأمان والأخلاقيات | Safety & Ethics
تخضع مرحلة التحقق النشط من الثغرات (المرحلة 12) لقيود صارمة ولا تعمل إلا عند استخدام علم التصريح --authorize. تم تصميم الأداة للاستخدام الأخلاقي فقط؛ ولا تقوم الأداة بتنفيذ أي استغلال تدميري، أو هجمات حجب الخدمة، أو حقن حمولات خبيثة.
Active vulnerability verification (Stage 12) is strictly gated behind the --authorize flag. VulnHunter is designed for ethical use only; it never performs destructive exploitation, DoS attacks, or weaponized payload delivery. Ensure explicit permission before scanning any target.
🧪 بيئة الاختبار | Testing Suite
لتشغيل حزمة الاختبارات الآلية والمدمجة:
Run the full automated unit and integration test suite:
pytest -v

📜 الترخيص | License
هذا المشروع موزع تحت ترخيص MIT. راجع ملف LICENSE لمزيد من التفاصيل.
Distributed under the MIT License. See LICENSE for details.
