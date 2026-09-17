"""Standalone Modern HTML Executive Report Generator for VulnHunter."""

from pathlib import Path
from jinja2 import Template
from vulnhunter.core.models import ScanReport

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ report.brand }} {{ report.product }} - Scan Report: {{ report.target }}</title>
  <style>
    :root {
      --bg-color: #0b0f19;
      --card-bg: #111827;
      --border-color: #1f2937;
      --text-main: #f9fafb;
      --text-muted: #9ca3af;
      --accent-cyan: #06b6d4;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --info: #6b7280;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg-color);
      color: var(--text-main);
      margin: 0;
      padding: 30px;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    .header {
      border-bottom: 2px solid var(--accent-cyan);
      padding-bottom: 20px;
      margin-bottom: 30px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .brand {
      font-size: 28px;
      font-weight: 800;
      letter-spacing: 1px;
      color: var(--accent-cyan);
    }
    .tagline {
      font-size: 14px;
      color: var(--text-muted);
      margin-top: 4px;
    }
    .meta-box {
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 30px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
    }
    .meta-item {
      display: flex;
      flex-direction: column;
    }
    .meta-label {
      font-size: 12px;
      color: var(--text-muted);
      text-transform: uppercase;
    }
    .meta-val {
      font-size: 18px;
      font-weight: 600;
      margin-top: 4px;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 15px;
      margin-bottom: 30px;
    }
    .badge-card {
      background: var(--card-bg);
      border-left: 4px solid var(--border-color);
      padding: 15px;
      border-radius: 6px;
    }
    .badge-card.critical { border-left-color: var(--critical); }
    .badge-card.high { border-left-color: var(--high); }
    .badge-card.medium { border-left-color: var(--medium); }
    .badge-card.low { border-left-color: var(--low); }
    
    .section-title {
      font-size: 22px;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 10px;
      margin-top: 40px;
      margin-bottom: 20px;
      color: var(--accent-cyan);
    }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 15px;
    }
    .finding-title {
      font-size: 18px;
      font-weight: 700;
    }
    .pill {
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .pill.CRITICAL { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .pill.HIGH { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
    .pill.MEDIUM { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
    .pill.LOW { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }
    .pill.CONFIRMED { background: rgba(34, 197, 94, 0.2); color: #22c55e; border: 1px solid #22c55e; }
    
    .reasoning-box {
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 6px;
      padding: 15px;
      margin-top: 15px;
    }
    .reasoning-row {
      margin-bottom: 12px;
    }
    .reasoning-label {
      font-size: 13px;
      font-weight: 700;
      color: var(--accent-cyan);
      text-transform: uppercase;
    }
    .reasoning-content {
      font-size: 14px;
      color: #e5e7eb;
      margin-top: 4px;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div class="brand">{{ report.brand }}.{{ report.product }}</div>
        <div class="tagline">{{ report.tagline }}</div>
      </div>
      <div>
        <span class="pill CONFIRMED">SCAN COMPLETED</span>
      </div>
    </div>

    <div class="meta-box">
      <div class="meta-item">
        <span class="meta-label">Target</span>
        <span class="meta-val">{{ report.target }}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Scan ID</span>
        <span class="meta-val">{{ report.scan_id }}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Duration</span>
        <span class="meta-val">{{ "%.2f"|format(report.duration_seconds) }}s</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Total Findings</span>
        <span class="meta-val">{{ report.total_findings }}</span>
      </div>
    </div>

    <div class="summary-grid">
      <div class="badge-card critical">
        <div class="meta-label">Critical Findings</div>
        <div class="meta-val" style="color: var(--critical);">{{ report.summary_by_severity.get('CRITICAL', 0) }}</div>
      </div>
      <div class="badge-card high">
        <div class="meta-label">High Findings</div>
        <div class="meta-val" style="color: var(--high);">{{ report.summary_by_severity.get('HIGH', 0) }}</div>
      </div>
      <div class="badge-card medium">
        <div class="meta-label">Medium Findings</div>
        <div class="meta-val" style="color: var(--medium);">{{ report.summary_by_severity.get('MEDIUM', 0) }}</div>
      </div>
      <div class="badge-card low">
        <div class="meta-label">Low / Info Findings</div>
        <div class="meta-val" style="color: var(--low);">{{ report.summary_by_severity.get('LOW', 0) + report.summary_by_severity.get('INFO', 0) }}</div>
      </div>
    </div>

    <h2 class="section-title">Vulnerability Findings & Evidence</h2>
    {% if report.findings %}
      {% for f in report.findings %}
      <div class="finding-card">
        <div class="finding-header">
          <div class="finding-title">{{ f.title }}</div>
          <div>
            <span class="pill {{ f.severity.value }}">{{ f.severity.value }}</span>
            <span class="pill {{ f.status.value }}">{{ f.status.value }} ({{ "%.0f"|format(f.confidence_score * 100) }}%)</span>
          </div>
        </div>

        <div class="reasoning-box">
          <div class="reasoning-row">
            <div class="reasoning-label">1. WHAT IS IT?</div>
            <div class="reasoning-content">{{ f.reasoning.what_is_it }}</div>
          </div>
          <div class="reasoning-row">
            <div class="reasoning-label">2. WHY WAS IT DETECTED?</div>
            <div class="reasoning-content">{{ f.reasoning.why_detected }}</div>
          </div>
          <div class="reasoning-row">
            <div class="reasoning-label">3. WHAT EVIDENCE SUPPORTS IT?</div>
            <div class="reasoning-content">{{ f.reasoning.evidence_supporting }}</div>
          </div>
          <div class="reasoning-row">
            <div class="reasoning-label">4. CONFIDENCE ANALYSIS</div>
            <div class="reasoning-content">{{ f.reasoning.confidence_explanation }}</div>
          </div>
          <div class="reasoning-row">
            <div class="reasoning-label">5. IMPACT ASSESSMENT</div>
            <div class="reasoning-content">{{ f.reasoning.impact_assessment }}</div>
          </div>
          <div class="reasoning-row">
            <div class="reasoning-label">6. AUTHORIZED VERIFICATION PROCEDURE</div>
            <div class="reasoning-content">{{ f.reasoning.verification_guide }}</div>
          </div>
          <div class="reasoning-row">
            <div class="reasoning-label">7. REMEDIATION GUIDANCE</div>
            <div class="reasoning-content">{{ f.reasoning.remediation_steps }}</div>
          </div>
        </div>
      </div>
      {% endfor %}
    {% else %}
      <p style="color: var(--text-muted);">No security vulnerabilities or exposure issues were identified during this assessment.</p>
    {% endif %}

  </div>
</body>
</html>
"""

def export_html_report(report: ScanReport, output_path: Path) -> Path:
    """Renders scan report as a standalone HTML file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    template = Template(HTML_TEMPLATE)
    html_out = template.render(report=report)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_out)
    return output_path
