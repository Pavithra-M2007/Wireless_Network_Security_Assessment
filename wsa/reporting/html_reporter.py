"""
Self-contained HTML report generator.

The output is a single, portable HTML file with:
- All CSS embedded in a ``<style>`` block (no external stylesheets).
- No JavaScript, no external fonts, no CDN references.
- A clean, professional layout with violet / pink accent colours.
- WCAG AA-compliant contrast ratios for all severity badge foreground / background pairs.

Security: XSS prevention
-------------------------
This module uses a ``jinja2.Environment`` with ``autoescape=True``.
Every value from a Python variable rendered with ``{{ expr }}`` is
HTML-escaped automatically.  PCAP-derived strings — SSIDs, filenames,
evidence strings, parser notes — are therefore safe to embed.

Trusted, internally-generated strings (CSS, static labels, severity
category names from our own YAML files) are inserted via ``{{ ... | safe }}``
or directly as template literals where no user input can reach.

Self-containment verification
------------------------------
The rendered HTML contains no ``http://`` or ``https://`` URLs, no
``<link>`` elements to external resources, and no ``<script src=...>``
tags.  Third-party resources are deliberately excluded so the report
can be viewed offline and shared as a standalone file.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, BaseLoader

from wsa.reporting.assessment import Assessment, SEVERITIES, data_source_note

# ---------------------------------------------------------------------------
# Inline CSS  (no external network requests)
# ---------------------------------------------------------------------------
# Colour palette:
#   Primary accent   #6d28d9  violet-700
#   Secondary accent #be185d  pink-700
#   Header gradient  #4c1d95 → #6d28d9 → #be185d
#   Background       #f5f3ff  (very light lavender)
# WCAG AA badge ratios: all ≥ 4.5:1 confirmed.

_CSS = """\
*,::before,::after{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  margin:0;padding:0;background:#f5f3ff;color:#1e1b4b;line-height:1.6;font-size:15px}
a{color:#6d28d9}
/* ── Header ─────────────────────────────────────────────────────────────── */
.wsa-header{background:linear-gradient(135deg,#4c1d95 0%,#6d28d9 55%,#be185d 100%);
  color:#fff;padding:2rem 1.5rem}
.wsa-header h1{margin:0 0 .375rem;font-size:1.65rem;font-weight:700;color:#fff;letter-spacing:-.02em}
.wsa-header p{margin:0;opacity:.82;font-size:.875rem;font-family:monospace}
/* ── Layout ─────────────────────────────────────────────────────────────── */
.wsa-container{max-width:1060px;margin:0 auto;padding:1.5rem}
section{margin-bottom:2rem}
h2{color:#4c1d95;border-bottom:2px solid #ede9fe;padding-bottom:.35rem;margin-top:1.75rem;font-size:1.25rem}
h3{color:#4c1d95;font-size:1.05rem;margin-top:1.5rem}
h4{color:#6d28d9;font-size:.975rem;margin-top:1.25rem}
/* ── Provenance banner ───────────────────────────────────────────────────── */
.wsa-prov{border-radius:8px;padding:.8rem 1rem;margin:1.25rem 0;font-size:.9rem;line-height:1.5}
.wsa-prov-simulated{background:#ede9fe;border:1px solid #7c3aed;color:#3730a3}
.wsa-prov-real{background:#dcfce7;border:1px solid #16a34a;color:#14532d}
.wsa-prov-unknown{background:#fef3c7;border:1px solid #d97706;color:#78350f}
/* ── Summary cards ───────────────────────────────────────────────────────── */
.wsa-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.875rem;margin:1rem 0}
.wsa-card{background:#fff;border-radius:10px;padding:1.125rem .75rem;text-align:center;
  box-shadow:0 1px 4px rgba(76,29,149,.13)}
.wsa-card-val{font-size:1.9rem;font-weight:700;color:#6d28d9;line-height:1.1}
.wsa-card-lbl{color:#64748b;font-size:.775rem;margin-top:.3rem;text-transform:uppercase;letter-spacing:.05em}
/* ── Tables ──────────────────────────────────────────────────────────────── */
.wsa-table{width:100%;border-collapse:collapse;margin:.875rem 0;background:#fff;
  border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(76,29,149,.09)}
.wsa-table th{background:#4c1d95;color:#fff;padding:.6rem .875rem;text-align:left;font-size:.825rem;font-weight:600}
.wsa-table td{padding:.475rem .875rem;border-bottom:1px solid #ede9fe;font-size:.875rem;vertical-align:top}
.wsa-table tr:last-child td{border-bottom:none}
.wsa-table tbody tr:nth-child(even) td{background:#f8f6ff}
/* ── Severity badges ─────────────────────────────────────────────────────── */
.wsa-badge{display:inline-block;padding:.15rem .6rem;border-radius:4px;
  font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}
.wsa-sev-CRITICAL{background:#fee2e2;color:#991b1b}
.wsa-sev-HIGH    {background:#ffedd5;color:#9a3412}
.wsa-sev-MEDIUM  {background:#fef9c3;color:#713f12}
.wsa-sev-LOW     {background:#dcfce7;color:#14532d}
.wsa-sev-INFO    {background:#dbeafe;color:#1e3a8a}
/* ── Network cards ───────────────────────────────────────────────────────── */
.wsa-net{background:#fff;border-radius:10px;padding:1.375rem 1.25rem;margin:1.25rem 0;
  box-shadow:0 2px 6px rgba(76,29,149,.1)}
.wsa-net h3{margin-top:0}
.wsa-bssid{font-family:monospace;font-size:.8rem;color:#7c3aed;margin-left:.5rem;opacity:.85}
.wsa-risk{font-size:.875rem;color:#475569;margin:.75rem 0}
/* ── Finding cards ───────────────────────────────────────────────────────── */
.wsa-finding{border-radius:8px;padding:1rem 1.125rem;margin:.75rem 0;border-left:4px solid}
.wsa-f-CRITICAL{border-color:#dc2626;background:#fff7f7}
.wsa-f-HIGH    {border-color:#ea580c;background:#fff9f5}
.wsa-f-MEDIUM  {border-color:#d97706;background:#fffef0}
.wsa-f-LOW     {border-color:#16a34a;background:#f0fdf4}
.wsa-f-INFO    {border-color:#2563eb;background:#f0f6ff}
.wsa-f-hdr{display:flex;align-items:center;flex-wrap:wrap;gap:.5rem;margin-bottom:.625rem}
.wsa-f-id{font-size:.725rem;color:#94a3b8;font-family:monospace;margin-right:.125rem}
.wsa-f-ev{margin:.5rem 0;font-size:.85rem}
.wsa-f-ev code{background:#f1f5f9;padding:.175rem .5rem;border-radius:4px;font-family:monospace;font-size:.8rem;word-break:break-all}
.wsa-f-sec{margin:.475rem 0;font-size:.875rem}
.wsa-f-sec strong{color:#4c1d95}
/* ── Special states ──────────────────────────────────────────────────────── */
.wsa-clean{background:#dcfce7;border:1px solid #86efac;border-radius:8px;
  padding:.8rem 1rem;color:#14532d;font-size:.875rem}
.wsa-empty{color:#94a3b8;font-style:italic;font-size:.9rem}
.wsa-notes{font-size:.825rem;color:#64748b;margin:.75rem 0}
.wsa-notes summary{cursor:pointer;color:#7c3aed;font-weight:500}
.wsa-notes ul{margin:.5rem 0;padding-left:1.25rem}
.wsa-err-list{background:#fff7f7;border:1px solid #fca5a5;border-radius:8px;
  padding:.875rem 1rem;font-size:.875rem;color:#7f1d1d}
/* ── Footer ──────────────────────────────────────────────────────────────── */
.wsa-footer{text-align:center;color:#a78bfa;font-size:.725rem;padding:2rem;
  border-top:1px solid #ede9fe;margin-top:2rem}
"""

# ---------------------------------------------------------------------------
# Jinja2 HTML template  (autoescape=True — all {{ }} expressions are escaped)
# ---------------------------------------------------------------------------
# CSS is injected via {{ css | safe }} because it is our own trusted constant.
# All other {{ }} references auto-escape any HTML-special characters.

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WSA Report &#8212; {{ filename }}</title>
  <style>{{ css | safe }}</style>
</head>
<body>

<header class="wsa-header">
  <div class="wsa-container">
    <h1>Wireless Network Security Assessment</h1>
    <p>{{ filename }} &nbsp;&middot;&nbsp; {{ assessment.analysis_timestamp }}</p>
  </div>
</header>

<div class="wsa-container">

  {# ── Provenance banner ─────────────────────────────────────────────────── #}
  <div class="wsa-prov wsa-prov-{{ prov_css_class }}">
    <strong>Data source: {{ assessment.data_source | upper }}</strong>
    &mdash; {{ note }}
  </div>

  {# ── Executive summary ─────────────────────────────────────────────────── #}
  <section>
    <h2>Executive Summary</h2>

    <div class="wsa-cards">
      <div class="wsa-card">
        <div class="wsa-card-val">{{ assessment.total_frames }}</div>
        <div class="wsa-card-lbl">Frames Analysed</div>
      </div>
      <div class="wsa-card">
        <div class="wsa-card-val">{{ assessment.total_networks }}</div>
        <div class="wsa-card-lbl">Networks</div>
      </div>
      <div class="wsa-card">
        <div class="wsa-card-val">{{ assessment.finding_count }}</div>
        <div class="wsa-card-lbl">Findings</div>
      </div>
      <div class="wsa-card">
        <div class="wsa-card-val">{{ assessment.total_risk_score }}</div>
        <div class="wsa-card-lbl">Risk Score</div>
      </div>
      <div class="wsa-card">
        <div class="wsa-card-val">{{ assessment.total_deauth_frames }}</div>
        <div class="wsa-card-lbl">Deauth Frames</div>
      </div>
      <div class="wsa-card">
        <div class="wsa-card-val">{{ assessment.total_eapol_frames }}</div>
        <div class="wsa-card-lbl">EAPOL Frames</div>
      </div>
    </div>

    <h3>Findings by Severity</h3>
    <table class="wsa-table" role="table" aria-label="Findings by severity">
      <thead><tr><th>Severity</th><th>Count</th></tr></thead>
      <tbody>
        {% for sev in severities %}
        <tr>
          <td><span class="wsa-badge wsa-sev-{{ sev }}">{{ sev }}</span></td>
          <td>{{ assessment.severity_counts[sev] }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>

  {# ── Networks ──────────────────────────────────────────────────────────── #}
  <section>
    <h2>Networks ({{ assessment.network_assessments | length }})</h2>

    {% if not assessment.network_assessments %}
      <p class="wsa-empty">No networks were discovered in this capture.</p>
    {% endif %}

    {% for na in assessment.network_assessments %}
    <div class="wsa-net">
      <h3>
        {{ na.network.ssid if na.network.ssid is not none else "(SSID IE absent)" }}
        <span class="wsa-bssid">{{ na.network.bssid }}</span>
      </h3>

      <table class="wsa-table" role="table" aria-label="Network properties">
        <tbody>
          <tr><td><strong>Channel</strong></td>
              <td>{{ na.network.channel if na.network.channel is not none else "Unknown" }}</td></tr>
          <tr><td><strong>Cipher</strong></td><td>{{ na.network.cipher }}</td></tr>
          <tr><td><strong>Auth type</strong></td><td>{{ na.network.auth_type }}</td></tr>
          <tr><td><strong>WPA versions</strong></td>
              <td>{{ na.network.wpa_versions | join(", ") or "—" }}</td></tr>
          <tr><td><strong>Pairwise ciphers</strong></td>
              <td>{{ na.network.pairwise_ciphers | join(", ") or "—" }}</td></tr>
          <tr><td><strong>Group cipher</strong></td>
              <td>{{ na.network.group_cipher if na.network.group_cipher is not none else "— (RSN IE absent)" }}</td></tr>
          <tr><td><strong>MFP capable</strong></td>
              <td>{% if na.network.mfp_capable is none %}— (RSN IE absent)
                  {% elif na.network.mfp_capable %}Yes{% else %}No{% endif %}</td></tr>
          <tr><td><strong>MFP required</strong></td>
              <td>{% if na.network.mfp_required is none %}— (RSN IE absent)
                  {% elif na.network.mfp_required %}Yes{% else %}No{% endif %}</td></tr>
          <tr><td><strong>WPS advertised</strong></td>
              <td>{{ "Yes" if na.network.wps_present else "No" }}</td></tr>
          <tr><td><strong>Average RSSI</strong></td>
              <td>{% if na.network.avg_rssi is none %}— (not recorded)
                  {% else %}{{ "%.1f"|format(na.network.avg_rssi) }} dBm{% endif %}</td></tr>
          <tr><td><strong>Beacon count</strong></td><td>{{ na.network.beacon_count }}</td></tr>
          <tr><td><strong>Deauth count</strong></td><td>{{ na.network.deauth_count }}</td></tr>
          <tr><td><strong>EAPOL frames</strong></td><td>{{ na.network.eapol_frame_count }}</td></tr>
        </tbody>
      </table>

      <div class="wsa-risk">
        Risk score: <strong>{{ na.risk_score }}</strong>
        {% if na.highest_severity %}
          &nbsp;&middot;&nbsp; Highest:
          <span class="wsa-badge wsa-sev-{{ na.highest_severity }}">{{ na.highest_severity }}</span>
        {% endif %}
      </div>

      {# ── Findings ────────────────────────────────────────────────────── #}
      <h4>Security Findings ({{ na.findings | length }})</h4>

      {% if not na.findings %}
        <div class="wsa-clean">
          &#10003; No security findings for this network.
          Configuration appears satisfactory based on available evidence.
        </div>
      {% else %}
        {% for finding in na.findings | sort(attribute="severity_order") %}
        <div class="wsa-finding wsa-f-{{ finding.severity }}">
          <div class="wsa-f-hdr">
            <span class="wsa-badge wsa-sev-{{ finding.severity }}">{{ finding.severity }}</span>
            <span class="wsa-f-id">{{ finding.rule_id }}</span>
            <strong>{{ finding.title }}</strong>
          </div>
          <div class="wsa-f-ev">
            <strong>Evidence:</strong> <code>{{ finding.evidence }}</code>
          </div>
          <div class="wsa-f-sec">
            <strong>Explanation:</strong> {{ finding.explanation }}
          </div>
          <div class="wsa-f-sec">
            <strong>Impact:</strong> {{ finding.impact }}
          </div>
          <div class="wsa-f-sec">
            <strong>Remediation:</strong> {{ finding.remediation }}
          </div>
        </div>
        {% endfor %}
      {% endif %}

      {# Parser notes (collapsible) #}
      {% if na.network.parser_notes %}
        <details class="wsa-notes">
          <summary>Parser notes ({{ na.network.parser_notes | length }})</summary>
          <ul>
            {% for note in na.network.parser_notes %}
              <li>{{ note }}</li>
            {% endfor %}
          </ul>
        </details>
      {% endif %}

    </div>{# /.wsa-net #}
    {% endfor %}
  </section>

  {# ── Parse errors ──────────────────────────────────────────────────────── #}
  {% if assessment.parse_errors %}
  <section>
    <h2>Parse Errors</h2>
    <div class="wsa-err-list">
      <p>The following non-fatal errors were recorded during PCAP loading or
      frame parsing. Other fields may still be valid.</p>
      <ul>
        {% for err in assessment.parse_errors %}
          <li>{{ err }}</li>
        {% endfor %}
      </ul>
    </div>
  </section>
  {% endif %}

</div>{# /.wsa-container #}

<footer class="wsa-footer">
  Generated by Wireless Network Security Assessment (WSA)
  &nbsp;&middot;&nbsp; {{ assessment.analysis_timestamp }}
</footer>

</body>
</html>"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def to_html(assessment: Assessment) -> str:
    """
    Render *assessment* as a self-contained HTML report string.

    All PCAP-derived values (SSIDs, evidence strings, parser notes, filenames)
    are HTML-escaped by Jinja2's autoescape mechanism before insertion into
    the document.

    The returned string contains no external URLs, no ``<link>`` elements
    to remote resources, and no ``<script src=...>`` tags.

    Parameters
    ----------
    assessment : Assessment

    Returns
    -------
    str
        A complete, self-contained HTML document.
    """
    env = Environment(loader=BaseLoader(), autoescape=True)

    # Jinja calls this as "%.1f"|format(rssi), so the format string is the
    # filter value and the observed number is the argument.
    env.filters["format"] = lambda fmt, value: (fmt % value) if value is not None else "—"

    template = env.from_string(_HTML_TEMPLATE)

    filename = Path(assessment.source_file).name
    note = data_source_note(assessment.data_source)

    # Map data_source to a CSS class (unknown sources get the warning style).
    _prov_classes = {"simulated": "simulated", "real": "real"}
    prov_css_class = _prov_classes.get(assessment.data_source, "unknown")

    return template.render(
        assessment=assessment,
        filename=filename,
        note=note,
        prov_css_class=prov_css_class,
        severities=SEVERITIES,
        css=_CSS,          # marked | safe in the template — trusted constant
    )
