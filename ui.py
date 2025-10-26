"""
Interfaz de usuario y exportación de informes
"""
from collections import Counter
from datetime import datetime
from pathlib import Path
import webbrowser
import json

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    import jinja2
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
SEV_COLOR = {
    "CRITICAL": "bold white on red",
    "HIGH": "red",
    "MEDIUM": "yellow3",
    "LOW": "green3",
    "UNKNOWN": "grey50"
}

def render_console(findings):
    """Muestra hallazgos en consola con Rich."""
    if not RICH_AVAILABLE:
        print(f"\n{'='*60}")
        print(f"RESUMEN: {len(findings)} hallazgos totales")
        print(f"{'='*60}")
        for f in findings[:20]:
            kev = "[KEV]" if f.get("kev") else ""
            print(f"{f['type']}: {f['title']} | {f['severity']} {kev}")
        return

    console = Console()
    sev_counts = Counter([f.get("severity","UNKNOWN") for f in findings])
    kev_count = sum(1 for f in findings if f.get("kev"))

    summary_lines = [
        f"Total hallazgos: {len(findings)}",
        f"CRITICAL: {sev_counts.get('CRITICAL',0)}",
        f"HIGH: {sev_counts.get('HIGH',0)}",
        f"MEDIUM: {sev_counts.get('MEDIUM',0)}",
        f"LOW: {sev_counts.get('LOW',0)}",
        f"UNKNOWN: {sev_counts.get('UNKNOWN',0)}",
        f"KEV (explotadas): {kev_count}",
        f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    ]
    console.print(Panel("\n".join(summary_lines), title="🔍 Resumen de Vulnerabilidades", border_style="blue"))

    table = Table(title="📋 Hallazgos por Criticidad", expand=True, show_lines=True)
    table.add_column("Tipo", no_wrap=True, style="cyan")
    table.add_column("Título", overflow="fold")
    table.add_column("Severidad", no_wrap=True)
    table.add_column("Score", no_wrap=True, justify="right")
    table.add_column("KEV", no_wrap=True, justify="center")

    for f in findings[:50]:
        sev = f.get("severity","UNKNOWN")
        sev_text = Text(sev, style=SEV_COLOR.get(sev,"grey50"))
        score = f.get("score", 0.0)
        kev = "✓" if f.get("kev") else "✗"

        title = f.get("title","")
        if len(title) > 80:
            title = title[:77] + "..."

        table.add_row(
            f.get("type",""),
            title,
            sev_text,
            f"{score:.1f}" if isinstance(score,(int,float)) else "-",
            kev
        )

    console.print(table)

    if len(findings) > 50:
        console.print(f"\n[dim]... y {len(findings)-50} hallazgos más (ver informe HTML)[/dim]")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>WinVulnScanner v1.0+ - Informe de Vulnerabilidades</title>
<style>
* { box-sizing: border-box; }
body { 
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  margin: 0; padding: 24px; background: #f8f9fa; color: #212529;
}
.container { max-width: 1400px; margin: 0 auto; background: white; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
h1 { margin: 0 0 8px 0; color: #1a73e8; font-size: 2rem; }
.meta { color: #5f6368; font-size: 0.9rem; margin-bottom: 24px; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr)); gap: 16px; margin-bottom: 32px; }
.card { border: 2px solid #e8eaed; border-radius: 8px; padding: 16px; text-align: center; }
.card-value { font-size: 2rem; font-weight: 700; margin-bottom: 4px; }
.card-label { color: #5f6368; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }
.sev { display: inline-block; padding: 4px 12px; border-radius: 999px; font-weight: 600; font-size: 0.8rem; }
.sev-CRITICAL { background: #d32f2f; color: white; }
.sev-HIGH { background: #f57c00; color: white; }
.sev-MEDIUM { background: #fbc02d; color: #212529; }
.sev-LOW { background: #388e3c; color: white; }
.sev-UNKNOWN { background: #9e9e9e; color: white; }
table { width: 100%; border-collapse: collapse; margin-top: 16px; background: white; }
thead { background: #f1f3f4; }
th, td { border: 1px solid #e8eaed; text-align: left; padding: 12px; vertical-align: top; }
th { font-weight: 600; color: #3c4043; }
tr:hover { background: #f8f9fa; }
.kev-badge { color: #1a73e8; font-weight: 700; }
.desc { color: #5f6368; font-size: 0.9rem; margin-top: 4px; }
.nowrap { white-space: nowrap; }
.footer { margin-top: 32px; padding-top: 16px; border-top: 2px solid #e8eaed; text-align: center; color: #5f6368; font-size: 0.85rem; }
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ WinVulnScanner v1.0+</h1>
  <div class="meta">
    <strong>Informe de Vulnerabilidades y Configuración - VERSIÓN COMPLETA</strong><br>
    Generado: {{ generated_at }} | Total hallazgos: {{ total }} | KEV: {{ kev_count }}
  </div>

  <div class="summary">
    <div class="card">
      <div class="card-value" style="color: #d32f2f;">{{ sev_counts.CRITICAL or 0 }}</div>
      <div class="card-label">Críticas</div>
    </div>
    <div class="card">
      <div class="card-value" style="color: #f57c00;">{{ sev_counts.HIGH or 0 }}</div>
      <div class="card-label">Altas</div>
    </div>
    <div class="card">
      <div class="card-value" style="color: #fbc02d;">{{ sev_counts.MEDIUM or 0 }}</div>
      <div class="card-label">Medias</div>
    </div>
    <div class="card">
      <div class="card-value" style="color: #388e3c;">{{ sev_counts.LOW or 0 }}</div>
      <div class="card-label">Bajas</div>
    </div>
    <div class="card">
      <div class="card-value" style="color: #1a73e8;">{{ kev_count }}</div>
      <div class="card-label">KEV (Explotadas)</div>
    </div>
  </div>

  <h2>📊 Detalle de Hallazgos</h2>
  <table>
    <thead>
      <tr>
        <th class="nowrap">Tipo</th>
        <th>Título / Descripción</th>
        <th class="nowrap">Severidad</th>
        <th class="nowrap">Score</th>
        <th class="nowrap">KEV</th>
        <th class="nowrap">Publicado</th>
      </tr>
    </thead>
    <tbody>
      {% for f in findings %}
      <tr>
        <td class="nowrap"><strong>{{ f.type }}</strong></td>
        <td>
          <div><strong>{{ f.title }}</strong></div>
          {% if f.description %}
          <div class="desc">{{ f.description[:300] }}{% if f.description|length > 300 %}...{% endif %}</div>
          {% endif %}
          {% if f.vector %}
          <div class="desc"><code>{{ f.vector }}</code></div>
          {% endif %}
        </td>
        <td class="nowrap"><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span></td>
        <td class="nowrap">{{ "%.1f"|format(f.score) if f.score else "-" }}</td>
        <td class="nowrap">{% if f.kev %}<span class="kev-badge">SÍ</span>{% else %}-{% endif %}</td>
        <td class="nowrap">{{ f.published[:10] if f.published else "-" }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <div class="footer">
    <strong>WinVulnScanner v1.0+ COMPLETA</strong> | Fuentes: NVD (NIST), KEV (CISA) | 
    Escaneo COMPLETO de TODAS las aplicaciones
  </div>
</div>
</body>
</html>"""

def render_html_report(findings, out_path):
    """Genera informe HTML."""
    if not JINJA_AVAILABLE:
        print("[!] Jinja2 no disponible")
        json_path = out_path.with_suffix('.json')
        json_path.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
        return json_path

    env = jinja2.Environment(autoescape=True)
    template = env.from_string(HTML_TEMPLATE)

    sev_counts = Counter([f.get("severity","UNKNOWN") for f in findings])
    kev_count = sum(1 for f in findings if f.get("kev"))

    html = template.render(
        findings=findings,
        sev_counts=sev_counts,
        kev_count=kev_count,
        total=len(findings),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    out_path.write_text(html, encoding="utf-8")
    print(f"[+] Informe HTML generado: {out_path}")
    return out_path

def open_in_browser(file_path):
    """Abre archivo en el navegador predeterminado."""
    try:
        webbrowser.open(file_path.resolve().as_uri())
        print(f"[+] Informe abierto en navegador")
    except Exception as e:
        print(f"[!] No se pudo abrir navegador: {e}")
        print(f"    Abra manualmente: {file_path.absolute()}")
