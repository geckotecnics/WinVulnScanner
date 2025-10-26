#!/usr/bin/env python3
"""
WinVulnScanner v1.3
Escáner de Vulnerabilidades - CPE Search
"""
import sys
from pathlib import Path

try:
    from scanner_cpe import scan
    from ui import render_console, render_html_report, open_in_browser
except ImportError as e:
    print(f"Error: {e}")
    sys.exit(1)

def main():
    print("=" * 60)
    print("  WinVulnScanner v1.3")
    print("  Escáner de Vulnerabilidades - CPE Search")
    print("=" * 60)
    print()

    if sys.platform != "win32":
        print("ADVERTENCIA: Este escáner está diseñado para Windows.")
        print()

    try:
        findings = scan()
    except Exception as e:
        print(f"\n[ERROR] Fallo durante el escaneo: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 60)
    print("RESULTADOS DEL ESCANEO")
    print("=" * 60)
    render_console(findings)

    print("\n" + "=" * 60)
    print("GENERANDO INFORME")
    print("=" * 60)

    out_file = Path("informe_vulnerabilidades.html")
    try:
        report_path = render_html_report(findings, out_file)
        if report_path.suffix == ".html":
            open_in_browser(report_path)
    except Exception as e:
        print(f"[ERROR] {e}")

    print("\n" + "=" * 60)
    print("ESCANEO COMPLETADO")
    print("=" * 60)
    print(f"Hallazgos totales: {len(findings)}")
    print(f"Críticos: {sum(1 for f in findings if f.get('severity') == 'CRITICAL')}")
    print(f"Altos: {sum(1 for f in findings if f.get('severity') == 'HIGH')}")
    print(f"KEV: {sum(1 for f in findings if f.get('kev'))}")
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrumpido")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR FATAL] {e}")
        sys.exit(1)
