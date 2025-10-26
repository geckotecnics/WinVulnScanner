"""
WinVulnScanner v1.3 - BÚSQUEDA POR CPE
Escáner de vulnerabilidades y configuración para Windows
CAMBIO PRINCIPAL: Búsqueda por CPE en lugar de keyword
"""
import json
import time
import subprocess
import requests
import winreg
from datetime import datetime, timedelta

NVD_BASE_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "WinVulnScanner/1.3"})

SOFTWARE_CPE_MAP = {
    "Mozilla Firefox": ("mozilla", "firefox"),
    "Google Chrome": ("google", "chrome"),
    "Chromium": ("chromium", "chromium"),
    "Microsoft Edge": ("microsoft", "edge"),
    "Java 8": ("oracle", "java"),
    "Java 11": ("oracle", "java"),
    "Java 17": ("oracle", "java"),
    "Java 21": ("oracle", "java"),
    "Python": ("python_software_foundation", "python"),
    "LibreOffice": ("libreoffice", "libreoffice"),
    "7-Zip": ("7-zip", "7-zip"),
    "VLC": ("videolan", "vlc"),
    "Apache": ("apache", "http_server"),
    "Nginx": ("nginx", "nginx"),
    "OpenSSL": ("openssl", "openssl"),
}

UNINSTALL_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
]

def _get_reg_str(key, value):
    try:
        v, t = winreg.QueryValueEx(key, value)
        if t in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            return v
    except OSError:
        return None

def _read_uninstall_hive(hive_handle, subkey):
    apps = []
    try:
        with winreg.OpenKey(hive_handle, subkey) as key:
            i = 0
            while True:
                try:
                    sk = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(key, sk) as appkey:
                        name = _get_reg_str(appkey, "DisplayName")
                        ver = _get_reg_str(appkey, "DisplayVersion")
                        pub = _get_reg_str(appkey, "Publisher")
                        if name:
                            apps.append({
                                "name": name.strip(),
                                "version": ver.strip() if ver else "",
                                "publisher": pub.strip() if pub else ""
                            })
                except OSError:
                    continue
    except OSError:
        pass
    return apps

def enumerate_installed_software():
    apps = []
    for subkey in UNINSTALL_KEYS:
        apps += _read_uninstall_hive(winreg.HKEY_LOCAL_MACHINE, subkey)
        try:
            apps += _read_uninstall_hive(winreg.HKEY_CURRENT_USER, subkey)
        except Exception:
            pass
    seen = set()
    unique = []
    for a in apps:
        k = (a["name"], a["version"])
        if k not in seen:
            seen.add(k)
            unique.append(a)
    return unique

def powershell_json(cmd):
    full = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd]
    try:
        res = subprocess.run(full, capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            return None
        out = res.stdout.strip()
        return json.loads(out) if out else None
    except Exception:
        return None

def check_firewall_profiles():
    ps = r"Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
    result = powershell_json(ps)
    profiles = {}
    if isinstance(result, list):
        for p in result:
            profiles[p.get("Name", "Unknown")] = bool(p.get("Enabled", False))
    elif isinstance(result, dict):
        profiles[result.get("Name", "Unknown")] = bool(result.get("Enabled", False))
    return profiles

def check_smb1_server_disabled():
    ps = r"Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol | ConvertTo-Json"
    result = powershell_json(ps)
    if isinstance(result, dict):
        return result.get("EnableSMB1Protocol") is False
    return None

def find_cpe_for_software(name, version):
    for key, cpe_data in SOFTWARE_CPE_MAP.items():
        if key.lower() in name.lower():
            vendor, product = cpe_data[:2]
            ver = version.split(".")[0] if version else "*"
            return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"
    return None

def search_cves_with_cpe(cpe_string):
    try:
        params = {"cpeName": cpe_string, "resultsPerPage": 100}
        r = SESSION.get(NVD_BASE_CVE, params=params, timeout=30)
        if r.status_code == 429:
            time.sleep(6)
            r = SESSION.get(NVD_BASE_CVE, params=params, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception:
        return {"vulnerabilities": []}

def extract_cves(nvd_json):
    cves = []
    for item in nvd_json.get("vulnerabilities", []):
        c = item.get("cve", {})
        cve_id = c.get("id")
        metrics = c.get("metrics", {})
        score = None
        severity = None
        vector = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics and metrics[key]:
                data = metrics[key][0].get("cvssData", {})
                score = data.get("baseScore")
                severity = data.get("baseSeverity")
                vector = data.get("vectorString")
                break
        if score is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            m = metrics["cvssMetricV2"][0]
            score = m.get("baseScore")
            severity = m.get("baseSeverity")
        desc = ""
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        cves.append({
            "id": cve_id,
            "score": score if score is not None else 0.0,
            "severity": severity if severity else "UNKNOWN",
            "vector": vector if vector else "",
            "description": desc,
            "published": c.get("published", ""),
            "modified": c.get("lastModified", "")
        })
    return cves

def load_cisa_kev():
    try:
        r = SESSION.get(KEV_URL, timeout=30)
        r.raise_for_status()
        data = r.json()
        return {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}
    except Exception:
        return set()

def scan():
    print("[*] Iniciando escaneo v1.3 (CPE - Búsqueda Precisa)...")
    findings = []

    print("[*] Cargando catálogo KEV de CISA...")
    kev = load_cisa_kev()
    print(f"[+] KEV cargado: {len(kev)} CVE conocidas")

    print("[*] Verificando configuración de firewall...")
    fw = check_firewall_profiles()
    if fw:
        for prof, enabled in fw.items():
            if not enabled:
                findings.append({
                    "type": "CONFIG",
                    "title": f"Firewall deshabilitado en perfil {prof}",
                    "score": 8.0,
                    "severity": "HIGH",
                    "kev": False,
                    "description": f"El perfil de firewall '{prof}' está deshabilitado.",
                    "published": datetime.now().isoformat(),
                    "modified": datetime.now().isoformat(),
                    "vector": "",
                })

    print("[*] Verificando SMBv1...")
    smb1_disabled = check_smb1_server_disabled()
    if smb1_disabled is False:
        findings.append({
            "type": "CONFIG",
            "title": "SMBv1 está habilitado (protocolo obsoleto)",
            "score": 9.0,
            "severity": "CRITICAL",
            "kev": False,
            "description": "SMBv1 es un protocolo obsoleto y vulnerable.",
            "published": datetime.now().isoformat(),
            "modified": datetime.now().isoformat(),
            "vector": "",
        })

    print("[*] Enumerando software instalado...")
    apps = enumerate_installed_software()
    print(f"[+] Software detectado: {len(apps)} aplicaciones")

    print("[*] Buscando vulnerabilidades usando CPE...")
    for idx, app in enumerate(apps, 1):
        cpe = find_cpe_for_software(app["name"], app["version"])
        if not cpe:
            continue

        print(f"[{idx}/{len(apps)}] {app['name']} {app['version']}")
        print(f"    └─ CPE: {cpe}")

        try:
            nvd_json = search_cves_with_cpe(cpe)
            cves = extract_cves(nvd_json)

            if cves:
                print(f"    └─ Encontradas {len(cves)} CVE ✓")
                for c in cves:
                    findings.append({
                        "type": "CVE",
                        "title": f"{app['name']} {app['version']} - {c['id']}",
                        "score": c["score"],
                        "severity": c["severity"],
                        "kev": c["id"] in kev,
                        "description": c["description"][:500],
                        "published": c["published"],
                        "modified": c["modified"],
                        "vector": c["vector"],
                    })
            time.sleep(0.5)
        except Exception as e:
            print(f"    └─ Error: {e}")
            continue

    findings.sort(key=lambda f: (0 if f["kev"] else 1, -f["score"]))
    print(f"\n[+] Escaneo completado: {len(findings)} hallazgos")
    return findings
