"""
antivirus_monitor.py — Flagg Antivirus Module v2.0
====================================================
Fonctionnalités :
  - Scan processus (noms malveillants, Temp, PowerShell encodé, cmd suspect)
  - Scan fichiers sensibles (extensions ransomware, signatures hex, exécutables dans Temp)
  - Heuristique ransomware (chiffrement massif)
  - Scan persistance Windows (Run keys, dossier Startup)
  - Notification système Windows (toast) à chaque détection HIGH
  - Dialogue de suppression avec accord utilisateur (via HTTP vers le client Qt)
  - Intégration VirusTotal API v3 (hash SHA-256 → rapport + URL rapport)

Communications :
  antivirus_monitor.py
        ├─► alert_server.py    POST /alert        (logs SSE navigateur)
        └─► client.py (Qt)     POST /av_threat     (popup Qt + suppression)

Variables d'environnement :
  VT_API_KEY   →  clé API VirusTotal (optionnel, désactivé si absent)
"""

import os
import sys
import time
import hashlib
import logging
import platform
import threading
import requests
import psutil

from pathlib import Path
from datetime import datetime

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

ALERT_SERVER  = "http://localhost:5000/alert"    # alert_server Flask
CLIENT_SERVER = "http://localhost:5100/av_threat" # client Qt ThreatReceiver

SCAN_INTERVAL      = 5   # secondes — scan processus
FILE_SCAN_INTERVAL = 3   # secondes — scan fichiers
RENAME_THRESHOLD   = 8   # renommages/min avant alerte ransomware
LOG_FILE           = "antivirus_monitor.log"

VT_API_KEY    = os.environ.get("VT_API_KEY", "")
VT_BASE_URL   = "https://www.virustotal.com/api/v3"
VT_REPORT_URL = "https://www.virustotal.com/gui/file/{sha256}"

# ──────────────────────────────────────────────
# LISTES
# ──────────────────────────────────────────────

SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz", "meterpreter", "cobaltstrike", "empire",
    "pwdump", "fgdump", "wce.exe", "gsecdump", "procdump",
    "netcat", "nc.exe", "ncat.exe", "psexec", "psexesvc",
    "wmiexec", "smbexec", "dcomexec", "atexec",
    "lazagne", "credstealer", "keylogger",
    "cryptolocker", "wannacry", "petya", "locky",
}

RANSOMWARE_EXTENSIONS = {
    ".locked", ".encrypted", ".enc", ".crypt", ".crypted",
    ".crypto", ".locky", ".zepto", ".cerber", ".wnry",
    ".wncry", ".wcry", ".petya", ".darkness", ".no_more_ransom",
    ".breaking_bad", ".da_vinci_code", ".decoder_globe",
}

MALWARE_SIGNATURES = [
    ("Mimikatz",     b"mimikatz"),
    ("Metasploit",   b"meterpreter"),
    ("WannaCry",     b"WANACRY!"),
    ("CobaltStrike", b"cobaltstrike"),
    ("EICAR_test",   b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"),
    ("PS_B64",       b"powershell -e "),
    ("CmdHidden",    b"cmd.exe /c start /b"),
    ("RegPersist",   b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
]

# Dossiers sensibles
SENSITIVE_DIRS: list = []
if platform.system() == "Windows":
    appdata      = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    temp         = os.environ.get("TEMP", "C:\\Windows\\Temp")
    SENSITIVE_DIRS = [
        Path(temp),
        Path("C:\\Windows\\Temp"),
        Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        Path(localappdata) / "Temp",
    ]
else:
    SENSITIVE_DIRS = [Path("/tmp"), Path("/var/tmp")]

# ──────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────

logging.basicConfig(
    filename=LOG_FILE, level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

def log(msg: str):
    print(msg, flush=True)
    logging.info(msg)

# ──────────────────────────────────────────────
# NOTIFICATION SYSTÈME WINDOWS
# ──────────────────────────────────────────────

def _win_toast(title: str, body: str):
    """Toast Windows natif via win10toast ou PowerShell fallback."""
    try:
        from win10toast import ToastNotifier
        ToastNotifier().show_toast(title, body, duration=8, threaded=True)
        return
    except ImportError:
        pass
    # Fallback PowerShell NotifyIcon
    ps = (
        "Add-Type -AssemblyName System.Windows.Forms; "
        "$n = New-Object System.Windows.Forms.NotifyIcon; "
        "$n.Icon = [System.Drawing.SystemIcons]::Warning; "
        "$n.Visible = $true; "
        f"$n.ShowBalloonTip(8000, '{title}', '{body}', "
        "[System.Windows.Forms.ToolTipIcon]::Warning); "
        "Start-Sleep -Seconds 9; $n.Dispose()"
    )
    try:
        import subprocess
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.Popen(["powershell", "-WindowStyle", "Hidden", "-Command", ps],
                         creationflags=flags)
    except Exception as e:
        log(f"[Notif] Erreur toast : {e}")


def notify(title: str, body: str):
    """Notification non-bloquante (Windows seulement)."""
    if platform.system() != "Windows":
        log(f"[Notif] {title} | {body}")
        return
    threading.Thread(target=_win_toast, args=(title, body), daemon=True).start()

# ──────────────────────────────────────────────
# VIRUSTOTAL v3
# ──────────────────────────────────────────────

def vt_lookup(sha256: str) -> dict:
    """
    Cherche un hash SHA-256 sur VirusTotal.
    Retourne :
      found, malicious, total, verdict, report_url, names, error
    """
    result = {
        "found": False, "malicious": 0, "total": 0,
        "verdict": "unknown",
        "report_url": VT_REPORT_URL.format(sha256=sha256),
        "names": [], "error": None,
    }
    if not VT_API_KEY:
        result["error"] = "VT_API_KEY non configurée"
        return result
    try:
        r = requests.get(
            f"{VT_BASE_URL}/files/{sha256}",
            headers={"x-apikey": VT_API_KEY},
            timeout=10,
        )
        if r.status_code == 404:
            result["error"] = "Hash inconnu de VirusTotal"
            return result
        if r.status_code == 401:
            result["error"] = "Clé API invalide"
            return result
        r.raise_for_status()
        data  = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        result["found"]     = True
        result["malicious"] = stats.get("malicious", 0)
        result["total"]     = sum(stats.values())
        # Noms de menaces
        res_map = data["data"]["attributes"].get("last_analysis_results", {})
        names = [
            v["result"] for v in res_map.values()
            if v.get("category") == "malicious" and v.get("result")
        ]
        result["names"] = list(set(names))[:5]
        ratio = result["malicious"] / result["total"] if result["total"] else 0
        result["verdict"] = "clean" if ratio == 0 else ("suspicious" if ratio < 0.1 else "malicious")
    except Exception as e:
        result["error"] = str(e)
    return result


def vt_upload(path: Path) -> dict:
    """Upload un fichier vers VT (hash inconnu)."""
    result = {"found": False, "malicious": 0, "total": 0,
               "verdict": "unknown", "report_url": "", "names": [], "error": None}
    if not VT_API_KEY:
        result["error"] = "VT_API_KEY non configurée"
        return result
    try:
        with open(path, "rb") as f:
            r = requests.post(
                f"{VT_BASE_URL}/files",
                headers={"x-apikey": VT_API_KEY},
                files={"file": (path.name, f)},
                timeout=30,
            )
        r.raise_for_status()
        aid = r.json()["data"]["id"]
        result["report_url"] = f"https://www.virustotal.com/gui/file-analysis/{aid}"
        result["error"]      = f"Soumis à VT, analyse en cours (ID: {aid})"
        result["found"]      = True
    except Exception as e:
        result["error"] = str(e)
    return result

# ──────────────────────────────────────────────
# ENVOI D'ALERTE
# ──────────────────────────────────────────────

def send_alert(level: str, type_: str, message: str, details: dict):
    """Alerte vers alert_server.py (navigateur SSE)."""
    payload = {
        "level": level, "type": type_, "message": message,
        "details": details, "timestamp": datetime.now().isoformat(),
        "source": "AntivirusMonitor",
    }
    try:
        requests.post(ALERT_SERVER, json=payload, timeout=2)
    except Exception:
        pass
    log(f"[{level}] {type_} — {message}")


def send_threat(level: str, type_: str, message: str, details: dict):
    """
    Envoie vers client Qt (dialogue suppression) + notification toast + alert_server.
    """
    notify(f"⚠ Flagg — Menace {level}", message[:120])

    payload = {
        "level": level, "type": type_, "message": message,
        "details": details, "timestamp": datetime.now().isoformat(),
    }
    try:
        requests.post(CLIENT_SERVER, json=payload, timeout=2)
    except Exception:
        pass

    send_alert(level, type_, message, details)


def analyze_and_report(path: Path, type_: str, message: str, level: str = "HIGH"):
    """
    Dans un thread : hash SHA-256 → VirusTotal → send_threat enrichi.
    """
    def _run():
        details: dict = {"path": str(path)}
        try:
            raw    = path.read_bytes()
            sha256 = hashlib.sha256(raw).hexdigest()
            details["sha256"] = sha256

            vt = vt_lookup(sha256)
            details["virustotal"] = vt

            if vt["found"] and vt["verdict"] in ("suspicious", "malicious"):
                enriched = (
                    f"{message} | VT: {vt['malicious']}/{vt['total']}"
                    + (f" ({', '.join(vt['names'][:3])})" if vt["names"] else "")
                )
                send_threat(level, type_, enriched, details)
            elif vt.get("error") == "Hash inconnu de VirusTotal":
                up = vt_upload(path)
                details["vt_upload"] = up
                send_threat(level, type_, message, details)
            else:
                send_threat(level, type_, message, details)

        except (PermissionError, OSError):
            send_threat(level, type_, message, details)

    threading.Thread(target=_run, daemon=True).start()

# ──────────────────────────────────────────────
# SCANNER 1 : PROCESSUS
# ──────────────────────────────────────────────

_alerted_pids: set = set()

def scan_processes():
    while True:
        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                try:
                    pid     = proc.info["pid"]
                    name    = (proc.info["name"] or "").lower()
                    exe     = proc.info["exe"] or ""
                    cmdline = " ".join(proc.info["cmdline"] or []).lower()

                    if pid in _alerted_pids:
                        continue

                    # Nom malware connu
                    for sus in SUSPICIOUS_PROCESS_NAMES:
                        if sus in name or sus in cmdline:
                            _alerted_pids.add(pid)
                            send_threat(
                                "HIGH", "SUSPICIOUS_PROCESS",
                                f"Processus malveillant détecté : {name} (PID {pid})",
                                {"pid": pid, "name": name, "exe": exe, "cmdline": cmdline[:300]},
                            )
                            break

                    # Exécutable depuis Temp
                    if exe and any(
                        s in exe.lower() for s in ["\\temp\\", "\\appdata\\local\\temp\\", "/tmp/"]
                    ) and pid not in _alerted_pids:
                        _alerted_pids.add(pid)
                        msg = f"Exécutable lancé depuis Temp : {exe}"
                        p = Path(exe)
                        if p.exists():
                            analyze_and_report(p, "PROCESS_FROM_TEMP", msg)
                        else:
                            send_threat("HIGH", "PROCESS_FROM_TEMP", msg,
                                        {"pid": pid, "name": name, "exe": exe})

                    # PowerShell encodé
                    if "powershell" in name and ("-enc" in cmdline or "-encodedcommand" in cmdline) \
                            and pid not in _alerted_pids:
                        _alerted_pids.add(pid)
                        send_threat(
                            "HIGH", "POWERSHELL_ENCODED",
                            f"PowerShell encodé (évasion probable) — PID {pid}",
                            {"pid": pid, "cmdline": cmdline[:500]},
                        )

                    # cmd.exe suspect
                    if name in ("cmd.exe", "cmd") and "/c" in cmdline \
                            and pid not in _alerted_pids:
                        if any(x in cmdline for x in
                               ["start /b", "reg add", "schtasks", "wscript", "mshta"]):
                            _alerted_pids.add(pid)
                            send_threat(
                                "MEDIUM", "SUSPICIOUS_CMD",
                                f"cmd.exe avec commande suspecte — PID {pid}",
                                {"pid": pid, "cmdline": cmdline[:400]},
                            )

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            log(f"[AntivirusMonitor][ERR] scan_processes: {e}")
        time.sleep(SCAN_INTERVAL)

# ──────────────────────────────────────────────
# SCANNER 2 : FICHIERS SENSIBLES
# ──────────────────────────────────────────────

_seen_files:     dict = {}
_rename_counter: dict = {}
_alerted_files:  set  = set()

def scan_files():
    while True:
        try:
            minute_key = int(time.time() // 60)
            for directory in SENSITIVE_DIRS:
                if not directory.exists():
                    continue
                try:
                    for entry in directory.iterdir():
                        if not entry.is_file():
                            continue
                        ps = str(entry)
                        try:
                            mtime = entry.stat().st_mtime
                        except OSError:
                            continue
                        if ps not in _seen_files:
                            _seen_files[ps] = mtime
                            _check_new_file(entry)
                        elif mtime != _seen_files[ps]:
                            _seen_files[ps] = mtime
                            if entry.suffix.lower() in RANSOMWARE_EXTENSIONS:
                                _rename_counter[minute_key] = \
                                    _rename_counter.get(minute_key, 0) + 1
                                if _rename_counter[minute_key] >= RENAME_THRESHOLD \
                                        and "ransomware_wave" not in _alerted_files:
                                    _alerted_files.add("ransomware_wave")
                                    send_threat(
                                        "HIGH", "RANSOMWARE_HEURISTIC",
                                        f"{_rename_counter[minute_key]} fichiers "
                                        f"chiffrés en 1 min dans {directory.name}",
                                        {"directory": str(directory),
                                         "count": _rename_counter[minute_key]},
                                    )
                except PermissionError:
                    continue
        except Exception as e:
            log(f"[AntivirusMonitor][ERR] scan_files: {e}")
        time.sleep(FILE_SCAN_INTERVAL)


def _check_new_file(path: Path):
    ps = str(path)
    if path.suffix.lower() in RANSOMWARE_EXTENSIONS:
        if ps not in _alerted_files:
            _alerted_files.add(ps)
            analyze_and_report(path, "RANSOMWARE_FILE",
                                f"Fichier chiffré créé : {path.name} ({path.suffix})")
        return
    if path.suffix.lower() in (".exe", ".bat", ".vbs", ".ps1", ".hta", ".scr", ".com", ".pif"):
        if ps not in _alerted_files:
            _alerted_files.add(ps)
            analyze_and_report(path, "EXECUTABLE_IN_TEMP",
                                f"Exécutable dans zone sensible : {path.name}", level="MEDIUM")
        return
    try:
        if path.stat().st_size < 5_000_000:
            raw  = path.read_bytes()
            low  = raw.lower()
            for sig_name, pattern in MALWARE_SIGNATURES:
                if pattern.lower() in low:
                    if ps not in _alerted_files:
                        _alerted_files.add(ps)
                        analyze_and_report(path, "MALWARE_SIGNATURE",
                                           f"Signature '{sig_name}' dans {path.name}")
                    break
    except (PermissionError, OSError):
        pass

# ──────────────────────────────────────────────
# SCANNER 3 : PERSISTANCE WINDOWS
# ──────────────────────────────────────────────

_alerted_persistence: set = set()

def scan_persistence():
    if platform.system() != "Windows":
        log("[AntivirusMonitor] Scan persistance : Windows uniquement.")
        return
    import winreg
    RUN_KEYS = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    known: dict = {}
    for hive, kp in RUN_KEYS:
        try:
            k = winreg.OpenKey(hive, kp, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    n, v, _ = winreg.EnumValue(k, i); known[f"{hive}\\{kp}\\{n}"] = v; i += 1
                except OSError:
                    break
            winreg.CloseKey(k)
        except OSError:
            continue
    while True:
        time.sleep(10)
        for hive, kp in RUN_KEYS:
            try:
                k = winreg.OpenKey(hive, kp, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        n, v, _ = winreg.EnumValue(k, i)
                        eid = f"{hive}\\{kp}\\{n}"
                        if eid not in known:
                            known[eid] = v
                            if eid not in _alerted_persistence:
                                _alerted_persistence.add(eid)
                                send_threat("HIGH", "PERSISTENCE_REGISTRY",
                                            f"Nouvelle clé Run détectée : {n}",
                                            {"key": kp, "name": n, "value": v})
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(k)
            except OSError:
                continue
        # Dossier Startup
        startup = (Path(os.environ.get("APPDATA", ""))
                   / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
        if startup.exists():
            for f in startup.iterdir():
                fid = str(f)
                if fid not in _alerted_persistence:
                    _alerted_persistence.add(fid)
                    msg = f"Nouveau fichier dans Startup : {f.name}"
                    if f.is_file():
                        analyze_and_report(f, "PERSISTENCE_STARTUP", msg, level="MEDIUM")
                    else:
                        send_threat("MEDIUM", "PERSISTENCE_STARTUP", msg, {"path": fid})

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    log("[AntivirusMonitor] Démarrage v2.0...")
    log(f"[AntivirusMonitor] VirusTotal : {'ACTIVÉ' if VT_API_KEY else 'DÉSACTIVÉ (VT_API_KEY manquante)'}.")

    threads = [
        threading.Thread(target=scan_processes,   name="proc",    daemon=True),
        threading.Thread(target=scan_files,        name="files",   daemon=True),
       