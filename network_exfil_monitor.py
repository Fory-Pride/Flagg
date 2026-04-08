"""
network_exfil_monitor.py
Détecte les tentatives d'exfiltration de cookies/tokens via le réseau sous Windows.
Analyse les connexions sortantes suspectes en temps réel.

Installation : pip install psutil requests scapy
Lance en administrateur pour la capture réseau complète.
"""

import re
import json
import time
import base64
import logging
import requests
import psutil
from datetime import datetime
from collections import defaultdict

# ── Configuration ──────────────────────────────────────────────────────────────
ALERT_WEBHOOK     = "http://localhost:5000/alert"
LOG_FILE          = "network_monitor.log"
POLL_INTERVAL     = 3       # secondes entre chaque scan
CONN_THRESHOLD    = 10      # connexions/minute vers un même domaine = suspect
PAYLOAD_MIN_LEN   = 100     # longueur min pour analyser un payload base64

# Processus navigateurs légitimes — leurs connexions sortantes sont normales
LEGIT_BROWSERS = {"chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe"}

# Patterns suspects dans les URLs / payloads sortants
SUSPICIOUS_PATTERNS = [
    r"[A-Za-z0-9+/]{40,}={0,2}",          # Base64 long (token potentiel)
    r"token=[A-Za-z0-9\-_.]{20,}",         # Token dans query string
    r"cookie=[^\s&]{20,}",                  # Cookie dans query string
    r"Authorization:\s*Bearer\s+\S{20,}",  # Bearer token
    r"discord\.com/api/webhooks/",          # Webhook Discord (exfil classique)
    r"pastebin\.com",                       # Paste sites
    r"ngrok\.io",                           # Tunnels
    r"\.onion",                             # Tor
]
SUSPICIOUS_RE = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_PATTERNS]

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ── État global ────────────────────────────────────────────────────────────────
conn_history = defaultdict(list)   # {pid: [timestamps]}
known_conns  = set()               # connexions déjà vues


# ── Utilitaires ────────────────────────────────────────────────────────────────

def send_alert(alert: dict):
    try:
        requests.post(ALERT_WEBHOOK, json=alert, timeout=2)
    except requests.RequestException as e:
        log.warning(f"Impossible d'envoyer l'alerte : {e}")


def get_proc_info(pid: int) -> dict:
    try:
        p = psutil.Process(pid)
        return {
            "pid":      pid,
            "name":     p.name(),
            "exe":      p.exe(),
            "cmdline":  " ".join(p.cmdline()),
            "username": p.username(),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {"pid": pid, "name": "unknown"}


def is_private_ip(ip: str) -> bool:
    """Retourne True pour les IPs locales (pas d'exfil possible)."""
    prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                "172.30.", "172.31.", "192.168.", "127.", "::1")
    return any(ip.startswith(p) for p in prefixes)


def check_base64_payload(data: str) -> bool:
    """Essaie de décoder du base64 et cherche des patterns de tokens/cookies."""
    try:
        decoded = base64.b64decode(data + "==").decode("utf-8", errors="ignore")
        token_hints = ["token", "cookie", "session", "auth", "discord", "access"]
        return any(hint in decoded.lower() for hint in token_hints)
    except Exception:
        return False


def analyze_connection(conn) -> dict | None:
    """
    Analyse une connexion réseau sortante.
    Retourne un dict d'alerte si suspecte, None sinon.
    """
    if conn.status != "ESTABLISHED":
        return None
    if not conn.raddr:
        return None

    remote_ip   = conn.raddr.ip
    remote_port = conn.raddr.port

    # Ignore les IPs privées
    if is_private_ip(remote_ip):
        return None

    pid  = conn.pid
    proc = get_proc_info(pid) if pid else {"pid": None, "name": "unknown"}
    name = proc.get("name", "").lower()

    # Connexion depuis un processus non-navigateur vers l'extérieur
    is_suspicious_proc = name not in LEGIT_BROWSERS and name != "system"

    # Ports suspects (pas HTTP/HTTPS standard)
    suspicious_port = remote_port not in (80, 443, 8080, 8443)

    # Fréquence : même PID → trop de nouvelles connexions en 1 min ?
    now = time.time()
    conn_history[pid].append(now)
    conn_history[pid] = [t for t in conn_history[pid] if now - t < 60]
    high_frequency = len(conn_history[pid]) > CONN_THRESHOLD

    if not (is_suspicious_proc or high_frequency):
        return None

    severity = "HIGH" if (is_suspicious_proc and high_frequency) else "MEDIUM"

    return {
        "timestamp":  datetime.now().isoformat(),
        "type":       "NETWORK_EXFIL",
        "severity":   severity,
        "remote_ip":  remote_ip,
        "remote_port": remote_port,
        "process":    proc,
        "suspicious_port":    suspicious_port,
        "high_frequency":     high_frequency,
        "non_browser_process": is_suspicious_proc,
        "conn_count_last_min": len(conn_history[pid]),
        "message": (
            f"[{severity}] Connexion suspecte vers {remote_ip}:{remote_port} "
            f"depuis {proc.get('name', '?')} (PID {pid})"
        ),
    }


# ── Scan en boucle ─────────────────────────────────────────────────────────────

def scan_connections():
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        log.error("Accès refusé — relance le script en administrateur.")
        return

    for conn in conns:
        # Déduplique pour ne pas respammer la même connexion
        key = (conn.pid, getattr(conn.raddr, "ip", ""), getattr(conn.raddr, "port", 0))
        if key in known_conns:
            continue
        known_conns.add(key)

        alert = analyze_connection(conn)
        if alert:
            if alert["severity"] == "HIGH":
                log.warning(alert["message"])
            else:
                log.info(alert["message"])
            send_alert(alert)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    log.info("=== Network Exfil Monitor démarré ===")
    log.info(f"Scan toutes les {POLL_INTERVAL}s | Seuil fréquence : {CONN_THRESHOLD} conn/min")

    while True:
        scan_connections()
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Arrêt du moniteur réseau.")
