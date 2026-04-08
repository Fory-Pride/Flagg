"""
alert_server.py
Serveur Flask local qui reçoit les alertes des deux moniteurs
et les affiche sur une interface web en temps réel (SSE).

Nouveauté : ouvre automatiquement le navigateur dès qu'une alerte HIGH est reçue.

Installation : pip install flask flask-cors
Lancement    : python alert_server.py
Interface    : http://localhost:5000
"""

import json
import queue
import logging
import time
import threading
import webbrowser
from datetime import datetime
from flask import Flask, Response, request, jsonify, render_template_string
from flask_cors import CORS

# ── App ────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

alert_queue: queue.Queue = queue.Queue()
alerts_log: list = []
MAX_HISTORY = 200

# Anti-spam : ouvre le navigateur max 1 fois toutes les 30 secondes
_last_browser_open = 0.0
BROWSER_COOLDOWN   = 30  # secondes

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def open_browser_on_alert():
    """Ouvre l'interface filtrée sur HIGH dans le navigateur par défaut."""
    global _last_browser_open
    now = time.time()
    if now - _last_browser_open < BROWSER_COOLDOWN:
        return  # évite le spam si plusieurs HIGH arrivent en même temps
    _last_browser_open = now
    url = "http://localhost:5000/?filter=HIGH"
    threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()
    log.info("🔴 Navigateur ouvert automatiquement — alerte HIGH détectée")


# ── HTML de l'interface ────────────────────────────────────────────────────────
HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cookie & Token Monitor</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

  :root {
    --bg:      #0a0c10;
    --panel:   #0f1318;
    --border:  #1e2530;
    --accent:  #00ff88;
    --danger:  #ff3a3a;
    --warn:    #ffaa00;
    --info:    #3af0ff;
    --text:    #c8d8e8;
    --dim:     #4a5568;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Rajdhani', sans-serif;
    font-size: 15px;
    min-height: 100vh;
  }

  /* ── Toast d'alerte HIGH ── */
  #toast {
    position: fixed;
    top: 20px; right: 20px;
    background: #1a0505;
    border: 1px solid var(--danger);
    border-left: 4px solid var(--danger);
    color: var(--danger);
    font-family: 'Share Tech Mono', monospace;
    font-size: .85rem;
    padding: 14px 20px;
    border-radius: 6px;
    box-shadow: 0 0 20px rgba(255,58,58,.3);
    z-index: 9999;
    display: none;
    animation: toastIn .3s ease;
    max-width: 360px;
  }
  #toast.show { display: block; }
  @keyframes toastIn {
    from { opacity: 0; transform: translateX(20px); }
    to   { opacity: 1; transform: translateX(0); }
  }
  #toast .toast-title { font-weight: 700; margin-bottom: 4px; font-size: .9rem; }
  #toast .toast-close {
    float: right; cursor: pointer; margin-left: 12px;
    opacity: .6; font-size: 1rem;
  }
  #toast .toast-close:hover { opacity: 1; }

  /* ── Header ── */
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 28px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(90deg, #0a0c10 0%, #0f1820 100%);
  }

  .logo {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.3rem;
    color: var(--accent);
    letter-spacing: 2px;
  }
  .logo span { color: var(--dim); }

  #status-dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 8px var(--accent);
    display: inline-block;
    margin-right: 8px;
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%,100% { opacity: 1; }
    50%      { opacity: .3; }
  }
  .status-label { font-size: .85rem; color: var(--dim); }

  /* ── Stats bar ── */
  .stats {
    display: flex;
    gap: 24px;
    padding: 14px 28px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
  }
  .stat { display: flex; flex-direction: column; align-items: center; }
  .stat-val {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.6rem; font-weight: 700;
  }
  .stat-lbl { font-size: .75rem; color: var(--dim); text-transform: uppercase; letter-spacing: 1px; }
  .val-high  { color: var(--danger); }
  .val-med   { color: var(--warn); }
  .val-info  { color: var(--info); }
  .val-total { color: var(--accent); }

  /* ── Filters ── */
  .filters {
    display: flex; gap: 10px;
    padding: 12px 28px;
    background: var(--bg);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }
  .filter-btn {
    padding: 5px 16px; border-radius: 20px;
    border: 1px solid var(--border); background: transparent;
    color: var(--dim); cursor: pointer;
    font-family: 'Rajdhani', sans-serif; font-size: .85rem;
    letter-spacing: .5px; transition: all .2s;
  }
  .filter-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(0,255,136,.07); }
  .filter-btn:hover  { border-color: var(--text); color: var(--text); }
  #btn-clear { margin-left: auto; border-color: var(--danger); color: var(--danger); }
  #btn-clear:hover { background: rgba(255,58,58,.1); }

  /* ── Alert list ── */
  #alerts {
    padding: 16px 28px; display: flex; flex-direction: column; gap: 10px;
    max-height: calc(100vh - 240px); overflow-y: auto;
  }

  .alert-card {
    border-radius: 6px; padding: 14px 18px;
    border-left: 3px solid var(--dim);
    background: var(--panel);
    position: relative; overflow: hidden;
    animation: slideIn .25s ease;
  }
  @keyframes slideIn {
    from { opacity: 0; transform: translateY(-8px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  .alert-card::before {
    content: ''; position: absolute; inset: 0; opacity: .03; pointer-events: none;
  }
  .alert-card.HIGH   { border-color: var(--danger); }
  .alert-card.HIGH::before   { background: var(--danger); }
  .alert-card.MEDIUM { border-color: var(--warn); }
  .alert-card.MEDIUM::before { background: var(--warn); }
  .alert-card.INFO   { border-color: var(--info); }
  .alert-card.INFO::before   { background: var(--info); }

  .alert-header { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
  .badge {
    font-family: 'Share Tech Mono', monospace; font-size: .72rem;
    padding: 2px 8px; border-radius: 3px; font-weight: 700; letter-spacing: 1px;
  }
  .badge.HIGH   { background: rgba(255,58,58,.2);  color: var(--danger); }
  .badge.MEDIUM { background: rgba(255,170,0,.2);  color: var(--warn); }
  .badge.INFO   { background: rgba(58,240,255,.2); color: var(--info); }

  .alert-type  { font-family: 'Share Tech Mono', monospace; font-size: .75rem; color: var(--dim); }
  .alert-time  { margin-left: auto; font-size: .75rem; color: var(--dim); font-family: 'Share Tech Mono', monospace; }
  .alert-msg   { font-size: .95rem; color: var(--text); margin-bottom: 6px; }

  .alert-details {
    font-family: 'Share Tech Mono', monospace; font-size: .75rem; color: var(--dim);
    background: rgba(0,0,0,.3); border-radius: 4px; padding: 6px 10px;
    white-space: pre-wrap; word-break: break-all; display: none; margin-top: 6px;
  }

  .toggle-detail {
    font-size: .75rem; color: var(--dim); cursor: pointer;
    text-decoration: underline; text-underline-offset: 2px;
  }
  .toggle-detail:hover { color: var(--text); }

  #empty {
    text-align: center; padding: 60px 0; color: var(--dim);
    font-family: 'Share Tech Mono', monospace; font-size: .9rem; display: block;
  }

  #alerts::-webkit-scrollbar { width: 4px; }
  #alerts::-webkit-scrollbar-track { background: transparent; }
  #alerts::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
</style>
</head>
<body>

<!-- Toast d'alerte HIGH -->
<div id="toast">
  <span class="toast-close" onclick="document.getElementById('toast').classList.remove('show')">✕</span>
  <div class="toast-title">🔴 ALERTE CRITIQUE DÉTECTÉE</div>
  <div id="toast-msg">—</div>
</div>

<header>
  <div class="logo">COOKIE<span>/</span>TOKEN<span> ›</span> MONITOR</div>
  <div>
    <span id="status-dot"></span>
    <span class="status-label" id="conn-status">En attente…</span>
  </div>
</header>

<div class="stats">
  <div class="stat"><span class="stat-val val-total" id="cnt-total">0</span><span class="stat-lbl">Total</span></div>
  <div class="stat"><span class="stat-val val-high"  id="cnt-high">0</span><span class="stat-lbl">Critiques</span></div>
  <div class="stat"><span class="stat-val val-med"   id="cnt-med">0</span><span class="stat-lbl">Moyennes</span></div>
  <div class="stat"><span class="stat-val val-info"  id="cnt-info">0</span><span class="stat-lbl">Infos</span></div>
</div>

<div class="filters">
  <button class="filter-btn active" data-filter="ALL">Toutes</button>
  <button class="filter-btn" data-filter="HIGH">🔴 Critiques</button>
  <button class="filter-btn" data-filter="MEDIUM">🟡 Moyennes</button>
  <button class="filter-btn" data-filter="INFO">🔵 Infos</button>
  <button class="filter-btn" data-filter="FILE_ACCESS">Fichiers</button>
  <button class="filter-btn" data-filter="NETWORK_EXFIL">Réseau</button>
  <button class="filter-btn" id="btn-clear">Vider</button>
</div>

<div id="alerts">
  <span id="empty">Aucune alerte — les moniteurs envoient ici leurs détections.</span>
</div>

<script>
  let allAlerts = [];
  let currentFilter = 'ALL';
  const counts = { HIGH: 0, MEDIUM: 0, INFO: 0 };

  // Applique le filtre depuis l'URL (?filter=HIGH)
  const urlFilter = new URLSearchParams(window.location.search).get('filter');
  if (urlFilter) {
    currentFilter = urlFilter;
    document.querySelectorAll('.filter-btn[data-filter]').forEach(b => {
      b.classList.toggle('active', b.dataset.filter === urlFilter);
    });
  }

  // ── Toast ──
  let toastTimer = null;
  function showToast(msg) {
    const toast = document.getElementById('toast');
    document.getElementById('toast-msg').textContent = msg;
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 8000);
    // Notification navigateur si permission accordée
    if (Notification.permission === 'granted') {
      new Notification('🔴 Alerte critique — Cookie Monitor', { body: msg });
    }
  }

  // Demande la permission de notification au chargement
  if (Notification.permission === 'default') Notification.requestPermission();

  // ── SSE ──
  const evtSource = new EventSource('/stream');
  evtSource.onopen = () => {
    document.getElementById('conn-status').textContent = 'Connecté — surveillance active';
  };
  evtSource.onerror = () => {
    document.getElementById('conn-status').textContent = 'Déconnecté';
    document.getElementById('status-dot').style.background = '#ff3a3a';
  };
  evtSource.addEventListener('alert', e => {
    const alert = JSON.parse(e.data);
    allAlerts.unshift(alert);
    if (allAlerts.length > 200) allAlerts.pop();
    updateCounts(alert);
    // Toast si HIGH
    if (alert.severity === 'HIGH') showToast(alert.message || 'Accès suspect détecté');
    renderAlerts();
  });

  // Charge l'historique au démarrage
  fetch('/alerts').then(r => r.json()).then(data => {
    allAlerts = data.reverse();
    data.forEach(a => updateCounts(a));
    renderAlerts();
  });

  function updateCounts(alert) {
    const sev = alert.severity || 'INFO';
    counts[sev] = (counts[sev] || 0) + 1;
    document.getElementById('cnt-total').textContent = allAlerts.length;
    document.getElementById('cnt-high').textContent  = counts.HIGH   || 0;
    document.getElementById('cnt-med').textContent   = counts.MEDIUM || 0;
    document.getElementById('cnt-info').textContent  = counts.INFO   || 0;
  }

  function renderAlerts() {
    const container = document.getElementById('alerts');
    const empty     = document.getElementById('empty');
    const filtered  = allAlerts.filter(a => {
      if (currentFilter === 'ALL') return true;
      if (['HIGH','MEDIUM','INFO'].includes(currentFilter)) return a.severity === currentFilter;
      return a.type === currentFilter;
    });

    empty.style.display = filtered.length ? 'none' : 'block';
    container.querySelectorAll('.alert-card').forEach(el => el.remove());

    filtered.forEach(alert => {
      const card = document.createElement('div');
      card.className = `alert-card ${alert.severity || 'INFO'}`;
      const t = new Date(alert.timestamp).toLocaleTimeString('fr-FR');
      const details = JSON.stringify(alert, null, 2);
      card.innerHTML = `
        <div class="alert-header">
          <span class="badge ${alert.severity}">${alert.severity || 'INFO'}</span>
          <span class="alert-type">${alert.type || '—'}</span>
          <span class="alert-time">${t}</span>
        </div>
        <div class="alert-msg">${alert.message || 'Alerte sans message'}</div>
        <span class="toggle-detail" onclick="
          var d=this.nextElementSibling;
          d.style.display=d.style.display==='block'?'none':'block';
          this.textContent=this.textContent==='▸ Détails'?'▾ Masquer':'▸ Détails';
        ">▸ Détails</span>
        <pre class="alert-details">${details}</pre>
      `;
      container.appendChild(card);
    });
  }

  // ── Filtres ──
  document.querySelectorAll('.filter-btn[data-filter]').forEach(btn => {
    if (btn.id === 'btn-clear') return;
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn[data-filter]').forEach(b => {
        if (b.id !== 'btn-clear') b.classList.remove('active');
      });
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      renderAlerts();
    });
  });

  document.getElementById('btn-clear').addEventListener('click', () => {
    fetch('/clear', { method: 'POST' }).then(() => {
      allAlerts = [];
      counts.HIGH = counts.MEDIUM = counts.INFO = 0;
      document.getElementById('cnt-total').textContent = 0;
      document.getElementById('cnt-high').textContent  = 0;
      document.getElementById('cnt-med').textContent   = 0;
      document.getElementById('cnt-info').textContent  = 0;
      renderAlerts();
    });
  });
</script>
</body>
</html>
"""

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/alert", methods=["POST"])
def receive_alert():
    """Reçoit une alerte JSON des moniteurs."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "payload JSON invalide"}), 400

    data.setdefault("timestamp", datetime.now().isoformat())
    data.setdefault("severity",  "INFO")

    alerts_log.append(data)
    if len(alerts_log) > MAX_HISTORY:
        alerts_log.pop(0)

    alert_queue.put(data)
    log.info(f"[{data['severity']}] {data.get('message', '?')}")

    # ── Ouvre le navigateur automatiquement sur alerte HIGH ──
    if data["severity"] == "HIGH":
        open_browser_on_alert()

    return jsonify({"status": "ok"}), 200


@app.route("/alerts")
def get_alerts():
    return jsonify(alerts_log)


@app.route("/clear", methods=["POST"])
def clear_alerts():
    alerts_log.clear()
    return jsonify({"status": "cleared"})


@app.route("/stream")
def stream():
    """SSE — pousse les nouvelles alertes au navigateur."""
    def generate():
        yield "data: connected\n\n"
        while True:
            try:
                alert = alert_queue.get(timeout=30)
                yield f"event: alert\ndata: {json.dumps(alert)}\n\n"
            except queue.Empty:
                yield ": ping\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("=== Alert Server démarré sur http://localhost:5000 ===")
    # Ouvre l'interface au démarrage
    threading.Timer(1.5, lambda: webbrowser.open("http://localhost:5000")).start()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
