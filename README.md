# Flagg — Guide d'installation

Trois scripts Python qui fonctionnent ensemble pour détecter
les tentatives de vol de cookies/tokens sous Windows.

---

## Architecture

```
cookie_file_monitor.py   ──┐
                            ├──► alert_server.py  ◄──  navigateur  http://localhost:5000
network_exfil_monitor.py ──┘        (Flask + SSE)
```

---

## Installation

### 1. Python 3.10+

Télécharge sur https://python.org

### 2. Dépendances

Les dependances sont installer par : install.bat ou par 
```bash
pip install flask watchdog PyQt6 flask-cors requests psutil
```

---

## Lancement (utiliser Launcher.bat pour la version portable et Install.bat pour le client)

> ⚠️ Les fichier Launcher.bat et Install.bat doivent être lancés **en tant qu'administrateur**
> (clic droit → "Exécuter en tant qu'administrateur").

**Terminal 1 — serveur web d'alertes**
- Reçoit les alertes des deux scripts via HTTP POST
- Les affiche en temps réel via Server-Sent Events (SSE)
- Filtres par sévérité (HIGH / MEDIUM / INFO) et par type
- Hover sur une alerte pour voir les détails JSON complets

### LE NAVIGATEUR PEUX ETRE FERMER APRES LE LANCEMENT DU SERVEUR LA VERSION CLIENT.

**Terminal 2 — surveillance des fichiers**
- Surveille les fichiers de cookies de Chrome, Firefox, Edge, Discord
- Alerte si un processus **autre qu'un navigateur** lit ou modifie ces fichiers
- Niveau HIGH si le processus est non-légitime

**Terminal 3 — surveillance réseau**
- Scanne toutes les connexions sortantes actives
- Alerte si un processus non-navigateur se connecte à une IP externe
- Détecte les connexions à haute fréquence (> 10/min vers le même endpoint)
- Signale les ports non-standard (pas 80/443)

> ⚠️ Les terminaux 2 et 3 doivent être lancés **en tant qu'administrateur**
> (clic droit → "Exécuter en tant qu'administrateur").

---

## Niveaux de sévérité

| Niveau | Signification |
|--------|--------------|
| 🔴 HIGH   | Processus suspect + accès fichier sensible / haute fréquence |
| 🟡 MEDIUM | Connexion externe depuis un processus non-navigateur |
| 🔵 INFO   | Accès par un processus légitime (log seulement) |

---

## Personnalisation

Dans `cookie_file_monitor.py` :
- `SENSITIVE_PATHS` — ajoute des chemins à surveiller
- `LEGIT_BROWSERS` — liste blanche des processus autorisés

Dans `network_exfil_monitor.py` :
- `CONN_THRESHOLD` — nombre de connexions/min avant alerte
- `LEGIT_BROWSERS` — liste blanche réseau

---

## Logs

- `cookie_monitor.log` — accès fichiers
- `network_monitor.log` — connexions réseau

---

## Usage légal

Ces outils sont conçus pour :
- Surveiller **ta propre machine** ou un environnement de lab
- Tester des **machines sur lesquelles tu as l'autorisation écrite**
- Apprendre la détection d'intrusion / blue team

Ne pas utiliser sur des systèmes tiers sans autorisation explicite.
