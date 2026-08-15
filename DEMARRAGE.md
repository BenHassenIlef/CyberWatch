# Fiche de démarrage rapide — CyberWatch AI

Commandes PowerShell, à copier-coller dans l'ordre. 3 fenêtres de terminal nécessaires : MongoDB, Backend, Frontend.

## Terminal 1 — MongoDB

Vous avez **MongoDB Server installé en local** (service Windows `MongoDB`, démarrage automatique) — rien à faire, il tourne déjà. Vérifier :

```powershell
Get-Service MongoDB
```

S'il est arrêté (`Status` ≠ `Running`), il faut un PowerShell **en administrateur** (clic droit sur PowerShell → "Exécuter en tant qu'administrateur"), sinon `Start-Service` échoue avec "Impossible d'ouvrir le service" :

```powershell
Start-Service MongoDB
```

En pratique, comme le service est en démarrage automatique, il tourne déjà dès l'ouverture de session Windows — vous n'aurez presque jamais besoin de cette commande.

**MongoDB Compass** (l'app graphique) sert uniquement à *consulter* les données — connectez-vous avec l'URI `mongodb://127.0.0.1:27017`, base `cyberwatch`. Ce n'est pas le serveur lui-même, donc l'ouvrir ne suffit pas à faire tourner MongoDB, mais comme le service Windows est déjà actif, vous n'avez rien à démarrer manuellement.

> Remarque : si un jour vous préférez utiliser Docker à la place, un conteneur `mongo:7` sur le port 27017 fonctionne aussi — mais **pas les deux en même temps** (conflit de port). Le projet est actuellement configuré (`.env` → `MONGO_URI=mongodb://127.0.0.1:27017`) pour utiliser le service Windows local.

## Terminal 2 — Backend (FastAPI)

À faire **une seule fois** (installation) :

```powershell
cd "c:\Users\benha\Desktop\Nouveau dossier\Advancia\CyberWatch AI\app\backend"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
Copy-Item .env "c:\Users\benha\Desktop\Nouveau dossier\Advancia\CyberWatch AI\.env"
```

À faire **à chaque démarrage** :

```powershell
cd "c:\Users\benha\Desktop\Nouveau dossier\Advancia\CyberWatch AI"
.\app\backend\.venv\Scripts\python.exe -m uvicorn app.backend.main:app --reload --port 8000
```

✅ Vérifier : http://localhost:8000/health doit afficher `{"status":"ok"}`
📖 Documentation API : http://localhost:8000/docs

## Terminal 3 — Frontend (React)

À faire **une seule fois** (installation) :

```powershell
cd "c:\Users\benha\Desktop\Nouveau dossier\Advancia\CyberWatch AI\app\frontend"
npm install
```

À faire **à chaque démarrage** :

```powershell
cd "c:\Users\benha\Desktop\Nouveau dossier\Advancia\CyberWatch AI\app\frontend"
npm run dev
```

✅ Ouvrir : http://localhost:5173

## Résumé — pour redémarrer après le premier setup

Une fois l'installation faite une première fois, à chaque fois que vous voulez relancer le projet, il suffit de 3 commandes (une par terminal) :

| Terminal | Commande |
|---|---|
| 1 | rien — le service Windows `MongoDB` tourne déjà automatiquement |
| 2 | `cd "...\CyberWatch AI"` puis `.\app\backend\.venv\Scripts\python.exe -m uvicorn app.backend.main:app --reload --port 8000` |
| 3 | `cd "...\CyberWatch AI\app\frontend"` puis `npm run dev` |

## Premier compte à créer

1. Aller sur http://localhost:5173/admin/signup
2. Créer un compte Admin → vous arrivez directement sur le Dashboard
3. Depuis la barre latérale : créer un consultant (page Consultants), une source (page Sources & clés API → "Nouvelle source" → vérifier → valider), un client (page Clients) et l'assigner à un consultant
4. Se déconnecter, puis se connecter en tant que consultant sur http://localhost:5173/consultant/signin pour tester l'envoi d'e-mail à un client assigné

Détails complets et explications : voir [README.md](README.md).
