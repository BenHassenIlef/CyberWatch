# CyberWatch AI

Plateforme de veille en vulnérabilités avec deux espaces séparés — **Admin** et **Consultant** — chacun avec sa propre inscription / connexion.

- **Backend** : FastAPI + MongoDB (`app/backend`)
- **Frontend** : React + Vite + Tailwind CSS (`app/frontend`)
- **Assistant IA** : RAG ancré sur les CVE collectées + réponses générales de cybersécurité ([section 4](#4-agent-ia-de-lassistant))

## Prérequis

- Python 3.11+ (testé avec 3.14)
- Node.js 18+ et npm
- MongoDB accessible (local, Docker, ou Atlas)
- Docker Desktop (optionnel, seulement si vous utilisez MongoDB via conteneur)

## 1. Lancer MongoDB

Si MongoDB Server est déjà installé en local (souvent le cas si vous avez MongoDB Compass — Compass n'est qu'un client de visualisation, pas le serveur), il tourne généralement déjà comme service Windows :



```powershell
Get-Service MongoDB      # doit afficher Status = Running
Start-Service MongoDB    # si besoin de le démarrer
```

Sinon, via Docker :

```bash
docker run -d --name cyberwatch-mongo -p 27017:27017 mongo:7
```

⚠️ N'utilisez qu'une seule des deux méthodes à la fois (conflit sur le port 27017). Ce projet est configuré par défaut sur `mongodb://127.0.0.1:27017`.

## 2. Backend (FastAPI)

```bash
cd "app/backend"

# créer et activer l'environnement virtuel
python -m venv .venv
./.venv/Scripts/activate        # PowerShell : .venv\Scripts\Activate.ps1

# installer les dépendances
pip install -r requirements.txt

# copier la config d'exemple (valeurs par défaut = MongoDB local sur 27017)
cp .env.example .env
```

Le fichier `.env` doit se trouver **à la racine du projet** (`CyberWatch AI/.env`), pas seulement dans `app/backend/`, car c'est de là que le serveur est lancé :

```bash
cd "CyberWatch AI"          # racine du projet
cp app/backend/.env.example .env
```

Lancer le serveur :

```bash
cd "CyberWatch AI"
./app/backend/.venv/Scripts/python.exe -m uvicorn app.backend.main:app --reload --port 8000
```

- API disponible sur http://localhost:8000
- Documentation interactive (Swagger) sur http://localhost:8000/docs
- Test rapide : `curl http://localhost:8000/health` → `{"status":"ok"}`

### Variables importantes (`app/backend/.env`)

| Variable | Rôle |
|---|---|
| `MONGO_URI` / `DB_NAME` | Connexion MongoDB |
| `JWT_SECRET` | Secret de signature des tokens — à changer en production |
| `CORS_ORIGINS` | Origine autorisée pour le frontend (`http://localhost:5173` par défaut) |
| `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | Optionnel — si vide, les e-mails envoyés par les consultants sont simplement journalisés (pas de vrai envoi) |
| `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL` | Agent IA de l'assistant — voir [section 4](#4-agent-ia-de-lassistant). Si vide, l'assistant reste en synthèse déterministe |
| `ASSISTANT_EXTERNAL_ANSWERS` | `true` = l'assistant peut répondre aux questions générales hors base ; `false` = mode strictement documentaire |

## 3. Frontend (React)

```bash
cd "app/frontend"
npm install
npm run dev
```

- Application disponible sur http://localhost:5173
- `VITE_API_URL` (optionnel, `app/frontend/.env`) pointe vers l'API — par défaut `http://localhost:8000`

## 4. Agent IA de l'assistant

L'assistant du consultant (`/consultant/assistant`) répond selon **deux portées**, toujours distinguées dans l'API (champ `scope`) et dans l'interface (badge coloré) :

| Portée | Quand | Origine de la réponse |
|---|---|---|
| `internal` | La question porte sur les CVE collectées | **Uniquement** les documents MongoDB réellement récupérés, reformulés par le LLM sous bridage strict |
| `external` | Question générale (définition, méthode) ou CVE absente de la base | Connaissances propres du modèle, avec badge « hors base » + clause d'avertissement |

**Garde-fou principal** : sur une requête catalogue sans résultat (« affiche les CVE critiques d'aujourd'hui »), l'assistant répond « non disponible » et ne bascule **jamais** en externe. Le modèle ne peut donc pas fabriquer une CVE qui passerait pour une donnée de votre base.

### Configuration

Dans le `.env` **à la racine du projet** :

```bash
LLM_PROVIDER=groq     # groq | grok | openai | anthropic  (vide = agent désactivé)
LLM_API_KEY=gsk_...   # clé du fournisseur
LLM_MODEL=            # vide = modèle par défaut du fournisseur
LLM_BASE_URL=         # vide = URL officielle (à renseigner derrière un proxy)
LLM_TIMEOUT=45        # secondes avant repli sur la synthèse déterministe
ASSISTANT_EXTERNAL_ANSWERS=true
```

⚠️ **Redémarrez le backend** après toute modification : la configuration est lue une seule fois au démarrage.

### Fournisseurs supportés

| `LLM_PROVIDER` | Fournisseur | Préfixe de clé | Modèle par défaut | Où obtenir la clé |
|---|---|---|---|---|
| `groq` | Groq | `gsk_…` | `openai/gpt-oss-120b` | [console.groq.com/keys](https://console.groq.com/keys) |
| `grok` (ou `xai`) | xAI | `xai-…` | `grok-4` | [console.x.ai](https://console.x.ai) |
| `openai` | OpenAI | `sk-…` | `gpt-4o-mini` | [platform.openai.com](https://platform.openai.com) |
| `anthropic` | Anthropic | `sk-ant-…` | `claude-sonnet-4-5` | [console.anthropic.com](https://console.anthropic.com) |

⚠️ **Ne confondez pas « Groq » et « Grok »** : noms quasi identiques, sociétés différentes. Groq (`gsk_…`) héberge des modèles ouverts (Llama, GPT-OSS, Qwen) ; Grok (`xai-…`) est le modèle propriétaire de xAI. Le préfixe de votre clé tranche.

Modèles Groq alternatifs, à mettre dans `LLM_MODEL` : `llama-3.3-70b-versatile` (bon compromis), `llama-3.1-8b-instant` (le plus rapide), `openai/gpt-oss-20b`.

### Vérifier que l'agent répond

```bash
GET /consultant/assistant/health     # authentification consultant requise
```

Retourne le fournisseur, le modèle, l'URL de base et un **test de connexion réel** :

```json
{ "enabled": true, "provider": "groq", "model": "openai/gpt-oss-120b",
  "external_answers": true, "ok": true, "error": null, "sample": "ok" }
```

Si `ok: false`, le champ `error` contient le code HTTP et le message du fournisseur (clé invalide, modèle inconnu, quota dépassé…).

### Fonctionnement sans clé API

L'agent est un **améliorateur, pas un maillon critique**. Sans `LLM_API_KEY`, ou en cas d'erreur / timeout / dépassement de quota, l'assistant retombe silencieusement sur sa synthèse déterministe ancrée : l'application fonctionne exactement comme avant, seules les questions externes sont refusées.

### Réglages avancés

La **température** (`0.2`) est volontairement basse — l'agent restitue des scores CVSS et des versions qui ne doivent pas varier. Elle est fixée dans le code, à `app/backend/services/assistant/llm.py`, et non dans le `.env`.

## 5. Parcours de démonstration

1. Ouvrir http://localhost:5173/admin/signup et créer un compte **Admin**.
2. Vous arrivez sur la page d'accueil Admin (bannière bleue "Admin" + liste des fonctionnalités).
3. Dans **Gestion des consultants**, créer un compte consultant.
4. Dans **Gestion des clients**, créer un client et l'assigner au consultant créé.
5. Se déconnecter, puis se connecter sur  avec le compte consultant.
6. Dans **Mes clients**, envoyer un e-mail au client assigné (journalisé si aucun SMTP n'est configuré).
7. Retourner sur le compte Admin → **Dashboard** : le compteur d'e-mails envoyés et les logs se mettent à jour.

## Structure du projet

```
app/
  backend/     API FastAPI (auth JWT, routes admin/consultant, MongoDB)
    core/                  configuration (.env), sécurité, chiffrement
    routers/               endpoints REST + WebSocket
    services/
      collection/          collecte, parsing et enrichissement des CVE
      verification/        vérification et scoring de crédibilité des sources
      assistant/           agent IA
        rag.py             compréhension de la question, portée, récupération, synthèse
        llm.py             adaptateur multi-fournisseurs (Groq / xAI / OpenAI / Anthropic)
        summary.py         résumés structurés d'une CVE ou d'un groupe de CVE
        external.py        réponses hors base, étiquetées et encadrées
  frontend/    Application React (pages admin/consultant, auth, UI)
```
