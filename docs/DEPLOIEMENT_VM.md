# Déploiement sur une machine virtuelle

Guide de mise en service de CyberWatch AI sur un serveur Linux, avec Docker.

> Aucun mot de passe ne figure dans ce document, ni ne doit y figurer. Les secrets vivent
> dans le fichier `.env` du serveur, qui n'entre jamais dans une image ni dans le dépôt.

---

## 1. Ce qu'il faut sur la VM

| | Minimum | Confortable |
|---|---|---|
| Processeur | 2 cœurs | 4 cœurs |
| Mémoire | 4 Go | 8 Go |
| Disque | 20 Go | 40 Go |

La mémoire est le point sensible : la collecte ouvre un navigateur Chromium pour les
portails qui rendent leurs pages en JavaScript. En dessous de 4 Go, ces sources échouent —
et l'échec ressemble à une panne réseau, ce qui égare le diagnostic.

Ports à ouvrir : **5173** (interface) et **8000** (API). MongoDB n'est jamais exposé.

Installation de Docker :

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER      # puis se reconnecter
```

---

## 2. Récupérer le projet et le configurer

```bash
git clone <votre-dépôt> cyberwatch && cd cyberwatch
cp .env.docker.example .env
```

### Les trois secrets à générer

```bash
python3 -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(64))"
python3 -c "import secrets; print('CREDENTIALS_ENCRYPTION_KEY=' + secrets.token_urlsafe(32))"
```

`JWT_SECRET` signe les jetons de connexion. **Laisser la valeur d'exemple revient à
autoriser n'importe qui à forger un jeton administrateur** : c'est la seule ligne de ce
fichier dont l'oubli est une faille, pas une gêne.

La troisième valeur est votre clé LLM (`LLM_API_KEY`), à reporter telle quelle.

---

## 3. LE PIÈGE : les URL figées sur `localhost`

C'est l'erreur qui fait perdre le plus de temps, et elle ne produit aucun message clair.

Deux réglages désignent l'adresse **vue par le navigateur du consultant** — pas celle du
conteneur. Laissés à `localhost`, l'interface se charge mais **aucune donnée n'apparaît** :
le navigateur cherche l'API sur la machine du consultant, où elle n'existe pas.

Dans `.env` :

```env
VITE_API_URL=http://cyberwatch.entreprise.fr:8000
CORS_ORIGINS=http://cyberwatch.entreprise.fr:5173
```

Remplacez par le nom DNS ou l'adresse IP de la VM.

> `VITE_API_URL` est **incrusté à la construction** de l'image : le modifier impose
> `docker compose build frontend`. Un simple redémarrage ne suffit pas.

`CORS_ORIGINS` est déjà écrasé par `docker-compose.yml` sur des valeurs locales : pour un
déploiement, retirez ces deux lignes de la section `environment` du service `backend`, ou
remplacez-les par l'adresse réelle.

---

## 4. Configurer l'envoi de courriels — Microsoft 365

Depuis le poste Windows, l'outil interactif fait tout :

```powershell
.\app\backend\.venv\Scripts\python.exe configurer_smtp.py
```

Sur la VM, où l'application tourne en conteneur, renseignez directement `.env` :

```env
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=cyberwatch@entreprise.fr
SMTP_PASSWORD=<le mot de passe du compte d'envoi>
SMTP_FROM=cyberwatch@entreprise.fr
EMAIL_NOTIFICATIONS_ENABLED=true
NOTIFY_EXTRA_RECIPIENTS=vous@entreprise.fr,collegue@entreprise.fr
```

Trois points qui font échouer une configuration pourtant exacte :

**`SMTP_FROM` doit valoir `SMTP_USER`.** Microsoft 365 refuse d'expédier au nom d'une autre
adresse que l'identifiant.

**L'authentification SMTP est désactivée par défaut** sur chaque boîte depuis 2023.
L'administrateur du locataire doit l'autoriser :

```powershell
Connect-ExchangeOnline
Set-CASMailbox -Identity cyberwatch@entreprise.fr -SmtpClientAuthenticationDisabled $false
```

Sans cela, le serveur répond *« basic authentication is disabled »* — et **le mot de passe
n'est pas en cause**. L'application traduit ce refus, mais autant le savoir d'avance.

**Un compte d'envoi dédié vaut mieux qu'une boîte nominative.** Les notifications ne
s'arrêteront pas le jour où quelqu'un change de mot de passe ou quitte l'entreprise.

Vérification, une fois la pile démarrée :

```bash
docker compose exec backend python -c \
  "import asyncio; from app.backend.services import notifications as n; \
   print(asyncio.run(n.essai_de_remise('vous@entreprise.fr')))"
```

---

## 5. Démarrer

```bash
docker compose up -d --build
docker compose ps
```

Trois conteneurs doivent être `healthy` : `mongo`, `backend`, `frontend`.

| Service | Adresse |
|---|---|
| Interface | `http://<vm>:5173` |
| API | `http://<vm>:8000/docs` |

Au premier démarrage, l'application crée ses index et amorce le catalogue de produits
surveillés. La première collecte a lieu à l'heure planifiée — ou immédiatement :

```bash
docker compose exec backend python collect_once.py
```

---

## 6. La collecte quotidienne

Sur Windows, elle est déclenchée par une Tâche planifiée. **Ce mécanisme n'existe pas en
conteneur** : `docker-compose.yml` bascule donc sur le planificateur interne du backend
(`COLLECTION_TRIGGER=internal`).

Ne mettez jamais `external` ici : plus rien ne déclencherait la collecte, et rien ne le
signalerait — la veille s'arrêterait en silence.

Le fuseau horaire compte : `SCHEDULER_TIMEZONE=Europe/Paris` (ou `Africa/Tunis`). Sans lui,
« aujourd'hui » désigne la journée UTC, et la veille du matin porterait sur la veille.

---

## 7. Sécurité

**Le fichier `.env` n'entre jamais dans une image** — `.dockerignore` l'exclut, et
`docker-compose.yml` le lit à l'exécution (`env_file`). Une image contenant un mot de passe
le distribue à quiconque la récupère.

**Protégez-le sur le serveur :**

```bash
chmod 600 .env
```

**MongoDB ne doit pas être exposé.** En production, retirez du service `mongo` :

```yaml
ports:
  - "127.0.0.1:27017:27017"     # ← à supprimer
```

Le backend le joint par le réseau interne ; cette ligne ne sert qu'à l'inspection locale.

**HTTPS.** L'application est servie en clair sur 5173. Placez un reverse proxy devant —
Caddy suffit et obtient son certificat seul :

```
cyberwatch.entreprise.fr {
    reverse_proxy /api/* backend:8000
    reverse_proxy frontend:80
}
```

Sans chiffrement, les mots de passe de connexion des consultants traversent le réseau en
clair.

---

## 8. Sauvegarde

Les données vivent dans le volume `mongo-data`. `docker compose down` les conserve ;
`docker compose down -v` **les détruit**.

```bash
docker compose exec -T mongo mongodump --archive --gzip --db=cyberwatch \
  > sauvegarde-$(date +%F).gz
```

Restauration :

```bash
docker compose exec -T mongo mongorestore --archive --gzip --drop < sauvegarde-2026-08-28.gz
```

---

## 9. Diagnostic

```bash
docker compose logs -f backend          # journal en direct
docker compose exec backend cat /app/logs/collect_once.log
```

Trois vérifications utiles au démarrage :

**La configuration est-elle lue ?** Le backend annonce au démarrage le fichier réellement
chargé. S'il signale que `app/backend/.env` existe mais n'est pas lu, c'est normal — seule
la racine fait foi.

**Les courriels partent-ils ?** L'écran *Notifications* de l'espace consultant affiche la
cause exacte en cas d'échec, sans jamais divulguer de secret.

**La collecte a-t-elle abouti ?** L'écran *Planification* indique le nombre de sources
abouties. Une collecte où *aucune* source n'aboutit est marquée en échec, jamais « journée
calme » — la distinction est ce qui empêche une veille de s'arrêter sans que personne le
remarque.
