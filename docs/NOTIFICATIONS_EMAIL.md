# Notifications par courriel

La veille quotidienne est envoyée à chaque consultant, à l'adresse de son compte, après
chaque collecte. Ce document décrit ce qu'il faut renseigner pour que la remise fonctionne,
et comment diagnostiquer un envoi qui n'aboutit pas.

> Aucun mot de passe ne figure dans ce document, ni ne doit y figurer. Les secrets vivent
> dans le fichier `.env`, qui est exclu du dépôt (`.gitignore`).

---

## 1. Variables d'environnement

Toutes se déclarent dans le fichier **`.env` situé à la racine du projet**.

| Variable | Rôle | Exemple |
|---|---|---|
| `SMTP_HOST` | Serveur d'envoi | `smtp.gmail.com` |
| `SMTP_PORT` | Port | `587` |
| `SMTP_USE_TLS` | Chiffrement de la liaison | `true` |
| `SMTP_USER` | Identifiant de connexion | votre adresse d'expédition |
| `SMTP_PASSWORD` | Mot de passe **d'application** | *(16 caractères, jamais versionné)* |
| `SMTP_FROM` | Adresse d'expédition affichée | identique à `SMTP_USER` pour Gmail |
| `EMAIL_NOTIFICATIONS_ENABLED` | Interrupteur général | `true` |
| `NOTIFY_EXTRA_RECIPIENTS` | Adresses de supervision, séparées par des virgules | *(facultatif)* |

### Le port détermine le protocole

| Port | Chiffrement | Réglage |
|---|---|---|
| `587` | STARTTLS — la liaison démarre en clair puis bascule | `SMTP_USE_TLS=true` |
| `465` | TLS implicite — chiffrée dès l'ouverture | `SMTP_USE_TLS=true` |
| `25` | aucun — **relais local uniquement** | `SMTP_USE_TLS=false` |

L'application refuse d'envoyer des identifiants vers un serveur **distant** sur une liaison
non chiffrée : `AUTH PLAIN` transmet le mot de passe en base64, donc lisible par quiconque
observe le réseau. Un relais local (`localhost`, `127.0.0.1`) échappe à cette règle, puisque
rien ne traverse le réseau.

---

## 2. Cas de Gmail

Google n'accepte plus le mot de passe du compte pour SMTP. Il faut un **mot de passe
d'application** :

1. `myaccount.google.com` → **Sécurité** → activer la **validation en deux étapes** ;
2. même page → **Mots de passe des applications** → en créer un pour « CyberWatch AI » ;
3. reporter les 16 caractères dans `SMTP_PASSWORD` ;
4. redémarrer le backend.

`SMTP_FROM` doit valoir exactement `SMTP_USER` : Gmail refuse d'expédier au nom d'une autre
adresse.

---

## 3. Vérifier sans attendre la collecte

Espace Consultant → **Notifications** → bouton **« Envoyer un message d'essai »**.

Le message part vers l'adresse du compte connecté — jamais vers une adresse saisie, ce qui
ferait de ce bouton un relais d'envoi pour un tiers. Le résultat s'affiche immédiatement, en
nommant la cause en cas d'échec.

En ligne de commande :

```bash
python -c "import asyncio; from app.backend.services import notifications as n; \
print(asyncio.run(n.essai_de_remise('adresse@exemple.fr')))"
```

---

## 4. Diagnostic

L'écran **Notifications** affiche en permanence l'état de la remise. Les causes possibles :

| Cause | Signification | Geste |
|---|---|---|
| `non_configure` | `SMTP_HOST` absent | renseigner le serveur |
| `desactive` | `EMAIL_NOTIFICATIONS_ENABLED=false` | passer à `true` |
| `identifiant_manquant` | `SMTP_USER` absent | renseigner l'identifiant |
| `mot_de_passe_manquant` | `SMTP_PASSWORD` absent | créer un mot de passe d'application |
| `aucun_destinataire` | aucun compte consultant n'a d'adresse | compléter les comptes |

Les refus du serveur sont traduits en gestes concrets plutôt qu'en codes bruts :

| Réponse du serveur | Ce qui s'affiche |
|---|---|
| `535-5.7.8 Username and Password not accepted` | mot de passe **d'application** requis, validation en deux étapes à activer |
| `534-5.7.14 Please log in via your web browser` | compte bloqué pour activité inhabituelle |
| `getaddrinfo failed` | nom de serveur non résolu |
| `Connection refused` | serveur ou port injoignable |

Aucun de ces messages ne contient le mot de passe, même lorsque le serveur le renvoie dans
sa propre réponse d'erreur.

---

## 5. Où la configuration est lue

**Un seul fichier est chargé : `.env` à la racine du projet.**

Le chemin est ancré en absolu (`app/backend/core/config.py`), de sorte que le comportement ne
dépend pas du répertoire depuis lequel l'application est lancée — service Windows, tâche
planifiée ou terminal.

Le fichier `app/backend/.env` existe pour des raisons historiques mais **n'est jamais lu**.
Le backend le signale au démarrage :

```
Le fichier …/app/backend/.env existe mais N'EST PAS LU : seule la configuration
de la racine est chargée. Toute valeur saisie ici reste sans effet.
```

---

## 6. Quand les courriels partent

| Déclencheur | Contenu |
|---|---|
| Après chaque collecte | veille du jour, groupée par produit surveillé |
| Journée sans nouveauté | message explicite : *« N vulnérabilités publiées aujourd'hui, aucune ne concerne vos produits »* |
| Bouton d'essai | message de vérification |

Un même contenu n'est jamais envoyé deux fois le même jour : plusieurs collectes quotidiennes
ne produisent qu'un seul message, sauf si de nouvelles vulnérabilités apparaissent entre-temps.
