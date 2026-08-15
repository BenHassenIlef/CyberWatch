# Planification de la collecte quotidienne CVE

## Pourquoi cette architecture

Historiquement, la collecte était déclenchée par un **scheduler interne à FastAPI** démarré dans
le `lifespan`. Il ne vivait donc que **tant qu'Uvicorn tournait** : PC éteint / fenêtre fermée /
backend redémarré à 08:00 ⇒ **aucune collecte** (au mieux un rattrapage tardif au prochain
démarrage). D'où des collectes à des heures aléatoires et des runs `interrupted`.

La collecte quotidienne est désormais déclenchée par la **Tâche planifiée Windows**, qui lance un
script *one-shot* `collect_once.py`, **indépendamment d'Uvicorn**.

```
Windows Task Scheduler ──08:00 (rattrapage si PC éteint)──▶ collect_once.py
FastAPI / Uvicorn ....................... API + UI uniquement (ne collecte pas)
                                                   │
                                                   ▼
                             scheduler.execute_due()   ← runner PARTAGÉ (verrou anti-doublon)
                                                   ▼
                             pipeline.run_collection() ← service de collecte existant (inchangé)
                             sources → dédup → enrichissement → MongoDB → bulletins à la demande
```

`collect_once.py` **réutilise exactement** le même service de collecte que le scheduler interne :
il n'y a **aucune duplication** de la logique de collecte.

## Anti-double-collecte (important)

Deux protections empêchent une double collecte simultanée :

1. **Interrupteur de mode** — `COLLECTION_TRIGGER` dans `app/backend/.env` :
   - `external` (**défaut, recommandé**) : Windows Task est le déclencheur ; **FastAPI ne collecte
     pas**.
   - `internal` : ancien comportement (scheduler interne dans FastAPI). N'installez **pas** la
     Tâche Windows dans ce mode.
2. **Verrou en base** (`scheduler_state/_id:"lock"`, auto-expiration 60 min) : même si les deux
   déclencheurs se lançaient, **une seule** collecte s'exécuterait (l'autre renvoie `skipped_locked`).

## Installation (une fois)

```powershell
# 1) S'assurer du mode external (défaut). Dans app/backend/.env :
#    COLLECTION_TRIGGER=external

# 2) Installer la tâche (08:00 par défaut) :
.\setup_scheduler.ps1

#    Heure personnalisée :        .\setup_scheduler.ps1 -Time 07:30
#    Installer puis tester tout de suite : .\setup_scheduler.ps1 -RunNow
#    Désinstaller :               .\setup_scheduler.ps1 -Uninstall
```

La tâche est enregistrée avec des réglages robustes :

| Réglage | Valeur | Effet |
|---|---|---|
| Déclencheur | Quotidien à l'heure choisie | 1 collecte / jour |
| `StartWhenAvailable` | activé | **rattrape** une exécution manquée (PC éteint à 08:00 → lance dès le démarrage) |
| `MultipleInstances` | `IgnoreNew` | ne démarre **pas** une 2ᵉ instance si une tourne déjà |
| `ExecutionTimeLimit` | 1 h | borne la durée (pas de tâche zombie) |
| `RestartCount/Interval` | 2 × 5 min | ré-essai en cas d'échec transitoire |
| Batteries | autorisé | fonctionne sur portable |
| Principal | selon privilège | PowerShell **admin** → S4U (**connecté ou non**) ; sinon → Interactive (utilisateur **connecté**) |

> Le script s'enregistre via `schtasks /Create /XML` : il **ne nécessite pas d'élévation** pour
> une tâche par-utilisateur. Pour l'option « exécuter que l'utilisateur soit connecté ou non »
> (S4U), lancez-le depuis une **PowerShell administrateur**.

## Exécution manuelle / test

```powershell
# Directement (venv) :
app\backend\.venv\Scripts\python.exe collect_once.py          # collecte si échéance non honorée
app\backend\.venv\Scripts\python.exe collect_once.py --force  # force la collecte

# Via la tâche :
Start-ScheduledTask -TaskName "CyberWatch AI - Daily CVE Collection"
Get-ScheduledTaskInfo -TaskName "CyberWatch AI - Daily CVE Collection"   # LastTaskResult=0 => OK
```

Journal : **`logs/collect_once.log`** (rotation 5 × 2 Mo).

## PC éteint à 08:00 (échéance manquée)

- **Échéance prévue** (`due_date` / `scheduled_time`) = 08:00.
- **Exécution réelle** (`actual_start`) = moment où Windows lance la tâche manquée après démarrage.
- Le statut devient **`completed_late`** — on n'affirme **jamais** que la collecte a eu lieu à
  08:00 si le PC était éteint. Les deux horodatages sont conservés dans `scheduler_state.last_report`
  et sur le run `collection_runs`.

## Statuts d'une échéance quotidienne

Écrits dans `scheduler_state.last_report.status` et sur le run (`collection_runs.daily_status`).
`last_completed_due` **n'avance que** pour `completed`, `completed_late`, `degraded`.

| Statut | Sens | Avance l'échéance ? |
|---|---|---|
| `completed` | Toutes les sources honorées, CVE collectées, à l'heure | ✅ |
| `completed_late` | Idem mais en retard (rattrapage) | ✅ |
| `degraded` | Échéance validée malgré des sources en échec **persistant** (alerte levée) | ✅ |
| `partial` | Des sources récupérables restent à ré-essayer | ❌ (reprise) |
| `suspicious_empty` | Sources joignables mais **0 CVE au total** → anomalie | ❌ (reprise) |
| `interrupted` | Process arrêté en pleine collecte | ❌ (reprise) |
| `failed` | Exception globale | ❌ (reprise) |

### Protection « run vide suspect »

Un run où **toutes** les sources sont joignables mais **0 CVE** au total n'est **plus** considéré
comme un succès : il est marqué `suspicious_empty` et **n'avance pas** `last_completed_due`, pour
que la collecte soit **re-tentée** (sinon de vraies CVE du jour seraient perdues).

## Timeouts de sources (problème indépendant)

Cause racine identifiée (mesurée) : le collecteur HTML **lançait un navigateur Chromium neuf par
page** ; avec ~9 sources HTML en parallèle × jusqu'à 20 pages de détail, des dizaines de Chromium
tournaient simultanément → épuisement CPU/RAM → un rendu de 3 s dépassait le timeout de 150 s.

Correctif (sans augmenter aveuglément le timeout) :
- **un seul** navigateur Chromium **partagé** pour tout le process (contextes légers par page) ;
- un **sémaphore global** `RENDER_CONCURRENCY` (défaut 3) plafonnant les rendus simultanés.

> **`programm` (https://www.cve.org/) est mal configurée** : c'est une page d'accueil SPA **sans
> liste de CVE** (rendu ~21 s pour 0 CVE). À **désactiver** ou repointer vers une vraie page de
> liste dans l'interface Admin (le correctif ci-dessus l'empêche de bloquer les autres sources,
> mais elle restera `empty`).

## Fichiers

| Fichier | Rôle |
|---|---|
| `collect_once.py` | Entrée one-shot (Tâche Windows). Réutilise `scheduler.run_scheduled_collection`. |
| `setup_scheduler.ps1` | Crée / met à jour / supprime la Tâche planifiée Windows. |
| `app/backend/services/collection/scheduler.py` | `execute_due` (runner partagé), verrou, statuts. |
| `app/backend/core/config.py` | `COLLECTION_TRIGGER`, `RENDER_CONCURRENCY`. |
| `tests/test_scheduling.py` | Tests de la machine à états (`python tests/test_scheduling.py`). |

## Vérifier l'état en base

```javascript
db.scheduler_state.findOne({_id:"global"})   // last_completed_due, last_report{...}
db.collection_runs.find().sort({started_at:-1}).limit(5)  // due_date, daily_status, trigger
```
