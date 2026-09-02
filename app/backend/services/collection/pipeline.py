"""Orchestrateur de la collecte des CVE.

Pipeline (points 1 à 10 du cahier des charges) :
    sources validées (BDD)  ->  parcours PARALLÈLE, tolérant aux pannes
      ->  collecteur selon la méthode de chaque source (API/RSS/HTML/XML/Sitemap/JSON…)
      ->  enrichissement des champs manquants (normalisation canonique NVD)
      ->  déduplication par identifiant CVE (fusion multi-sources)
      ->  sauvegarde (insertion des nouvelles, mise à jour des sources des existantes)
      ->  rapport détaillé

Aucune source codée en dur : tout provient de la base. Ajouter une source (ou une méthode)
ne nécessite aucune modification de cet orchestrateur.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from app.backend.core.config import settings
from app.backend.services.collection import (dedup, enrichment, isolation, monitored,
                                             source_state as ss, storage, translation)
from app.backend.services.collection.collectors import base as collectors
from app.backend.services.collection.collectors.base import SourceParseError, SourceUnreachable
from app.backend.services.collection.logs import RunLogger
from app.backend.services.collection.schema import CANONICAL_KEYS, CVE_RE, add_source
from app.backend.services.collection.source_manager import get_active_sources
from app.backend.utils import utcnow

# Journal TECHNIQUE du module. Ailleurs dans ce fichier, « logger » designe le RunLogger
# recu en parametre, qui ecrit dans `collection_logs` : celui-ci sert aux diagnostics
# internes, la ou aucun RunLogger n'est disponible.
_journal = logging.getLogger("cyberwatch.collection.pipeline")

NEW_ENRICH_MAX = 400        # borne de sécurité : nb max de NOUVELLES CVE enrichies / exécution
UPDATE_ENRICH_BUDGET = 40   # nb max de CVE EXISTANTES ré-analysées (détection de mise à jour)
SOURCE_TIMEOUT = 150        # marge pour les portails d'avis deux niveaux (crawl + rendus)


ENRICH_CONCURRENCY = 6  # nb de CVE enrichies en parallèle (sources rapides, non limitées en débit)

# COLLECTE EN DEUX VAGUES — corrige la perte des sources les plus autoritaires.
#
# Toutes les sources partaient ensemble. Les portails HTML ouvrent un navigateur Chromium et
# parcourent plusieurs pages ; les API, elles, se contentent d'une requête. Lancés en même
# temps, les premiers saturaient la machine et le lien réseau, et les secondes expiraient.
#
# Mesuré sur cette installation : NVD, le catalogue KEV de la CISA et l'API MSRC échouaient
# TOUS LES TROIS en collecte complète (délai HTTP de 40 s dépassé, 0 CVE) alors que, lancés
# seuls, ils répondent en 20 secondes et rapportent 2 210 vulnérabilités. On perdait donc
# exactement les trois sources qui font autorité, sans que rien ne le signale : le rapport
# annonçait « 6 sources en erreur » comme si les serveurs distants étaient en cause.
#
# Les API et flux passent donc EN PREMIER, seuls ; les portails HTML ensuite, par petits lots.
METHODES_SANS_NAVIGATEUR = {"json", "xml", "rss", "sitemap"}
SOURCES_HTML_SIMULTANEES = 3


async def _collecter_par_vagues(sources: list[dict], logger: RunLogger) -> list[dict]:
    """Collecte les sources en deux vagues. Renvoie les résultats DANS L'ORDRE des sources.

    L'ordre est contractuel : l'appelant apparie `sources[i]` et `results[i]` pour journaliser
    l'état de chaque source et faire avancer `last_sync_at`. Une correspondance décalée
    attribuerait les CVE d'une source à une autre.
    """
    resultats: list[dict] = [None] * len(sources)                      # type: ignore[list-item]
    legeres, lourdes = [], []
    for i, s in enumerate(sources):
        _, cle = collectors.resolve(s)
        (legeres if cle in METHODES_SANS_NAVIGATEUR else lourdes).append(i)

    if legeres:
        logger.info(f"Vague 1 — {len(legeres)} source(s) d'API ou de flux, sans navigateur.")
        obtenus = await asyncio.gather(*[_collect_one(sources[i], logger) for i in legeres])
        for i, r in zip(legeres, obtenus):
            resultats[i] = r

    if lourdes:
        logger.info(f"Vague 2 — {len(lourdes)} portail(s) HTML, "
                    f"{SOURCES_HTML_SIMULTANEES} à la fois.")
        for i, r in await _collecter_en_lots(sources, lourdes, logger):
            resultats[i] = r
    return resultats


async def _collecter_en_lots(sources: list[dict], indices: list[int],
                             logger: RunLogger) -> list[tuple[int, dict]]:
    """Collecte les sources désignées, au plus `SOURCES_HTML_SIMULTANEES` en parallèle."""
    verrou = asyncio.Semaphore(SOURCES_HTML_SIMULTANEES)

    async def _borne(i: int) -> tuple[int, dict]:
        async with verrou:
            return i, await _collect_one(sources[i], logger)

    return list(await asyncio.gather(*[_borne(i) for i in indices]))


async def refresh_scope(db) -> None:
    """Recharge le catalogue des produits surveillés depuis la base (produits activés, domaines
    activés). Un produit ajouté ou désactivé dans « Produits surveillés » est ainsi pris en
    compte dès la collecte suivante, sans aucune modification de code."""
    # AMORÇAGE UNE SEULE FOIS, sur une base vierge.
    #
    # `seed_catalog` recrée les produits par défaut manquants. Appelé à CHAQUE collecte, il
    # défaisait les décisions de l'administrateur : un produit supprimé dans « Produits
    # surveillés » réapparaissait au passage suivant, et désactiver le dernier produit
    # ramenait tout le catalogue codé en dur. Une fois la base peuplée, elle fait autorité.
    if await db.monitored_products.count_documents({}) == 0:
        await monitored.seed_catalog(db)
    await monitored.refresh_catalog(db)


def prefilter_scope(records: list[dict]) -> list[dict]:
    """PRÉ-FILTRE, AVANT enrichissement — économise les appels réseau.

    Conserve une CVE qui correspond DÉJÀ à un produit surveillé, ou dont le produit est encore
    INCONNU (aucune information structurée : l'enrichissement tranchera). Écarte immédiatement
    celles dont le produit est connu ET hors périmètre : inutile d'interroger NVD/MITRE pour une
    CVE qui ne sera pas conservée.
    """
    return [r for r in records if monitored.candidate(r)]


def _bornes_du_jour() -> tuple[datetime, datetime]:
    """Fenêtre de la veille du jour, en UTC naïf — le format stocké en base."""
    from app.backend.core.config import settings
    from app.backend.services.collection.scheduler import _tz

    jours = max(1, int(getattr(settings, "DAILY_COLLECTION_WINDOW_DAYS", 1) or 1))
    minuit = datetime.now(_tz()).replace(hour=0, minute=0, second=0, microsecond=0)
    debut = (minuit - timedelta(days=jours - 1)).astimezone(timezone.utc).replace(tzinfo=None)
    fin = (minuit + timedelta(days=1)).astimezone(timezone.utc).replace(tzinfo=None)
    return debut, fin


# Plafond de rattrapage. Une application arrêtée trois semaines ne doit pas rapatrier d'un
# coup trois semaines de vulnérabilités : le consultant se retrouverait devant des centaines
# de fiches sans savoir laquelle relève d'aujourd'hui. Au-delà, on s'en tient à la journée.
RATTRAPAGE_MAX = timedelta(days=7)


async def _bornes_de_la_veille(db) -> tuple[datetime, datetime, str]:
    """Fenêtre RÉELLEMENT couverte par cette collecte : depuis la PRÉCÉDENTE, pas depuis minuit.

    Renvoie (début, fin, motif).

    POURQUOI PAS MINUIT
    Une collecte du matin ne voit que ce qui a paru depuis minuit. Or la collecte précédente
    a pu avoir lieu la veille à 10 h : tout ce qui a été publié entre 10 h et minuit tombe
    alors dans un angle mort — ni « publié aujourd'hui », ni déjà collecté. Mesuré sur cette
    installation : **13 heures** pendant lesquelles une vulnérabilité nouvelle était écartée
    en silence, comme « ancienne et inconnue ».

    Partir de la dernière collecte ferme ce trou par construction : deux passages successifs
    couvrent toujours l'intervalle qui les sépare, quelle que soit l'heure à laquelle ils
    tombent.

    Le rattrapage est BORNÉ (voir `RATTRAPAGE_MAX`) et ne descend jamais sous minuit : la
    fenêtre couvre au minimum la journée en cours, même après une collecte survenue il y a
    dix minutes.
    """
    minuit, fin = _bornes_du_jour()

    try:
        precedente = await db.collection_runs.find_one(
            {"status": "completed"}, sort=[("started_at", -1)])
    except Exception as exc:  # noqa: BLE001 - sans historique, on retombe sur la journée
        _journal.warning("Historique des collectes illisible (%s) : "
                         "fenêtre ramenée à la journée en cours.", exc)
        return minuit, fin, "journée en cours (historique indisponible)"

    depart = (precedente or {}).get("started_at")
    if not isinstance(depart, datetime):
        return minuit, fin, "journée en cours (aucune collecte précédente)"

    plancher = fin - RATTRAPAGE_MAX
    if depart < plancher:
        _journal.info("Dernière collecte le %s : au-delà du rattrapage de %d jours, "
                      "la fenêtre est ramenée d'autant.",
                      str(depart)[:16], RATTRAPAGE_MAX.days)
        return plancher, fin, f"rattrapage plafonné à {RATTRAPAGE_MAX.days} jours"

    # PLANCHER DE 24 HEURES, quoi qu'il arrive.
    #
    # Deux notions de « dernier passage » coexistent : celle du PIPELINE (dernière exécution)
    # et celle de CHAQUE SOURCE (`last_sync_at`, qui n'avance qu'en cas de réussite). Elles
    # divergent dès qu'une source échoue : celle-ci re-demandera deux jours de publications
    # au passage suivant, que le filtre rejetterait comme « anciennes » si sa fenêtre s'était
    # refermée sur la seule dernière exécution.
    #
    # Couvrir systématiquement les 24 dernières heures aligne les deux sans les coupler. Le
    # surcoût est nul à l'arrivée : une vulnérabilité déjà collectée est reconnue par la
    # déduplication et n'est ni ré-enregistrée, ni recomptée.
    plancher_24h = fin - timedelta(days=2)
    if depart >= minuit:
        return min(minuit, plancher_24h), fin, "journée en cours et 24 h précédentes"

    return depart, fin, f"depuis la collecte du {depart:%d/%m à %Hh%M}"


def _compter_publiees_du_jour(records: list[dict]) -> int:
    """Nombre de vulnérabilités PARUES aujourd'hui parmi celles détectées, périmètre ignoré.

    Sert uniquement au rapport : c'est ce chiffre qui permet d'écrire « 36 vulnérabilités
    publiées aujourd'hui, aucune ne concerne vos produits » plutôt qu'un « aucune CVE » muet
    que rien ne distingue d'une panne.
    """
    debut, fin = _bornes_du_jour()
    total = 0
    for r in records:
        publiee = r.get("published_at")
        if not isinstance(publiee, datetime):
            continue
        p = publiee.replace(tzinfo=None) if publiee.tzinfo else publiee
        if debut <= p < fin:
            total += 1
    return total


async def filtrer_veille_du_jour(db, records: list[dict]) -> tuple[list[dict], int, int]:
    """Veille du jour = NOUVEAUTÉS publiées aujourd'hui **+ MISES À JOUR** des CVE déjà suivies.

    Renvoie (gardées, écartées, dont sans date).

    DEUX natures d'actualité, et il faut les deux :

      • une vulnérabilité PUBLIÉE aujourd'hui — c'est la veille au sens strict ;
      • une vulnérabilité DÉJÀ EN BASE dont les données ont changé : score réévalué,
        correctif publié, exploitation constatée. Sa date de publication est ancienne par
        construction, mais l'information, elle, est du jour.

    Ne garder que le premier cas — ce que faisait la version précédente de ce filtre —
    supprimait toutes les mises à jour : un correctif publié ce matin pour une faille de la
    semaine dernière n'atteignait plus le consultant. Ne garder aucun des deux critères
    rapatriait au contraire des centaines de CVE anciennes jamais vues, qui noyaient les
    nouvelles.

    Une CVE INCONNUE et SANS date de publication est écartée : rien ne permet d'affirmer
    qu'elle relève d'aujourd'hui. Elle reviendra dès qu'une source lui donnera une date.
    """
    from app.backend.core.config import settings

    if not getattr(settings, "DAILY_COLLECTION_TODAY_ONLY", False):
        return records, 0, 0, "filtre désactivé (toutes les CVE conservées)"

    debut, fin, motif = await _bornes_de_la_veille(db)
    identifiants = [r.get("cve_id") for r in records if r.get("cve_id")]
    # Un seul aller-retour : les CVE déjà suivies sont celles dont la mise à jour compte.
    connues = set()
    if identifiants:
        connues = {d["cve_id"] async for d in
                   db.cves.find({"cve_id": {"$in": identifiants}}, {"cve_id": 1})}

    gardees, ecartees, sans_date = [], 0, 0
    for r in records:
        if r.get("cve_id") in connues:
            gardees.append(r)                 # déjà suivie : toute évolution est du jour
            continue
        publiee = r.get("published_at")
        if not isinstance(publiee, datetime):
            sans_date += 1
            ecartees += 1
            continue
        p = publiee.replace(tzinfo=None) if publiee.tzinfo else publiee
        if debut <= p < fin:
            gardees.append(r)                 # nouveauté publiée aujourd'hui
        else:
            ecartees += 1                     # ancienne et inconnue : hors veille du jour
    # Le MOTIF de la fenêtre remonte à l'appelant, qui l'inscrit dans le journal de collecte :
    # « depuis la collecte du 26/08 à 10h02 » explique un volume inhabituel, là où une ligne
    # muette laisserait croire à un dysfonctionnement.
    return gardees, ecartees, sans_date, motif


def tag_and_filter(records: list[dict]) -> tuple[list[dict], int]:
    """CLASSIFICATION DÉFINITIVE, APRÈS enrichissement : ne CONSERVE que les CVE rattachées à un
    produit surveillé. Renvoie (CVE conservées, nombre d'écartées).

    Le premier produit trouvé est « primaire » (`monitored_product` / `domain`) ; les tableaux
    (`monitored_products` / `domains`) permettent qu'une CVE référence PLUSIEURS produits sans
    jamais dupliquer l'enregistrement.

    NB : le périmètre s'applique à la COLLECTE. Les CVE déjà en base ne sont jamais supprimées
    lorsqu'un produit est retiré du catalogue.
    """
    kept: list[dict] = []
    for rec in records:
        # Appariements GRADUÉS : chacun porte son niveau de confiance et sa preuve.
        details = monitored.classify_detailed(rec)
        retenus = [h for h in details if h["confidence"] != monitored.REJECTED]
        if not retenus:
            # Traçabilité : on note POURQUOI la CVE a été écartée quand un produit avait
            # semblé correspondre. Sans cela, un rejet légitime est indiscernable d'un oubli.
            rejetes = [h for h in details if h["confidence"] == monitored.REJECTED]
            if rejetes:
                rec["match_confidence"] = monitored.REJECTED
                rec["match_evidence"] = rejetes[0]["evidence"]
            continue
        rec["monitored_products"] = list(dict.fromkeys(h["product"] for h in retenus))
        rec["domains"] = list(dict.fromkeys(h["domain"] for h in retenus if h["domain"]))
        rec["monitored_product"] = retenus[0]["product"]
        rec["domain"] = retenus[0]["domain"]
        rec["match_confidence"] = retenus[0]["confidence"]
        rec["match_evidence"] = retenus[0]["evidence"]
        # DERNIÈRE BARRIÈRE avant la base : une fiche qui porte des données d'une autre
        # vulnérabilité est marquée `needs_review` plutôt que publiée telle quelle. Elle
        # n'est pas écartée — une vulnérabilité réelle ne disparaît pas parce qu'un de ses
        # champs est douteux — mais l'anomalie cesse d'être invisible.
        isolation.appliquer(rec)
        kept.append(rec)
    return kept, len(records) - len(kept)


async def update_product_stats(db) -> None:
    """Rafraîchit le statut de chaque produit surveillé (nb de CVE, nouvelles, dernière collecte).
    Lecture seule côté CVE ; ne met à jour que la collection `monitored_products`."""
    try:
        pipe = [{"$match": {"monitored_products": {"$exists": True, "$ne": []}}},
                {"$unwind": "$monitored_products"},
                {"$group": {"_id": "$monitored_products", "n": {"$sum": 1},
                            "new": {"$sum": {"$cond": [{"$eq": ["$is_new", True]}, 1, 0]}}}}]
        counts = {r["_id"]: r async for r in db.cves.aggregate(pipe)}
        now = utcnow()
        for name, r in counts.items():
            await db.monitored_products.update_one(
                {"name": name},
                {"$set": {"cve_count": r["n"], "new_count": r["new"], "last_collection_at": now}})
    except Exception as exc:  # noqa: BLE001 - le statut ne doit jamais casser la collecte
        logging.getLogger("cyberwatch.collection").warning("update_product_stats: %s", exc)


async def _enrich_record(rec: dict, use_nvd: bool = False) -> bool:
    """Enrichit un enregistrement par croisement multi-sources officielles. Renvoie True si
    des données ont été récupérées. Par défaut sans NVD (rapide : MITRE/OSV/Red Hat/GitHub
    fournissent déjà les VRAIES dates de publication/modification et souvent le CVSS)."""
    # Les entrées « avis CERT seul » (identifiant non-CVE) ne sont pas interrogeables sur NVD/MITRE.
    if not CVE_RE.fullmatch(rec.get("cve_id", "")):
        return False
    merged, confirmed = await enrichment.enrich(rec["cve_id"], seed=rec, use_nvd=use_nvd)
    for key in CANONICAL_KEYS:
        if key != "detail_url" and merged.get(key) not in (None, [], ""):
            rec[key] = merged[key]
    rec["confirmed_sources"] = confirmed
    return bool(confirmed)


async def _enrich_batch(records: list[dict], use_nvd: bool = False) -> int:
    """Enrichit une liste de CVE en parallèle par lots. Renvoie le nombre enrichi."""
    enriched = 0
    for i in range(0, len(records), ENRICH_CONCURRENCY):
        chunk = records[i:i + ENRICH_CONCURRENCY]
        results = await asyncio.gather(*[_enrich_record(r, use_nvd) for r in chunk], return_exceptions=True)
        enriched += sum(1 for r in results if r is True)
    return enriched


async def _collect_one(source: dict, logger: RunLogger) -> dict:
    """Collecte UNE source et CLASSE le résultat (SUCCESS/EMPTY/FAILED/TIMEOUT/PARSE_ERROR).

    Le nombre de CVE ne détermine JAMAIS l'échec : une source joignable et analysée mais sans
    nouveauté est un SUCCÈS « EMPTY ». Seuls FAILED/TIMEOUT/PARSE_ERROR (ok=False) sont ré-essayés.
    """
    fn, key = collectors.resolve(source)
    since = source.get("last_sync_at")
    logger.info(f"Source « {source.get('name')} » : démarrage (méthode={key}, url={source.get('url')}).", source)
    try:
        records = await asyncio.wait_for(fn(source, since), timeout=SOURCE_TIMEOUT)
    except asyncio.TimeoutError:
        logger.error(f"Source « {source.get('name')} » : délai dépassé ({key}).", source)
        return {"ok": False, "status": ss.TIMEOUT, "key": key, "records": [], "detected": 0, "error": "timeout"}
    except SourceUnreachable as exc:
        logger.error(f"Source « {source.get('name')} » : injoignable ({key}) : {exc}", source)
        return {"ok": False, "status": ss.FAILED, "key": key, "records": [], "detected": 0, "error": f"unreachable: {str(exc)[:120]}"}
    except SourceParseError as exc:
        logger.error(f"Source « {source.get('name')} » : contenu non analysable ({key}) : {exc}", source)
        return {"ok": False, "status": ss.PARSE_ERROR, "key": key, "records": [], "detected": 0, "error": f"parse_error: {str(exc)[:120]}"}
    except Exception as exc:  # noqa: BLE001 - une source défaillante n'arrête pas la collecte
        logger.error(f"Source « {source.get('name')} » : échec ({key}) : {exc}", source)
        return {"ok": False, "status": ss.FAILED, "key": key, "records": [], "detected": 0, "error": str(exc)[:150]}

    for rec in records:
        add_source(rec, source)
    status = ss.SUCCESS if records else ss.EMPTY  # EMPTY = joignable + analysé, sans nouveauté
    logger.info(f"Source « {source.get('name')} » : {len(records)} CVE ({status}) via {key}.", source)
    return {"ok": True, "status": status, "key": key, "records": records, "detected": len(records), "error": None}


async def mark_interrupted_runs(db) -> int:
    """Clôture les exécutions restées « running » (backend arrêté en pleine collecte).

    Appelé au démarrage : une exécution « running » orpheline ne peut plus se terminer, on la
    marque « interrupted » pour ne jamais laisser d'exécution incomplète en base.
    """
    result = await db.collection_runs.update_many(
        {"status": "running"},
        {"$set": {"status": "interrupted", "finished_at": utcnow(),
                  "error": "Backend arrêté pendant la collecte (exécution interrompue)."}},
    )
    if result.modified_count:
        logging.getLogger("cyberwatch.collection").warning(
            "%d exécution(s) « running » orpheline(s) marquée(s) « interrupted ».", result.modified_count)
    return result.modified_count


async def _consistency_sample(db, sources, results, logger, in_scope: set[str] | None = None) -> None:
    """Vérification de cohérence de fin de cycle (point 9) : chaque CVE que la collecte a RETENUE
    doit exister en base après sauvegarde. Signale toute CVE conservée mais absente (perte).

    `in_scope` : identifiants effectivement conservés après application du périmètre de
    surveillance. Les CVE écartées faute de produit surveillé sont volontairement absentes de
    la base — les compter comme « manquantes » produirait une fausse alerte de perte de données.
    """
    report = []
    total_missing = 0
    for src, res in zip(sources, results):
        cids = [r["cve_id"] for r in res.get("records", [])
                if in_scope is None or r["cve_id"] in in_scope][:300]
        if not cids:
            report.append({"source": src.get("name"), "status": res["status"], "checked": 0, "missing": 0})
            continue
        present = {d["cve_id"] async for d in db.cves.find({"cve_id": {"$in": cids}}, {"cve_id": 1})}
        missing = [c for c in cids if c not in present]
        total_missing += len(missing)
        report.append({"source": src.get("name"), "status": res["status"], "checked": len(cids),
                       "missing": len(missing), "missing_sample": missing[:5]})
        if missing:
            logger.error(f"Cohérence : {len(missing)} CVE collectée(s) MAIS absente(s) en base "
                         f"pour « {src.get('name')} » (ex. {missing[:3]}).")
    await db.consistency_reports.insert_one({"created_at": utcnow(), "total_missing": total_missing,
                                             "sources": report})
    logger.info(f"Vérification de cohérence : {total_missing} CVE manquante(s) sur l'échantillon "
                f"({sum(r['checked'] for r in report)} vérifiée(s)).")


async def run_collection(db, scope: str = "collect-all", source_ids: list | None = None,
                         due=None) -> dict:
    """Exécute la collecte. Si `source_ids` est fourni, ne collecte QUE ces sources (recouvrement
    partiel : on ne re-collecte jamais les sources déjà réussies). `due` = échéance planifiée
    (pour l'état par source).

    Cycle de vie complet : `collection_runs` créé « running » puis « completed »/« failed ».
    Chaque source est suivie INDÉPENDAMMENT (statut, réussite, erreur, tentatives). `last_sync_at`
    n'avance que pour une source dont la collecte a RÉUSSI (SUCCESS ou EMPTY).
    """
    logger = RunLogger(db, scope)
    started = utcnow()
    run_id = (await db.collection_runs.insert_one({
        "scope": scope, "status": "running", "started_at": started, "finished_at": None,
        "sources_total": 0, "sources_ok": 0, "sources_failed": 0, "new_saved": 0,
    })).inserted_id
    logger.info(f"COLLECTE DÉMARRÉE [run {run_id}] (scope={scope}"
                f"{', partiel' if source_ids else ''}).")

    try:
        # Réarme les disjoncteurs : un quota épuisé lors d'une collecte précédente s'est
        # peut-être reconstitué depuis (GitHub se recharge à l'heure).
        enrichment.reset_breakers()
        sources = await get_active_sources(db)
        if source_ids is not None:
            wanted = {str(s) for s in source_ids}
            sources = [s for s in sources if str(s["_id"]) in wanted]
        logger.info(f"{len(sources)} source(s) à collecter"
                    f"{' (recouvrement partiel)' if source_ids else ''}.")

        # 1-4) Parcours EN DEUX VAGUES, chaque source isolée et tolérante aux pannes :
        # les API et flux d'abord, les portails HTML ensuite par petits lots (voir plus haut).
        results = await _collecter_par_vagues(sources, logger)

        # Robustesse : seules FAILED/TIMEOUT/PARSE_ERROR sont ré-essayées UNE fois (jamais EMPTY).
        # La reprise est BORNÉE elle aussi : relancer huit portails d'un coup reproduisait
        # exactement la saturation qui les avait fait échouer, et la 2e tentative échouait
        # pour la même raison que la première.
        retry_idx = [i for i, r in enumerate(results) if r["status"] in ss.RETRYABLE]
        if retry_idx:
            logger.info(f"Nouvelle tentative immédiate pour {len(retry_idx)} source(s) en échec.")
            for i, r in await _collecter_en_lots(sources, retry_idx, logger):
                if r["ok"]:
                    logger.info(f"Source « {sources[i].get('name')} » : succès à la 2e tentative.")
                    results[i] = r

        all_records: list[dict] = []
        per_source = []
        ok_count = fail_count = detected_total = 0
        status_counts: dict[str, int] = {}
        for src, res in zip(sources, results):
            status_counts[res["status"]] = status_counts.get(res["status"], 0) + 1
            per_source.append({"source": src.get("name"), "method": res["key"], "ok": res["ok"],
                               "status": res["status"], "detected": res["detected"], "error": res["error"]})
            # État INDÉPENDANT par source (statut/réussite/erreur/tentatives). L'échéance HONORÉE
            # (last_success_due) n'est marquée qu'APRÈS la sauvegarde (voir plus bas) : sinon un
            # run interrompu avant la sauvegarde marquerait la source « faite » sans avoir persisté
            # ses CVE -> la reprise partielle la sauterait et les CVE du jour seraient perdues.
            await ss.record_result(db, src, res)
            if res["ok"]:
                ok_count += 1
                detected_total += res["detected"]
                all_records.extend(res["records"])
                # 5) last_sync (fenêtre incrémentale) n'avance que sur une collecte RÉUSSIE.
                await db.sources.update_one(
                    {"_id": src["_id"]},
                    # L'ERREUR PRÉCÉDENTE EST EFFACÉE. Elle survivait à la réussite suivante :
                    # une source affichait « succès, 29 CVE » tout en portant encore
                    # « timeout » comme dernière erreur. Qui lit cette fiche conclut à une
                    # panne persistante, et cherche un problème qui n'existe plus.
                    {"$set": {"last_sync_at": utcnow(), "last_sync_status": res["status"],
                              "last_sync_detected": res["detected"]},
                     "$unset": {"last_sync_error": ""}},
                )
            else:
                fail_count += 1
                await db.sources.update_one(
                    {"_id": src["_id"]},
                    {"$set": {"last_sync_status": res["status"], "last_sync_error": res["error"]}},
                )

        # 6-8) Déduplication par identifiant CVE (fusion multi-sources).
        unique = dedup.deduplicate(all_records)

        # PÉRIMÈTRE DE SURVEILLANCE — la collecte ne retient que les CVE concernant les produits
        # de « Produits surveillés ». Le pré-filtre intervient AVANT l'enrichissement : inutile
        # d'interroger NVD/MITRE pour une CVE qui sera écartée. Les CVE au produit encore inconnu
        # sont conservées ici, l'enrichissement permettra de trancher juste après.
        await refresh_scope(db)
        before_scope = len(unique)

        # COMBIEN A-T-ON VU PARAÎTRE AUJOURD'HUI, tous produits confondus ? Compté AVANT le
        # périmètre de surveillance, sinon l'information est perdue.
        #
        # Sans ce chiffre, une journée sans vulnérabilité sur le parc surveillé s'affiche
        # exactement comme une collecte en panne : « aucune CVE ». Le consultant n'a aucun
        # moyen de distinguer « rien ne vous concerne aujourd'hui » — un fait rassurant — de
        # « la collecte n'a rien rapporté » — une alerte. On mesure donc les deux.
        publiees_du_jour = _compter_publiees_du_jour(unique)

        unique = prefilter_scope(unique)
        logger.info(f"Périmètre : {len(unique)}/{before_scope} CVE retenues pour enrichissement "
                    f"({before_scope - len(unique)} hors produits surveillés).")
        logger.info(f"Publications du jour : {publiees_du_jour} vulnérabilité(s) parue(s) "
                    f"aujourd'hui, toutes sources et tous produits confondus.")

        # VEILLE DU JOUR : nouveautés publiées aujourd'hui ET mises à jour des CVE déjà
        # suivies. Les portails d'avis listent en permanence des vulnérabilités anciennes ;
        # sans cette borne, la collecte en rapatriait des centaines et noyait les nouvelles.
        unique, ecartees, sans_date, fenetre = await filtrer_veille_du_jour(db, unique)
        logger.info(f"Fenêtre de veille : {fenetre}.")
        if ecartees:
            logger.info(f"Veille du jour : {len(unique)} CVE conservée(s) (nouveautés du jour "
                        f"+ mises à jour des CVE suivies) — {ecartees} écartée(s), dont "
                        f"{sans_date} sans date de publication.")

        ids = [r["cve_id"] for r in unique]
        existing_ids = {d["cve_id"] async for d in db.cves.find({"cve_id": {"$in": ids}}, {"cve_id": 1})}
        new_recs = [r for r in unique if r["cve_id"] not in existing_ids]
        upd_recs = [r for r in unique if r["cve_id"] in existing_ids]
        logger.info(f"{len(unique)} CVE unique(s) : {len(new_recs)} nouvelle(s), "
                    f"{len(upd_recs)} déjà connue(s) — enrichissement en cours.")

        # 9) Enrichissement (vraies dates + champs canoniques) : toutes les nouvelles, un lot des
        #    existantes. DÉSACTIVABLE (`ENRICHMENT_ENABLED=false`) : la collecte se limite alors
        #    aux sources configurées par l'administrateur, sans aucun appel par identifiant CVE.
        if settings.ENRICHMENT_ENABLED:
            enriched = await _enrich_batch(new_recs[:NEW_ENRICH_MAX])
            upd_recs.sort(key=lambda r: 0 if r.get("cvss_score") is None else 1)
            enriched += await _enrich_batch(upd_recs[:UPDATE_ENRICH_BUDGET])
        else:
            enriched = 0
            logger.info("Enrichissement DÉSACTIVÉ (ENRICHMENT_ENABLED=false) : la collecte "
                        "s'en tient aux sources configurées par l'administrateur.")

        # Classification DÉFINITIVE après enrichissement : les champs produit/CPE remontés par
        # NVD/MITRE permettent de trancher le cas des CVE au produit initialement inconnu.
        # Celles qui ne relèvent d'aucun produit surveillé sont écartées et ne seront PAS stockées.
        unique, ecartees = tag_and_filter(unique)
        logger.info(f"Périmètre : {len(unique)} CVE conservée(s), {ecartees} écartée(s) après "
                    f"enrichissement (aucun produit surveillé correspondant).")

        # AGENT DE TRADUCTION — DÉSACTIVÉ par défaut dans la collecte (voir
        # `TRANSLATION_IN_COLLECTION`). Traduire ici ferait dépendre la durée de la collecte du
        # quota du fournisseur LLM. La traduction se fait donc HORS collecte, via
        # `translate_existing.py`, qui rattrape les CVE sans `translation_status`.
        if settings.TRANSLATION_IN_COLLECTION:
            tr = await translation.translate_batch(unique)
            logger.info(f"Traduction : {tr['translated']} traduite(s), {tr['not_required']} déjà "
                        f"en français, {tr['failed']} en échec, {tr['skipped']} déjà faite(s).")

        # 10) Sauvegarde (insertion des nouvelles, mise à jour des modifiées).
        saved = await storage.save_records(db, unique)
        await update_product_stats(db)

        # APRÈS sauvegarde seulement : on marque l'échéance HONORÉE pour les sources réussies
        # (garantit qu'un run interrompu avant ce point sera intégralement re-collecté au prochain).
        if due is not None:
            ok_ids = [src["_id"] for src, res in zip(sources, results) if res["ok"]]
            if ok_ids:
                await db.sources.update_many({"_id": {"$in": ok_ids}},
                                             {"$set": {"sync_state.last_success_due": due}})
        # Hors périmètre = écartées faute de produit surveillé correspondant. Comptabilisées à
        # part : les confondre avec les doublons rendrait le rapport de collecte illisible.
        out_of_scope = (before_scope - len(ids)) + ecartees
        duplicates_ignored = max(0, detected_total - out_of_scope - saved["inserted"])
        notifications_created = saved["notified_new"] + saved["notified_updates"]

        report = {
            "scope": scope, "status": "completed", "run_id": str(run_id),
            "started_at": started, "finished_at": utcnow(),
            "duration_ms": int((utcnow() - started).total_seconds() * 1000),
            "sources_total": len(sources), "sources_ok": ok_count, "sources_failed": fail_count,
            "status_counts": status_counts,  # {success, empty, failed, timeout, parse_error}
            "cve_detected": detected_total, "cve_unique": len(unique),
            # Vue d'ensemble de la journée : ce qui a paru, et ce qui vous concerne. Les deux
            # chiffres se lisent ensemble — « 36 parues, 0 retenue » est une information
            # complète ; « 0 retenue » seul ressemble à une panne.
            "published_today": publiees_du_jour,
            "new_saved": saved["inserted"], "notified_new": saved["notified_new"],
            "updated": saved["updated"], "important_updates": saved["important_updates"],
            "notifications_created": notifications_created,
            "already_known": saved["already_known"], "sources_added": saved["sources_added"],
            "duplicates_ignored": duplicates_ignored, "out_of_scope": out_of_scope,
            "enriched": enriched,
            "errors": [{"source": p["source"], "error": p["error"]} for p in per_source if p["error"]],
            "per_source": per_source,
            # Sources non honorées (à ré-essayer) — vide = toutes les sources sont OK/EMPTY.
            "failed_source_ids": [str(src["_id"]) for src, res in zip(sources, results)
                                  if res["status"] in ss.RETRYABLE],
        }
        logger.info(
            f"COLLECTE TERMINÉE en {report['duration_ms']}ms : {len(sources)} sources "
            f"({status_counts.get(ss.SUCCESS,0)} succès, {status_counts.get(ss.EMPTY,0)} vides, "
            f"{fail_count} en erreur), {detected_total} détectées, {len(new_recs)} nouvelles, "
            f"{saved['updated']} MAJ, {out_of_scope} hors périmètre, "
            f"{duplicates_ignored} doublons, {notifications_created} notif."
        )
        await logger.flush()
        # Cycle de vie : on MET À JOUR l'entrée créée au début (jamais un doublon).
        await db.collection_runs.update_one({"_id": run_id}, {"$set": report})

        # VEILLE PAR COURRIEL — appelée APRÈS CHAQUE COLLECTE, sans condition.
        #
        # L'envoi était conditionné aux notifications produites par CE passage. Une collecte
        # qui ne détectait rien de neuf n'appelait donc même pas la fonction d'envoi, alors
        # que des fiches non lues attendaient en base depuis les passages précédents : le
        # consultant ne recevait rien et n'avait aucun moyen de distinguer « rien de neuf »
        # d'une panne de la veille. C'est la couche de notification — et elle seule — qui sait
        # ce que le consultant a déjà vu ; c'est donc à elle de décider s'il faut écrire.
        try:
            from app.backend.services import notifications as notif
            await notif.notify_new_cves(db, saved["notified_new"], saved["notified_updates"],
                                        published_today=publiees_du_jour)
        except Exception as exc:  # noqa: BLE001 - l'email ne doit jamais casser la collecte
            logger.error(f"Envoi des notifications email : {exc}")

        # Supervision : recalcul des alertes (sources périmées, trop d'échecs, vides récurrentes).
        try:
            await ss.compute_alerts(db)
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Calcul des alertes : {exc}")
        # Vérification de cohérence légère (échantillon), best-effort.
        try:
            await _consistency_sample(db, sources, results, logger,
                                      in_scope={r["cve_id"] for r in unique})
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Vérification de cohérence : {exc}")
        return report

    except Exception as exc:  # noqa: BLE001 - marque l'exécution « failed », ne laisse rien d'incomplet
        logging.getLogger("cyberwatch.collection").exception("COLLECTE ÉCHOUÉE [run %s] : %s", run_id, exc)
        await db.collection_runs.update_one({"_id": run_id}, {"$set": {
            "status": "failed", "error": str(exc)[:500], "finished_at": utcnow(),
            "duration_ms": int((utcnow() - started).total_seconds() * 1000),
        }})
        try:
            await logger.flush()
        except Exception:  # noqa: BLE001
            pass
        raise


async def run_collection_safe(db, scope: str = "collect-all") -> None:
    """Exécute la collecte globale en arrière-plan ; l'échec est déjà marqué/journalisé dans run_collection."""
    try:
        await run_collection(db, scope)
    except Exception:  # noqa: BLE001 - déjà enregistré « failed » dans collection_runs
        pass


async def collect_single(db, source: dict, scope: str = "collect-one", enrich_budget: int = 25) -> dict:
    """Collecte d'UNE source (bouton « Relancer la collecte »). Même pipeline, une seule source."""
    logger = RunLogger(db, scope)
    started = utcnow()
    res = await _collect_one(source, logger)
    unique = dedup.deduplicate(res["records"])

    # Même périmètre que la collecte globale : pré-filtre, enrichissement, puis classification
    # définitive. Seules les CVE relevant d'un produit surveillé sont conservées.
    await refresh_scope(db)
    detecte = len(unique)
    unique = prefilter_scope(unique)

    unique.sort(key=lambda r: 0 if r.get("cvss_score") is None else 1)
    if settings.ENRICHMENT_ENABLED:
        await _enrich_batch(unique[:enrich_budget])

    unique, hors_perimetre = tag_and_filter(unique)
    if settings.TRANSLATION_IN_COLLECTION:
        await translation.translate_batch(unique)
    saved = await storage.save_records(db, unique)
    await update_product_stats(db)
    await db.sources.update_one({"_id": source["_id"]}, {"$set": {"last_sync_at": utcnow()}})

    report = {
        "ok": res["ok"], "method_used": res["key"], "error": res["error"],
        "detected_count": res["detected"], "collected_count": len(unique),
        "new_saved": saved["inserted"], "updated": saved["updated"],
        "important_updates": saved["important_updates"], "already_known": saved["already_known"],
        # Hors périmètre : CVE détectées mais ne concernant aucun produit surveillé.
        "out_of_scope": (detecte - len(unique)) + hors_perimetre,
        "duplicates_ignored": res["detected"] - saved["inserted"],
        "duration_ms": int((utcnow() - started).total_seconds() * 1000),
    }
    await logger.flush()
    return report
