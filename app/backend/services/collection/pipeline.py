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

from app.backend.core.config import settings
from app.backend.services.collection import (dedup, enrichment, monitored, source_state as ss,
                                             storage, translation)
from app.backend.services.collection.collectors import base as collectors
from app.backend.services.collection.collectors.base import SourceParseError, SourceUnreachable
from app.backend.services.collection.logs import RunLogger
from app.backend.services.collection.schema import CANONICAL_KEYS, CVE_RE, add_source
from app.backend.services.collection.source_manager import get_active_sources
from app.backend.utils import utcnow

NEW_ENRICH_MAX = 400        # borne de sécurité : nb max de NOUVELLES CVE enrichies / exécution
UPDATE_ENRICH_BUDGET = 40   # nb max de CVE EXISTANTES ré-analysées (détection de mise à jour)
SOURCE_TIMEOUT = 150        # marge pour les portails d'avis deux niveaux (crawl + rendus)


ENRICH_CONCURRENCY = 6  # nb de CVE enrichies en parallèle (sources rapides, non limitées en débit)


async def refresh_scope(db) -> None:
    """Recharge le catalogue des produits surveillés depuis la base (produits activés, domaines
    activés). Un produit ajouté ou désactivé dans « Produits surveillés » est ainsi pris en
    compte dès la collecte suivante, sans aucune modification de code."""
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
        hits = monitored.classify_all(rec)   # une CVE peut affecter PLUSIEURS produits
        if not hits:
            continue
        rec["monitored_products"] = list(dict.fromkeys(h[0] for h in hits))
        rec["domains"] = list(dict.fromkeys(h[1] for h in hits if h[1]))
        rec["monitored_product"], rec["domain"] = hits[0]
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

        # 1-4) Parcours PARALLÈLE, chaque source isolée et tolérante aux pannes.
        results = list(await asyncio.gather(*[_collect_one(s, logger) for s in sources]))

        # Robustesse : seules FAILED/TIMEOUT/PARSE_ERROR sont ré-essayées UNE fois (jamais EMPTY).
        retry_idx = [i for i, r in enumerate(results) if r["status"] in ss.RETRYABLE]
        if retry_idx:
            logger.info(f"Nouvelle tentative immédiate pour {len(retry_idx)} source(s) en échec.")
            retried = await asyncio.gather(*[_collect_one(sources[i], logger) for i in retry_idx])
            for k, i in enumerate(retry_idx):
                if retried[k]["ok"]:
                    logger.info(f"Source « {sources[i].get('name')} » : succès à la 2e tentative.")
                    results[i] = retried[k]

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
                    {"$set": {"last_sync_at": utcnow(), "last_sync_status": res["status"],
                              "last_sync_detected": res["detected"]}},
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
        unique = prefilter_scope(unique)
        logger.info(f"Périmètre : {len(unique)}/{before_scope} CVE retenues pour enrichissement "
                    f"({before_scope - len(unique)} hors produits surveillés).")

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

        if notifications_created:
            try:
                from app.backend.services import notifications as notif
                await notif.notify_new_cves(db, saved["notified_new"], saved["notified_updates"])
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
