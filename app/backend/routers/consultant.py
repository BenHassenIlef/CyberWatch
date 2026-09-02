from datetime import datetime, timedelta, timezone

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import (APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response,
                     status)

from app.backend.db.mongodb import get_database
from app.backend.dependencies.auth import require_role
from app.backend.schemas.schedule import CollectionScheduleUpdate
from app.backend.services.audit import log_action
from app.backend.services.collection import (advisory_bulletin, bulletin_pdf, enrichment,
                                             pipeline, product_bulletin, provenance,
                                             translation)
from app.backend.services.collection.schema import CANONICAL_KEYS, CVE_RE, LIST_FIELDS
from app.backend.utils import serialize_doc, utcnow

router = APIRouter(prefix="/consultant", tags=["consultant"], dependencies=[Depends(require_role("consultant"))])

DEFAULT_SCHEDULE = {"frequency": "daily", "hour": 8, "minute": 0}


async def _monitored_names(db) -> list[str]:
    """Noms des produits ACTUELLEMENT surveillés (activés, dans un domaine activé). Sert à ne
    proposer que les produits EXISTANTS — un produit supprimé, désactivé ou renommé disparaît du
    filtre même si d'anciennes CVE portent encore son étiquette."""
    disabled_domains = [d["name"] async for d in db.domains.find({"enabled": False}, {"name": 1})]
    q: dict = {"enabled": {"$ne": False}}
    if disabled_domains:
        q["domain"] = {"$nin": disabled_domains}
    names = {d["name"] async for d in db.monitored_products.find(q, {"name": 1}) if d.get("name")}
    return sorted(names)


def _object_id(raw_id: str) -> ObjectId:
    try:
        return ObjectId(raw_id)
    except InvalidId:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Identifiant invalide.")


def _cve_out(cve: dict, sources: dict) -> dict:
    # LOCALISATION : point de passage UNIQUE des CVE vers l'interface (liste et détail). Les
    # champs traduits par l'agent remplacent l'original ; l'original reste exposé sous
    # `*_original`. Sans traduction disponible, le texte d'origine est servi tel quel — un
    # champ n'est donc jamais vide à cause d'un échec de traduction.
    doc = serialize_doc(translation.apply_localization(cve))
    source = sources.get(cve.get("source_id"))
    doc["source"] = source["name"] if source else (doc.get("source_name") or "—")
    # Rendre la liste multi-sources sérialisable (ObjectId -> str) — points 7 & 8.
    doc["sources"] = [
        {"name": s.get("name"), "url": s.get("url"), "source_id": str(s.get("source_id"))}
        for s in (cve.get("sources") or [])
    ]
    return doc


# Projection LISTE : uniquement les champs affichés dans le tableau (documents réduits = rapide).
_LIST_PROJECTION = {
    "cve_id": 1, "title": 1, "product": 1, "affected_products": 1, "vuln_type": 1, "category": 1,
    # EDITEUR — « C# Driver » ne dit pas de quel logiciel il s'agit ; « MongoDB / C# Driver »
    # le dit. Le champ est renseigne sur 91 % des fiches ; les 9 % restants s'affichent en
    # « Non identifie » plutot qu'en tiret muet, qui laisserait croire a un oubli.
    "vendor": 1,
    "cvss_score": 1, "severity": 1, "published_at": 1, "updated_at": 1, "collected_at": 1,
    # Dernier passage de collecte : distingue une fiche revue aujourd'hui d'une fiche
    # simplement découverte il y a des mois.
    "last_collected": 1,
    "is_new": 1, "source_id": 1, "source_name": 1, "sources": 1,
    # Titre traduit (affiché à la place de l'original quand il existe) + état de traduction.
    "title_fr": 1, "translation_status": 1,
    # Synchronisation incrémentale (badge « Mise à jour », complétude, temps relatif).
    "is_updated": 1, "update_unread": 1, "information_completeness": 1, "first_published": 1,
    "sync_status": 1, "change_summary": 1,
    # DATE DE DÉTECTION du changement par l'application — à ne pas confondre avec
    # `updated_at`, qui est la date de révision annoncée par la SOURCE.
    #
    # L'onglet « Mises à jour aujourd'hui » filtre sur ce champ, mais affichait `updated_at` :
    # une CVE détectée comme modifiée aujourd'hui apparaissait avec la date « 13/08 » que
    # l'éditeur avait apposée à sa révision. La liste semblait alors montrer de vieilles
    # mises à jour, alors qu'elle montrait exactement ce qu'on lui demandait.
    "last_important_update": 1,
}


def _parse_day(s: str | None, end: bool = False):
    """« YYYY-MM-DD » -> datetime UTC NAÏF (début, ou fin de journée). None si invalide.

    La journée est celle du fuseau de l'APPLICATION, converti dans le format stocké en base —
    exactement la convention de `_day_bounds`. Sans cette conversion, le jour sélectionné
    dans l'interface commençait à minuit UTC alors que « aujourd'hui » commence à minuit
    local : deux définitions du même jour cohabitaient, décalées de l'offset du fuseau, et
    une CVE publiée en fin de soirée basculait dans la mauvaise journée selon le filtre
    employé.
    """
    if not s:
        return None
    from app.backend.services.collection.scheduler import _tz

    try:
        jour = datetime.strptime(s[:10], "%Y-%m-%d")
    except ValueError:
        return None
    minuit_local = jour.replace(tzinfo=_tz())
    debut = minuit_local.astimezone(timezone.utc).replace(tzinfo=None)
    # Fin de journée = la seconde précédant le minuit local SUIVANT (bornes incluses côté
    # appelant), ce qui couvre la journée entière quel que soit le décalage.
    return (debut + timedelta(days=1) - timedelta(seconds=1)) if end else debut


@router.get("/cves")
async def list_cves(
    q: str | None = Query(None),
    severity: str | None = Query(None),
    product: str | None = Query(None),
    category: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    only_new: bool = Query(False),
    collected_today: bool = Query(False),  # vue « Collectées aujourd'hui » (date de collecte)
    updated_today: bool = Query(False),    # vue « Mises à jour aujourd'hui » (fiches déjà suivies)
    published_today: bool = Query(False),  # vue « Publiées aujourd'hui » (date OFFICIELLE)
    sort_by: str = Query("date"),  # "date" | "cvss" | "collected"
    order: str = Query("desc"),    # "desc" | "asc"
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    db = get_database()
    # Les enregistrements RÉVOQUÉS par le programme CVE (« DO NOT USE THIS CVE RECORD »)
    # ne sont pas des vulnérabilités : les compter et les afficher parmi les autres serait
    # une information fausse. Ils restent en base — la trace du retrait a sa valeur — mais
    # sortent des listes de veille.
    query: dict = {"cve_status": {"$ne": "rejected"}}
    if severity:
        query["severity"] = severity
    if product:
        # Le menu propose des PRODUITS SURVEILLÉS ; on accepte aussi l'ancien champ `affected_products`
        # pour rester correct sur les CVE collectées avant la mise en place du périmètre.
        # `$and` (et non `$or` à la racine) : le champ `$or` est déjà pris par la recherche `q`.
        query["$and"] = [{"$or": [{"monitored_products": product}, {"affected_products": product}]}]
    if category:
        query["category"] = category
    if only_new:
        query["is_new"] = True
    if collected_today:
        # COLLECTÉES AUJOURD'HUI = ENTRÉES EN BASE AUJOURD'HUI. Rien d'autre.
        #
        # Cette vue mêlait auparavant deux choses : les fiches découvertes du jour ET les
        # fiches anciennes dont les données avaient changé. Le résultat affichait « Collectée
        # le 12/08 » dans un onglet intitulé « Collectées aujourd'hui » — un onglet qui
        # contredit sa propre colonne ne peut inspirer aucune confiance.
        #
        # Ce mélange se justifiait tant qu'aucune vue ne montrait les mises à jour. L'onglet
        # « Mises à jour aujourd'hui » existe désormais et les présente correctement : les
        # deux vues sont maintenant DISJOINTES, et chacune tient exactement la promesse de
        # son intitulé.
        #
        # `collected_at` — et non `last_collected` — est la date de PREMIÈRE découverte.
        # Filtrer sur le dernier passage remplirait la liste de centaines de CVE de 2019
        # simplement revues sans avoir bougé.
        debut, fin = _day_bounds()
        query["collected_at"] = {"$gte": debut, "$lt": fin}
        sort_by = "collected"
    if updated_today:
        # MISES À JOUR DU JOUR — fiches connues DEPUIS PLUS LONGTEMPS dont les données ont
        # changé aujourd'hui : score réévalué, correctif publié, référence ajoutée.
        #
        # Distinct de « Collectées aujourd'hui », qui mêle nouveautés et mises à jour : un
        # consultant qui a déjà traité la veille du matin veut savoir ce qui a BOUGÉ sur des
        # vulnérabilités qu'il connaît, sans re-parcourir les nouvelles.
        debut, _fin = _day_bounds()
        query["last_important_update"] = {"$gte": debut}
        # DÉTECTÉE AVANT AUJOURD'HUI : c'est ce qui distingue une mise à jour d'une
        # nouveauté. Une fiche découverte ce matin et complétée dans la foulée n'est pas
        # une « mise à jour » pour le consultant — elle est simplement nouvelle.
        query["collected_at"] = {"$lt": debut}
        sort_by = "collected"

    if published_today:
        # Vue « CVE PUBLIÉES aujourd'hui » : date OFFICIELLE de publication de la CVE, jamais la
        # date de collecte ni de mise à jour. Filtrage poussé côté MongoDB (index published_at).
        query.update(published_today_filter())
        sort_by = "date"
    # Filtre de date (published_at) poussé CÔTÉ MONGODB.
    if date_from or date_to:
        rng = {}
        if (d := _parse_day(date_from)) is not None:
            rng["$gte"] = d
        if (d := _parse_day(date_to, end=True)) is not None:
            rng["$lte"] = d
        if rng:
            query["published_at"] = rng
    if q:
        query["$or"] = [
            {"cve_id": {"$regex": q, "$options": "i"}},
            {"title": {"$regex": q, "$options": "i"}},
            {"product": {"$regex": q, "$options": "i"}},
            {"affected_products": {"$regex": q, "$options": "i"}},
        ]

    # PAGINATION CÔTÉ MONGODB : tri + skip + limit + projection. On ne charge QUE la page demandée
    # (~20 documents réduits), plus toute la collection -> affichage quasi instantané.
    # Tri « collecte » : sur le DERNIER passage, pour que les mises a jour du jour remontent
    # en tete au meme titre que les nouveautes.
    sort_field = {"cvss": "cvss_score", "collected": "last_collected"}.get(sort_by, "published_at")
    direction = 1 if order == "asc" else -1
    total = await db.cves.count_documents(query)
    page = await (
        db.cves.find(query, _LIST_PROJECTION)
        .sort(sort_field, direction).skip(skip).limit(limit).to_list(limit)
    )

    source_ids = [c["source_id"] for c in page if c.get("source_id")]
    sources = {s["_id"]: s async for s in db.sources.find({"_id": {"$in": source_ids}})}
    return {"total": total, "items": [_cve_out(c, sources) for c in page]}


def _day_bounds(offset_days: int = 0) -> tuple[datetime, datetime]:
    """Bornes [minuit, minuit+24 h[ d'une journée, en UTC NAÏF — le format stocké en base.

    « Aujourd'hui » se définit dans le fuseau de l'APPLICATION (`SCHEDULER_TIMEZONE`, sinon
    fuseau local du serveur), et non en UTC : à UTC+1, la journée du 14/08 commence le 13/08
    à 23:00 UTC. Comparer bêtement des dates UTC décalerait la frontière d'une heure et
    ferait basculer les CVE publiées en fin de soirée dans le mauvais jour.

    Le même fuseau que le planificateur est utilisé, pour que « aujourd'hui » désigne la même
    journée partout dans l'application.
    """
    from app.backend.services.collection.scheduler import _tz

    midnight = (datetime.now(_tz()).replace(hour=0, minute=0, second=0, microsecond=0)
                + timedelta(days=offset_days))
    start = midnight.astimezone(timezone.utc).replace(tzinfo=None)
    return start, start + timedelta(days=1)


def _start_of_today_utc() -> datetime:
    """Début de la journée courante en UTC naïf (compat. — voir `_day_bounds`)."""
    return _day_bounds()[0]


def published_today_filter() -> dict:
    """Critère MongoDB « CVE PUBLIÉE aujourd'hui », sur la date OFFICIELLE de publication.

    Volontairement basé sur `published_at` (date de publication de la CVE par sa source), et
    JAMAIS sur `collected_at` / `updated_at` / `last_collected`, qui décrivent l'activité de
    CyberWatch AI. Une CVE publiée hier et mise à jour aujourd'hui n'est donc PAS retenue.

    Les CVE sans date de publication (578 en base) sont exclues : on ne peut pas affirmer
    qu'elles ont été publiées aujourd'hui.
    """
    start, end = _day_bounds()
    return {"published_at": {"$gte": start, "$lt": end}}


@router.get("/cve-stats")
async def cve_stats():
    """Compteurs pour les cartes de synthèse du consultant.

    Deux notions distinctes (non ambiguës) :
      - `new` / `published_recent` : CVE réellement PUBLIÉES récemment (date officielle).
      - `collected_today` : CVE COLLECTÉES aujourd'hui (activité de collecte du jour), même si
        leur date de publication est ancienne.
    """
    db = get_database()
    total = await db.cves.count_documents({})
    new = await db.cves.count_documents({"is_new": True})
    debut, fin = _day_bounds()
    # MÊME DÉFINITION QUE LA VUE : entrées en base aujourd'hui. Un compteur qui ne compte pas
    # ce que la liste affiche envoie le consultant chercher des lignes qui n'existent pas.
    collected_today = await db.cves.count_documents(
        {"collected_at": {"$gte": debut, "$lt": fin}})
    # Fiches ANCIENNES dont un changement a été détecté aujourd'hui — l'onglet « Mises à jour
    # aujourd'hui ». Distinct du précédent : les deux ensembles ne se recouvrent jamais.
    updated_today = await db.cves.count_documents(
        {"last_important_update": {"$gte": debut}, "collected_at": {"$lt": debut}})
    # Compteur BORNÉ à la journée : sans borne haute, une CVE datée du futur (erreur de source)
    # serait comptée comme « publiée aujourd'hui ».
    published_today = await db.cves.count_documents(published_today_filter())
    by_severity = {}
    for level in ("critical", "high", "medium", "low"):
        by_severity[level] = await db.cves.count_documents({"severity": level})
    return {"total": total, "new": new, "collected_today": collected_today,
            "updated_today": updated_today,
            "published_today": published_today, **by_severity}


@router.get("/cve-facets")
async def cve_facets():
    """Facettes de filtrage de la page CVE. Le menu « produit » liste TOUS les produits SURVEILLÉS
    existants (activés, dans un domaine activé) — jamais la liste brute des produits affectés
    remontés par les sources.

    On n'exige PAS qu'un produit ait déjà des CVE : un produit qui vient d'être ajouté est
    filtrable IMMÉDIATEMENT, sans attendre la collecte qui lui rattachera ses premières CVE. Le
    filtre renvoie alors 0 résultat, ce qui est l'information juste (« rien de connu à ce jour »).
    """
    db = get_database()
    categories = await db.cves.distinct("category")
    return {
        "products": await _monitored_names(db),
        "categories": sorted(c for c in categories if c),
    }


def _is_incomplete(cve: dict) -> bool:
    """La fiche manque-t-elle d'informations importantes (à agréger depuis d'autres sources) ?"""
    return (
        cve.get("cvss_score") is None
        or not cve.get("description")
        or not cve.get("published_at")
        or not cve.get("cwe")
        or len(cve.get("references") or []) < 2
    )


async def _aggregate_on_demand(db, oid, cve: dict) -> dict:
    """Agrégation multi-sources à l'ouverture d'une CVE : si la fiche est incomplète, on
    interroge toutes les sources officielles (NVD, MSRC, MITRE, Red Hat, OSV, GitHub) avec
    l'identifiant CVE comme clé, on fusionne par priorité et on complète la base."""
    # Les entrées « avis CERT seul » (identifiant non-CVE) ne sont pas interrogeables sur NVD/MITRE.
    if not CVE_RE.fullmatch(cve.get("cve_id", "")):
        return cve
    last = cve.get("enriched_at")
    recent = isinstance(last, datetime) and (utcnow().replace(tzinfo=None) - last.replace(tzinfo=None)).days < 1
    # On (ré)interroge les sources officielles pour COMPLÉTER la fiche ET pour LISTER toutes les
    # sources qui confirment la CVE (NVD, MITRE, CISA, GitHub, OSV, Red Hat…). On ne saute que si
    # c'est déjà fait récemment ET que la confirmation croisée est déjà renseignée.
    if recent and cve.get("confirmed_sources"):
        return cve
    if not _is_incomplete(cve) and cve.get("confirmed_sources"):
        return cve

    merged, confirmed = await enrichment.enrich(cve["cve_id"], seed=cve, use_nvd=True)

    set_fields: dict = {"enriched_at": utcnow()}
    # Les valeurs viennent de sources d'AUTORITÉ interrogées par identifiant CVE : elles sont
    # donc écrites AVEC leur provenance, et soumises aux mêmes garde-fous que la collecte.
    # Sans cela, ce chemin contournerait la protection anti-contamination de `storage`.
    source = confirmed[0] if confirmed else "enrichment"
    travail = {"provenance": dict(cve.get("provenance") or {})}
    for key in CANONICAL_KEYS:
        if key == "detail_url":
            continue
        if key in LIST_FIELDS:
            union = list(dict.fromkeys((cve.get(key) or []) + (merged.get(key) or [])))
            if len(union) != len(cve.get(key) or []):
                set_fields[key] = union
            continue
        valeur = merged.get(key)
        if valeur in (None, "", []):
            continue
        # Ne jamais dégrader le barème CVSS déjà en base (4.0 -> 3.1 serait un recul).
        if key in ("cvss_score", "cvss_vector") and not provenance.allows_cvss_replacement(
                cve.get("cvss_vector"), merged.get("cvss_vector")):
            continue
        champ_prov = "cve_published_at" if key == "published_at" else key
        if provenance.apply(travail, champ_prov, valeur, source, merged.get("detail_url"),
                            provenance.VERIFIED):
            set_fields[key] = valeur
    if travail["provenance"] != (cve.get("provenance") or {}):
        set_fields["provenance"] = travail["provenance"]
        set_fields["validation_status"] = provenance.validation_status(
            {**cve, **set_fields, "provenance": travail["provenance"]})
    if confirmed:
        conf = list(dict.fromkeys((cve.get("confirmed_sources") or []) + confirmed))
        set_fields["confirmed_sources"] = conf

    await db.cves.update_one({"_id": oid}, {"$set": set_fields})
    cve.update(set_fields)
    return cve


@router.get("/cves/{cve_id}")
async def get_cve(cve_id: str):
    db = get_database()
    oid = _object_id(cve_id)
    cve = await db.cves.find_one({"_id": oid})
    if cve is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CVE introuvable.")

    # Agrégation multi-sources à la demande (complète les champs manquants).
    try:
        cve = await _aggregate_on_demand(db, oid, cve)
    except Exception:  # noqa: BLE001 - l'agrégation ne doit jamais casser l'affichage
        pass

    # Consulter une CVE la marque comme « lue » : ni « Nouvelle » ni « Mise à jour ».
    if cve.get("is_new") or cve.get("update_unread"):
        await db.cves.update_one({"_id": oid}, {"$set": {"is_new": False, "update_unread": False}})
        cve["is_new"] = False
        cve["update_unread"] = False

    source = await db.sources.find_one({"_id": cve.get("source_id")}) if cve.get("source_id") else None
    sources = {source["_id"]: source} if source else {}
    return _cve_out(cve, sources)


# ---------- Bulletin de sécurité normalisé (moteur générique multi-sources) ----------

_BULLETIN_TTL_HOURS = 24


async def _cached_bulletin(db, url: str, seed: dict | None, refresh: bool) -> dict:
    """Construit le bulletin (Phases 1→4) avec cache 24 h dans `bulletins`.

    Un bulletin mis en cache AVANT un changement de modèle est reconstruit d'office : sans ce
    contrôle de version, les anciens documents continueraient d'exposer les champs retirés et
    une « source officielle » calculée selon l'ancienne règle.
    """
    # CLÉ DE CACHE : l'URL **et** la CVE.
    #
    # Une même page de collecte couvre souvent des centaines de vulnérabilités — un portail
    # éditeur, un bulletin d'autorité, une revue de presse. Indexé sur la seule URL, le cache
    # rendait à TOUTES ces fiches le bulletin de la première consultée : mauvais éditeur,
    # mauvaise source officielle, mauvaise remédiation. Le bulletin d'une fiche est propre à
    # sa CVE ; sa clé doit l'être aussi. Les bulletins « par URL » (sans fiche) gardent la
    # leur, inchangée.
    cle = f"{url}#{seed['cve_id']}" if seed and seed.get("cve_id") else url

    cached = await db.bulletins.find_one({"_id": cle})
    if cached and not refresh:
        built = cached.get("built_at")
        fresh = isinstance(built, datetime) and \
            (utcnow().replace(tzinfo=None) - built.replace(tzinfo=None)).total_seconds() < _BULLETIN_TTL_HOURS * 3600
        current = cached.get("schema_version") == advisory_bulletin.BULLETIN_SCHEMA_VERSION
        if fresh and current:
            return serialize_doc(cached)
    bulletin = await advisory_bulletin.build_bulletin(url, seed=seed, db=db)
    # REMPLACEMENT complet (et non « $set ») : un « $set » conserverait les clés d'un modèle
    # antérieur — les champs retirés du bulletin réapparaîtraient depuis le cache.
    await db.bulletins.replace_one({"_id": cle}, {**bulletin, "_id": cle}, upsert=True)
    return serialize_doc({**bulletin, "_id": cle})


@router.get("/bulletin")
async def bulletin_from_url(url: str = Query(..., description="URL de la page d'avis"),
                            refresh: bool = Query(False)):
    """Génère un bulletin normalisé depuis N'IMPORTE QUELLE page d'avis (moteur générique)."""
    db = get_database()
    return await _cached_bulletin(db, url, seed=None, refresh=refresh)


@router.get("/cves/{cve_id}/community-discussions")
async def community_discussions(cve_id: str, refresh: bool = Query(False)):
    """DISCUSSIONS PUBLIQUES mentionnant cette CVE — couche d'enrichissement, jamais officielle.

    Ces échanges n'alimentent AUCUN champ de la fiche : ni la solution, ni les produits
    affectés, ni les références, ni le score. Ils sont lus depuis une collection distincte et
    renvoyés séparément, pour que rien ne puisse se confondre avec un avis d'éditeur.

    `refresh` relance la recherche auprès des communautés ; sinon on sert ce qui est déjà
    vérifié en base, sans dépendre de la disponibilité des sources externes.
    """
    from app.backend.services.community import discussions as dc

    db = get_database()
    if not CVE_RE.fullmatch(cve_id.upper()):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Identifiant CVE invalide.")

    etats_sources: list[dict] = []
    existantes = await dc.lire(db, cve_id)
    if refresh or not existantes:
        trouvees, etats_sources = await dc.rechercher(cve_id)
        if trouvees:
            await dc.enregistrer(db, trouvees)
        existantes = await dc.lire(db, cve_id)

    resume, origine = await dc.resume_communautaire(existantes)
    return {
        "cve_id": cve_id.upper(),
        "community_summary": resume,
        "summary_origin": origine,
        "discussions": [serialize_doc(d) for d in existantes],
        # ÉTAT DE CHAQUE SOURCE, jamais réduit à un booléen.
        #
        # « aucun résultat », « indisponible » et « non configurée » sont trois situations
        # distinctes : la première est un fait sur la communauté, la deuxième une panne
        # passagère, la troisième une action attendue de l'administrateur. Les confondre
        # ferait croire au consultant que personne n'a discuté de la vulnérabilité.
        #
        # Aucun identifiant ni jeton d'accès ne transite ici : uniquement un statut et un
        # motif rédigé pour un lecteur humain.
        "sources": etats_sources,
        "disclaimer": ("Ces informations proviennent de discussions publiques et ne "
                       "remplacent pas les recommandations officielles de l'éditeur."),
    }


@router.get("/cves/{cve_id}/bulletin")
async def bulletin_from_cve(cve_id: str, refresh: bool = Query(False)):
    """Bulletin normalisé construit à partir de la page d'avis où la CVE a été COLLECTÉE.

    Cette page est la source de COLLECTE ; la source officielle est déterminée séparément,
    à partir des références de l'éditeur (voir `advisory_bulletin.official_source`).
    """
    db = get_database()
    oid = _object_id(cve_id)
    cve = await db.cves.find_one({"_id": oid})
    if cve is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CVE introuvable.")
    url = cve.get("detail_url")
    if not url:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cette CVE n'a pas de page d'avis d'origine.")
    return await _cached_bulletin(db, url, seed=cve, refresh=refresh)


@router.post("/cves/{cve_id}/deep-synthesis")
async def deep_synthesis(cve_id: str, refresh: bool = Query(False)):
    """Lit les pages sources de la CVE et produit un résumé approfondi + la meilleure solution.

    Opération COÛTEUSE (jusqu'à 6 pages + 1 appel LLM) : déclenchée à la demande, mise en cache
    14 jours dans la CVE. `refresh=true` force un recalcul.
    """
    from app.backend.services.assistant import deep_synthesis as ds

    db = get_database()
    cve = await db.cves.find_one({"_id": _object_id(cve_id)})
    if cve is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CVE introuvable.")
    return serialize_doc({"v": await ds.synthesize(db, cve, refresh=refresh)})["v"]


def _pdf_response(pdf: bytes | None, filename: str) -> Response:
    """Réponse de TÉLÉCHARGEMENT d'un PDF (`attachment` -> enregistrement direct, jamais
    d'ouverture dans une visionneuse ni de boîte d'impression)."""
    if not pdf:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Génération du PDF indisponible : le moteur de rendu (Chromium/Playwright) n'a pas "
            "pu être démarré. Exécutez « python -m playwright install chromium ».")
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/cves/{cve_id}/bulletin.pdf")
async def bulletin_pdf_from_cve(cve_id: str, refresh: bool = Query(False)):
    """Export PDF RÉEL du bulletin d'une CVE (aucune boîte d'impression navigateur)."""
    bulletin = await bulletin_from_cve(cve_id, refresh=refresh)
    return _pdf_response(await bulletin_pdf.build_pdf(bulletin),
                         bulletin_pdf.filename_for(bulletin))


# ---------- Tableau de bord de SYNCHRONISATION (moteur type OpenCVE) ----------

@router.get("/sync-stats")
async def sync_stats():
    """Statistiques du moteur de synchro : nouvelles / mises à jour / enrichies / inchangées,
    complétude moyenne, échecs, dernière & prochaine synchro, durée."""
    db = get_database()
    by_status = {}
    for st in ("new", "enriched", "updated", "unchanged"):
        by_status[st] = await db.cves.count_documents({"sync_status": st})
    agg = [a async for a in db.cves.aggregate(
        [{"$group": {"_id": None, "avg": {"$avg": "$information_completeness"}}}])]
    avg_completeness = round(agg[0]["avg"]) if agg and agg[0].get("avg") is not None else 0
    failed = await db.sources.count_documents(
        {"sync_state.status": {"$in": ["failed", "timeout", "parse_error"]}})
    from app.backend.services.collection import scheduler
    sched = await scheduler.status(db)
    last_run = await db.collection_runs.find_one({"status": "completed"}, sort=[("finished_at", -1)])
    return {
        "by_status": by_status,
        "avg_completeness": avg_completeness,
        "failed_syncs": failed,
        "last_sync": serialize_doc({"v": sched.get("last_run")})["v"] if sched.get("last_run") else None,
        "next_sync": sched.get("next_run"),
        "collecting": sched.get("collecting"),
        "last_run": {
            "finished_at": serialize_doc({"v": (last_run or {}).get("finished_at")})["v"],
            "duration_ms": (last_run or {}).get("duration_ms"),
            "new_saved": (last_run or {}).get("new_saved"),
            "updated": (last_run or {}).get("updated"),
            "notifications_created": (last_run or {}).get("notifications_created"),
        } if last_run else None,
    }


# ---------- Bulletins GROUPÉS PAR PRODUIT / ÉDITEUR (vue CERT) ----------

def _bornes_periode(start: str | None, end: str | None):
    """Convertit les bornes reçues (AAAA-MM-JJ) en dates, ou lève une erreur explicite.

    Le filtrage a lieu EN BASE, pas à l'affichage : renvoyer toutes les CVE et les masquer
    côté navigateur donnerait des compteurs faux — un produit annoncerait quinze
    vulnérabilités là où la période n'en contient que trois.
    """
    def _lire(valeur, nom):
        if not valeur:
            return None
        try:
            return datetime.strptime(valeur[:10], "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                f"Date « {nom} » invalide : format attendu AAAA-MM-JJ.")

    debut, fin = _lire(start, "start"), _lire(end, "end")
    if debut and fin and debut > fin:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "La date de début est postérieure à la date de fin.")
    return debut, fin


@router.get("/product-bulletins")
async def product_bulletins(days: int = Query(45, ge=1, le=365), severity: str | None = Query(None),
                            q: str | None = Query(None), skip: int = Query(0, ge=0),
                            limit: int = Query(24, ge=1, le=100),
                            start: str | None = Query(None, description="Début de période (AAAA-MM-JJ)"),
                            end: str | None = Query(None, description="Fin de période (AAAA-MM-JJ)")):
    """Bulletins groupés PAR PRODUIT SURVEILLÉ sur la période demandée.

    `start`/`end` définissent la période ; à défaut, `days` conserve l'ancienne fenêtre
    glissante, de sorte qu'un appel existant continue de fonctionner à l'identique.
    """
    db = get_database()
    debut, fin = _bornes_periode(start, end)
    return await product_bulletin.list_product_bulletins(db, days=days, severity=severity,
                                                         q=q, skip=skip, limit=limit,
                                                         debut=debut, fin=fin)


@router.get("/product-bulletins/{vendor_key}")
async def product_bulletin_detail(vendor_key: str, days: int = Query(45, ge=1, le=365),
                                  start: str | None = Query(None), end: str | None = Query(None)):
    """Bulletin complet d'un produit surveillé : UNE LIGNE PAR CVE, chacune avec ses données."""
    db = get_database()
    debut, fin = _bornes_periode(start, end)
    bulletin = await product_bulletin.build_product_bulletin(db, vendor_key, days=days,
                                                             debut=debut, fin=fin)
    if not bulletin:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "Aucune vulnérabilité pour ce produit sur la période choisie.")
    return serialize_doc(bulletin)


@router.get("/product-bulletins/{vendor_key}/details.pdf")
async def product_bulletin_details_pdf(vendor_key: str, days: int = Query(45, ge=1, le=365),
                                       start: str | None = Query(None),
                                       end: str | None = Query(None)):
    """Export PDF du SEUL détail des vulnérabilités — une ligne par CVE.

    Document distinct du bulletin de synthèse : les deux répondent à des usages différents
    (transmettre une alerte / travailler ligne à ligne), et un consultant veut souvent l'un
    sans l'autre.
    """
    bulletin = await product_bulletin_detail(vendor_key, days=days, start=start, end=end)
    if start and end:
        bulletin["periode_libelle"] = f"période du {start} au {end}"
    return _pdf_response(await bulletin_pdf.build_details_pdf(bulletin),
                         bulletin_pdf.details_filename_for(bulletin))


@router.get("/product-bulletins/{vendor_key}/bulletin.pdf")
async def product_bulletin_pdf(vendor_key: str, days: int = Query(45, ge=1, le=365),
                               start: str | None = Query(None), end: str | None = Query(None)):
    """Export PDF RÉEL du bulletin groupé d'un produit (plusieurs CVE dans un seul document)."""
    bulletin = await product_bulletin_detail(vendor_key, days=days, start=start, end=end)
    return _pdf_response(await bulletin_pdf.build_pdf(bulletin),
                         bulletin_pdf.filename_for(bulletin))


# ---------- Notifications (nouvelles CVE détectées par la collecte) ----------

_UNREAD_FILTER = {"$or": [{"is_new": True}, {"update_unread": True}]}


@router.get("/notifications/email-status")
async def email_status(user: dict = Depends(require_role("consultant"))):
    """La veille par courriel peut-elle réellement partir, et vers quelle adresse ?

    Un consultant qui ne reçoit rien n'a aujourd'hui aucun moyen de savoir pourquoi : le
    diagnostic n'existe que dans les journaux du serveur, qu'il ne lit pas. Il en conclut que
    l'application est en panne, alors qu'il manque le plus souvent une seule ligne de
    configuration — et personne ne s'en aperçoit tant que rien ne l'affiche.

    Ce point d'entrée expose l'état RÉEL, sans jamais divulguer de secret : on dit qu'un mot
    de passe manque, jamais sa valeur.
    """
    from app.backend.core.config import settings
    from app.backend.services import notifications as notif

    # LA MÊME SOURCE QUE L'ENVOI. Cet écran recomposait la liste de son côté : le jour où
    # l'envoi s'est restreint, il aurait continué d'annoncer « vous recevrez la veille » à
    # des consultants qui ne reçoivent plus rien. Un diagnostic qui diverge de ce qu'il
    # diagnostique est pire que pas de diagnostic — on cesse de chercher ailleurs.
    prevus = await notif._liste_de_diffusion(get_database())
    adresses = {(u.get("email") or "").lower() for u in prevus if u.get("email")}
    mienne = (user.get("email") or "").lower()

    # Cause BLOQUANTE, s'il y en a une. L'ordre suit celui des vérifications de l'envoi.
    if not settings.SMTP_HOST:
        cause, detail = "non_configure", "Aucun serveur d'envoi (SMTP_HOST) n'est renseigné."
    elif not settings.EMAIL_NOTIFICATIONS_ENABLED:
        cause, detail = "desactive", "Les notifications par courriel sont désactivées."
    elif not notif._serveur_local(settings.SMTP_HOST) and not settings.SMTP_USER:
        cause, detail = "identifiant_manquant", (
            f"Le serveur « {settings.SMTP_HOST} » exige une authentification, mais aucun "
            "identifiant (SMTP_USER) n'est renseigné.")
    elif not notif._serveur_local(settings.SMTP_HOST) and not settings.SMTP_PASSWORD:
        cause, detail = "mot_de_passe_manquant", (
            f"Le serveur « {settings.SMTP_HOST} » exige une authentification, mais le mot de "
            "passe (SMTP_PASSWORD) n'est pas renseigné. Aucun message ne peut donc être remis.")
    elif not adresses:
        cause, detail = "aucun_destinataire", (
            "Aucun compte consultant ne porte d'adresse de courriel.")
    else:
        cause, detail = None, None

    return {
        "operationnel": cause is None,
        "cause": cause,
        "detail": detail,
        "serveur": settings.SMTP_HOST or None,
        "expediteur": settings.SMTP_FROM or None,
        "destinataires": len(adresses),
        # « Suis-je moi-même destinataire ? » est la question que se pose le consultant.
        "je_suis_destinataire": bool(mienne and mienne in adresses),
        "mon_adresse": user.get("email"),
    }


@router.post("/notifications/email-test")
async def email_test(user: dict = Depends(require_role("consultant"))):
    """Envoie un message d'essai à SA PROPRE adresse et rapporte ce qui s'est passé.

    Valider une configuration ne devrait pas demander d'attendre la collecte du lendemain.
    Sans cet essai, un administrateur colle un mot de passe puis attend — et si rien n'arrive,
    il ignore si la faute revient au mot de passe, au compte ou au réseau.

    L'adresse est celle du COMPTE CONNECTÉ, jamais un paramètre : un point d'entrée qui
    accepterait une adresse arbitraire deviendrait un relais d'envoi pour un tiers.
    """
    from app.backend.services import notifications as notif

    adresse = user.get("email")
    if not adresse:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Votre compte ne porte pas d'adresse de courriel.")
    resultat = await notif.essai_de_remise(adresse)
    await log_action(str(user["_id"]), "consultant", "email_test",
                     f"essai de remise vers {adresse} : "
                     f"{'succès' if resultat['envoye'] else 'échec'}")
    return {**resultat, "adresse": adresse}


@router.get("/notifications")
async def list_notifications(limit: int = Query(40, ge=1, le=100)):
    """Nouvelles CVE ET CVE ayant reçu une mise à jour importante, non encore consultées."""
    db = get_database()
    news = await db.cves.find(_UNREAD_FILTER).sort("collected_at", -1).to_list(limit)
    source_ids = [c["source_id"] for c in news if c.get("source_id")]
    sources = {s["_id"]: s async for s in db.sources.find({"_id": {"$in": source_ids}})}
    items = []
    from app.backend.services.collection.storage import decrire_changements

    for c in news:
        doc = _cve_out(c, sources)
        est_maj = bool(c.get("update_unread") and not c.get("is_new"))
        # CE QUI A CHANGÉ, et pas seulement QU'il y a eu un changement.
        #
        # « Mise à jour de CVE » n'aide pas un consultant : un score réévalué de 7.1 à 9.8,
        # un correctif qui vient de paraître et une exploitation confirmée n'appellent pas
        # la même réaction. Le dernier enregistrement d'historique porte les valeurs
        # avant/après ; on les restitue telles quelles, sans les interpréter.
        details = []
        if est_maj:
            historique = c.get("history") or []
            if historique:
                details = decrire_changements((historique[-1] or {}).get("changes") or {})
            if not details:
                details = list(c.get("change_summary") or [])
        items.append({
            "id": doc["id"],
            "cve_id": doc.get("cve_id"),
            "product": doc.get("product") or (doc.get("affected_products") or ["—"])[0],
            "severity": doc.get("severity"),
            "cvss_score": doc.get("cvss_score"),
            "source": doc.get("source"),
            "type": "update" if est_maj else "new",
            # Détail lisible des modifications (vide pour une nouvelle CVE).
            "changes": details,
            # Date du changement lui-même, distincte de la publication et de la collecte.
            "updated_at": doc.get("last_important_update") or doc.get("updated_at"),
            # Vraie date de publication de la CVE (source officielle).
            "published_at": doc.get("published_at"),
            # Date à laquelle notre agent l'a détectée (technique).
            "collected_at": doc.get("last_important_update") or doc.get("collected_at"),
        })
    return {"total": len(items), "items": items}


@router.get("/notifications/count")
async def notifications_count():
    """Nombre de CVE nouvelles ou mises à jour non consultées (badge)."""
    db = get_database()
    return {"count": await db.cves.count_documents(_UNREAD_FILTER)}


@router.post("/notifications/read")
async def mark_notifications_read(user: dict = Depends(require_role("consultant"))):
    """Marque toutes les notifications comme consultées (vide le badge)."""
    db = get_database()
    result = await db.cves.update_many(_UNREAD_FILTER, {"$set": {"is_new": False, "update_unread": False}})
    await log_action(str(user["_id"]), "consultant", "read_notifications", {"count": result.modified_count})
    return {"ok": True, "marked": result.modified_count}


# ---------- Planification de la collecte (config globale, gérée par le consultant) ----------

@router.get("/collection-status")
async def collection_status():
    """État de la collecte du jour : a-t-elle eu lieu, avec quel résultat, peut-on relancer ?

    Le consultant a besoin de savoir si la veille du jour est faite AVANT de décider de la
    relancer. Sans cette information, il relance à l'aveugle — ou pire, il croit la veille
    faite alors que la machine était hors ligne à l'heure prévue.
    """
    db = get_database()
    debut, _fin = _day_bounds()
    dernier = await db.collection_runs.find_one({"started_at": {"$gte": debut}},
                                                sort=[("started_at", -1)])
    planning = await get_collection_schedule()
    en_cours = bool(dernier and not dernier.get("finished_at"))
    return {
        "scheduled_at": f"{planning.get('hour', 0):02d}:{planning.get('minute', 0):02d}",
        "ran_today": bool(dernier),
        "running": en_cours,
        "status": (dernier or {}).get("daily_status") or (dernier or {}).get("status"),
        "started_at": (dernier or {}).get("started_at"),
        "finished_at": (dernier or {}).get("finished_at"),
        "new_saved": (dernier or {}).get("new_saved"),
        "updated": (dernier or {}).get("updated"),
        "sources_ok": (dernier or {}).get("sources_ok"),
        "sources_total": (dernier or {}).get("sources_total"),
        # CE QUI A PARU AUJOURD'HUI, tous produits confondus — à lire avec `new_saved`.
        #
        # « 0 nouvelle vulnérabilité » ne dit pas si la journée a été calme ou si la collecte
        # a échoué. Avec « 36 parues aujourd'hui, 0 concernant vos produits », le consultant
        # tranche seul, et n'a plus de raison de croire l'application en panne.
        "published_today": (dernier or {}).get("published_today"),
        "cve_detected": (dernier or {}).get("cve_detected"),
    }


@router.post("/collection/run")
async def run_collection_now(background: BackgroundTasks,
                             user: dict = Depends(require_role("consultant"))):
    """RELANCE la collecte du jour, à la demande du consultant.

    Utile quand l'exécution planifiée a échoué — machine éteinte à l'heure dite, réseau
    indisponible, portail momentanément injoignable : le consultant n'a plus à attendre le
    lendemain pour disposer de sa veille.

    Le traitement part en ARRIÈRE-PLAN : il dure plusieurs minutes et ne doit pas maintenir
    la requête ouverte. Un lancement pendant qu'une collecte tourne déjà est REFUSÉ — deux
    exécutions simultanées se disputeraient les mêmes sources et fausseraient les compteurs.
    """
    db = get_database()
    etat = await collection_status()
    if etat["running"]:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Une collecte est déjà en cours. Patientez quelques minutes.")

    background.add_task(pipeline.run_collection_safe, db, "manual")
    await log_action(str(user["_id"]), "consultant", "collection.run_now", {})
    return {"status": "started",
            "message": "Collecte lancée. Les résultats apparaîtront dans quelques minutes."}


@router.get("/collection-schedule")
async def get_collection_schedule():
    db = get_database()
    doc = await db.collection_schedule.find_one({"_id": "global"})
    if doc is None:
        return DEFAULT_SCHEDULE
    doc.pop("_id", None)
    return {**DEFAULT_SCHEDULE, **doc}


@router.put("/collection-schedule")
async def update_collection_schedule(payload: CollectionScheduleUpdate, user: dict = Depends(require_role("consultant"))):
    db = get_database()
    data = payload.model_dump()
    await db.collection_schedule.update_one({"_id": "global"}, {"$set": data}, upsert=True)

    await log_action(str(user["_id"]), "consultant", "update_collection_schedule", data)
    return data
