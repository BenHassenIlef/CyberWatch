"""Collecteur API / Fichier JSON (site-agnostique, avec pagination générique par startIndex)."""
import json
from datetime import datetime, timedelta

from app.backend.services.collection import net, parser
from app.backend.services.collection.collectors.base import SourceUnreachable, register, target_url
from app.backend.services.collection.schema import detail_url_for

MAX_PER_SOURCE = 2000    # borne de sécurité par source et par collecte
PAGE_SIZE = 2000
RECENT_DAYS = 15         # fenêtre par défaut pour « nouvelles CVE » si première collecte
NVD_MAX_WINDOW = 120     # l'API NVD limite la fenêtre à 120 jours
# Chevauchement rétroactif : on re-balaye quelques jours AVANT la dernière collecte afin de
# rattraper les CVE publiées EN RETARD, republiées ou dont la date a changé (la déduplication
# par identifiant CVE évite tout doublon). Sans ce chevauchement, une CVE arrivée tardivement
# sous une date antérieure à la dernière collecte serait DÉFINITIVEMENT manquée.
NVD_OVERLAP_DAYS = 3
# Fenêtre minimale : même juste après une collecte réussie, on regarde toujours ≥ N jours en
# arrière (sinon une 2e exécution le même jour interrogerait une fenêtre quasi vide -> 0 CVE).
MIN_LOOKBACK_DAYS = 3


def _nvd_recency_window(url: str, since) -> str:
    """Ajoute un filtre de date à l'endpoint NVD pour récupérer les CVE récemment publiées.

    La fenêtre part de (dernière collecte − chevauchement), avec un minimum de MIN_LOOKBACK_DAYS,
    afin de ne JAMAIS manquer une publication tardive/rétrodatée. La déduplication garantit
    l'absence de doublons.
    """
    if "services.nvd.nist.gov" not in url or "StartDate" in url:
        return url
    now = datetime.utcnow()
    if isinstance(since, datetime):
        start = since - timedelta(days=NVD_OVERLAP_DAYS)
    else:
        start = now - timedelta(days=RECENT_DAYS)
    start = min(start, now - timedelta(days=MIN_LOOKBACK_DAYS))     # fenêtre toujours large
    start = max(start, now - timedelta(days=NVD_MAX_WINDOW - 1))    # borne API NVD (120 j)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}pubStartDate={start.strftime(fmt)}&pubEndDate={now.strftime(fmt)}"


@register("json", "api_public", "api_protected")
async def collect(source: dict, since) -> list[dict]:
    url = target_url(source)
    if not url:
        return []
    # Sources NVD : on demande les CVE publiées depuis la dernière collecte (nouvelles).
    url = _nvd_recency_window(url, since)
    host = source.get("api_endpoint", "") + source.get("url", "")
    records: list[dict] = []
    start_index = 0
    while len(records) < MAX_PER_SOURCE:
        page_url = url
        # Pagination générique : si l'URL supporte startIndex (motif NVD/OData).
        if start_index:
            sep = "&" if "?" in url else "?"
            page_url = f"{url}{sep}startIndex={start_index}&resultsPerPage={PAGE_SIZE}"
        resp = await (net.nvd_get(page_url) if "services.nvd.nist.gov" in url else net.get(page_url))
        if resp is None or resp.status_code != 200:
            # 1re page injoignable = source NON collectée (à ré-essayer), pas une source « vide ».
            if start_index == 0:
                raise SourceUnreachable(f"HTTP {getattr(resp, 'status_code', 'timeout')} sur {page_url[:80]}")
            break  # pages suivantes : on garde ce qu'on a déjà.
        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError):
            if start_index == 0:
                raise SourceUnreachable("réponse non-JSON en 1re page")
            break
        objects = parser.iter_cve_objects(data)
        for obj in objects:
            rec = parser.extract_from_json_object(obj)
            if rec:
                rec["detail_url"] = detail_url_for(rec["cve_id"], host)
                records.append(rec)
                if len(records) >= MAX_PER_SOURCE:
                    break
        # Poursuite de la pagination uniquement pour les réponses paginées connues (shape).
        total = data.get("totalResults") if isinstance(data, dict) else None
        got = len(objects)
        if not total or not got:
            break
        start_index += got
        if start_index >= int(total):
            break
    return records
