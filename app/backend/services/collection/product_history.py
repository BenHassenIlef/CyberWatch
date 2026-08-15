"""Collecte HISTORIQUE CIBLÉE d'un produit qui vient d'être ajouté au périmètre.

Objectif (point 10 du cahier des charges) : sans relancer TOUTES les sources, récupérer les CVE
RÉCENTES d'UN produit précis sur une fenêtre (7 / 30 / 90 jours) via la recherche par mot-clé de
NVD, puis les classer (`monitored.classify_all`) et les enregistrer (`storage.save_records`).

Réutilise l'infrastructure existante : `net.nvd_get` (limitation de débit + clé API), le parseur NVD
d'`enrichment`, et le pipeline de sauvegarde. Aucune source codée en dur, aucune duplication de CVE
(les enregistrements existants sont fusionnés par `save_records`).
"""
import logging
from datetime import timedelta

from app.backend.services.collection import monitored, net, storage
from app.backend.services.collection.enrichment import _from_nvd  # parseur NVD réutilisé
from app.backend.utils import utcnow

logger = logging.getLogger("cyberwatch.collection.history")

_MAX_KEYWORDS = 4          # nb max de requêtes NVD par produit (une par mot-clé pertinent)
_RESULTS_PER_PAGE = 200    # borne NVD par page


def _keywords_for(product: dict) -> list[str]:
    """Mots-clés de recherche les plus SPÉCIFIQUES d'abord (nom + « vendor product » + alias/keywords)."""
    name = (product.get("name") or "").strip()
    vendor = (product.get("vendor") or "").strip()
    kws: list[str] = []
    if vendor and name:
        kws.append(f"{vendor} {name}")
    if name:
        kws.append(name)
    for k in (product.get("keywords") or []) + (product.get("aliases") or []):
        if k and len(k) >= 4:
            kws.append(k)
    # Déduplique en conservant l'ordre, borne le nombre de requêtes.
    return list(dict.fromkeys(kws))[:_MAX_KEYWORDS]


def _record_from_nvd(cve_id: str, nvd: dict) -> dict:
    rec = {"cve_id": cve_id}
    rec.update({k: v for k, v in nvd.items() if v not in (None, "", [])})
    rec.setdefault("detail_url", f"https://nvd.nist.gov/vuln/detail/{cve_id}")
    return rec


async def collect_product_history(db, product: dict, days: int) -> dict:
    """Collecte ciblée d'un produit sur `days` jours. `days<=0` -> aucune collecte historique.
    Renvoie {queried, detected, matched, saved, updated}."""
    if not days or days <= 0:
        return {"queried": 0, "detected": 0, "matched": 0, "saved": 0, "updated": 0, "skipped": True}

    await monitored.refresh_catalog(db)  # garantit que le nouveau produit est dans le catalogue actif
    end = utcnow()
    start = end - timedelta(days=days)
    iso = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000")  # noqa: E731 - format NVD

    seen: set[str] = set()
    detected = 0
    for kw in _keywords_for(product):
        url = (f"{net.NVD_API}?keywordSearch={kw.replace(' ', '%20')}"
               f"&pubStartDate={iso(start)}&pubEndDate={iso(end)}&resultsPerPage={_RESULTS_PER_PAGE}")
        resp = await net.nvd_get(url)
        if not resp:
            logger.warning("Historique %s : NVD injoignable pour « %s ».", product.get("name"), kw)
            continue
        try:
            vulns = resp.json().get("vulnerabilities", [])
        except Exception:  # noqa: BLE001
            continue
        for v in vulns:
            cid = (v.get("cve") or {}).get("id")
            if cid and cid not in seen:
                seen.add(cid)
        detected += len(vulns)

    # Enrichit chaque CVE candidate via le parseur NVD, puis classe (multi-produits) et enregistre.
    records: list[dict] = []
    for cid in seen:
        try:
            nvd = await _from_nvd(cid)
        except Exception:  # noqa: BLE001
            nvd = {}
        rec = _record_from_nvd(cid, nvd)
        hits = monitored.classify_all(rec)
        if hits:
            rec["monitored_products"] = list(dict.fromkeys(h[0] for h in hits))
            rec["domains"] = list(dict.fromkeys(h[1] for h in hits if h[1]))
            rec["monitored_product"], rec["domain"] = hits[0]
            records.append(rec)

    saved = await storage.save_records(db, records) if records else {"inserted": 0, "updated": 0}
    result = {"queried": len(seen), "detected": detected, "matched": len(records),
              "saved": saved.get("inserted", 0), "updated": saved.get("updated", 0), "skipped": False}
    logger.info("Historique ciblé « %s » (%dj) : %d détectées, %d dans le périmètre, %d nouvelles.",
                product.get("name"), days, len(seen), len(records), result["saved"])
    return result
