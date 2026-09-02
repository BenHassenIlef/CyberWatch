"""RÉTABLIT LA DATE DE DIVULGATION sur toutes les fiches déjà en base.

LA FAUTE CORRIGÉE

Un enregistrement CVE porte DEUX dates, et nous retenions la mauvaise :

    datePublic     2026-08-11   le CNA (Microsoft, Cisco, Red Hat…) a DIVULGUÉ la faille.
                                C'est la date qu'affiche l'avis officiel de l'éditeur.
    datePublished  2026-08-19   la fiche a été ENREGISTRÉE au registre CVE, huit jours après.

L'application affichait le 19. Une vulnérabilité connue depuis plus d'une semaine apparaissait
donc comme « publiée aujourd'hui », en contradiction visible avec la page de l'éditeur — et
elle remontait à tort dans la veille du jour.

MÉTHODE — une requête MITRE par CVE, la source qui publie `datePublic`. Aucun autre appel.

GARANTIES
  • GÉNÉRIQUE   : aucun identifiant, aucune date, aucune source en dur.
  • PRUDENT     : la date n'est remplacée que si la divulgation est ANTÉRIEURE à la date
                  stockée. Une vulnérabilité ne peut pas être divulguée après son
                  enregistrement ; l'inverse serait une régression.
  • BORNÉ       : une date hors de l'ère CVE ou postérieure à aujourd'hui est refusée.
  • TRAÇABLE    : la nouvelle valeur porte sa provenance (`cna`, vérifiée).
  • IDEMPOTENT  : `disclosure_checked_at` marque les fiches traitées.
  • REPRENABLE  : interruption sans perte.

    python repair_disclosure_dates.py                 # SIMULATION
    python repair_disclosure_dates.py --apply
    python repair_disclosure_dates.py --apply --limit 500
"""
import argparse
import asyncio
import os
import sys
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

CONCURRENCE = 4        # requêtes MITRE simultanées (courtoisie envers le service)
LOT = 200              # fiches traitées par tour


def _naif(d):
    return d.replace(tzinfo=None) if isinstance(d, datetime) and d.tzinfo else d


async def _date_de_divulgation(cve_id: str):
    """`datePublic` déclarée par le CNA, ou None. Ne lève jamais."""
    from app.backend.services.collection import net
    from app.backend.services.collection.schema import parse_dt

    try:
        resp = await net.get(f"https://cveawg.mitre.org/api/cve/{cve_id}")
        if resp is None or resp.status_code != 200:
            return None
        cna = (resp.json().get("containers") or {}).get("cna") or {}
        return _naif(parse_dt(cna.get("datePublic")))
    except Exception:  # noqa: BLE001 - source indisponible : on ne modifie rien
        return None


def _acceptable(nouvelle, ancienne) -> bool:
    """Vrai si la divulgation doit remplacer la date stockée."""
    from app.backend.services.collection.storage import _CVE_ERA_START
    from app.backend.utils import utcnow

    if nouvelle is None:
        return False
    if nouvelle < _CVE_ERA_START or nouvelle > _naif(utcnow()) + timedelta(days=2):
        return False
    # Strictement ANTÉRIEURE : on ne recule jamais vers une date plus tardive.
    return ancienne is None or nouvelle < _naif(ancienne)


async def run(appliquer: bool, limite: int | None) -> int:
    from app.backend.db.mongodb import get_database
    from app.backend.services.collection import provenance as pv
    from app.backend.utils import utcnow

    db = get_database()
    filtre = {"disclosure_checked_at": {"$exists": False},
              "cve_status": {"$ne": "rejected"}}
    total = await db.cves.count_documents(filtre)
    print(f"Fiches a examiner : {total}")
    if not total:
        print("Rien a faire.")
        return 0

    sem = asyncio.Semaphore(CONCURRENCE)
    examinees = corrigees = inchangees = sans_date = 0
    exemples: list[tuple] = []

    async def _une(doc):
        nonlocal examinees, corrigees, inchangees, sans_date
        cid = doc.get("cve_id")
        async with sem:
            divulgation = await _date_de_divulgation(cid)
        examinees += 1
        ancienne = doc.get("published_at")

        if divulgation is None:
            sans_date += 1
            if appliquer:
                await db.cves.update_one({"_id": doc["_id"]},
                                         {"$set": {"disclosure_checked_at": utcnow()}})
            return
        if not _acceptable(divulgation, ancienne):
            inchangees += 1
            if appliquer:
                await db.cves.update_one({"_id": doc["_id"]},
                                         {"$set": {"disclosure_checked_at": utcnow()}})
            return

        corrigees += 1
        if len(exemples) < 8:
            exemples.append((cid, str(ancienne)[:10], str(divulgation)[:10]))
        if appliquer:
            prov = dict(doc.get("provenance") or {})
            prov["cve_published_at"] = pv.entry(
                divulgation, "cna",
                source_url=f"https://www.cve.org/CVERecord?id={cid}",
                confidence=pv.VERIFIED)
            await db.cves.update_one(
                {"_id": doc["_id"]},
                {"$set": {"published_at": divulgation, "provenance": prov,
                          "disclosure_checked_at": utcnow()}})

    traites = 0
    plafond = limite or total
    while traites < plafond:
        taille = min(LOT, plafond - traites)
        # Les PLUS RECENTES d abord : c est la ou l ecart entre divulgation et
        # enregistrement se voit, et ou une date fausse fait remonter a tort une CVE
        # dans la veille du jour.
        curseur = db.cves.find(filtre).sort("published_at", -1).limit(taille)
        lot = await curseur.to_list(taille)
        if not lot:
            break
        await asyncio.gather(*[_une(d) for d in lot])
        traites += len(lot)
        print(f"  ... {examinees}/{plafond} examinees | {corrigees} corrigees | "
              f"{inchangees} deja justes | {sans_date} sans date de divulgation")
        if not appliquer:
            break

    print()
    for cid, avant, apres in exemples:
        print(f"  {cid:<18} {avant}  ->  {apres}")

    print()
    print(f"Examinees {examinees} | corrigees {corrigees} | deja justes {inchangees} | "
          f"sans date publiee par le CNA {sans_date}")
    if not appliquer:
        print("SIMULATION — aucune ecriture. Relancez avec --apply.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Retablit la date de divulgation des CVE.")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args()
    try:
        return asyncio.run(run(a.apply, a.limit))
    except KeyboardInterrupt:
        print("\nInterrompu. Relancez : la reprise repart ou elle s'est arretee.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
