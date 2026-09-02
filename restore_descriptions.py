"""RESTAURE les descriptions vidées à tort par l'audit global.

POURQUOI CE SCRIPT EXISTE

L'audit global vide les descriptions jugées inexploitables. Son filtre traitait alors le mot
« cookie » comme un marqueur de bandeau de consentement — or c'est un terme technique
courant. Une description parfaitement valable comme

    « does not sign or verify its guest-session cookie, allowing unauthenticated attackers
      to forge it and impersonate any ticket owner »

a donc pu être effacée. Le filtre est corrigé ; ce script répare les fiches concernées.

MÉTHODE — on redemande la description à MITRE, la source qui l'a publiée. Rien n'est
reconstitué de mémoire : si la source ne répond pas, le champ reste vide.

GARANTIES
  • N'écrit QUE sur les fiches dont la description est ABSENTE. Aucune valeur en place n'est
    touchée.
  • La valeur restaurée repasse par le filtre CORRIGÉ : un vrai déchet ne revient pas.
  • Provenance renseignée (`mitre`, vérifiée).
  • Idempotent et reprenable.

    python restore_descriptions.py            # SIMULATION
    python restore_descriptions.py --apply
"""
import argparse
import asyncio
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

CONCURRENCE = 4
LOT = 100


async def _description_officielle(cve_id: str):
    """Description publiée par MITRE, assainie par le filtre corrigé. None si indisponible."""
    from app.backend.services.collection import net, sanitize

    try:
        resp = await net.get(f"https://cveawg.mitre.org/api/cve/{cve_id}")
        if resp is None or resp.status_code != 200:
            return None
        cna = (resp.json().get("containers") or {}).get("cna") or {}
        brute = next((d.get("value") for d in cna.get("descriptions", [])
                      if (d.get("lang") or "").startswith("en")), None)
        return sanitize.clean_description(brute)
    except Exception:  # noqa: BLE001 - source indisponible : on n'invente rien
        return None


async def run(appliquer: bool, limite: int | None) -> int:
    from app.backend.db.mongodb import get_database
    from app.backend.services.collection import provenance as pv
    from app.backend.utils import utcnow

    db = get_database()
    filtre = {"description": None,
              "audit_global_at": {"$exists": True},
              "description_restauree_at": {"$exists": False},
              "cve_status": {"$ne": "rejected"}}
    total = await db.cves.count_documents(filtre)
    print(f"Fiches sans description a restaurer : {total}")
    if not total:
        print("Rien a faire.")
        return 0

    sem = asyncio.Semaphore(CONCURRENCE)
    examinees = restaurees = introuvables = 0
    exemples: list[tuple] = []

    async def _une(doc):
        nonlocal examinees, restaurees, introuvables
        cid = doc.get("cve_id")
        async with sem:
            texte = await _description_officielle(cid)
        examinees += 1
        if not texte:
            introuvables += 1
            if appliquer:
                await db.cves.update_one({"_id": doc["_id"]},
                                         {"$set": {"description_restauree_at": utcnow()}})
            return
        restaurees += 1
        if len(exemples) < 6:
            exemples.append((cid, " ".join(texte.split())[:90]))
        if appliquer:
            prov = dict(doc.get("provenance") or {})
            prov["description"] = pv.entry(
                texte, "mitre",
                source_url=f"https://www.cve.org/CVERecord?id={cid}",
                confidence=pv.VERIFIED)
            await db.cves.update_one(
                {"_id": doc["_id"]},
                {"$set": {"description": texte, "provenance": prov,
                          "description_restauree_at": utcnow()}})

    traites = 0
    plafond = limite or total
    while traites < plafond:
        taille = min(LOT, plafond - traites)
        lot = await db.cves.find(filtre).limit(taille).to_list(taille)
        if not lot:
            break
        await asyncio.gather(*[_une(d) for d in lot])
        traites += len(lot)
        print(f"  ... {examinees}/{plafond} | {restaurees} restaurees | "
              f"{introuvables} sans description publiee")
        if not appliquer:
            break

    print()
    for cid, texte in exemples:
        print(f"  {cid:<18} {texte}")
    print()
    print(f"Examinees {examinees} | restaurees {restaurees} | introuvables {introuvables}")
    if not appliquer:
        print("SIMULATION — aucune ecriture. Relancez avec --apply.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Restaure les descriptions manquantes.")
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
