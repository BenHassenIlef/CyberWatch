"""MIGRATION — sépare les données d'AVIS des faits de la CVE, sur les enregistrements existants.

Contexte : jusqu'au correctif de `advisory.py`, un bulletin CERT recopiait ses propres champs
(description, produit, éditeur, impact, versions, ET DATE DE PUBLICATION) sur chacune des CVE
qu'il citait. Un avis de 40 CVE produisait donc 40 fiches identiques.

Ce script traite les enregistrements ANTÉRIEURS au correctif. Il ne SUPPRIME rien :

  1. la date de l'avis est déplacée vers `advisory_published_at` ;
  2. `published_at` n'est vidé QUE si sa valeur provient manifestement de l'avis ;
  3. les champs recopiés reçoivent une provenance `advisory` / `unverified` ;
  4. la fiche passe en `validation_status = needs_review` ;
  5. l'enrichissement par identifiant (s'il est actif) écrasera ensuite ces valeurs.

GÉNÉRIQUE : aucun identifiant de CVE, aucune date, aucune source en dur.
IDEMPOTENT : un enregistrement déjà migré porte `advisory_separated: true` et est ignoré.
REPRENABLE : la sélection exclut les migrés ; une interruption ne perd aucun avancement.

    python migrate_advisory_separation.py                 # SIMULATION, aucune écriture
    python migrate_advisory_separation.py --sample 20     # simulation sur un échantillon
    python migrate_advisory_separation.py --apply
    python migrate_advisory_separation.py --apply --batch-size 200
"""
import argparse
import asyncio
import os
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Champs que l'avis recopiait sur chaque CVE : leur provenance devient `advisory`.
CHAMPS_CONTAMINABLES = ("description", "product", "vendor", "impact", "severity",
                        "affected_versions", "fixed_version", "platform", "solution")


def _naive(d):
    return d.replace(tzinfo=None) if isinstance(d, datetime) and d.tzinfo else d


def analyser(doc: dict) -> dict | None:
    """Décrit ce qu'il faudrait corriger sur ce document. None si rien à faire."""
    from app.backend.services.collection import provenance as pv

    if doc.get("advisory_separated"):
        return None                                   # déjà migré (idempotence)

    url = doc.get("advisory_url") or doc.get("detail_url")
    changements: list[dict] = []
    prov = dict(doc.get("provenance") or {})

    # 1) La date de publication provient-elle de l'avis ? Indice : elle est identique à la
    #    date de l'avis, ou postérieure à la première date observée.
    pub = _naive(doc.get("published_at"))
    adv_pub = _naive(doc.get("advisory_published_at"))
    first = _naive(doc.get("first_published"))
    # Seul un écart SIGNIFICATIF (>= 1 jour) trahit une date d'avis. Quelques minutes
    # d'écart proviennent d'horodatages de collecte successifs, pas d'une contamination.
    suspecte = False
    if isinstance(pub, datetime):
        if isinstance(adv_pub, datetime) and pub == adv_pub:
            suspecte = True
        elif isinstance(first, datetime) and (pub - first).days >= 1:
            suspecte = True
    if suspecte:
        changements.append({"champ": "published_at", "avant": pub,
                            "apres": first, "raison": "date de l'avis prise pour celle de la CVE"})

    # 2) Les champs recopiés reçoivent une provenance `advisory` s'ils n'en ont aucune.
    for champ in CHAMPS_CONTAMINABLES:
        if doc.get(champ) in (None, "", []):
            continue
        if champ in prov:
            continue                                   # provenance déjà connue : on n'y touche pas
        brut = str(doc[champ])
        pollue = any(m in brut for m in ("@media", "{", "PageFoo", "Overview, Insights"))
        raison = ("valeur inexploitable extraite de la page (CSS/titre), marquée non vérifiée"
                  if pollue else "valeur issue de l'avis, marquée non vérifiée")
        changements.append({"champ": champ, "avant": doc[champ], "apres": doc[champ],
                            "raison": raison})
        prov[champ] = pv.entry(doc[champ], "advisory", url, pv.UNVERIFIED)

    if not changements:
        return None
    return {"_id": doc["_id"], "cve_id": doc.get("cve_id"),
            "advisory_id": doc.get("advisory_id"), "changements": changements,
            "provenance": prov, "date_corrigee": first if suspecte else None,
            "advisory_date": adv_pub or (pub if suspecte else None)}


async def run(appliquer: bool, sample: int | None, batch: int) -> int:
    from app.backend.db.mongodb import get_database
    from app.backend.services.collection import provenance as pv

    db = get_database()
    filtre = {"data_origin": "CERT advisory", "advisory_separated": {"$ne": True}}
    total = await db.cves.count_documents(filtre)
    print(f"Enregistrements issus d'un avis, non migrés : {total}")
    if not total:
        print("Rien à faire.")
        return 0

    traites = corriges = 0
    exemples: list[dict] = []
    while True:
        lot = await db.cves.find(filtre).limit(batch).to_list(batch)
        if not lot:
            break
        for doc in lot:
            traites += 1
            plan = analyser(doc)
            if plan is None:
                if appliquer:
                    await db.cves.update_one({"_id": doc["_id"]},
                                             {"$set": {"advisory_separated": True}})
                continue
            corriges += 1
            if len(exemples) < 6:
                exemples.append(plan)
            if appliquer:
                maj = {"provenance": plan["provenance"], "advisory_separated": True,
                       "validation_status": "needs_review"}
                if plan["advisory_date"]:
                    maj["advisory_published_at"] = plan["advisory_date"]
                if plan["date_corrigee"]:
                    maj["published_at"] = plan["date_corrigee"]
                await db.cves.update_one({"_id": doc["_id"]}, {"$set": maj})
        if not appliquer:
            break                                      # simulation : un seul lot suffit
        if sample and traites >= sample:
            break
    print(f"Analysés : {traites} | à corriger : {corriges}")

    for e in exemples:
        print()
        print(f"  {e['cve_id']}  (avis {e['advisory_id']})")
        for c in e["changements"][:4]:
            av = str(c["avant"])[:44]
            ap = str(c["apres"])[:44]
            print(f"    {c['champ']:<20} {av:<46} -> {ap}")
            print(f"      raison : {c['raison']}")

    if not appliquer:
        print()
        print("SIMULATION — aucune écriture. Relancez avec --apply.")
    else:
        print()
        print(f"{corriges} enregistrement(s) corrigé(s). Migration idempotente : "
              "une nouvelle exécution ignorera les enregistrements déjà traités.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Sépare les données d'avis des faits de la CVE.")
    ap.add_argument("--apply", action="store_true", help="Écrire (sinon simulation).")
    ap.add_argument("--sample", type=int, default=None, help="Limiter le nombre traité.")
    ap.add_argument("--batch-size", type=int, default=100, help="Taille de lot (défaut 100).")
    a = ap.parse_args()
    try:
        return asyncio.run(run(a.apply, a.sample, a.batch_size))
    except KeyboardInterrupt:
        print()
        print("Interrompu. Relancez : la migration reprend où elle s'était arrêtée.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
