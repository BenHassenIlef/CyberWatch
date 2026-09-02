"""RÉPARATION des dates de publication corrompues.

Contexte : certains collecteurs d'avis (ANCS, DGSSI, SecAlerts, Tenable) fournissaient la date
de L'AVIS comme date de publication de la CVE. Chaque republication repoussait donc
`published_at` vers aujourd'hui, faisant apparaître de vieilles CVE dans « Publiées aujourd'hui ».

La cause est corrigée dans `storage.accept_publication_date` (une date de publication ne peut
plus avancer). Ce script répare les enregistrements ANTÉRIEURS au correctif.

Référence de réparation : `first_published`, figé à l'insertion et jamais réécrit — il conserve
la première date observée, donc la bonne.

    python repair_publication_dates.py              # RAPPORT seul, aucune écriture
    python repair_publication_dates.py --apply      # applique les réparations sûres
    python repair_publication_dates.py --apply --min-days 30
"""
import argparse
import asyncio
import os
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

CVE_ERA_START = datetime(1999, 1, 1)


def _naive(d):
    return d.replace(tzinfo=None) if isinstance(d, datetime) and d.tzinfo else d


def classer(pub, first, maintenant, provenance=None):
    """(reparable, motif). Ne répare QUE les cas non ambigus.

    `provenance` : bloc de provenance du document. Une date déjà VÉRIFIÉE auprès d'une source
    d'autorité (NVD, MITRE, Red Hat…) ne doit JAMAIS être remplacée par `first_published`, qui
    n'est qu'une première observation. L'autorité prime sur l'ancienneté : une CVE peut
    légitimement être publiée après la date à laquelle nous l'avons aperçue pour la première fois.
    """
    prov = ((provenance or {}).get("cve_published_at") or {})
    if prov.get("confidence") == "verified":
        return False, f"date verifiee par {prov.get('source')} : intouchable"
    pub, first = _naive(pub), _naive(first)
    if not isinstance(pub, datetime) or not isinstance(first, datetime):
        return False, "date manquante"
    if pub <= first:
        return False, "coherent"
    ecart = (pub - first).days
    if ecart < 1:
        return False, "ecart negligeable"
    if first < CVE_ERA_START:
        return False, "AMBIGU : first_published anterieur au programme CVE"
    if first > maintenant:
        return False, "AMBIGU : first_published dans le futur"
    return True, f"reparable (+{ecart} j)"


async def run(appliquer: bool, min_days: int) -> int:
    from app.backend.db.mongodb import get_database
    from app.backend.utils import utcnow

    db = get_database()
    maintenant = _naive(utcnow())
    total = await db.cves.count_documents({})

    reparables, ambigus, proteges = [], [], []
    cur = db.cves.find({"published_at": {"$ne": None}, "first_published": {"$ne": None}},
                       {"cve_id": 1, "published_at": 1, "first_published": 1,
                        "collected_at": 1, "provenance": 1})
    async for c in cur:
        ok, motif = classer(c["published_at"], c["first_published"], maintenant,
                            c.get("provenance"))
        ecart = (_naive(c["published_at"]) - _naive(c["first_published"])).days
        if ok and ecart >= min_days:
            reparables.append((c, ecart))
        elif motif.startswith("AMBIGU"):
            ambigus.append((c, motif))
        elif "verifiee" in motif:
            proteges.append((c, motif))

    print(f"Base : {total} CVE")
    print(f"À réparer (écart >= {min_days} j) : {len(reparables)}")
    print(f"Cas ambigus (NON touchés)        : {len(ambigus)}")
    print(f"Dates vérifiées (protégées)      : {len(proteges)}")

    if reparables:
        print()
        print("  exemples :")
        for c, e in sorted(reparables, key=lambda x: -x[1])[:8]:
            print(f"    {c['cve_id']:<20} affichee {str(c['published_at'])[:10]}"
                  f"  ->  reelle {str(c['first_published'])[:10]}  (+{e} j)")
    for c, motif in ambigus[:5]:
        print(f"    AMBIGU {c['cve_id']:<18} {motif}")

    if not appliquer:
        print()
        print("Rapport seul. Relancez avec --apply pour écrire.")
        return 0

    n = 0
    for c, _e in reparables:
        await db.cves.update_one({"_id": c["_id"]},
                                 {"$set": {"published_at": c["first_published"],
                                           "publication_date_repaired": True}})
        n += 1
    print()
    print(f"{n} CVE réparées (published_at = first_published).")
    print("Les cas ambigus ont été laissés intacts, pour examen manuel.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Répare les dates de publication corrompues.")
    ap.add_argument("--apply", action="store_true", help="Écrire (sinon : rapport seul).")
    ap.add_argument("--min-days", type=int, default=1,
                    help="Écart minimal en jours pour réparer (défaut : 1).")
    a = ap.parse_args()
    return asyncio.run(run(a.apply, a.min_days))


if __name__ == "__main__":
    sys.exit(main())
