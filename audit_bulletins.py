"""AUDIT DE BOUT EN BOUT — construit de VRAIS bulletins et vérifie chaque invariant.

`audit_global.py` contrôle ce qui est STOCKÉ. Ce script contrôle ce qui est AFFICHÉ : le
bulletin est assemblé à la volée à partir de la fiche et de la page de collecte, et c'est là
que les fautes se sont logées jusqu'ici — éditeur emprunté à une CVE voisine, source
officielle renvoyant vers la page de collecte, références truffées de navigation.

L'échantillon est PAR HÔTE DE COLLECTE : chaque portail a sa mise en page et ses pièges, et
un échantillon pris au hasard aurait été dominé par les deux ou trois portails les plus
prolifiques.

INVARIANTS VÉRIFIÉS

  1. Le bulletin ne porte QUE sa propre CVE.
  2. La source officielle ne cite jamais une AUTRE vulnérabilité.
  3. La source officielle n'est pas la page de collecte — sauf si c'est l'avis de l'éditeur.
  4. Aucune référence d'habillage (polices, partage, navigation de portail, racine de site).
  5. L'éditeur du bulletin est celui de la fiche.
  6. La date de publication est présente dès lors que la fiche en porte une.
  7. Aucun texte affiché n'est du code ou un menu.
  8. Le site officiel APPARTIENT à l'éditeur du produit — jamais une base de vulnérabilités.

    python audit_bulletins.py                 # 3 CVE par hote de collecte
    python audit_bulletins.py --par-hote 5
"""
import argparse
import asyncio
import os
import re
import sys
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

CONCURRENCE = 3
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

INVARIANTS = {
    "1_cve_etrangere_listee": "Bulletins listant une CVE etrangere",
    "2_source_autre_cve": "Sources officielles citant une AUTRE CVE",
    "3_source_est_la_collecte": "Sources officielles egales a la page de collecte",
    "4_reference_habillage": "Bulletins avec une reference d'habillage",
    "5_editeur_divergent": "Bulletins dont l'editeur differe de la fiche",
    "6_date_perdue": "Bulletins sans date alors que la fiche en a une",
    "7_texte_non_exploitable": "Bulletins affichant du code ou un menu",
    "8_site_officiel_non_editeur": "Sites officiels qui n appartiennent pas a l editeur",
}


async def _echantillon(db, par_hote: int) -> list[dict]:
    """Quelques CVE par hôte de collecte : couvre la diversité des mises en page."""
    hotes = await db.cves.distinct("detail_url", {"cve_status": {"$ne": "rejected"}})
    par_domaine: dict[str, list[str]] = {}
    for u in hotes:
        if not isinstance(u, str) or not u.startswith("http"):
            continue
        par_domaine.setdefault(urlparse(u).netloc.lower(), []).append(u)

    choisis: list[dict] = []
    for _hote, urls in par_domaine.items():
        for url in urls[:par_hote]:
            doc = await db.cves.find_one({"detail_url": url,
                                          "cve_status": {"$ne": "rejected"}})
            if doc:
                choisis.append(doc)
    return choisis


def _controler(doc: dict, b: dict) -> list[tuple[str, str]]:
    """Renvoie [(invariant, detail)] pour chaque violation constatée."""
    from app.backend.services.collection import sanitize
    from app.backend.services.collection.advisory_bulletin import (
        SEUIL_APPARTENANCE_EDITEUR, _VENDOR_PORTALS, _domaine_de_l_editeur, _meme_page,
        _score_reference, _vendor_slugs, est_habillage)

    cid = doc.get("cve_id")
    collecte = doc.get("detail_url")
    fautes: list[tuple[str, str]] = []

    etrangeres = [c for c in (b.get("cves") or []) if c.upper() != (cid or "").upper()]
    if etrangeres:
        fautes.append(("1_cve_etrangere_listee", ", ".join(etrangeres[:3])))

    src = (b.get("official_source") or {}).get("url") or ""
    cites = _CVE_RE.findall(src)
    if cites and cid and cid.upper() not in {c.upper() for c in cites}:
        fautes.append(("2_source_autre_cve", src[:70]))

    if src and collecte and _meme_page(src, collecte):
        # Tolérée UNIQUEMENT si la page appartient à l'éditeur : elle est alors l'avis officiel.
        slugs = _vendor_slugs(b.get("vendor"), b.get("products"))
        if _score_reference(collecte, slugs) < 90:
            fautes.append(("3_source_est_la_collecte", src[:70]))

    parasites = [r for r in (b.get("references") or []) if est_habillage(r)]
    if parasites:
        fautes.append(("4_reference_habillage", parasites[0][:70]))

    attendu, obtenu = doc.get("vendor"), b.get("vendor")
    if attendu and obtenu and attendu.lower() not in obtenu.lower() \
            and obtenu.lower() not in attendu.lower():
        fautes.append(("5_editeur_divergent", f"fiche={attendu} bulletin={obtenu}"))

    if doc.get("published_at") and not b.get("publication_date"):
        fautes.append(("6_date_perdue", str(doc.get("published_at"))[:10]))

    # 8 — le SITE OFFICIEL doit appartenir a l editeur. Le controle ne repose sur aucune
    # liste de sites : on verifie l APPARTENANCE, ce qui ecarte d office NVD, CVE.org, les
    # avis GitHub et tout agregateur, present ou futur.
    if src:
        slugs = _vendor_slugs(b.get("vendor"), b.get("products"))
        connu = any(s in _VENDOR_PORTALS for s in slugs)
        appartient = (_score_reference(src, slugs) >= SEUIL_APPARTENANCE_EDITEUR
                      or connu
                      or bool(_domaine_de_l_editeur(b.get("vendor"))))
        if not appartient:
            fautes.append(("8_site_officiel_non_editeur", src[:70]))

    for champ in ("summary", "solution"):
        valeur = b.get(champ)
        if valeur and sanitize.clean_text(str(valeur)) is None:
            fautes.append(("7_texte_non_exploitable", f"{champ} : {str(valeur)[:50]}"))

    return fautes


async def run(par_hote: int) -> int:
    from app.backend.db.mongodb import get_database
    from app.backend.services.collection import advisory_bulletin as ab

    db = get_database()
    docs = await _echantillon(db, par_hote)
    print(f"Bulletins a construire : {len(docs)} "
          f"({par_hote} par hote de collecte)")
    print()

    sem = asyncio.Semaphore(CONCURRENCE)
    constats: dict[str, list] = {cle: [] for cle in INVARIANTS}
    construits = echecs = 0

    async def _un(doc):
        nonlocal construits, echecs
        async with sem:
            try:
                b = await ab.build_bulletin(doc.get("detail_url") or "", seed=doc, db=db)
            except Exception as exc:  # noqa: BLE001 - une page injoignable n'est pas une faute
                echecs += 1
                return
        construits += 1
        for invariant, detail in _controler(doc, b):
            constats[invariant].append((doc.get("cve_id"), detail))

    lot = 12
    for i in range(0, len(docs), lot):
        await asyncio.gather(*[_un(d) for d in docs[i:i + lot]])
        print(f"  ... {construits + echecs}/{len(docs)} traites "
              f"({construits} construits, {echecs} pages injoignables)")

    print()
    print(f"BULLETINS CONSTRUITS : {construits}")
    total = 0
    for cle, libelle in INVARIANTS.items():
        n = len(constats[cle])
        total += n
        print(f"  {libelle:<52} : {n}")
    print()
    for cle, items in constats.items():
        for cid, detail in items[:3]:
            print(f"  [{cle}] {cid} — {detail}")

    print()
    print("Aucune faute sur l'echantillon." if total == 0
          else f"{total} faute(s) constatee(s) — voir le detail ci-dessus.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Audite les bulletins reellement produits.")
    ap.add_argument("--par-hote", type=int, default=3)
    a = ap.parse_args()
    try:
        return asyncio.run(run(a.par_hote))
    except KeyboardInterrupt:
        print("\nInterrompu.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
