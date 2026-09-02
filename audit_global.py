"""AUDIT ET RÉPARATION DE TOUTE LA BASE — recherche des fautes factuelles, fiche par fiche.

Objectif : qu'AUCUNE fiche ne porte une information fausse. Une information manquante est
acceptable et s'affiche « Non disponible » ; une information FAUSSE ne l'est jamais, parce
qu'un consultant agit dessus sur un système réel.

CE QUI EST UNE FAUTE, ET CE QUI N'EN EST PAS

Un premier essai jugeait fautif tout texte partagé par plusieurs fiches. C'était faux : les
370 vulnérabilités corrigées par une même version de Chrome partagent légitimement la même
remédiation. Le critère n'est pas le PARTAGE, c'est la NATURE du texte — un menu de
navigation ou un script de page ne décrit aucune vulnérabilité, qu'il soit sur une fiche ou
sur mille.

FAUTES RECHERCHÉES (règles générales, aucun identifiant de CVE en dur)

  A. Références d'habillage    polices, boutons de partage, liens d'affiliation ramassés sur
                               une page de collecte. Aucune valeur documentaire.
  B. Date d'avis prise pour    la date d'un bulletin n'est pas celle de la vulnérabilité.
     date de publication
  C. Description non           code, menu de portail, page d'erreur présentés comme la
     exploitable               description de la faille.
  D. Remédiation non           idem pour la solution. C'est le champ le plus dangereux :
     exploitable               un menu affiché comme correctif induit une action réelle.
  E. Source officielle         URL stockée portant l'identifiant d'une AUTRE vulnérabilité.
     étrangère
  F. Texte encore balisé       description encadrée de « <p>…</p> », lisible mais mal rendue.
                               NORMALISÉE, jamais supprimée : l'information est bonne.
  G. Fiche RETIRÉE             enregistrement officiellement révoqué (« DO NOT USE THIS CVE
                               RECORD ») présenté comme une vulnérabilité active.

RÉPARATION — deux principes, jamais transgressés :
  • On ne fabrique aucune valeur. Faute de valeur sûre, le champ est VIDÉ.
  • On ne supprime que ce qui est inexploitable ; un texte valable est conservé, au besoin
    normalisé.

    python audit_global.py            # AUDIT SEUL, aucune écriture
    python audit_global.py --apply    # audit, réparation, puis contre-vérification
"""
import argparse
import asyncio
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# Une VRAIE balise commence par une lettre, une barre oblique ou un point d'exclamation.
# Dans ces descriptions, « < » sert le plus souvent de comparateur de version.
_BALISE_RE = re.compile(r"<[a-zA-Z/!][^>]{0,80}>")
# Seules les entites de PRESENTATION sont une faute de rendu. « &lt; », « &gt; », « &amp; »
# et leurs equivalents numeriques portent le payload documente d une faille XSS : les
# signaler reviendrait a vouloir corriger la description de l attaque elle-meme.
_ENTITE_RE = re.compile(r"&(nbsp|apos|#39);")
# Formule normalisée du programme CVE pour un enregistrement révoqué.
_RETIREE_RE = re.compile(r"do not use this cve (record|id)|rejected reason", re.I)

LIBELLES = {
    "A_references_habillage": "Fiches portant des references d'habillage",
    "B_date_avis_comme_publication": "Fiches ou la date d'avis sert de date de publication",
    "C_description_non_exploitable": "Descriptions non exploitables (code, menu, erreur)",
    "D_solution_non_exploitable": "Remediations non exploitables (code, menu, erreur)",
    "E_source_officielle_etrangere": "Sources officielles portant une AUTRE CVE",
    "F_texte_balise": "Textes encore encadres de balises HTML",
    "G_fiche_retiree": "Fiches officiellement RETIREES du programme CVE",
}


def _cve_etrangere(url, cve_id) -> bool:
    if not isinstance(url, str) or not cve_id:
        return False
    cites = _CVE_RE.findall(url)
    return bool(cites) and cve_id.upper() not in {c.upper() for c in cites}


async def auditer(db):
    """Parcourt toute la base et renvoie (total, constats). Ne modifie rien."""
    from app.backend.services.collection import sanitize
    from app.backend.services.collection.advisory_bulletin import est_habillage

    constats = {cle: [] for cle in LIBELLES}
    total = 0
    projection = {"cve_id": 1, "references": 1, "published_at": 1, "advisory_published_at": 1,
                  "description": 1, "solution": 1, "official_source_url": 1, "provenance": 1}

    async for d in db.cves.find({}, projection):
        total += 1
        cid = d.get("cve_id")

        if any(est_habillage(r) for r in (d.get("references") or [])):
            constats["A_references_habillage"].append(cid)

        pub, avis = d.get("published_at"), d.get("advisory_published_at")
        if pub and avis and pub == avis:
            constats["B_date_avis_comme_publication"].append(cid)

        desc, sol = d.get("description"), d.get("solution")
        if desc and sanitize.clean_description(desc) is None:
            constats["C_description_non_exploitable"].append(cid)
        if sol and sanitize.clean_text(sol) is None:
            constats["D_solution_non_exploitable"].append(cid)

        if _cve_etrangere(d.get("official_source_url"), cid):
            constats["E_source_officielle_etrangere"].append(cid)

        # Une VRAIE balise seulement : dans ces descriptions, « < » est le plus souvent un
        # opérateur de comparaison de version (« extension < 2.4.1 »), pas du balisage.
        if any(_BALISE_RE.search(str(v)) or _ENTITE_RE.search(str(v))
               for v in (desc, sol) if v):
            constats["F_texte_balise"].append(cid)

        if desc and _RETIREE_RE.search(str(desc)):
            constats["G_fiche_retiree"].append(cid)

    return total, constats


def _afficher(total, constats, titre):
    print(titre)
    print(f"  Fiches examinees : {total}")
    for cle, libelle in LIBELLES.items():
        print(f"    {libelle:<56} : {len(constats[cle])}")
    print()


async def reparer(db, constats):
    """Applique les corrections. Ne fabrique jamais une valeur."""
    from app.backend.services.collection import sanitize
    from app.backend.services.collection.advisory_bulletin import est_habillage
    from app.backend.utils import utcnow

    compteurs = dict.fromkeys(
        ("references", "dates", "descriptions", "solutions", "sources", "normalises",
         "retirees"), 0)
    horodatage = utcnow()

    for cid in constats["A_references_habillage"]:
        d = await db.cves.find_one({"cve_id": cid}, {"references": 1})
        propres = [r for r in (d.get("references") or []) if not est_habillage(r)]
        await db.cves.update_one({"cve_id": cid}, {"$set": {"references": propres}})
        compteurs["references"] += 1

    for cid in constats["B_date_avis_comme_publication"]:
        # La date de l'avis reste dans `advisory_published_at` : rien n'est perdu, la fiche
        # cesse simplement de la presenter comme la date de la vulnerabilite.
        await db.cves.update_one(
            {"cve_id": cid},
            {"$set": {"published_at": None, "validation_status": "insufficient_data",
                      "audit_global_at": horodatage}})
        compteurs["dates"] += 1

    for cid in constats["C_description_non_exploitable"]:
        await db.cves.update_one({"cve_id": cid},
                                 {"$set": {"description": None, "audit_global_at": horodatage}})
        compteurs["descriptions"] += 1

    for cid in constats["D_solution_non_exploitable"]:
        await db.cves.update_one({"cve_id": cid},
                                 {"$set": {"solution": None, "audit_global_at": horodatage}})
        compteurs["solutions"] += 1

    for cid in constats["E_source_officielle_etrangere"]:
        await db.cves.update_one({"cve_id": cid},
                                 {"$set": {"official_source_url": None,
                                           "audit_global_at": horodatage}})
        compteurs["sources"] += 1

    # F — NORMALISATION, pas suppression : le texte est bon, seule sa presentation est fautive.
    for cid in constats["F_texte_balise"]:
        d = await db.cves.find_one({"cve_id": cid}, {"description": 1, "solution": 1})
        maj = {}
        for champ in ("description", "solution"):
            valeur = d.get(champ)
            if isinstance(valeur, str) and (_BALISE_RE.search(valeur)
                                            or _ENTITE_RE.search(valeur)):
                propre = sanitize.sans_balises(valeur)
                if propre and propre != valeur:
                    maj[champ] = propre
        if maj:
            await db.cves.update_one({"cve_id": cid},
                                     {"$set": {**maj, "audit_global_at": horodatage}})
            compteurs["normalises"] += 1

    # G — une fiche revoquee n est pas une vulnerabilite active : on la MARQUE, sans
    # la supprimer (son historique reste consultable et la trace du retrait est utile).
    for cid in constats["G_fiche_retiree"]:
        await db.cves.update_one({"cve_id": cid},
                                 {"$set": {"cve_status": "rejected",
                                           "audit_global_at": horodatage}})
        compteurs["retirees"] += 1

    print("REPARATIONS APPLIQUEES")
    print(f"  references nettoyees                : {compteurs['references']}")
    print(f"  dates de publication retirees       : {compteurs['dates']}")
    print(f"  descriptions inexploitables retirees: {compteurs['descriptions']}")
    print(f"  remediations inexploitables retirees: {compteurs['solutions']}")
    print(f"  sources officielles retirees        : {compteurs['sources']}")
    print(f"  textes normalises (balises retirees): {compteurs['normalises']}")
    print(f"  fiches marquees RETIREE             : {compteurs['retirees']}")
    print()


async def run(appliquer: bool) -> int:
    from app.backend.db.mongodb import get_database

    db = get_database()
    total, constats = await auditer(db)
    _afficher(total, constats, "AUDIT INITIAL")

    if not appliquer:
        print("AUDIT SEUL — aucune ecriture. Relancez avec --apply pour corriger.")
        return 0

    await reparer(db, constats)
    total, constats = await auditer(db)
    _afficher(total, constats, "CONTRE-VERIFICATION APRES REPARATION")
    restants = sum(len(v) for k, v in constats.items() if k != "G_fiche_retiree")
    print("Aucune faute restante." if restants == 0
          else f"ATTENTION : {restants} constat(s) subsistent — voir le detail ci-dessus.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Audite et repare toutes les fiches CVE.")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    try:
        return asyncio.run(run(a.apply))
    except KeyboardInterrupt:
        print("\nInterrompu. Relancez : l'audit reprend la base dans son etat courant.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
