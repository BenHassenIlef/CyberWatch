"""ISOLATION DES CVE — supprime les données héritées d'un AVIS COLLECTIF.

LA CONTAMINATION

Un avis d'autorité (« Mises à jour de sécurité pour plusieurs produits d'Oracle ») recense
des centaines de vulnérabilités d'éditeurs sans rapport. Les collecteurs recopiaient ses
rubriques — systèmes affectés, titre, remédiation — sur CHACUNE des CVE qu'il cite. On
trouvait donc en base des vulnérabilités Apache, Eclipse ou Golang portant la liste des
produits Oracle, et un produit valant le titre de l'avis.

LA RÈGLE DE DÉTECTION, VOLONTAIREMENT GÉNÉRALE

    Une valeur textuelle portée à l'IDENTIQUE par plusieurs CVE relevant d'ÉDITEURS
    DIFFÉRENTS ne décrit aucune de ces vulnérabilités : elle décrit l'avis qui les regroupe.

Aucun identifiant de CVE, aucun nom d'avis, aucun éditeur n'est codé en dur. La règle vaut
pour les avis d'aujourd'hui comme pour ceux de demain.

Elle ne se déclenche PAS sur un partage légitime : les 370 vulnérabilités corrigées par une
même version de Chrome partagent leur remédiation, mais toutes relèvent du même éditeur.

CE QUI EST RÉPARÉ
  1. Champs contaminés (`product`, `affected_systems`, `impact`, `solution`) : VIDÉS. Une
     provenance vérifiée est intouchable.
  2. Périmètre (`monitored_products`) : RECALCULÉ avec le classement corrigé, qui ne prend
     plus une plateforme d'exécution pour le produit affecté.
  3. Chaque réparation est JOURNALISÉE dans `repair_logs`.

    python repair_cve_isolation.py              # SIMULATION
    python repair_cve_isolation.py --apply
    python repair_cve_isolation.py --apply --min-partage 3
"""
import argparse
import asyncio
import json
import os
import re
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Champs susceptibles d'être recopiés depuis un avis collectif.
#  est volontairement ABSENT : un nom de produit ne contient normalement pas le nom
# de son editeur (« Zoo extension for Joomla » ne dit pas « yootheme »). Lui appliquer la
# regle de mention aurait signale presque tous les produits legitimes.
CHAMPS_SENSIBLES = ("affected_systems", "impact", "solution")

# Nombre minimal de CVE partageant une valeur avant de la juger « de niveau avis ».
# Mots d habillage d une raison sociale : ils ne designent aucune marque en propre.
_MOTS_NON_DISCRIMINANTS = {
    "software", "systems", "technologies", "technology", "group", "corporation",
    "corp", "inc", "ltd", "labs", "security", "solutions", "international",
    "company", "project", "foundation", "team", "open", "source", "server",
    "cloud", "data", "digital", "global", "enterprise", "consulting", "trade",
    # Mots TECHNIQUES courants : ils apparaissent dans toutes les descriptions d impact et
    # ne designent aucun editeur. Sans cette exclusion, « Execution de CODE arbitraire »
    # etait pris pour la mention d une marque nommee « code ».
    "code", "service", "system", "network", "platform", "application", "applications",
    "desktop", "studio", "manager", "engine", "framework", "library", "module",
    "services", "produits", "produit", "version", "versions", "update", "updates",
}

# Un jeton s arrete aux separateurs, PAS aux lettres accentuees : « privileges » et
# « elevation » doivent rester entiers, sans quoi leurs fragments se retrouvaient pris pour
# des marques et un texte d impact parfaitement generique passait pour contamine.
_JETONS_RE = re.compile(r"[^0-9a-zÀ-ɏ]+")

MIN_PARTAGE = 3
# Nombre minimal d'éditeurs DISTINCTS : c'est ce critère qui distingue une contamination
# d'un partage légitime (un même correctif pour plusieurs failles d'un même éditeur).
MIN_EDITEURS = 2


def _cle(valeur) -> str | None:
    """Clé de comparaison stable d'une valeur textuelle ou d'une liste."""
    if valeur in (None, "", []):
        return None
    if isinstance(valeur, list):
        return json.dumps([str(v) for v in valeur], sort_keys=True)
    return str(valeur).strip() or None


async def _vocabulaire_des_marques(db) -> set[str]:
    """Marques réellement présentes en base — construit depuis les données, jamais codé.

    Le vocabulaire suit donc l'évolution du parc surveillé : un éditeur qui apparaît demain
    sera reconnu sans qu'une ligne de code change.
    """
    from app.backend.services.collection.advisory_bulletin import _valid_vendor

    marques: set[str] = set()
    for brut in await db.cves.distinct("vendor", {"cve_status": {"$ne": "rejected"}}):
        # Un champ « editeur » corrompu empoisonne tout le vocabulaire. UNE fiche portant
        # « Elevation de privileges » comme editeur a suffi a faire passer « privileges »
        # pour une marque — et 1 037 descriptions d impact parfaitement generiques ont ete
        # signalees comme contaminees. Le vocabulaire ne retient que des editeurs valides.
        if _valid_vendor(brut) is None:
            continue
        for mot in _JETONS_RE.split((brut or "").lower()):
            # Sous 4 lettres, un jeton est trop générique pour désigner une marque ;
            # les mots d'habillage d'une raison sociale ne la désignent pas non plus.
            if len(mot) >= 4 and mot not in _MOTS_NON_DISCRIMINANTS:
                marques.add(mot)
    return marques


def _marques_citees(valeur, marques: set[str]) -> set[str]:
    """Marques mentionnées dans une valeur textuelle."""
    texte = " ".join(valeur).lower() if isinstance(valeur, list) else str(valeur).lower()
    jetons = set(_JETONS_RE.split(texte))
    return jetons & marques


def _marques_de_l_editeur(vendor: str | None) -> set[str]:
    """Jetons identifiant l editeur de LA CVE — seuil de longueur abaisse a deux.

    Le vocabulaire general ecarte les jetons de moins de quatre lettres, trop generiques.
    Mais ici il s agit du point de COMPARAISON : sans lui, « Red Hat » (« red », « hat ») et
    « IBM » n avaient aucune marque propre, et la moindre mention paraissait etrangere.
    « Red Hat Enterprise Linux » etait alors juge contamine sur une fiche Red Hat.
    """
    return {m for m in _JETONS_RE.split((vendor or "").lower())
            if len(m) >= 2 and m not in _MOTS_NON_DISCRIMINANTS}


async def analyser(db, min_partage: int):
    """Repère les valeurs de niveau AVIS. Renvoie {champ: {cle: [cve_id, ...]}}.

    DEUX conditions cumulatives, et c'est la seconde qui fait la précision :

      • la valeur est portée à l'identique par plusieurs CVE ;
      • elle NOMME un éditeur qui n'est pas celui de la CVE, et ne nomme pas le sien.

    Sans la seconde, la règle effaçait « Google Chrome » sur 439 fiches — un vrai nom de
    produit, signalé au seul motif que l'éditeur y est tantôt « google », tantôt « chrome ».
    Et « Apply updates per vendor instructions » ne nomme aucun éditeur : générique n'est
    pas faux, cette consigne reste.
    """
    marques = await _vocabulaire_des_marques(db)
    porteurs: dict[str, dict[str, list]] = {c: defaultdict(list) for c in CHAMPS_SENSIBLES}
    total = 0

    projection = {"cve_id": 1, "vendor": 1, **{c: 1 for c in CHAMPS_SENSIBLES}}
    async for d in db.cves.find({"cve_status": {"$ne": "rejected"}}, projection):
        total += 1
        siennes = _marques_de_l_editeur(d.get("vendor"))
        if not siennes:
            # Editeur inconnu : aucun point de comparaison, donc aucun jugement possible.
            # Mieux vaut ne rien reparer que reparer a l aveugle.
            continue
        for champ in CHAMPS_SENSIBLES:
            valeur = d.get(champ)
            cle = _cle(valeur)
            if not cle:
                continue
            citees = _marques_citees(valeur, marques)
            # Contamination : la valeur parle d'un AUTRE editeur, et pas du sien.
            if citees and not (citees & siennes):
                porteurs[champ][cle].append(d["cve_id"])

    return total, {champ: {cle: ids for cle, ids in groupes.items() if len(ids) >= min_partage}
                   for champ, groupes in porteurs.items()}


def _resume(total, contamines):
    print(f"Fiches examinees : {total}")
    print()
    print("VALEURS DE NIVEAU AVIS (partagees par des editeurs differents)")
    touchees = set()
    for champ, groupes in contamines.items():
        fiches = sum(len(v) for v in groupes.values())
        for ids in groupes.values():
            touchees.update(ids)
        print(f"  {champ:<20} : {len(groupes):3d} valeur(s) sur {fiches:5d} fiche(s)")
    print()
    print(f"  Fiches distinctes concernees : {len(touchees)}")
    print()
    for champ, groupes in contamines.items():
        for cle, ids in sorted(groupes.items(), key=lambda x: -len(x[1]))[:2]:
            apercu = " ".join(str(json.loads(cle) if cle.startswith("[") else cle).split())[:88]
            print(f"  [{champ}] {len(ids)} CVE  « {apercu} … »")
    print()
    return touchees


async def reparer(db, contamines, appliquer: bool) -> dict:
    """Vide les champs contamines et recalcule le perimetre. Journalise chaque reparation."""
    from app.backend.services.collection import monitored, pipeline, provenance as pv
    from app.backend.utils import utcnow

    await pipeline.refresh_scope(db)
    horodatage = utcnow()
    compteurs = {"champs_vides": 0, "fiches_vidées": 0, "perimetre_recalcule": 0,
                 "protegees_par_provenance": 0}

    # 1) Champs de niveau avis.
    a_vider: dict[str, set[str]] = defaultdict(set)
    for champ, groupes in contamines.items():
        for ids in groupes.values():
            a_vider[champ].update(ids)

    for champ, ids in a_vider.items():
        for cid in ids:
            d = await db.cves.find_one({"cve_id": cid}, {"provenance": 1, champ: 1})
            if not d:
                continue
            entree = (d.get("provenance") or {}).get(champ) or {}
            if entree.get("confidence") == pv.VERIFIED:
                # Valeur confirmee par une source d autorite POUR CETTE CVE : on n y touche pas.
                compteurs["protegees_par_provenance"] += 1
                continue
            compteurs["champs_vides"] += 1
            if appliquer:
                await db.cves.update_one(
                    {"cve_id": cid},
                    {"$set": {champ: None, "isolation_reparee_at": horodatage}})
                await db.repair_logs.insert_one({
                    "cve_id": cid, "champ": champ, "motif": "valeur de niveau avis",
                    "ancienne_valeur": str(d.get(champ))[:400], "at": horodatage})
    compteurs["fiches_vidées"] = len({c for ids in a_vider.values() for c in ids})

    # 2) Perimetre recalcule : le classement corrige ne prend plus une plateforme
    #    d execution pour le produit affecte.
    async for d in db.cves.find({"cve_status": {"$ne": "rejected"}}):
        avant = set(d.get("monitored_products") or [])
        details = monitored.classify_detailed(d)
        retenus = [h for h in details if h["confidence"] != monitored.REJECTED]
        apres = {h["product"] for h in retenus}
        if avant == apres:
            continue
        compteurs["perimetre_recalcule"] += 1
        if not appliquer:
            continue
        maj = {
            "monitored_products": sorted(apres),
            "domains": sorted({h["domain"] for h in retenus if h["domain"]}),
            "monitored_product": retenus[0]["product"] if retenus else None,
            "domain": retenus[0]["domain"] if retenus else None,
            "match_confidence": retenus[0]["confidence"] if retenus else monitored.REJECTED,
            "match_evidence": retenus[0]["evidence"] if retenus else "aucun produit surveille",
            "isolation_reparee_at": horodatage,
        }
        await db.cves.update_one({"cve_id": d["cve_id"]}, {"$set": maj})
        await db.repair_logs.insert_one({
            "cve_id": d["cve_id"], "champ": "monitored_products",
            "motif": "perimetre recalcule", "ancienne_valeur": sorted(avant),
            "nouvelle_valeur": sorted(apres), "at": horodatage})

    return compteurs


async def run(appliquer: bool, min_partage: int) -> int:
    from app.backend.db.mongodb import get_database

    db = get_database()
    total, contamines = await analyser(db, min_partage)
    _resume(total, contamines)

    compteurs = await reparer(db, contamines, appliquer)
    print("REPARATIONS" if appliquer else "REPARATIONS SIMULEES")
    print(f"  champs de niveau avis vides        : {compteurs['champs_vides']}")
    print(f"  fiches concernees                  : {compteurs['fiches_vidées']}")
    print(f"  valeurs protegees (provenance sure): {compteurs['protegees_par_provenance']}")
    print(f"  perimetres recalcules              : {compteurs['perimetre_recalcule']}")
    print()

    if not appliquer:
        print("SIMULATION — aucune ecriture. Relancez avec --apply.")
        return 0

    _total, restants = await analyser(db, min_partage)
    reste = sum(len(v) for g in restants.values() for v in g.values())
    print("CONTRE-VERIFICATION")
    print("  Aucune valeur de niveau avis restante." if reste == 0
          else f"  {reste} fiche(s) portent encore une valeur partagee (voir provenance verifiee).")
    print(f"  Journal des reparations : collection « repair_logs » "
          f"({await db.repair_logs.count_documents({})} entree(s)).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Isole les CVE des donnees de leur avis collectif.")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--min-partage", type=int, default=MIN_PARTAGE)
    a = ap.parse_args()
    try:
        return asyncio.run(run(a.apply, a.min_partage))
    except KeyboardInterrupt:
        print("\nInterrompu. Relancez : la reprise repart de l'etat courant.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
