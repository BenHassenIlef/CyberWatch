"""RÉSOLUTION DES SOLUTIONS — lit les pages officielles de chaque CVE et en extrait la remédiation.

Objectif : qu'une fiche CVE et son bulletin portent la MEILLEURE solution disponible, avec la
source qui la prescrit — jamais une remédiation reformulée anonymement.

Réutilise `assistant/deep_synthesis.py`, déjà en place et éprouvé :

    CVE -> pages officielles (avis éditeur > NVD/CVE.org) -> lecture -> UN appel LLM
        -> validation des jetons techniques -> {solution, solution_source}

POURQUOI UN SCRIPT SÉPARÉ, ET NON DANS LA COLLECTE
Chaque CVE coûte jusqu'à 6 requêtes HTTP plus un appel LLM. Intégré à la collecte, ce coût
multiplierait sa durée par dix et la rendrait dépendante du quota du fournisseur LLM — l'erreur
déjà commise avec la traduction, puis corrigée. La résolution se fait donc À PART, à son rythme,
sans jamais retarder la veille.

GARANTIES
  • GÉNÉRIQUE   : aucun identifiant de CVE, aucune URL, aucune source en dur.
  • ATTRIBUÉE   : toute solution retenue cite la page qui la prescrit. Sans source
                  identifiable, rien n'est écrit — « Non disponible » plutôt qu'une invention.
  • NON DESTRUCTIF : n'écrit que `deep_synthesis`. Ne touche à aucun champ factuel.
  • IDEMPOTENT  : une CVE déjà résolue et fraîche est ignorée (`deep_synthesis.generated_at`).
  • REPRENABLE  : interruption sans perte.

    python resolve_solutions.py                      # SIMULATION
    python resolve_solutions.py --apply --limit 20   # essai borné
    python resolve_solutions.py --apply              # tout le reliquat
    python resolve_solutions.py --apply --missing-only   # seulement les CVE SANS solution
"""
import argparse
import asyncio
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

CONCURRENCE = 1      # 1 seule CVE a la fois : le quota LLM est la ressource rare, pas le reseau

# DEUX limites distinctes chez le fournisseur, et c'est la seconde qui gouverne reellement :
#   • par MINUTE : 8 000 jetons  -> la cadence ci-dessous suffit a la respecter ;
#   • par JOUR   : 200 000 jetons -> a ~3 000 jetons par CVE, environ 65 CVE PAR JOUR.
# Le plafond quotidien ne se contourne pas en attendant : quand il est atteint, le seul choix
# est de reprendre le lendemain ou de relever le palier chez le fournisseur.
CADENCE_SECONDES = 30.0
JETONS_PAR_CVE = 3000        # ordre de grandeur, sert a annoncer la capacite du jour
ECHECS_CONSECUTIFS_MAX = 3   # au-dela, on considere le quota epuise et on s'arrete net


def _selection(missing_only: bool, monitored_only: bool, redo_insufficient: bool) -> dict:
    """CVE à traiter. On ignore celles dont la synthèse est déjà présente.

    Les CVE sont ensuite traitées de la PLUS RÉCENTE à la plus ancienne : une CVE de 1999 n'a
    ni avis éditeur ni page de remédiation, la traiter en premier gaspille le budget d'appels.

    `redo_insufficient` reprend les synthèses conclues « les pages lues ne contiennent rien
    d'exploitable ». Ce verdict dépend de la QUALITÉ DE LECTURE : lorsqu'elle s'améliore
    (nettoyage du JavaScript, cadrage sur l'identifiant), il doit pouvoir être réexaminé.
    Les synthèses ABOUTIES ne sont jamais rejouées — leur coût serait dépensé pour rien.
    """
    # Les conditions alternatives sont empilées dans `$and` : deux clés « $or » posées
    # directement sur le filtre se remplaceraient l'une l'autre, et l'un des deux critères
    # disparaîtrait sans le moindre signal.
    conditions: list[dict] = []
    if redo_insufficient:
        conditions.append({"$or": [{"deep_synthesis": {"$exists": False}},
                                   {"deep_synthesis.status": "insufficient"}]})
    else:
        conditions.append({"deep_synthesis": {"$exists": False}})
    if missing_only:
        # Priorité aux fiches SANS remédiation : c'est là que le gain est le plus fort.
        conditions.append({"$or": [{"solution": None}, {"solution": ""}]})
    base: dict = {"$and": conditions}
    if monitored_only:
        # Restreint aux CVE qui concernent un produit réellement surveillé.
        base["monitored_products"] = {"$exists": True, "$ne": []}
    # Sans références, aucune page à lire : inutile de dépenser un appel.
    base["references.2"] = {"$exists": True}
    return base


async def run(appliquer: bool, limite: int | None, missing_only: bool,
              monitored_only: bool, redo_insufficient: bool, batch: int) -> int:
    from app.backend.db.mongodb import get_database
    from app.backend.services.assistant import deep_synthesis as ds

    db = get_database()
    filtre = _selection(missing_only, monitored_only, redo_insufficient)
    total = await db.cves.count_documents(filtre)
    sans_solution = await db.cves.count_documents(
        {"$or": [{"solution": None}, {"solution": ""}]})
    print(f"CVE en base sans remediation      : {sans_solution}")
    print(f"CVE a traiter (selon le filtre)   : {total}")
    if not total:
        print("Rien a faire.")
        return 0

    sem = asyncio.Semaphore(CONCURRENCE)
    traites = avec_solution = sans_source = echecs = 0
    deja = 0   # decalage de lecture : en simulation rien n'est ecrit, il faut avancer
    exemples: list[dict] = []

    premier = True
    consecutifs = 0        # echecs d'affilee : signature d'un quota epuise
    quota_epuise = False

    async def _une(doc):
        nonlocal traites, avec_solution, sans_source, echecs, premier
        nonlocal consecutifs, quota_epuise
        if quota_epuise:
            return
        async with sem:
            # Cadence tenue DANS le verrou : les CVE se suivent, jamais en rafale.
            if premier:
                premier = False
            else:
                await asyncio.sleep(CADENCE_SECONDES)
            try:
                # `synthesize` n'ecrit en base que si on lui passe `db`. En simulation, on
                # lui passe None : elle lit les pages et rend le resultat sans rien stocker.
                res = await ds.synthesize(db if appliquer else None, doc,
                                          refresh=redo_insufficient)
            except Exception as exc:  # noqa: BLE001 - une CVE ne doit pas casser le lot
                echecs += 1
                consecutifs += 1
                return
        traites += 1
        if res.get("status") != "completed":
            echecs += 1
            # Plusieurs echecs d'affilee ne viennent pas des donnees : c'est le quota du
            # fournisseur. Poursuivre parcourrait des milliers de CVE sans rien produire.
            consecutifs += 1
            if consecutifs >= ECHECS_CONSECUTIFS_MAX:
                quota_epuise = True
            return
        consecutifs = 0
        sol = (res.get("solution") or "").strip()
        src = res.get("solution_source") or {}
        if not sol:
            sans_source += 1
            return
        if not src.get("url"):
            # Solution non rattachable a une page lue : on ne l'affiche pas.
            sans_source += 1
            return
        avec_solution += 1
        if len(exemples) < 6:
            exemples.append({"cve_id": doc.get("cve_id"), "solution": sol,
                             "source": src.get("name"), "url": src.get("url"),
                             "avant": doc.get("solution")})

    reste = limite or total
    while reste > 0:
        taille = min(batch, reste)
        # Tri DÉCROISSANT par date de publication : les CVE récentes ont des avis
        # éditeur exploitables, les anciennes n'en ont pas.
        curseur = db.cves.find(filtre).sort("published_at", -1).skip(deja).limit(taille)
        lot = await curseur.to_list(taille)
        if not lot:
            break
        await asyncio.gather(*[_une(d) for d in lot])
        deja += len(lot)
        reste -= len(lot)
        print(f"  ... {traites} traitees | {avec_solution} avec solution attribuee | "
              f"{sans_source} sans source exploitable | {echecs} echecs")
        if quota_epuise:
            print()
            print(f"ARRET : {ECHECS_CONSECUTIFS_MAX} echecs consecutifs — quota du "
                  "fournisseur LLM vraisemblablement epuise pour aujourd'hui.")
            print("Les CVE deja resolues sont conservees ; relancez demain, la reprise "
                  "repart exactement ou elle s'est arretee.")
            break
        if not appliquer:
            break

    for e in exemples:
        print()
        print(f"  {e['cve_id']}")
        if e["avant"]:
            print(f"    avant  : {' '.join(str(e['avant']).split())[:80]}")
        print(f"    apres  : {' '.join(e['solution'].split())[:90]}")
        print(f"    source : {e['source']} — {e['url'][:70]}")

    print()
    print(f"Traitees {traites} | solutions attribuees {avec_solution} | "
          f"sans source {sans_source} | echecs {echecs}")
    if not appliquer:
        print("SIMULATION — aucune ecriture. Relancez avec --apply.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Resout la meilleure solution de chaque CVE.")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--missing-only", action="store_true",
                    help="Ne traiter que les CVE sans remediation.")
    ap.add_argument("--monitored-only", action="store_true",
                    help="Ne traiter que les CVE liees a un produit surveille.")
    ap.add_argument("--redo-insufficient", action="store_true",
                    help="Rejouer les syntheses conclues sans information exploitable.")
    ap.add_argument("--batch-size", type=int, default=10)
    a = ap.parse_args()
    try:
        return asyncio.run(run(a.apply, a.limit, a.missing_only, a.monitored_only,
                               a.redo_insufficient, a.batch_size))
    except KeyboardInterrupt:
        print("\nInterrompu. Relancez : la resolution reprend ou elle s'etait arretee.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
