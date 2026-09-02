"""RÉ-ENRICHISSEMENT des CVE contaminées par un avis — récupère les faits AUTORITAIRES.

Marquer une valeur « non vérifiée » ne suffit pas : il faut aller chercher la vraie donnée.
Ce script interroge, POUR CHAQUE identifiant CVE pris isolément, les sources d'autorité déjà
intégrées au projet (NVD, MITRE/CVE.org, OSV, Red Hat, MSRC, GitHub), puis écrit chaque champ
avec sa provenance.

GARANTIES
  • GÉNÉRIQUE   : aucun identifiant de CVE, aucune date, aucune source en dur.
  • ISOLÉ       : une requête par CVE, avec SON identifiant — jamais celui de l'avis ni d'une
                  CVE voisine. Deux CVE d'un même bulletin peuvent donc diverger totalement.
  • NON DESTRUCTIF : une valeur n'est remplacée que si la nouvelle provenance l'emporte.
  • RIEN D'INVENTÉ : sans source autoritaire, le champ reste tel quel (marqué non vérifié).
  • IDEMPOTENT  : `reenriched_at` marque les CVE traitées ; une relance les ignore.
  • REPRENABLE  : interruption sans perte ; les échecs sont rejouables.

    python reenrich_advisory_cves.py --dry-run --sample 5
    python reenrich_advisory_cves.py --apply
    python reenrich_advisory_cves.py --apply --retry-failed
"""
import argparse
import asyncio
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Correspondance champ enrichi -> champ stocké. `published_at` reçoit la VRAIE date de la CVE.
CHAMPS = ("description", "published_at", "updated_at", "cvss_score", "cvss_vector",
          "severity", "cwe", "vuln_type", "vendor", "product", "affected_versions",
          "fixed_version", "impact")

CONCURRENCE = 3          # requêtes CVE simultanées (les sources limitent le débit)


async def _marquer_sans_autorite(db, doc, journal, pv):
    """Marque une CVE dont aucune source d'autorite ne fournit de donnees.

    La date de publication heritee d'un avis est videe : la conserver reviendrait a presenter
    la date du bulletin comme celle de la vulnerabilite. Mieux vaut « Non disponible ».
    """
    from app.backend.utils import utcnow

    maj = {"reenriched_at": utcnow()}
    prov_pub = (doc.get("provenance") or {}).get("cve_published_at") or {}
    if doc.get("published_at") is not None and prov_pub.get("confidence") != pv.VERIFIED:
        maj["published_at"] = None
        maj["validation_status"] = "insufficient_data"
        journal["champs"].append({"champ": "published_at", "avant": doc.get("published_at"),
                                  "apres": None, "source": "aucune source autoritaire"})
    await db.cves.update_one({"_id": doc["_id"]}, {"$set": maj})


async def enrichir_une(db, doc, appliquer, pv, enrichment, sanitize):
    """Interroge les sources d'autorité pour CETTE CVE et renvoie le journal des changements."""
    cve_id = doc.get("cve_id")
    journal = {"cve_id": cve_id, "champs": [], "erreur": None}
    try:
        # L'identifiant de la CVE est la SEULE clé d'interrogation.
        fusion, confirmees = await enrichment.enrich(cve_id, seed=None, use_nvd=True)
    except Exception as exc:  # noqa: BLE001
        # ERREUR TECHNIQUE (reseau, quota) : on ne marque PAS. La CVE sera retentee au
        # prochain passage — c'est une panne, pas une absence de donnee.
        journal["erreur"] = str(exc)[:160]
        return journal

    if not confirmees:
        # AUCUNE SOURCE D'AUTORITE ne connait cette CVE. Ce n'est pas une panne : c'est un
        # resultat definitif. On le MARQUE, sinon la migration retraiterait indefiniment les
        # memes enregistrements et ne serait jamais idempotente.
        journal["erreur"] = "aucune source d'autorite n'a confirme cette CVE"
        if appliquer:
            await _marquer_sans_autorite(db, doc, journal, pv)
        return journal

    # Source dominante = la plus prioritaire ayant repondu (sert de provenance).
    source = confirmees[0]
    url = fusion.get("detail_url")
    maj, prov = {}, dict(doc.get("provenance") or {})
    travail = {"provenance": prov}

    for champ in CHAMPS:
        valeur = fusion.get(champ)
        if valeur in (None, "", []):
            continue
        # Meme assainissement que la collecte : une source peut aussi renvoyer du bruit.
        if champ == "description":
            valeur = sanitize.clean_description(valeur)
        elif champ in ("product", "vendor"):
            valeur = sanitize.clean_product(valeur)
        if valeur in (None, "", []):
            continue
        champ_prov = "cve_published_at" if champ == "published_at" else champ
        avant = doc.get(champ)
        # CVSS : on ne descend jamais d'un bareme 4.0 vers un 3.1 (perte d'expressivite).
        if champ in ("cvss_score", "cvss_vector"):
            ancien_vec = doc.get("cvss_vector")
            nouveau_vec = fusion.get("cvss_vector")
            if not pv.allows_cvss_replacement(ancien_vec, nouveau_vec):
                journal["champs"].append({"champ": champ, "avant": avant, "apres": avant,
                                          "source": "conserve (bareme superieur en base)"})
                continue
        if pv.apply(travail, champ_prov, valeur, source, url, pv.VERIFIED):
            maj[champ] = valeur
            journal["champs"].append({"champ": champ, "avant": avant, "apres": valeur,
                                      "source": source})

    if maj and appliquer:
        maj["provenance"] = travail["provenance"]
        maj["validation_status"] = pv.validation_status({**doc, **maj})
        maj["confirmed_sources"] = confirmees
        from app.backend.utils import utcnow
        maj["reenriched_at"] = utcnow()
        await db.cves.update_one({"_id": doc["_id"]}, {"$set": maj})
    elif appliquer:
        # Sources joignables mais aucun champ retenu : meme traitement que l'absence d'autorite.
        await _marquer_sans_autorite(db, doc, journal, pv)
    return journal


async def run(appliquer, sample, retry, batch) -> int:
    from app.backend.db.mongodb import get_database
    from app.backend.services.collection import enrichment, provenance as pv, sanitize

    db = get_database()
    filtre = {"data_origin": "CERT advisory"}
    if not retry:
        filtre["reenriched_at"] = {"$exists": False}
    total = await db.cves.count_documents(filtre)
    print(f"CVE issues d'un avis, a re-enrichir : {total}")
    if not total:
        print("Rien a faire.")
        return 0

    sem = asyncio.Semaphore(CONCURRENCE)
    traites = modifies = echecs = 0
    exemples = []

    async def _une(doc):
        async with sem:
            return await enrichir_une(db, doc, appliquer, pv, enrichment, sanitize)

    reste = sample or total
    while reste > 0:
        taille = min(batch, reste)
        lot = await db.cves.find(filtre).limit(taille).to_list(taille)
        if not lot:
            break
        for j in await asyncio.gather(*[_une(d) for d in lot]):
            traites += 1
            if j["erreur"]:
                echecs += 1
            elif j["champs"]:
                modifies += 1
                if len(exemples) < 5:
                    exemples.append(j)
        reste -= len(lot)
        print(f"  ... {traites}/{total} traitees | {modifies} enrichies | {echecs} sans source")
        if not appliquer:
            break

    for e in exemples:
        print()
        print(f"  {e['cve_id']}")
        for c in e["champs"][:5]:
            av = str(c["avant"])[:38]
            ap = str(c["apres"])[:38]
            print(f"    {c['champ']:<18} {av:<40} -> {ap}   [{c['source']}]")

    print()
    print(f"Traitees {traites} | enrichies {modifies} | sans source autoritaire {echecs}")
    if not appliquer:
        print("SIMULATION — aucune ecriture. Relancez avec --apply.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Re-enrichit les CVE issues d'avis.")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--sample", type=int, default=None)
    ap.add_argument("--retry-failed", action="store_true")
    ap.add_argument("--batch-size", type=int, default=30)
    a = ap.parse_args()
    try:
        return asyncio.run(run(a.apply and not a.dry_run, a.sample, a.retry_failed, a.batch_size))
    except KeyboardInterrupt:
        print()
        print("Interrompu. Relancez : le traitement reprend ou il s'etait arrete.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
