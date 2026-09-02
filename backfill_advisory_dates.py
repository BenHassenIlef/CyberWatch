"""RATTRAPAGE de la date de publication des AVIS (`advisory_published_at`).

Contexte : le collecteur d'avis renseigne désormais `advisory_published_at`, mais les CVE
collectées AVANT ce correctif ne l'ont pas. Or c'est la donnée qui réconcilie l'écran :

    Page d'origine                : https://dgssi.gov.ma/.../vulnerabilite-affectant-docker-desktop-0
    Date de publication de l'AVIS : 12 août 2026   <-- manquante
    Date de publication de la CVE : 18 août 2026   (MITRE, vérifiée)
    Date de collecte              : 12 août 2026

Sans la ligne du milieu, l'utilisateur voit une CVE « publiée après avoir été collectée »
sans comprendre pourquoi.

MÉTHODE — relit la page d'avis et en extrait la date, en réutilisant l'analyseur existant
(`advisory._fetch` + `advisory.parse_advisory`). Aucune logique d'extraction dupliquée.

GARANTIES
  • GÉNÉRIQUE   : aucun identifiant de CVE, aucune URL, aucune date en dur.
  • ÉCONOME     : une page = UNE requête, quel que soit le nombre de CVE qu'elle cite.
  • NON DESTRUCTIF : n'écrit QUE `advisory_published_at`. Ne touche jamais `published_at`,
    ni aucun champ factuel de la CVE.
  • IDEMPOTENT  : `advisory_date_backfilled` marque les pages traitées ; une relance les ignore.
  • REPRENABLE  : interruption sans perte.
  • RIEN D'INVENTÉ : page illisible ou sans date -> on marque comme traité, on n'invente pas.

    python backfill_advisory_dates.py                # SIMULATION
    python backfill_advisory_dates.py --apply
    python backfill_advisory_dates.py --apply --limit 20
"""
import argparse
import asyncio
import os
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

CONCURRENCE = 3        # pages lues simultanément (courtoisie envers les portails)


def _naive(d):
    return d.replace(tzinfo=None) if isinstance(d, datetime) and d.tzinfo else d


async def _date_de_l_avis(url: str):
    """Date de publication lue sur la page d'avis, ou None. Ne lève jamais."""
    from app.backend.services.collection.collectors import advisory

    try:
        html = await advisory._fetch(url, expect_cve=False)
    except Exception:  # noqa: BLE001 - page injoignable : on n'invente pas de date
        return None
    if not html:
        return None
    try:
        adv = advisory.parse_advisory(html, url)
    except Exception:  # noqa: BLE001 - structure inattendue
        return None
    return _naive(adv.get("published_at"))


async def run(appliquer: bool, limite: int | None) -> int:
    from app.backend.db.mongodb import get_database

    db = get_database()
    # Une page d'avis cite souvent des dizaines de CVE : on regroupe par URL pour ne la
    # télécharger QU'UNE FOIS.
    filtre = {"data_origin": "CERT advisory",
              "advisory_published_at": None,
              "advisory_date_backfilled": {"$ne": True}}
    urls = await db.cves.distinct("detail_url", filtre)
    urls = [u for u in urls if isinstance(u, str) and u.startswith("http")]
    if limite:
        urls = urls[:limite]

    total_cves = await db.cves.count_documents(filtre)
    print(f"CVE sans date d'avis : {total_cves}")
    print(f"Pages d'avis à relire : {len(urls)}  (une requête par page)")
    if not urls:
        print("Rien à faire.")
        return 0

    sem = asyncio.Semaphore(CONCURRENCE)
    trouvees = introuvables = cves_maj = 0
    exemples = []

    async def _une(url: str):
        nonlocal trouvees, introuvables, cves_maj
        async with sem:
            date = await _date_de_l_avis(url)
        concernees = await db.cves.count_documents({**filtre, "detail_url": url})
        if date is None:
            introuvables += 1
            if appliquer:
                # Marqué quand même : la page a été essayée, inutile d'y revenir sans fin.
                await db.cves.update_many({**filtre, "detail_url": url},
                                          {"$set": {"advisory_date_backfilled": True}})
            return
        trouvees += 1
        cves_maj += concernees
        if len(exemples) < 6:
            exemples.append((url, date, concernees))
        if appliquer:
            await db.cves.update_many(
                {**filtre, "detail_url": url},
                {"$set": {"advisory_published_at": date, "advisory_date_backfilled": True}})

    lot = 20
    for i in range(0, len(urls), lot):
        await asyncio.gather(*[_une(u) for u in urls[i:i + lot]])
        print(f"  ... {min(i + lot, len(urls))}/{len(urls)} pages | "
              f"{trouvees} datées | {introuvables} sans date | {cves_maj} CVE concernées")

    print()
    for url, date, n in exemples:
        print(f"  {str(date)[:10]}  <- {url[:76]}")
        print(f"     applique a {n} CVE de cet avis")

    print()
    print(f"Pages datées : {trouvees} | sans date exploitable : {introuvables}")
    print(f"CVE recevant une date d'avis : {cves_maj}")
    if not appliquer:
        print("SIMULATION — aucune écriture. Relancez avec --apply.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Rattrape la date de publication des avis.")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args()
    try:
        return asyncio.run(run(a.apply, a.limit))
    except KeyboardInterrupt:
        print("\nInterrompu. Relancez : le rattrapage reprend où il s'était arrêté.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
