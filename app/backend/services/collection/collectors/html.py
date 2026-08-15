"""Collecteur HTML Scraping : extrait les identifiants CVE réels de la page (rendu navigateur
si nécessaire). Si la page de LISTE contient des liens vers des pages de DÉTAIL de
vulnérabilités, on suit ces liens (même domaine, borné) pour extraire les CVE des pages
enfants — car certaines sources (CERT nationaux…) n'affichent le CVE que sur la page détail.
Ensuite les champs canoniques sont récupérés par enrichissement (NVD/MITRE…). Aucune fabrication."""
import logging
import re
from urllib.parse import urljoin, urlparse

from app.backend.services.collection import net
from app.backend.services.collection.collectors.base import register, target_url, host_of
from app.backend.services.collection.schema import CVE_RE, new_record, detail_url_for
from app.backend.services.verification import browser_client

logger = logging.getLogger("cyberwatch.collection.html")

MAX_PER_SOURCE = 60      # borné : chaque CVE nécessite une requête NVD (débit)
FOLLOW_MAX = 20          # nb max de pages de détail suivies par collecte
# Si la page de LISTE expose déjà au moins ce nombre de CVE, c'est un agrégateur « liste plate »
# (cvemon, cvefind, secalerts…) : les identifiants sont déjà là et l'enrichissement (NVD/MITRE)
# complète les champs. On NE suit alors AUCUNE page de détail — c'était la cause des timeouts
# (jusqu'à 20 rendus navigateur par source, × N sources en parallèle). Le suivi de détail reste
# réservé aux portails dont la liste n'affiche PAS les CVE (CERT nationaux → crawl deux niveaux).
FOLLOW_IF_FEWER_THAN = 3
# Budget de rendus navigateur PAR SOURCE : empêche qu'UNE source mal configurée (ex. une page
# d'accueil SPA sans CVE) ne lance des dizaines de rendus et ne monopolise le pool Chromium
# partagé (famine des autres sources → timeouts en cascade). Au-delà, on se contente du HTML brut.
RENDER_BUDGET_PER_SOURCE = 6
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
# Un lien qui ressemble à une page de détail de vulnérabilité (générique, multi-CERT).
_DETAIL_HINT = re.compile(r"vuln|cve|detail|advisor|bulletin|alert|node/\d+|/\d{3,}", re.IGNORECASE)


def _detail_links(body: str, base_url: str, host: str) -> list[str]:
    """Liens de détail candidats, sur le MÊME domaine que la source."""
    links: list[str] = []
    for href in _HREF_RE.findall(body):
        absu = urljoin(base_url, href)
        if not absu.startswith("http"):
            continue
        if (urlparse(absu).hostname or "").lower() != host:
            continue  # jamais quitter le domaine de la source
        if absu == base_url or absu in links:
            continue
        if _DETAIL_HINT.search(absu):
            links.append(absu)
    return links


async def _extract_from_page(url: str, budget: list | None = None) -> str:
    """Récupère le HTML d'une page (avec rendu navigateur si contenu dynamique).

    `budget` : liste mutable [n] du nombre de rendus restants pour la SOURCE. On ne rend au
    navigateur que s'il reste du budget — au-delà, on se contente du HTML brut (protège le pool
    Chromium partagé d'une source mal configurée qui multiplierait les rendus)."""
    resp = await net.get(url)
    body = resp.text if (resp is not None and resp.status_code == 200) else ""
    if not CVE_RE.search(body) and (budget is None or budget[0] > 0):
        if budget is not None:
            budget[0] -= 1
        rendered = await browser_client.render_html(url)
        body = rendered or body
    return body


@register("html", "scraping")
async def collect(source: dict, since) -> list[dict]:
    from app.backend.services.collection import structure_detector  # import tardif (évite un cycle)
    from app.backend.services.collection.collectors import advisory

    url = target_url(source)
    if not url:
        return []
    host = host_of(url)

    # Portail d'avis CONNU : raccourci direct vers le crawl deux niveaux, SANS re-télécharger la
    # page liste ici (évite un rendu navigateur en double → gain de temps sous le timeout source).
    if advisory.is_known_portal_host(host):
        logger.info("[html] %s : portail d'avis connu (raccourci) → crawl deux niveaux.", host)
        recs = await advisory.crawl(source, since)
        if recs:
            return recs
        logger.info("[html] %s : crawl deux niveaux sans résultat → repli collecte simple niveau 1.", host)

    budget = [RENDER_BUDGET_PER_SOURCE]  # nb de rendus navigateur autorisés pour CETTE source
    body = await _extract_from_page(url, budget)

    # Détection GÉNÉRIQUE « liste → détail » (host-agnostique) pour tout autre site : analyse
    # structurelle prouvée par échantillonnage d'enfants — on n'assimile JAMAIS une page liste
    # sans CVE à un échec sans avoir exploré.
    if not advisory.is_known_portal_host(host):
        det = await structure_detector.detect_two_level(
            body, url, host, lambda u: advisory._fetch(u, expect_cve=True)
        )
        logger.info("[html] %s : détection structure → deux_niveaux=%s (%s) — %s",
                    host, det["is_two_level"], det["confidence"], det["reason"])
        if det["is_two_level"]:
            recs = await advisory.crawl(source, since)
            if recs:
                return recs
            logger.info("[html] %s : crawl deux niveaux sans résultat → repli collecte simple.", host)

    seen: list[str] = []

    def _harvest(text: str) -> None:
        for m in CVE_RE.finditer(text):
            cid = m.group(0).upper()
            if cid not in seen:
                seen.append(cid)

    _harvest(body)
    list_page_count = len(seen)

    # Suivre les pages de détail UNIQUEMENT si la liste n'expose (quasi) pas de CVE. Sur un
    # agrégateur qui affiche déjà les identifiants, on s'arrête ici (évite N rendus navigateur
    # inutiles → plus de timeout ; l'enrichissement complète les champs manquants).
    followed = 0
    if list_page_count < FOLLOW_IF_FEWER_THAN:
        for absu in _detail_links(body, url, host)[:FOLLOW_MAX]:
            if len(seen) >= MAX_PER_SOURCE:
                break
            child = await _extract_from_page(absu, budget)
            _harvest(child)
            followed += 1
        if followed:
            logger.info("[html] %s : %d CVE sur la liste, %d page(s) de détail suivie(s) -> %d CVE au total.",
                        url, list_page_count, followed, len(seen))
    else:
        logger.info("[html] %s : %d CVE directement sur la liste (agrégateur) → pas de suivi de détail.",
                    url, list_page_count)

    out: list[dict] = []
    for cid in seen[:MAX_PER_SOURCE]:
        rec = new_record(cid)
        rec["detail_url"] = detail_url_for(cid, host)
        rec["data_origin"] = "scraping"
        out.append(rec)
    return out
