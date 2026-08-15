"""Découverte GÉNÉRIQUE de la structure d'un site de bulletins de sécurité.

Objectif : décider, SANS aucune liste d'hôtes codée en dur, si une page fournie est une
PAGE LISTE d'un portail « liste → détail » (CERT nationaux, portails d'avis, blogs sécurité,
éditeurs…), en combinant des signaux structurels host-agnostiques :

  1. La page liste contient peu / pas de CVE.
  2. Elle référence plusieurs liens INTERNES vers des pages détail (motif de chemin « rubrique
     d'avis » et/ou ancres « En savoir plus / Lire la suite / Read more / المزيد »).
  3. Présence éventuelle d'une pagination (?page=, rel="next", pagination numérotée).
  4. PREUVE : on échantillonne quelques pages enfants ; si elles contiennent des CVE (ou une
     section d'identifiants), c'est un portail deux niveaux. On EXPLORE avant de conclure
     « aucune CVE » (exigence : ne jamais considérer une page liste comme un échec).

Ce module est réutilisable par le collecteur (routage) ET par la vérification (Phase 2). Il ne
dépend d'aucun site particulier : ajouter une nouvelle source ne nécessite aucun code dédié.
"""
import html as _html
import logging
import re
from urllib.parse import urljoin, urlparse

from app.backend.services.collection.schema import CVE_RE

logger = logging.getLogger("cyberwatch.collection.structure")

_TAG_RE = re.compile(r"<[^>]+>")
# Ancre <a href="…">texte</a> (texte capturé pour repérer « en savoir plus »).
_ANCHOR_RE = re.compile(r'<a\b[^>]*?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.S)

# Libellés « en savoir plus » multilingues (FR / EN / AR).
READ_MORE_RE = re.compile(
    r"(en\s+savoir\s+plus|lire\s+la\s+suite|voir\s+(?:plus|le\s+bulletin|l['’]avis)|"
    r"plus\s+de\s+d[ée]tails?|consulter(?:\s+(?:le\s+bulletin|l['’]avis))?|d[ée]tails?|"
    r"read\s+more|learn\s+more|view\s+(?:more|details|advisory|bulletin)|more\s+info|"
    r"المزيد|اقرأ\s+المزيد|التفاصيل|تفاصيل)",
    re.I,
)
# Segment de chemin d'une page DÉTAIL d'avis (générique, multi-CERT / multi-portail).
ADVISORY_PATH_RE = re.compile(
    r"/(?:bulletins?|bulletin[-_]?d\w*|vulnerabilit\w*|vuln\w*|advisor\w*|avis|alert\w*|"
    r"security[-_]?(?:advisor\w*|bulletin\w*|note\w*|update\w*)|cve\w*|note[-_]?d\w*|"
    r"actualit\w*|publications?|node)/[^/]{3,}/?$",
    re.I,
)
# Chemins de navigation / social à EXCLURE (ne sont pas des bulletins).
_NAV_STOP = re.compile(
    r"/(?:login|signin|sign-in|account|compte|contact|about|apropos|a-propos|mentions|"
    r"search|recherche|tag|tags|category|categorie|categories|rss|feed|flux|sitemap|"
    r"privacy|confidentialite|cookies|newsletter|share|partager|facebook|twitter|x|"
    r"linkedin|youtube|instagram|whatsapp|t\.me)(?:/|$|\?|#)",
    re.I,
)
_PAGINATION_QS = re.compile(r"[?&](?:page|p|start|offset|pg)=\d+", re.I)
_REL_NEXT_RE = re.compile(r'<(?:a|link)\b[^>]*\brel=["\'][^"\']*\bnext\b', re.I)

# Seuils de décision.
MIN_DETAIL_LINKS = 3   # nb min de liens de détail pour parler de « page liste »
MAX_LISTING_CVE = 2    # au-delà, la page liste expose déjà les CVE → collecte simple niveau 1
FLAT_LIST_MIN_CVE = 10  # une page qui expose DÉJÀ ≥ N CVE est une LISTE PLATE (agrégateur) → harvest
SAMPLE_CHILDREN = 2    # nb de pages enfants échantillonnées pour la preuve


def _clean(html_fragment: str) -> str:
    return re.sub(r"\s+", " ", _html.unescape(_TAG_RE.sub(" ", html_fragment or ""))).strip()


def _norm_host(host: str | None) -> str:
    """Hôte normalisé pour comparer « même site » (retire « www. » et un point de tête)."""
    return (host or "").lower().lstrip(".").removeprefix("www.")


def _same_site(link_host: str | None, base_host: str | None) -> bool:
    """Le lien appartient-il au MÊME site (gère www/non-www et sous-domaines) ?"""
    a, b = _norm_host(link_host), _norm_host(base_host)
    if not a or not b:
        return False
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def count_cves(text: str) -> int:
    """Nombre de CVE DISTINCTES dans un texte (regex robuste CVE-\\d{4}-\\d{4,7})."""
    return len({m.group(0).upper() for m in CVE_RE.finditer(text or "")})


def candidate_links(body: str, base_url: str, host: str) -> list[str]:
    """Liens INTERNES vers des pages détail (générique, sans dédié par site).

    Retenus si : enfant du chemin de la page liste, OU chemin « rubrique d'avis » (ADVISORY_PATH_RE),
    OU ancre « en savoir plus ». Exclut les liens externes, la navigation et la pagination.
    """
    base_parts = urlparse(base_url)
    base_host = host or base_parts.hostname
    base_path = base_parts.path.rstrip("/")
    links: list[str] = []
    seen: set[str] = set()
    for href, inner in _ANCHOR_RE.findall(body or ""):
        absu = urljoin(base_url, href)
        p = urlparse(absu)
        if not _same_site(p.hostname, base_host):
            continue  # liens INTERNES uniquement (www/non-www = même site)
        path = p.path.rstrip("/")
        if not path or path == base_path or _NAV_STOP.search(path):
            continue
        if _PAGINATION_QS.search(absu):
            continue  # c'est de la pagination, pas un bulletin
        text = _clean(inner)
        child_of_listing = bool(base_path) and path.startswith(base_path + "/") and len(path) > len(base_path) + 1
        matches_path = bool(ADVISORY_PATH_RE.search(path))
        read_more = bool(READ_MORE_RE.search(text)) and len((path.split("/")[-1] or "")) >= 4
        if child_of_listing or matches_path or read_more:
            # Normalise www<->non-www vers l'hôte de BASE (accès httpx cohérent, dédup www/non-www).
            netloc = base_parts.netloc if _norm_host(p.hostname) == _norm_host(base_host) else p.netloc
            clean = f"{p.scheme}://{netloc}{p.path}"  # sans query ni fragment
            if clean not in seen:
                seen.add(clean)
                links.append(clean)
    return links


def has_pagination(body: str, base_url: str) -> bool:
    if _REL_NEXT_RE.search(body or "") or _PAGINATION_QS.search(base_url or ""):
        return True
    return any(_PAGINATION_QS.search(href) for href, _ in _ANCHOR_RE.findall(body or ""))


def analyze_listing(body: str, base_url: str, host: str) -> dict:
    """Signaux structurels (synchrones, sans réseau) d'une page potentiellement « liste »."""
    return {
        "cve_on_listing": count_cves(body),
        "candidate_links": candidate_links(body, base_url, host),
        "has_pagination": has_pagination(body, base_url),
        "has_read_more": bool(READ_MORE_RE.search(_clean(body))),
    }


async def detect_two_level(body: str, base_url: str, host: str, fetch_child) -> dict:
    """Décide si (base_url, body) est un portail « liste → détail » (générique + preuve enfant).

    `fetch_child(url) -> html` : coroutine de récupération d'une page enfant (échantillonnage).
    Renvoie un rapport détaillé (utilisé pour les logs et la décision de routage).
    """
    a = analyze_listing(body, base_url, host)
    links = a["candidate_links"]
    report = {
        "is_two_level": False, "confidence": "none",
        "cve_on_listing": a["cve_on_listing"], "candidate_links": len(links),
        "has_pagination": a["has_pagination"], "has_read_more": a["has_read_more"],
        "sampled": 0, "sample_cves": 0, "reason": "",
    }

    # 0) La page expose DÉJÀ de nombreux CVE (agrégateur / liste plate type secalerts, cvefind) :
    #    on ne descend PAS en deux niveaux (qui suivrait des liens de catégorie et raterait les CVE
    #    récents affichés en tête). La collecte SIMPLE récupère directement les CVE visibles.
    if a["cve_on_listing"] >= FLAT_LIST_MIN_CVE:
        report["reason"] = (f"Liste PLATE : {a['cve_on_listing']} CVE directement sur la page "
                            f"→ collecte simple (harvest des CVE visibles, dont les plus récents).")
        logger.info("[structure] %s : %s", host, report["reason"])
        return report

    # 1) Peu de liens de détail : ce n'est pas une page « liste → détail ».
    #    Si en plus la page contient déjà des CVE, c'est une liste PLATE → collecte simple niveau 1.
    if len(links) < MIN_DETAIL_LINKS:
        if a["cve_on_listing"] > MAX_LISTING_CVE:
            report["reason"] = (f"Liste plate : {a['cve_on_listing']} CVE directement sur la page et "
                                f"seulement {len(links)} lien(s) de détail → collecte simple niveau 1.")
        else:
            report["reason"] = (f"Seulement {len(links)} lien(s) de détail candidat(s) "
                                f"(< {MIN_DETAIL_LINKS}) → pas un portail « liste → détail ».")
        logger.info("[structure] %s : %s", host, report["reason"])
        return report

    # 2) BEAUCOUP de liens de détail → page liste probable, MÊME si quelques CVE y sont intégrées
    #    (certains portails affichent le dernier bulletin en pleine page). On confirme par preuve.
    # 3) PREUVE : on explore quelques enfants AVANT de conclure (exigence : ne jamais conclure
    #    « aucune CVE » sur la seule page liste).
    sample_cves = 0
    sampled = 0
    for child_url in links[:SAMPLE_CHILDREN]:
        try:
            child = await fetch_child(child_url)
            sampled += 1
            n = count_cves(child or "")
            sample_cves += n
            logger.info("[structure] %s : échantillon %s → %d CVE.", host, child_url, n)
            if n:
                break  # une preuve suffit
        except Exception as exc:  # noqa: BLE001 - échantillonnage best-effort
            logger.warning("[structure] %s : échec échantillon %s : %s", host, child_url, str(exc)[:90])
    report["sampled"] = sampled
    report["sample_cves"] = sample_cves

    if sample_cves > 0:
        report.update(is_two_level=True, confidence="high",
                      reason=(f"Page liste sans CVE mais {len(links)} lien(s) de détail ; "
                              f"un échantillon enfant contient {sample_cves} CVE "
                              f"→ portail d'avis DEUX NIVEAUX confirmé."))
    elif len(links) >= MIN_DETAIL_LINKS and a["has_pagination"]:
        # Structure très marquée (beaucoup de liens + pagination) mais échantillon sans CVE :
        # on explore quand même (les CVE peuvent être plus bas dans la liste / en PDF).
        report.update(is_two_level=True, confidence="medium",
                      reason=(f"Aucune CVE dans l'échantillon, mais structure « liste → détail » "
                              f"marquée ({len(links)} liens + pagination) → exploration deux niveaux."))
    else:
        report["reason"] = (f"Structure ambiguë ({len(links)} liens, pagination="
                            f"{a['has_pagination']}) et échantillon sans CVE → collecte simple.")
    logger.info("[structure] %s : décision=%s (%s) — %s",
                host, report["is_two_level"], report["confidence"], report["reason"])
    return report
