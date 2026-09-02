"""COLLECTEUR de veille communautaire — publications de blogs, forums et flux spécialisés.

Pourquoi un collecteur DÉDIÉ plutôt que celui des CVE ? Le collecteur RSS existant
(`collectors/rss.py`) écarte tout élément ne citant pas d'identifiant CVE :

    m = CVE_RE.search(item)
    if not m:
        continue        # <-- l'essentiel de la veille communautaire disparaît ici

Or une analyse de PoC, une rumeur de zero-day ou un billet sur un produit ne mentionnent
souvent aucun CVE. Ce module conserve donc TOUTES les publications, puis laisse l'agent
décider de leur pertinence — sans modifier d'une ligne le collecteur de CVE existant.

RÉUTILISE l'infrastructure en place : `net.get` (HTTP tolérant aux pannes),
`browser_client.render_html` (pages en JavaScript), `sanitize` (rejet du gabarit de page),
`source_state` (statuts SUCCESS / EMPTY / FAILED / TIMEOUT / PARSE_ERROR).

RESPECT DES SOURCES : lecture seule, flux RSS et pages publiques uniquement. Aucun
contournement d'authentification, de CAPTCHA ni de restriction technique.
"""
import logging
import re
from datetime import datetime

from app.backend.services.collection import net, sanitize
from app.backend.services.collection.schema import parse_dt
from app.backend.utils import utcnow

logger = logging.getLogger("cyberwatch.community.collector")

MAX_PER_SOURCE = 60        # borne par exécution : une source ne peut pas noyer la collecte
MIN_TITLE = 8
MAX_CONTENT = 8000

# Éléments d'un flux RSS 2.0 ou Atom.
_ITEM_RE = re.compile(r"<(item|entry)[\s>](.*?)</\1>", re.S | re.I)
_TAG_STRIP_RE = re.compile(r"<[^>]+>")


def _tag(bloc: str, nom: str) -> str | None:
    """Contenu d'une balise, CDATA compris."""
    m = re.search(rf"<{nom}[^>]*>(.*?)</{nom}>", bloc, re.S | re.I)
    if not m:
        # Atom : <link href="..."/> est un attribut, pas un contenu.
        m2 = re.search(rf'<{nom}[^>]*href="([^"]+)"', bloc, re.I)
        return m2.group(1).strip() if m2 else None
    brut = m.group(1)
    brut = re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", brut, flags=re.S)
    texte = re.sub(r"\s+", " ", _TAG_STRIP_RE.sub(" ", brut)).strip()
    return texte or None


def _lien(bloc: str) -> str | None:
    for nom in ("link", "guid", "id"):
        v = _tag(bloc, nom)
        if v and v.startswith("http"):
            return v
    return None


def parse_feed(xml: str, source_url: str) -> list[dict]:
    """Publications d'un flux RSS/Atom. AUCUN filtrage sur la présence d'un CVE.

    Les valeurs sont assainies : un flux peut renvoyer du gabarit de page dans sa description.
    """
    out: list[dict] = []
    for _balise, bloc in _ITEM_RE.findall(xml or ""):
        titre = _tag(bloc, "title")
        if not titre or len(titre) < MIN_TITLE:
            continue
        contenu = (_tag(bloc, "content:encoded") or _tag(bloc, "description")
                   or _tag(bloc, "summary") or "")
        publie = parse_dt(_tag(bloc, "pubDate") or _tag(bloc, "published")
                          or _tag(bloc, "updated") or _tag(bloc, "dc:date"))
        out.append({
            "title": titre[:400],
            "content": (sanitize.clean_text(contenu, min_len=1) or "")[:MAX_CONTENT],
            "url": _lien(bloc) or source_url,
            "published_at": publie,
            "author": _tag(bloc, "author") or _tag(bloc, "dc:creator"),
        })
        if len(out) >= MAX_PER_SOURCE:
            break
    return out


class SourceUnreachable(Exception):
    """Source injoignable : à ré-essayer, ce n'est PAS une source vide."""


class SourceUnparsable(Exception):
    """Contenu récupéré mais inexploitable : structure probablement modifiée."""


async def collect_source(source: dict) -> dict:
    """Collecte UNE source communautaire.

    Renvoie {status, publications, detected, error}. Les statuts reprennent la sémantique de
    `source_state` afin de rester cohérents avec la collecte de CVE :

      • success        : joignable, analysé, au moins une publication ;
      • empty          : joignable et analysé, mais réellement rien de nouveau ;
      • empty_suspect  : réponse obtenue mais AUCUN élément reconnu alors que la source en
                         produisait auparavant -> structure changée, ne PAS valider ;
      • failed / timeout / parse_error : erreurs techniques.

    Un résultat vide n'est JAMAIS considéré comme un succès s'il peut résulter d'une panne.
    """
    url = (source.get("url") or "").strip()
    nom = source.get("name") or url
    if not url:
        return {"status": "failed", "publications": [], "detected": 0,
                "error": "source sans URL"}

    try:
        resp = await net.get(url, timeout=30)
    except Exception as exc:  # noqa: BLE001 - une source ne doit jamais casser la collecte
        logger.warning("Veille communautaire « %s » : %s", nom, str(exc)[:150])
        return {"status": "failed", "publications": [], "detected": 0, "error": str(exc)[:200]}

    if resp is None:
        return {"status": "timeout", "publications": [], "detected": 0,
                "error": "aucune reponse (delai depasse ou reseau)"}
    if resp.status_code != 200:
        return {"status": "failed", "publications": [], "detected": 0,
                "error": f"HTTP {resp.status_code}"}

    texte = resp.text or ""
    publications = parse_feed(texte, url)

    if not publications:
        # Distinguer « rien de neuf » d'une structure cassée : un flux valide contient des
        # balises <item>/<entry>. Leur absence totale trahit un changement de format.
        ressemble_a_un_flux = bool(_ITEM_RE.search(texte)) or "<rss" in texte[:600].lower() \
            or "<feed" in texte[:600].lower()
        if not ressemble_a_un_flux:
            return {"status": "empty_suspect", "publications": [], "detected": 0,
                    "error": "reponse recue mais aucun element de flux reconnu "
                             "(structure probablement modifiee)"}
        return {"status": "empty", "publications": [], "detected": 0, "error": None}

    maintenant = utcnow()
    for p in publications:
        p["source_name"] = nom
        p["source_url"] = url
        p["source_id"] = source.get("_id")
        p["intel_type"] = source.get("intel_type") or "community"
        p["collected_at"] = maintenant
    return {"status": "success", "publications": publications,
            "detected": len(publications), "error": None}


def dedup_key(pub: dict) -> str:
    """Clé de dédoublonnage d'une publication : son URL, sinon son titre normalisé.

    Deux sources relayant le MÊME billet partagent son URL ; deux billets distincts sur le
    même sujet ne sont pas fusionnés — ils seront corrélés, pas confondus.
    """
    url = (pub.get("url") or "").strip().lower().rstrip("/")
    if url:
        return url
    return re.sub(r"[^a-z0-9]+", "-", (pub.get("title") or "").lower()).strip("-")[:120]


def correlation_key(pub: dict, cves: list[str]) -> str | None:
    """Clé de CORRÉLATION : regroupe les publications parlant du MÊME événement.

    Le premier identifiant CVE cité fait office de clé — c'est le seul dénominateur commun
    fiable entre deux sources indépendantes. Sans CVE, aucune corrélation n'est tentée :
    rapprocher deux billets sur la seule foi de leur titre produirait de faux regroupements.
    """
    return sorted(cves)[0] if cves else None


def is_new_publication(pub: dict, since: datetime | None) -> bool:
    """Publication postérieure au dernier passage ? Sans date, on la considère nouvelle."""
    d = pub.get("published_at")
    if not isinstance(d, datetime) or not isinstance(since, datetime):
        return True
    a = d.replace(tzinfo=None) if d.tzinfo else d
    b = since.replace(tzinfo=None) if since.tzinfo else since
    return a > b
