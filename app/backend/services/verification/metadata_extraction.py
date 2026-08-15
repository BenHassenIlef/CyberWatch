"""Extraction avancée des métadonnées d'une source (date de publication, organisation).

Utilisé uniquement par l'agent de vérification appelé lors de l'ajout d'une source par
l'ADMIN (niveau 2 — crédibilité). Aucune dépendance externe : parsing HTML/JSON-LD par
expressions régulières sur le corps réellement récupéré.

Chaque extraction renvoie une structure typée :

    {"value": "2026-07-22", "source": "text_extraction", "confidence": 0.8, "raw": "22 juillet 2026"}

`source` (méthode de détection) ∈ {html_metadata, json_ld, text_extraction, domain_mapping}.
"""
import json
import re
from datetime import date, datetime, timezone

# --------------------------------------------------------------------------------------
# Correspondance domaine -> organisation officielle (méthode domain_mapping, confiance forte)
# --------------------------------------------------------------------------------------
ORG_DOMAIN_MAP = {
    "cert.ssi.gouv.fr": "CERT-FR / ANSSI",
    "ssi.gouv.fr": "ANSSI",
    "msrc.microsoft.com": "Microsoft Security Response Center",
    "microsoft.com": "Microsoft",
    "nvd.nist.gov": "NIST National Vulnerability Database",
    "nist.gov": "NIST",
    "cisa.gov": "Cybersecurity and Infrastructure Security Agency",
    "cve.org": "MITRE CVE Program",
    "mitre.org": "MITRE",
    "talosintelligence.com": "Cisco Talos",
    "cisco.com": "Cisco",
    "fortinet.com": "Fortinet",
    "paloaltonetworks.com": "Palo Alto Networks",
    "crowdstrike.com": "CrowdStrike",
    "sentinelone.com": "SentinelOne",
    "rapid7.com": "Rapid7",
    "tenable.com": "Tenable",
    # CERT nationaux / organismes gouvernementaux.
    "ancs.tn": "ANCS — Agence Nationale de la Cybersécurité (Tunisie)",
    "tuncert.tn": "TunCERT — CERT national tunisien (ANCS)",
    "cert.europa.eu": "CERT-EU",
}

# Organisations reconnues à rechercher dans le contenu (méthode text_extraction).
KNOWN_ORGS = [
    "CERT-FR", "ANSSI", "Microsoft Security Response Center", "MSRC",
    "NIST", "CISA", "MITRE", "Cisco Talos", "Fortinet", "Palo Alto Networks",
    "CrowdStrike", "SentinelOne", "Rapid7", "Tenable",
]

# --------------------------------------------------------------------------------------
# Dates : dictionnaires de mois et expressions régulières
# --------------------------------------------------------------------------------------
MONTHS_FR = {
    "janvier": 1, "février": 2, "fevrier": 2, "mars": 3, "avril": 4, "mai": 5, "juin": 6,
    "juillet": 7, "août": 8, "aout": 8, "septembre": 9, "octobre": 10, "novembre": 11,
    "décembre": 12, "decembre": 12,
}
MONTHS_EN = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6, "july": 7,
    "august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
}

ISO_RE = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})(?!\d)")
DMY_RE = re.compile(r"\b(\d{1,2})[/.](\d{1,2})[/.](\d{4})\b")
FR_TEXT_RE = re.compile(r"\b(\d{1,2})\s+([A-Za-zàâçéèêëîïôûùüÿ]+)\s+(\d{4})\b")
EN_TEXT_RE = re.compile(r"\b([A-Za-z]+)\s+(\d{1,2}),?\s+(\d{4})\b")
# Amorces de date visible ("Publié le…", "Publication :", "Published on…").
DATE_CUE_RE = re.compile(
    r"(?:publi[ée]\s+le|publication\s*:?|mis\s+à\s+jour\s+le|published\s+on|last\s+updated)\s*[:\-]?\s*(.{0,40})",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------------------
# Parsing HTML sans dépendance
# --------------------------------------------------------------------------------------

def _iter_meta(body: str):
    """Itère sur les balises <meta> en renvoyant leurs attributs (clé en minuscule)."""
    for tag in re.findall(r"<meta\b[^>]*>", body, re.IGNORECASE):
        attrs = dict(re.findall(r'([a-zA-Z:_-]+)\s*=\s*"([^"]*)"', tag))
        attrs.update(dict(re.findall(r"([a-zA-Z:_-]+)\s*=\s*'([^']*)'", tag)))
        yield {k.lower(): v for k, v in attrs.items()}


def _meta_content(body: str, keys: set[str]) -> str | None:
    """Contenu de la 1re balise meta dont name/property/itemprop ∈ keys."""
    for a in _iter_meta(body):
        ident = (a.get("name") or a.get("property") or a.get("itemprop") or "").lower()
        if ident in keys and a.get("content"):
            return a["content"].strip()
    return None


def _iter_jsonld(body: str):
    """Itère sur les objets JSON-LD (<script type='application/ld+json'>), y compris @graph."""
    for block in re.findall(r"<script[^>]+application/ld\+json[^>]*>(.*?)</script>", body, re.IGNORECASE | re.DOTALL):
        try:
            data = json.loads(block.strip())
        except (ValueError, TypeError):
            continue
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict):
                continue
            yield item
            graph = item.get("@graph")
            if isinstance(graph, list):
                for g in graph:
                    if isinstance(g, dict):
                        yield g


def _strip_tags(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text)


# --------------------------------------------------------------------------------------
# Normalisation de date -> "YYYY-MM-DD"
# --------------------------------------------------------------------------------------

def normalize_date(raw: str | None) -> str | None:
    """Convertit une chaîne de date (ISO, jj/mm/aaaa, texte FR/EN) en 'YYYY-MM-DD'."""
    if not raw:
        return None
    text = raw.strip()

    # 1) ISO (éventuellement avec heure : 2026-07-22T10:00:00Z)
    m = ISO_RE.search(text)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if _valid(y, mo, d):
            return f"{y:04d}-{mo:02d}-{d:02d}"

    # 2) jj/mm/aaaa ou jj.mm.aaaa
    m = DMY_RE.search(text)
    if m:
        d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if _valid(y, mo, d):
            return f"{y:04d}-{mo:02d}-{d:02d}"

    # 3) Texte français : "22 juillet 2026"
    m = FR_TEXT_RE.search(text)
    if m and m.group(2).lower() in MONTHS_FR:
        d, mo, y = int(m.group(1)), MONTHS_FR[m.group(2).lower()], int(m.group(3))
        if _valid(y, mo, d):
            return f"{y:04d}-{mo:02d}-{d:02d}"

    # 4) Texte anglais : "July 22, 2026"
    m = EN_TEXT_RE.search(text)
    if m and m.group(1).lower() in MONTHS_EN:
        mo, d, y = MONTHS_EN[m.group(1).lower()], int(m.group(2)), int(m.group(3))
        if _valid(y, mo, d):
            return f"{y:04d}-{mo:02d}-{d:02d}"

    return None


def _valid(year: int, month: int, day: int) -> bool:
    return 1900 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31


# --------------------------------------------------------------------------------------
# Extraction de la date de publication
# --------------------------------------------------------------------------------------

def extract_publication_date(body: str | None) -> dict | None:
    """Cherche la date dans : JSON-LD, métadonnées HTML, texte visible, format ISO.

    Renvoie {value, source, confidence, raw} ou None si aucune date exploitable.
    """
    if not body:
        return None

    # a) JSON-LD datePublished / dateCreated (le plus fiable).
    for obj in _iter_jsonld(body):
        for key in ("datePublished", "dateCreated", "dateModified"):
            if obj.get(key):
                norm = normalize_date(str(obj[key]))
                if norm:
                    return {"value": norm, "source": "json_ld", "confidence": 0.95, "raw": str(obj[key])}

    # b) Métadonnées HTML.
    meta_keys = {"article:published_time", "date", "dcterms.date", "datepublished", "dc.date", "pubdate"}
    meta_val = _meta_content(body, meta_keys)
    if meta_val:
        norm = normalize_date(meta_val)
        if norm:
            return {"value": norm, "source": "html_metadata", "confidence": 0.9, "raw": meta_val}

    # c) Texte visible avec amorce ("Publié le 22 juillet 2026", "Published on July 22, 2026").
    visible = _strip_tags(body)
    cue = DATE_CUE_RE.search(visible)
    if cue:
        norm = normalize_date(cue.group(1))
        if norm:
            return {"value": norm, "source": "text_extraction", "confidence": 0.8, "raw": cue.group(1).strip()}

    # d) Date en clair dans le texte (français, anglais, ISO) sans amorce.
    for regex in (FR_TEXT_RE, EN_TEXT_RE, DMY_RE, ISO_RE):
        m = regex.search(visible)
        if m:
            norm = normalize_date(m.group(0))
            if norm:
                return {"value": norm, "source": "text_extraction", "confidence": 0.7, "raw": m.group(0)}

    return None


# --------------------------------------------------------------------------------------
# Extraction de l'organisation / auteur
# --------------------------------------------------------------------------------------

def _host_matches(host: str, domain: str) -> bool:
    host = host.lower().strip(".")
    domain = domain.lower().strip(".")
    return host == domain or host.endswith("." + domain)


def extract_organization(body: str | None, host: str | None) -> dict | None:
    """Cherche l'organisation dans : mapping de domaine, JSON-LD, métadonnées, contenu.

    Renvoie {value, source, confidence} ou None.
    """
    # a) Mapping de domaine officiel (le plus fiable). Le plus long domaine gagne.
    if host:
        best = None
        for domain, org in ORG_DOMAIN_MAP.items():
            if _host_matches(host, domain) and (best is None or len(domain) > len(best[0])):
                best = (domain, org)
        if best:
            return {"value": best[1], "source": "domain_mapping", "confidence": 0.95}

    if body:
        # b) JSON-LD publisher.name / author.name.
        for obj in _iter_jsonld(body):
            for key in ("publisher", "author", "sourceOrganization"):
                node = obj.get(key)
                name = None
                if isinstance(node, dict):
                    name = node.get("name")
                elif isinstance(node, str):
                    name = node
                elif isinstance(node, list) and node:
                    first = node[0]
                    name = first.get("name") if isinstance(first, dict) else (first if isinstance(first, str) else None)
                if name:
                    return {"value": name.strip(), "source": "json_ld", "confidence": 0.9}

        # c) Métadonnées HTML.
        meta_val = _meta_content(body, {"author", "publisher", "og:site_name", "dc.publisher", "application-name"})
        if meta_val:
            return {"value": meta_val, "source": "html_metadata", "confidence": 0.8}

        # d) Contenu : organisation reconnue mentionnée dans la page.
        for org in KNOWN_ORGS:
            if re.search(r"\b" + re.escape(org) + r"\b", body, re.IGNORECASE):
                return {"value": org, "source": "text_extraction", "confidence": 0.7}

    return None


def extract_title(body: str | None) -> str | None:
    """Titre de la page : og:title, JSON-LD headline, <title>, <h1>."""
    if not body:
        return None
    meta_val = _meta_content(body, {"og:title", "twitter:title"})
    if meta_val:
        return meta_val
    for obj in _iter_jsonld(body):
        if obj.get("headline"):
            return str(obj["headline"]).strip()
        if obj.get("name") and obj.get("@type") in ("Article", "NewsArticle", "Report", "WebPage"):
            return str(obj["name"]).strip()
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip() or None
    m = re.search(r"<h1[^>]*>(.*?)</h1>", body, re.IGNORECASE | re.DOTALL)
    if m:
        return re.sub(r"\s+", " ", _strip_tags(m.group(1))).strip() or None
    return None


# Libellés lisibles pour la méthode de détection (affichés dans le rapport admin).
METHOD_LABELS = {
    "html_metadata": "Métadonnées HTML",
    "json_ld": "JSON-LD",
    "text_extraction": "Extraction depuis texte visible",
    "domain_mapping": "Mapping domaine officiel",
}


def method_label(source: str | None) -> str:
    return METHOD_LABELS.get(source, source or "inconnu")


def published_today(body: str | None, today: date | None = None) -> bool:
    """La date du jour apparaît-elle dans le contenu (source publiant aujourd'hui) ?

    Cherche la date d'aujourd'hui sous ses formes courantes : ISO (2026-07-24),
    jj/mm/aaaa (24/07/2026), texte français (« 24 juillet 2026 ») et anglais
    (« July 24, 2026 »). Sert à vérifier qu'une source est active aujourd'hui.
    """
    if not body:
        return False
    today = today or datetime.now(timezone.utc).date()

    month_en = {v: k for k, v in MONTHS_EN.items()}
    d, m, y = today.day, today.month, today.year
    fr_name = {1: "janvier", 2: "février", 3: "mars", 4: "avril", 5: "mai", 6: "juin",
               7: "juillet", 8: "août", 9: "septembre", 10: "octobre", 11: "novembre", 12: "décembre"}[m]
    en_name = month_en[m].capitalize()

    candidates = [
        f"{y:04d}-{m:02d}-{d:02d}",           # ISO
        f"{d:02d}/{m:02d}/{y:04d}",           # jj/mm/aaaa
        f"{d}/{m}/{y}",                        # j/m/aaaa
        f"{d} {fr_name} {y}",                  # 24 juillet 2026
        f"{en_name} {d}, {y}",                 # July 24, 2026
        f"{en_name} {d} {y}",                  # July 24 2026
    ]
    low = body.lower()
    return any(c.lower() in low for c in candidates)
