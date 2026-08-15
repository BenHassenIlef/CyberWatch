"""Validation générique de la date de publication des CVE d'une source.

Répond réellement à la question « y a-t-il de NOUVELLES CVE publiées aujourd'hui ? »
en extrayant la date de publication de CHAQUE CVE présente dans le contenu — et non en
cherchant la date du jour n'importe où dans la page (ce qui produisait des faux positifs :
p.ex. une « Due Date » future ou un horodatage « généré le… » suffisaient à tort).

Fonctionne pour les trois méthodes de collecte, sans règle propre à un site :
  - API      : champs JSON (publishedDate, published, datePublished, created, dateAdded…)
  - RSS/Atom : balises XML (pubDate, published, dc:date, updated…)
  - Scraping : JSON-LD, métadonnées HTML, puis association date↔CVE par proximité de texte
               avec reconnaissance des amorces (« Date Added », « Published », « Publié le »…)
               et exclusion des dates d'échéance (« Due Date », « Deadline »…) et de
               modification (« Last Updated », « Modified »…).

On sépare explicitement trois dates : date de collecte (= maintenant, jamais utilisée comme
date de publication), date de PUBLICATION du CVE, et date de MODIFICATION.
"""
import json
import re
from datetime import date, datetime, timezone

from app.backend.services.verification.cve import CVE_PATTERN
from app.backend.services.verification.metadata_extraction import (
    ISO_RE,
    DMY_RE,
    FR_TEXT_RE,
    EN_TEXT_RE,
    _iter_jsonld,
    _iter_meta,
    _strip_tags,
    normalize_date,
)

# --------------------------------------------------------------------------------------
# Vocabulaire des champs / amorces de date (générique, multi-sources, FR + EN)
# --------------------------------------------------------------------------------------
# Clés JSON considérées comme une date de PUBLICATION, par ordre de préférence.
JSON_PUBLISH_KEYS = [
    "publisheddate", "datepublished", "published", "date_published",
    "pubdate", "dateadded", "date_added", "created", "datecreated",
    "date", "dc:date", "disclosuredate", "releasedate",
]
JSON_MODIFIED_KEYS = ["lastmodified", "datemodified", "modified", "updated", "dateupdated"]

# Clés indiquant l'identifiant CVE dans un objet JSON.
JSON_CVE_KEYS = ["cveid", "cve_id", "cve", "id", "name", "identifier"]

# Amorces textuelles (scraping) : ce qui PRÉCÈDE une date et en donne le sens.
PUBLISH_CUES = (
    "date added", "dateadded", "added on", "published", "date published",
    "publication", "publié le", "publié", "date de publication", "pubdate",
    "pub date", "created", "date created", "disclosed", "disclosure",
    "release date", "released", "dc:date", "dc.date",
)
MODIFIED_CUES = (
    "last updated", "lastupdated", "modified", "date modified", "updated",
    "mis à jour", "dernière modification", "derniere modification",
)
DEADLINE_CUES = (
    "due date", "duedate", "date d'échéance", "date d'echeance", "échéance",
    "echeance", "deadline", "expires", "expire", "remediation due", "action due",
)

# Regexes de date combinées (ordre = priorité de reconnaissance).
_DATE_REGEXES = (ISO_RE, DMY_RE, FR_TEXT_RE, EN_TEXT_RE)

# Mois anglais abrégés (pour les dates RFC-822 des flux RSS : « Fri, 24 Jul 2026 … »).
_MONTHS_ABBR = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
_DAY_MON_YEAR = re.compile(r"\b(\d{1,2})\s+([A-Za-z]{3,9})\.?\s+(\d{4})\b")   # 24 Jul 2026
_MON_DAY_YEAR = re.compile(r"\b([A-Za-z]{3,9})\.?\s+(\d{1,2}),?\s+(\d{4})\b")  # Jul 24, 2026


def _normalize_any(raw) -> str | None:
    """Normalise une date en 'YYYY-MM-DD', avec en plus les mois anglais abrégés / RFC-822.

    S'appuie d'abord sur `normalize_date` (ISO, jj/mm/aaaa, texte FR/EN complet), puis
    reconnaît « 24 Jul 2026 » et « Jul 24, 2026 » fréquents dans les flux RSS et les API.
    """
    if raw is None:
        return None
    text = str(raw)
    nd = normalize_date(text)
    if nd:
        return nd
    for regex, order in ((_DAY_MON_YEAR, "dmy"), (_MON_DAY_YEAR, "mdy")):
        m = regex.search(text)
        if m:
            if order == "dmy":
                d, mon_raw, y = int(m.group(1)), m.group(2), int(m.group(3))
            else:
                mon_raw, d, y = m.group(1), int(m.group(2)), int(m.group(3))
            mo = _MONTHS_ABBR.get(mon_raw[:3].lower())
            if mo and 1900 <= y <= 2100 and 1 <= d <= 31:
                return f"{y:04d}-{mo:02d}-{d:02d}"
    return None

# Bornes de la fenêtre de proximité autour d'un identifiant CVE (scraping).
# La fenêtre est en plus bornée aux identifiants CVE voisins (voir `_cve_dates_from_html`)
# pour qu'un enregistrement n'emprunte jamais la date de son voisin.
_WINDOW_BEFORE = 120
_WINDOW_AFTER = 1400   # la date (« Date Added ») peut suivre un long paragraphe d'action
_MAX_CVE_SCAN = 400    # borne de sécurité sur le nombre d'occurrences analysées


# --------------------------------------------------------------------------------------
# Détection du format de contenu
# --------------------------------------------------------------------------------------

def _content_kind(source_data: dict) -> str:
    """Devine le format réel du corps : 'json', 'xml' ou 'html'."""
    body = (source_data.get("body") or "").lstrip()
    ctype = (source_data.get("content_type") or "").lower()
    method = (source_data.get("collection_method") or "").lower()

    if "json" in ctype or method.startswith("api") or body[:1] in ("{", "["):
        # Confirme que ça parse réellement en JSON avant de s'engager.
        if body[:1] in ("{", "["):
            return "json"
    if any(x in ctype for x in ("xml", "rss", "atom")) or method == "rss":
        return "xml"
    low = body[:2000].lower()
    if low.startswith("<?xml") or "<rss" in low or "<feed" in low:
        return "xml"
    return "html"


# --------------------------------------------------------------------------------------
# Extraction — API (JSON)
# --------------------------------------------------------------------------------------

def _norm_keys(obj: dict) -> dict:
    """Copie de l'objet avec clés en minuscules pour un accès insensible à la casse."""
    return {str(k).lower(): v for k, v in obj.items()}


def _cve_from_obj(low: dict) -> str | None:
    """Cherche un identifiant CVE parmi les valeurs des clés candidates d'un objet."""
    for key in JSON_CVE_KEYS:
        val = low.get(key)
        if isinstance(val, str):
            m = CVE_PATTERN.search(val)
            if m:
                return m.group(0).upper()
    return None


def _date_from_obj(low: dict, keys: list[str]) -> str | None:
    for key in keys:
        val = low.get(key)
        if isinstance(val, (str, int)) and val:
            nd = _normalize_any(str(val))
            if nd:
                return nd
    return None


def _cve_dates_from_json(body: str) -> list[dict]:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return []

    found: dict[str, dict] = {}

    def walk(node):
        if isinstance(node, dict):
            low = _norm_keys(node)
            cve = _cve_from_obj(low)
            if cve:
                published = _date_from_obj(low, JSON_PUBLISH_KEYS)
                modified = _date_from_obj(low, JSON_MODIFIED_KEYS)
                prev = found.get(cve)
                if prev is None or (prev["published"] is None and published):
                    found[cve] = {
                        "cve": cve, "published": published,
                        "modified": modified, "date_source": "api",
                    }
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    return list(found.values())


# --------------------------------------------------------------------------------------
# Extraction — RSS / Atom (XML)
# --------------------------------------------------------------------------------------

_ITEM_RE = re.compile(r"<(item|entry)\b[^>]*>(.*?)</\1>", re.IGNORECASE | re.DOTALL)
_XML_DATE_TAGS = ("pubdate", "published", "dc:date", "updated", "date", "lastbuilddate")


def _xml_tag(item: str, tag: str) -> str | None:
    m = re.search(rf"<{re.escape(tag)}\b[^>]*>(.*?)</{re.escape(tag)}>", item, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else None


def _cve_dates_from_xml(body: str) -> list[dict]:
    found: dict[str, dict] = {}
    for _, item in _ITEM_RE.findall(body):
        cm = CVE_PATTERN.search(item)
        if not cm:
            continue
        cve = cm.group(0).upper()
        published = None
        for tag in _XML_DATE_TAGS:
            raw = _xml_tag(item, tag)
            if raw:
                nd = _normalize_any(raw)
                if nd:
                    published = nd
                    break
        modified = None
        raw_mod = _xml_tag(item, "updated") or _xml_tag(item, "modified")
        if raw_mod:
            modified = _normalize_any(raw_mod)
        prev = found.get(cve)
        if prev is None or (prev["published"] is None and published):
            found[cve] = {"cve": cve, "published": published, "modified": modified, "date_source": "rss"}
    return list(found.values())


# --------------------------------------------------------------------------------------
# Extraction — Scraping (HTML : JSON-LD, méta, proximité)
# --------------------------------------------------------------------------------------

def _cve_dates_from_jsonld(body: str) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for obj in _iter_jsonld(body):
        blob = " ".join(str(obj.get(k, "")) for k in ("name", "headline", "identifier", "about", "@id"))
        m = CVE_PATTERN.search(blob)
        if not m:
            continue
        cve = m.group(0).upper()
        published = None
        for key in ("datePublished", "dateCreated"):
            if obj.get(key):
                published = _normalize_any(str(obj[key]))
                if published:
                    break
        modified = _normalize_any(str(obj.get("dateModified", ""))) if obj.get("dateModified") else None
        if cve not in found or (found[cve]["published"] is None and published):
            found[cve] = {"cve": cve, "published": published, "modified": modified, "date_source": "json_ld"}
    return found


def _iter_dates_in(text: str):
    """Génère (position, date_normalisée, texte_brut) pour chaque date reconnue dans le texte."""
    for regex in _DATE_REGEXES:
        for m in regex.finditer(text):
            nd = _normalize_any(m.group(0))
            if nd:
                yield m.start(), nd, m.group(0)


def _context_kind(prefix: str) -> str:
    """Classe une date d'après le texte qui la précède : 'publish' / 'modified' / 'deadline' / 'plain'."""
    low = prefix.lower()
    # On regarde l'amorce la plus proche de la date (fin du préfixe).
    best_kind, best_pos = "plain", -1
    for kind, cues in (("deadline", DEADLINE_CUES), ("modified", MODIFIED_CUES), ("publish", PUBLISH_CUES)):
        for cue in cues:
            pos = low.rfind(cue)
            if pos > best_pos:
                best_pos, best_kind = pos, kind
    return best_kind


def _publish_date_in_window(window: str, cve_offset: int) -> str | None:
    """Meilleure date de PUBLICATION dans une fenêtre de texte entourant un CVE.

    Dans une liste de CVE, la date suit presque toujours l'identifiant
    (« CVE-XXXX … Date Added: 2026-07-22 »). On priorise donc, dans l'ordre :
      1. date amorcée « publication » située APRÈS le CVE (la plus proche),
      2. date neutre après le CVE,
      3. date amorcée « publication » avant le CVE,
      4. date neutre avant le CVE.
    Les dates amorcées « échéance » (Due Date…) ou « modification » sont toujours écartées,
    ce qui évite le faux positif classique où une date d'échéance future = aujourd'hui.
    """
    after_pub: list[tuple[int, str]] = []
    after_plain: list[tuple[int, str]] = []
    before_pub: list[tuple[int, str]] = []
    before_plain: list[tuple[int, str]] = []
    for pos, nd, _raw in _iter_dates_in(window):
        prefix = window[max(0, pos - 28):pos]
        kind = _context_kind(prefix)
        if kind in ("deadline", "modified"):
            continue
        dist = abs(pos - cve_offset)
        if pos >= cve_offset:
            (after_pub if kind == "publish" else after_plain).append((dist, nd))
        else:
            (before_pub if kind == "publish" else before_plain).append((dist, nd))
    for bucket in (after_pub, after_plain, before_pub, before_plain):
        if bucket:
            bucket.sort(key=lambda t: t[0])
            return bucket[0][1]
    return None


def _cve_dates_from_html(body: str) -> list[dict]:
    found = _cve_dates_from_jsonld(body)

    # Association par proximité sur le texte visible (générique, sans structure connue).
    # La fenêtre de chaque CVE est bornée par les identifiants CVE voisins : un enregistrement
    # ne peut donc jamais capter la date d'un enregistrement voisin.
    visible = _strip_tags(body)
    matches = list(CVE_PATTERN.finditer(visible))[:_MAX_CVE_SCAN]
    positions = [m.start() for m in matches]
    for i, m in enumerate(matches):
        cve = m.group(0).upper()
        if found.get(cve, {}).get("published"):
            continue
        start = m.start()
        prev_end = matches[i - 1].end() if i > 0 else 0
        next_start = positions[i + 1] if i + 1 < len(positions) else len(visible)
        w_start = max(prev_end, start - _WINDOW_BEFORE)
        w_end = min(next_start, start + _WINDOW_AFTER)
        window = visible[w_start:w_end]
        cve_offset = start - w_start
        published = _publish_date_in_window(window, cve_offset)
        if cve not in found:
            found[cve] = {"cve": cve, "published": published, "modified": None, "date_source": "scraping"}
        elif published and found[cve]["published"] is None:
            found[cve]["published"] = published
    return list(found.values())


# --------------------------------------------------------------------------------------
# API publique
# --------------------------------------------------------------------------------------

def extract_cve_dates(source_data: dict) -> list[dict]:
    """Extrait, pour chaque CVE de la source, sa date de publication (et de modification).

    Renvoie une liste de dicts : {cve, published: 'YYYY-MM-DD'|None, modified: ..|None, date_source}.
    Choisit automatiquement l'extracteur selon le format réel du contenu (JSON / XML / HTML).
    """
    body = source_data.get("body") or ""
    if not body:
        return []
    kind = _content_kind(source_data)
    if kind == "json":
        rows = _cve_dates_from_json(body)
        if rows:
            return rows
        # Repli : du JSON a pu être servi avec un type HTML, ou l'inverse.
        return _cve_dates_from_html(body)
    if kind == "xml":
        rows = _cve_dates_from_xml(body)
        if rows:
            return rows
        return _cve_dates_from_html(body)
    return _cve_dates_from_html(body)


def check_cve_published_today(source_data: dict, today: date | None = None) -> dict:
    """Vérifie réellement si la source publie de NOUVELLES CVE aujourd'hui.

    La réponse repose UNIQUEMENT sur la date de publication de chaque CVE, jamais sur le
    simple fait que l'URL existe, que des CVE sont présentes, ou que la collecte fonctionne.
    """
    today = today or datetime.now(timezone.utc).date()
    today_str = today.isoformat()

    cve_dates = extract_cve_dates(source_data)
    total = len(cve_dates)
    dated = [c for c in cve_dates if c.get("published")]
    published_today = [c for c in dated if c["published"] == today_str]
    count_today = len(published_today)
    latest = max((c["published"] for c in dated), default=None)

    if not dated:
        # Gestion d'erreur : impossible de dater les CVE (source sans date exploitable).
        message = (
            "❌ Impossible de déterminer la date de publication des CVE de cette source "
            "(aucune date exploitable trouvée)."
        )
        return {
            "published_today": False,
            "count_today": 0,
            "total_cve": total,
            "dated_cve": 0,
            "latest_cve_date": None,
            "today": today_str,
            "has_dates": False,
            "message": message,
            "samples": cve_dates[:5],
        }

    if count_today > 0:
        message = f"✅ Cette source contient {count_today} nouvelle(s) CVE publiée(s) aujourd'hui."
    else:
        message = f"❌ Aucune nouvelle CVE publiée aujourd'hui. Dernière CVE trouvée : {latest}."

    return {
        "published_today": count_today > 0,
        "count_today": count_today,
        "total_cve": total,
        "dated_cve": len(dated),
        "latest_cve_date": latest,
        "today": today_str,
        "has_dates": True,
        "message": message,
        "samples": (published_today or dated)[:5],
    }
