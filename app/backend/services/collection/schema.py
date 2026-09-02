"""Schéma canonique d'une CVE et helpers de normalisation partagés.

Un enregistrement CVE normalisé contient toujours les mêmes clés ; toute information
absente vaut `None` (affichée « Non disponible »). Jamais de valeur inventée.
"""
import hashlib
import re
from datetime import datetime, timedelta, timezone

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Temps RELATIFs (« 2h ago », « il y a 30 minutes », « hier »…) -> datetime absolu UTC.
_REL_UNIT_RE = re.compile(
    r"(\d+)\s*(sec(?:onde|ond)?s?|min(?:ute)?s?|mn|m|he?(?:ure|our)?s?|j(?:our)?s?|d(?:ay)?s?|"
    r"sem(?:aine)?s?|w(?:eek)?s?)\b", re.IGNORECASE)
_REL_TRIGGER_RE = re.compile(
    r"\bago\b|il y a|auparavant|hier|yesterday|aujourd'?hui|today|just now|à l['’]instant|"
    r"\bmin\b|\bh\b", re.IGNORECASE)


def _parse_relative(text: str):
    """Convertit un temps relatif en datetime UTC absolu. None si non reconnu."""
    low = text.strip().lower()
    now = datetime.utcnow()
    if low in ("just now", "à l'instant", "à l’instant", "maintenant", "now"):
        return now
    if low in ("today", "aujourd'hui", "aujourd’hui", "aujourdhui"):
        return now
    if low in ("yesterday", "hier"):
        return now - timedelta(days=1)
    m = _REL_UNIT_RE.search(low)
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2).lower()
    if unit.startswith("sec") or unit == "s":
        return now - timedelta(seconds=n)
    if unit.startswith("min") or unit in ("m", "mn"):
        return now - timedelta(minutes=n)
    if unit.startswith("h"):
        return now - timedelta(hours=n)
    if unit.startswith(("sem", "w")):
        return now - timedelta(weeks=n)
    if unit.startswith(("j", "d")):
        return now - timedelta(days=n)
    return None


# Champs pris en compte pour l'EMPREINTE de contenu et la COMPLÉTUDE d'une CVE.
_HASH_FIELDS = ("title", "description", "solution", "severity", "cvss_score", "cwe", "vuln_type")
_HASH_LIST_FIELDS = ("references", "affected_products", "associated_cves", "patch_links")
_COMPLETENESS_FIELDS = ("description", "cvss_score", "severity", "cwe", "vuln_type", "solution",
                        "references", "affected_products", "published_at", "vendor", "product")


def content_hash(rec: dict) -> str:
    """Empreinte SHA-256 du CONTENU d'une CVE : change dès qu'un champ significatif évolue
    (CVSS ajouté, solution/références/produits enrichis…). Sert à détecter les mises à jour."""
    parts = [str(rec.get(f) or "") for f in _HASH_FIELDS]
    parts += [";".join(sorted(str(x) for x in (rec.get(f) or []))) for f in _HASH_LIST_FIELDS]
    return hashlib.sha256("|".join(parts).encode("utf-8", "ignore")).hexdigest()


def completeness(rec: dict) -> int:
    """Pourcentage de complétude de l'information (0-100) : proportion des champs clés renseignés."""
    filled = sum(1 for f in _COMPLETENESS_FIELDS if rec.get(f) not in (None, "", []))
    return round(100 * filled / len(_COMPLETENESS_FIELDS))


def _to_naive_utc(dt: datetime) -> datetime:
    """Ramène un datetime (naïf ou aware) en UTC naïf pour comparaison homogène."""
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def is_recent(published, window_days: int, now: datetime | None = None) -> bool:
    """La date de PUBLICATION est-elle dans la fenêtre (ex. dernières 24-48 h) ?

    Renvoie False si la date est absente ou ancienne : dans ce cas AUCUNE notification n'est
    créée. On ne se base JAMAIS sur la date de collecte (collected_at).
    """
    if not isinstance(published, datetime):
        return False
    now = now or datetime.utcnow()
    start = now - timedelta(days=window_days)
    p = _to_naive_utc(published)
    return start <= p <= now + timedelta(days=1)  # +1j : tolérance fuseau horaire

# Clés canoniques persistées / consommées par l'interface Consultant.
CANONICAL_KEYS = (
    "cve_id", "title", "description", "published_at", "updated_at",
    "cvss_score", "cvss_vector", "severity", "cwe", "vuln_type", "impact", "references",
    "vendor", "product", "affected_products", "affected_versions", "affected_systems",
    "fixed_version", "platform", "solution", "patch_links", "detail_url",
    # Portails CERT à identifiants d'avis (tunCERT/ANCS, CERT-FR…).
    "advisory_id", "advisory_ids", "associated_cves",
    # MÉTADONNÉES D'AVIS — appartiennent au bulletin, JAMAIS à la CVE. Séparées pour qu'une
    # republication d'avis ne puisse plus rajeunir la vulnérabilité qu'il cite.
    "advisory_title", "advisory_url", "advisory_published_at", "advisory_updated_at",
)

# Champs listes (fusionnés par UNION entre sources) vs scalaires (résolus par priorité).
LIST_FIELDS = ("references", "affected_products", "affected_systems", "patch_links",
               "advisory_ids", "associated_cves")

# Champs dont la modification déclenche une notification de « mise à jour importante ».
IMPORTANT_FIELDS = ("cvss_score", "severity", "cwe", "solution", "references", "affected_products", "affected_systems")


def detail_url_for(cve_id: str, host: str | None = None, override: str | None = None) -> str:
    """URL de la page contenant les informations de CETTE CVE (page par identifiant).

    On ne renvoie jamais une page « liste/catalogue » : on cible la page de la CVE elle-même
    (ex. NVD), afin qu'un clic ouvre directement les informations de cette vulnérabilité.
    """
    if override and override.startswith("http"):
        return override
    host = (host or "").lower()
    if "opencve" in host:
        return f"https://www.opencve.io/cve/{cve_id}"
    if "msrc.microsoft" in host:
        return f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"
    # Page officielle par identifiant (existe pour toute vraie CVE).
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def new_record(cve_id: str) -> dict:
    return {
        "cve_id": cve_id.upper(),
        "title": None, "description": None,
        "published_at": None, "updated_at": None,
        "cvss_score": None, "cvss_vector": None, "severity": None, "cwe": None,
        "vuln_type": None, "impact": None,
        "references": [], "vendor": None, "product": None,
        "affected_products": [], "affected_versions": None, "affected_systems": [],
        "fixed_version": None, "platform": None,
        "solution": None, "patch_links": [], "detail_url": None,
        # Avis CERT (portails à identifiants d'avis, ex. tunCERT/ANCS).
        "advisory_id": None,       # identifiant d'avis principal (ex. tunCERT/Vuln.2026-454)
        "advisory_ids": [],         # tous les avis référençant cette CVE
        "associated_cves": [],      # CVE liées à un avis (pour les entrées « avis seul »)
        "is_advisory": False,       # True si l'entrée est un avis sans CVE associé
        # Traçabilité multi-sources (points 7 et 8 du cahier des charges).
        "sources": [],           # [{source_id, name, url}] — sources admin ayant listé la CVE
        "confirmed_sources": [],  # sources OFFICIELLES ayant confirmé/enrichi la CVE
        "source_id": None,        # source principale (compat interface existante)
        "source_name": None,
        "data_origin": None,
        # --- Synchronisation incrémentale (moteur type OpenCVE) ---
        "first_published": None,        # 1re date de publication observée (immuable)
        "last_updated": None,           # dernière modification connue (source)
        "last_collected": None,         # dernière fois vue par un cycle de collecte
        "last_hash": None,              # empreinte du contenu (détection de changement)
        "last_sync": None,              # dernier passage de synchronisation
        "sync_status": None,            # "new" | "updated" | "unchanged"
        "information_completeness": 0,  # % de complétude des champs clés
        "is_updated": False,            # a reçu une mise à jour depuis sa 1re collecte
        "change_summary": [],           # libellés lisibles des dernières modifications
    }


_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8,
    "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
# Mois français en toutes lettres (portails CERT francophones : maCERT « 29 juillet 2026 »…).
# Correspondance sur le nom COMPLET (juin/juillet partagent « jui » -> pas de troncature).
_MONTHS_FR = {
    "janvier": 1, "février": 2, "fevrier": 2, "mars": 3, "avril": 4, "mai": 5,
    "juin": 6, "juillet": 7, "août": 8, "aout": 8, "septembre": 9,
    "octobre": 10, "novembre": 11, "décembre": 12, "decembre": 12,
}


def _month_num(token: str):
    """Numéro de mois depuis un nom EN (abrégé) ou FR (complet). None si inconnu."""
    tok = token.strip().lower()
    if tok in _MONTHS_FR:
        return _MONTHS_FR[tok]
    return _MONTHS.get(tok[:3])
# « Jan 13, 2026 » / « January 13, 2026 »
_MON_DAY_YEAR = re.compile(r"\b([A-Za-zÀ-ÿ]{3,9})\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})\b")
# « 13 Jan 2026 » / « 13 January 2026 » / « 29 juillet 2026 »
_DAY_MON_YEAR = re.compile(r"\b(\d{1,2})(?:st|nd|rd|th)?\s+([A-Za-zÀ-ÿ]{3,9})\.?\s+(\d{4})\b")
# « 01/13/2026 » ou « 13/01/2026 » (jour/mois ambigu -> on tente MM/DD puis DD/MM)
_SLASH = re.compile(r"\b(\d{1,2})[/.](\d{1,2})[/.](\d{4})\b")


def parse_dt(value):
    """Convertit une date de multiples formats en datetime.

    Reconnaît : ISO (2026-01-13[T...]), « Jan 13, 2026 », « January 13, 2026 »,
    « 13 Jan 2026 », « 13 January 2026 », « 01/13/2026 ». Renvoie None si non reconnu.
    (Pour la persistance/affichage : format cible ISO 8601, ex. 2026-01-13T00:00:00Z.)
    """
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    # 0) Temps RELATIF (« 2h ago », « il y a 30 minutes », « hier », « updated 1h ago »).
    if _REL_TRIGGER_RE.search(text):
        rel = _parse_relative(text)
        if rel is not None:
            return rel
    # 1) ISO (avec ou sans heure/fuseau).
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass
    m = re.search(r"\d{4}-\d{2}-\d{2}", text)
    if m:
        try:
            return datetime.fromisoformat(m.group(0))
        except ValueError:
            pass
    # 2) « Jan 13, 2026 » / « January 13, 2026 »
    m = _MON_DAY_YEAR.search(text)
    if m and _month_num(m.group(1)) is not None:
        mo, d, y = _month_num(m.group(1)), int(m.group(2)), int(m.group(3))
        return _safe_date(y, mo, d)
    # 3) « 13 Jan 2026 » / « 13 January 2026 » / « 29 juillet 2026 » (FR)
    m = _DAY_MON_YEAR.search(text)
    if m and _month_num(m.group(2)) is not None:
        d, mo, y = int(m.group(1)), _month_num(m.group(2)), int(m.group(3))
        return _safe_date(y, mo, d)
    # 4) « 01/13/2026 » (MM/DD) sinon « 13/01/2026 » (DD/MM)
    m = _SLASH.search(text)
    if m:
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return _safe_date(y, a, b) if a <= 12 else _safe_date(y, b, a)
    return None


def _safe_date(y: int, mo: int, d: int):
    try:
        return datetime(y, mo, d)
    except ValueError:
        return None


def severity_from_score(score):
    """Mapping qualitatif OFFICIEL CVSS v3 (définition CVSS, pas une invention)."""
    if score is None:
        return None
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return None


def norm_severity(label):
    if not label:
        return None
    low = str(label).strip().lower()
    return low if low in ("critical", "high", "medium", "low") else None


def add_source(record: dict, source: dict) -> None:
    """Associe une source à la CVE (sans doublon), en gardant la 1re comme principale."""
    entry = {
        "source_id": source.get("_id"),
        "name": source.get("name") or "—",
        "url": source.get("url") or source.get("api_endpoint"),
    }
    if any(s.get("source_id") == entry["source_id"] for s in record["sources"]):
        return
    record["sources"].append(entry)
    if record["source_id"] is None:
        record["source_id"] = entry["source_id"]
        record["source_name"] = entry["name"]


def merge_records(base: dict, other: dict) -> dict:
    """Fusionne deux enregistrements de la MÊME CVE (complète les champs manquants)."""
    for key in CANONICAL_KEYS:
        if key in LIST_FIELDS:
            base[key] = list(dict.fromkeys((base.get(key) or []) + (other.get(key) or [])))
        elif not base.get(key) and other.get(key):
            base[key] = other[key]
    for s in other.get("sources", []):
        if not any(x.get("source_id") == s.get("source_id") for x in base["sources"]):
            base["sources"].append(s)
    if not base.get("data_origin"):
        base["data_origin"] = other.get("data_origin")
    return base
