"""PROVENANCE PAR CHAMP — d'où vient chaque information affichée sur une CVE.

Problème résolu : jusqu'ici, une valeur écrite sur une CVE ne portait aucune trace de son
origine. Impossible de distinguer une date de publication issue de NVD d'une date recopiée
depuis un bulletin CERT — d'où des avis multi-CVE contaminant toutes leurs CVE.

Chaque champ important porte désormais :

    provenance.<champ> = {value, source, source_url, retrieved_at, confidence}

RÈGLE DE REMPLACEMENT : une valeur n'est écrasée que par une valeur de provenance PLUS FORTE.
Une donnée vérifiée (NVD, CNA) ne peut jamais être remplacée par une donnée d'avis.
"""
import re
from datetime import datetime

from app.backend.utils import utcnow

# Champs dont l'origine est tracée (ceux qu'un consultant lit comme des faits).
TRACKED_FIELDS = (
    "cve_published_at", "cve_modified_at", "description", "cvss_score", "cvss_vector",
    "severity", "cwe", "vuln_type", "impact", "vendor", "product",
    "affected_versions", "fixed_version",
)

# Niveaux de confiance, du plus fort au plus faible.
VERIFIED = "verified"          # source d'autorité interrogée PAR IDENTIFIANT CVE
CORROBORATED = "corroborated"  # plusieurs sources d'autorité concordantes
UNVERIFIED = "unverified"      # valeur reprise d'un avis, non recoupée par CVE
NOT_AVAILABLE = "not_available"

_CONFIDENCE_RANK = {NOT_AVAILABLE: 0, UNVERIFIED: 1, VERIFIED: 2, CORROBORATED: 3}

# Autorité d'une source POUR UN CHAMP. La priorité est volontairement par champ : NVD fait
# autorité sur le CVSS, l'éditeur sur les versions corrigées, le CNA sur les dates.
_FIELD_PRIORITY = {
    # DATE DE PUBLICATION : le CNA d'abord, puis MITRE, et NVD seulement ensuite.
    # NVD publie la date d'entrée dans SON registre, pas celle de la divulgation. Une faille
    # divulguée par son éditeur le 11 y apparaît le 19 : placer NVD en tête faisait afficher
    # le 19, en contradiction avec l'avis officiel que le consultant a sous les yeux.
    "cve_published_at": ("cna", "mitre", "nvd", "osv", "redhat", "msrc"),
    "cve_modified_at": ("nvd", "mitre", "cna", "osv"),
    "cvss_score": ("nvd", "cna", "msrc", "redhat", "osv"),
    "cvss_vector": ("nvd", "cna", "msrc", "redhat", "osv"),
    "severity": ("nvd", "cna", "msrc", "redhat", "osv"),
    "cwe": ("nvd", "cna", "mitre", "redhat"),
    "description": ("mitre", "nvd", "cna", "redhat", "osv"),
    "affected_versions": ("msrc", "redhat", "osv", "nvd", "vendor"),
    "fixed_version": ("msrc", "redhat", "vendor", "osv", "nvd"),
    "vendor": ("nvd", "cna", "mitre"),
    "product": ("nvd", "cna", "mitre"),
    "impact": ("cna", "mitre", "nvd"),
    "vuln_type": ("nvd", "cna", "mitre"),
}

# Sources qui ne décrivent PAS la CVE elle-même : elles la mentionnent seulement.
ADVISORY_SOURCES = ("advisory", "cert", "ancs", "dgssi", "cert-fr", "collection")


def field_rank(field: str, source: str) -> int:
    """Rang d'autorité (plus petit = plus fiable). Hors liste -> rang faible."""
    ordre = _FIELD_PRIORITY.get(field, ())
    s = (source or "").lower()
    return ordre.index(s) if s in ordre else len(ordre) + 1


# --------------------------------------------------------------------------------------
# CVSS — ne jamais DÉGRADER la version du barème
#
# Une source autoritaire peut renvoyer un vecteur CVSS 3.1 alors que la base détient déjà un
# CVSS 4.0. Remplacer serait un recul : 4.0 est plus récent et plus expressif. La provenance
# seule ne suffit donc pas à trancher pour ce champ — la VERSION du barème prime.
# --------------------------------------------------------------------------------------

_CVSS_VERSION_RE = re.compile(r"CVSS:(\d+\.\d+)")


def cvss_version(vector) -> float:
    """Version du barème lue dans le vecteur (0.0 si absente ou illisible)."""
    if not isinstance(vector, str):
        return 0.0
    m = _CVSS_VERSION_RE.search(vector)
    try:
        return float(m.group(1)) if m else 0.0
    except (TypeError, ValueError):
        return 0.0


def allows_cvss_replacement(ancien_vecteur, nouveau_vecteur) -> bool:
    """Le nouveau vecteur peut-il remplacer l'ancien ? Jamais vers une version INFÉRIEURE."""
    return cvss_version(nouveau_vecteur) >= cvss_version(ancien_vecteur)


def entry(value, source: str, source_url: str | None = None,
          confidence: str | None = None) -> dict:
    """Construit une entrée de provenance pour un champ."""
    if confidence is None:
        confidence = UNVERIFIED if (source or "").lower() in ADVISORY_SOURCES else VERIFIED
    return {"value": value, "source": source, "source_url": source_url,
            "retrieved_at": utcnow(), "confidence": confidence}


def should_replace(field: str, ancienne: dict | None, nouvelle: dict) -> bool:
    """Faut-il remplacer la provenance existante par la nouvelle ?

    Ordre de décision : confiance d'abord, autorité de la source ensuite. À égalité stricte,
    on conserve l'existant — on ne réécrit jamais sans gain démontrable.
    """
    if not isinstance(ancienne, dict):
        return True
    ca = _CONFIDENCE_RANK.get(ancienne.get("confidence"), 0)
    cn = _CONFIDENCE_RANK.get(nouvelle.get("confidence"), 0)
    if cn != ca:
        return cn > ca
    return field_rank(field, nouvelle.get("source")) < field_rank(field, ancienne.get("source"))


def apply(rec: dict, field: str, value, source: str, source_url: str | None = None,
          confidence: str | None = None) -> bool:
    """Pose une valeur ET sa provenance sur l'enregistrement, si elle l'emporte.

    Renvoie True si la valeur a été écrite. L'enregistrement conserve le champ « à plat »
    (compatibilité avec tout le code existant) et sa provenance dans `provenance`.
    """
    if value in (None, "", []):
        return False
    nouvelle = entry(value, source, source_url, confidence)
    prov = rec.setdefault("provenance", {})
    if not should_replace(field, prov.get(field), nouvelle):
        return False
    prov[field] = nouvelle
    rec[field] = value
    return True


def conflicts(rec: dict) -> list[dict]:
    """Champs dont la valeur à plat diverge de la provenance enregistrée (incohérence)."""
    out = []
    for field, p in (rec.get("provenance") or {}).items():
        if field in rec and rec[field] != p.get("value"):
            out.append({"field": field, "stored": rec[field], "provenance": p.get("value"),
                        "source": p.get("source")})
    return out


def validation_status(rec: dict) -> str:
    """État global : `validated` seulement si les champs critiques sont vérifiés."""
    prov = rec.get("provenance") or {}
    if not prov:
        return "insufficient_data"
    if conflicts(rec):
        return "source_conflict"
    critiques = ("cve_published_at", "description", "cvss_score")
    niveaux = [prov.get(f, {}).get("confidence") for f in critiques if f in prov]
    if not niveaux:
        return "insufficient_data"
    if any(n == UNVERIFIED for n in niveaux):
        return "needs_review"
    if len(niveaux) < len(critiques):
        return "partially_validated"
    return "validated"
