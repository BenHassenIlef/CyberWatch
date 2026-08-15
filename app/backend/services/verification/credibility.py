"""Niveau 2 — Vérification de crédibilité.

Attribue un score de confiance à la source au-delà de l'aspect purement technique :
domaine officiel, réputation (whitelist/blacklist), présence et existence d'un CVE,
métadonnées (titre / date / auteur), indicateurs de faible crédibilité, et recoupement
multi-sources.

Chaque contrôle est une fonction séparée et testable ; `verify_credibility` les compose.
"""
from typing import Awaitable, Callable

from app.backend.services.verification.common import make_check, weighted_score
from app.backend.services.verification.cve import (
    CveExistenceValidator,
    extract_cve_ids,
    get_default_validator,
)
from app.backend.services.verification.domains import ReputationStore, default_reputation_store, is_official_domain
from app.backend.services.verification.http_client import FetchResult
from app.backend.services.verification.metadata_extraction import (
    extract_organization,
    extract_publication_date,
    extract_title,
    method_label,
)

# Un « corroborateur » reçoit une liste d'identifiants CVE et renvoie le nombre de sources
# fiables distinctes qui les confirment déjà. Injecté par l'orchestrateur (voir admin.py).
Corroborator = Callable[[list[str]], Awaitable[int]]

# Mots-clés typiques de titres sensationnalistes / putaclic.
SENSATIONALIST_TERMS = [
    "choquant", "incroyable", "vous n'allez pas croire", "urgent", "alerte maximale",
    "catastrophe", "scandale", "explosif", "shocking", "you won't believe", "breaking",
    "must read", "insane", "terrifying",
]
MIN_CONTENT_LENGTH = 500  # en-dessous, contenu jugé trop court


# --------------------------------------------------------------------------------------
# Contrôles unitaires
# --------------------------------------------------------------------------------------

def verify_domain(host: str | None) -> dict:
    """1. Le domaine appartient-il à une organisation officielle reconnue ?"""
    official = is_official_domain(host)
    return make_check(
        "Domaine d'une organisation officielle reconnue",
        True if official else None,  # non officiel n'est pas éliminatoire (None), juste non bonifiant
        weight=3.0,
        detail=host or "domaine inconnu",
    )


def verify_reputation(host: str | None, store: ReputationStore) -> dict:
    """2. Réputation du domaine via whitelist / blacklist (architecture extensible)."""
    verdict = store.classify(host)
    if verdict == "blacklisted":
        return make_check("Réputation du domaine (liste noire)", False, weight=4.0, detail=host)
    if verdict == "whitelisted":
        return make_check("Réputation du domaine (liste blanche)", True, weight=2.0, detail=host)
    return make_check("Réputation du domaine", None, weight=2.0, detail="domaine non répertorié")


async def verify_cve(text: str, validator: CveExistenceValidator) -> tuple[list[dict], list[str]]:
    """3 & 4. Présence d'un identifiant CVE valide, puis existence réelle (NVD)."""
    cve_ids = extract_cve_ids(text)
    checks = [
        make_check(
            "Contient un identifiant CVE valide",
            bool(cve_ids),
            weight=1.5,
            detail=", ".join(cve_ids[:5]) if cve_ids else "aucun CVE détecté",
        )
    ]

    if cve_ids:
        # On vérifie l'existence du premier CVE (limite les appels réseau).
        exists = await validator.exists(cve_ids[0])
        checks.append(
            make_check(
                f"Le CVE {cve_ids[0]} existe dans la base officielle (NVD)",
                exists,  # True / False / None (indéterminé si NVD injoignable)
                weight=1.5,
                detail=None if exists is not None else "NVD indéterminé",
            )
        )
    return checks, cve_ids


def verify_metadata(fetched: FetchResult | None) -> list[dict]:
    """6. Titre, date de publication et organisation — extraction avancée avec méthode + confiance.

    Date : +2 de poids (≈ +10 pts) ; Organisation : +3 de poids (≈ +15 pts). Une information
    non trouvée n'élimine pas la source : elle réduit simplement le score (check à False).
    """
    if fetched is None or not fetched.reached:
        return [
            make_check("Titre", None, weight=1.0),
            make_check("Date de publication", None, weight=2.0),
            make_check("Organisation / éditeur", None, weight=3.0),
        ]

    body = fetched.body

    title = extract_title(body)
    date = extract_publication_date(body)
    org = extract_organization(body, fetched.host)

    title_check = make_check(
        "Titre",
        bool(title),
        weight=1.0,
        detail=(title[:120] if title else "titre introuvable"),
    )
    date_check = make_check(
        "Date de publication",
        bool(date),
        weight=2.0,
        detail=(
            f"{date['raw']} → {date['value']} · {method_label(date['source'])} (confiance {int(date['confidence'] * 100)} %)"
            if date
            else "date introuvable"
        ),
    )
    org_check = make_check(
        "Organisation / éditeur",
        bool(org),
        weight=3.0,
        detail=(
            f"{org['value']} · {method_label(org['source'])} (confiance {int(org['confidence'] * 100)} %)"
            if org
            else "organisation introuvable"
        ),
    )

    # Données structurées jointes (exploitables par le rapport / d'autres consommateurs).
    date_check["extraction"] = date
    org_check["extraction"] = org

    return [title_check, date_check, org_check]


def detect_low_credibility(fetched: FetchResult | None) -> list[dict]:
    """7. Indicateurs de faible crédibilité (formulés en positif : True = signe sain)."""
    if fetched is None or not fetched.reached:
        return [
            make_check("Titre non sensationnaliste", None, weight=1.0),
            make_check("Contenu de longueur suffisante", None, weight=1.0),
            make_check("Présence de sources / liens", None, weight=1.0),
        ]

    body = fetched.body
    body_lower = fetched.body_lower

    # Sensationnalisme : termes putaclic ou ponctuation excessive.
    sensational = any(term in body_lower for term in SENSATIONALIST_TERMS) or "!!!" in body
    # Longueur : corps textuel suffisamment fourni.
    long_enough = len(body.strip()) >= MIN_CONTENT_LENGTH
    # Sources : présence de liens/références.
    has_links = "<a " in body_lower or "http://" in body_lower or "https://" in body_lower or "<link" in body_lower

    return [
        make_check("Titre non sensationnaliste", not sensational, weight=1.0),
        make_check("Contenu de longueur suffisante", long_enough, weight=1.0),
        make_check("Présence de sources / liens", has_links, weight=1.0),
    ]


async def verify_cross_reference(cve_ids: list[str], corroborator: Corroborator | None) -> dict:
    """5. L'information est-elle confirmée par plusieurs sources fiables ?

    Utilise un corroborateur injecté (ex. recherche des mêmes CVE collectés par d'autres
    sources validées). Sans corroborateur, le contrôle reste indéterminé — point d'extension
    pour comparer titres/contenus avec des sources externes plus tard.
    """
    if not cve_ids or corroborator is None:
        return make_check(
            "Information recoupée par d'autres sources fiables",
            None,
            weight=1.5,
            detail="recoupement non disponible",
        )
    count = await corroborator(cve_ids)
    return make_check(
        "Information recoupée par d'autres sources fiables",
        count > 0,
        weight=1.5,
        detail=f"{count} autre(s) source(s) confirment" if count else "aucune corroboration",
    )


# --------------------------------------------------------------------------------------
# Composition
# --------------------------------------------------------------------------------------

def compute_credibility_score(checks: list[dict], hard_reject: bool) -> int:
    """Calcule le score de crédibilité (0–100). Une source blacklistée est plafonnée bas."""
    if hard_reject:
        return min(10, weighted_score(checks))
    return weighted_score(checks)


async def verify_credibility(
    source: dict,
    fetched: FetchResult | None,
    corroborator: Corroborator | None = None,
    reputation_store: ReputationStore | None = None,
    cve_validator: CveExistenceValidator | None = None,
) -> dict:
    """Exécute tous les contrôles de crédibilité et renvoie {'score', 'checks', 'hard_reject'}."""
    store = reputation_store or default_reputation_store
    validator = cve_validator or get_default_validator()
    host = fetched.host if fetched else None
    text = fetched.body if fetched else ""

    checks: list[dict] = []
    checks.append(verify_domain(host))

    reputation_check = verify_reputation(host, store)
    checks.append(reputation_check)
    hard_reject = reputation_check["passed"] is False  # domaine en liste noire

    cve_checks, cve_ids = await verify_cve(text, validator)
    checks.extend(cve_checks)

    checks.extend(verify_metadata(fetched))
    checks.extend(detect_low_credibility(fetched))
    checks.append(await verify_cross_reference(cve_ids, corroborator))

    return {
        "score": compute_credibility_score(checks, hard_reject),
        "checks": checks,
        "hard_reject": hard_reject,
    }
