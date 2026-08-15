"""Orchestrateur de l'agent de vérification.

Compose le niveau technique (niveau 1), le niveau crédibilité (niveau 2) et la détection
automatique de la méthode de collecte, calcule le score global, la décision finale et un
résumé lisible, puis expose `verify_source` et `test_connection`.
"""
import logging
from urllib.parse import urlparse

from app.backend.services.verification import browser_client
from app.backend.services.verification.credibility import Corroborator, verify_credibility
from app.backend.services.verification.cve import extract_cve_ids
from app.backend.services.verification.method_analyzer import analyze_source
from app.backend.services.verification.http_client import FetchResult, fetch
from app.backend.services.verification.technical import verify_technical
from app.backend.utils import utcnow

# Pondération du score global : la crédibilité prime (c'est l'objet de la mise à niveau),
# mais une source techniquement inexploitable ne peut pas être approuvée (voir gating).
TECHNICAL_WEIGHT = 0.4
CREDIBILITY_WEIGHT = 0.6

APPROVE_THRESHOLD = 70
REVIEW_THRESHOLD = 40
MIN_TECHNICAL_FOR_APPROVAL = 50  # une URL injoignable ne peut jamais être « approuvée »

# Correspondances recommandation interne -> libellés métier affichés.
DECISION_LABELS = {"approved": "FIABLE", "review": "À SURVEILLER", "rejected": "NON FIABLE"}


# Marqueurs de pages de blocage anti-bot (Akamai, Cloudflare, WAF…).
_BLOCK_MARKERS = (
    "access denied", "accès refusé", "forbidden", "captcha", "attention required",
    "cloudflare", "are you a robot", "request blocked", "bot detection",
)


def _fetch_blocked(fetched: FetchResult) -> bool:
    """La réponse HTTP ressemble-t-elle à un blocage anti-bot (à retenter via navigateur) ?

    On ne considère PAS 401 (authentification légitime d'une API) : seul un vrai blocage
    (403/429 ou page de refus) mérite une seconde tentative avec un navigateur headless.
    """
    if not fetched.reached:
        return False
    if fetched.status_code in (403, 429):
        return True
    body = fetched.body_lower
    return any(m in body for m in _BLOCK_MARKERS)


def _is_real_page(rendered: str) -> bool:
    """Le HTML rendu par le navigateur est-il une vraie page (et non une nouvelle page de refus) ?"""
    if len(rendered) < 2000:
        return False
    low = rendered.lower()
    return not any(m in low for m in _BLOCK_MARKERS)


def _recommendation(overall: int, technical_score: int, hard_reject: bool) -> str:
    if hard_reject or overall < REVIEW_THRESHOLD:
        return "rejected"
    if overall < APPROVE_THRESHOLD or technical_score < MIN_TECHNICAL_FOR_APPROVAL:
        return "review"
    return "approved"


def _confidence_level(overall: int) -> str:
    if overall >= APPROVE_THRESHOLD:
        return "ÉLEVÉ"
    if overall >= REVIEW_THRESHOLD:
        return "MOYEN"
    return "FAIBLE"


def build_summary(recommendation: str, fetched: FetchResult | None, detection: dict | None, credibility: dict) -> str:
    """Construit un résumé lisible citant les facteurs réels de la décision."""
    reasons: list[str] = []

    # Facteurs positifs / négatifs concrets tirés des contrôles réels.
    checks = {c["label"]: c["passed"] for c in credibility["checks"]}
    if any("officielle" in label and passed for label, passed in checks.items()):
        reasons.append("le domaine appartient à une organisation officielle reconnue")
    if any("existe dans la base officielle" in label and passed for label, passed in checks.items()):
        reasons.append("un CVE cité a été confirmé dans la base NVD")
    if fetched is not None and not fetched.status_ok:
        reasons.append(f"l'URL n'est pas correctement accessible ({fetched.error or 'réponse invalide'})")
    if credibility.get("hard_reject"):
        reasons.append("le domaine figure sur la liste noire")
    if detection and detection.get("authentication_required"):
        reasons.append("l'API nécessite une authentification à configurer avant collecte")
    if not reasons:
        reasons.append("les contrôles de crédibilité sont partiellement satisfaits")

    intro = {
        "approved": "Cette source est recommandée pour alimenter la plateforme de veille cyber car ",
        "review": "Cette source est à surveiller avant d'alimenter la plateforme de veille cyber car ",
        "rejected": "Cette source n'est pas recommandée pour alimenter la plateforme de veille cyber car ",
    }[recommendation]
    return intro + ", ".join(reasons) + "."


async def verify_source(source: dict, corroborator: Corroborator | None = None) -> dict:
    """Lance la vérification complète (détection + technique + crédibilité) et renvoie le rapport."""
    target = source.get("url")
    fetched: FetchResult | None = await fetch(target) if target else None

    # Rendu hybride : on rend la page avec un navigateur headless dans deux cas :
    #  - c'est une application JavaScript (contenu vide en HTML brut), ou
    #  - le téléchargement HTTP a été bloqué par une protection anti-bot (403/challenge)
    #    alors qu'un vrai navigateur, lui, obtient le contenu réel (ex. catalogue KEV de la CISA).
    rendered_with_browser = False
    if fetched is not None and target:
        blocked = _fetch_blocked(fetched)
        if browser_client.looks_like_spa(fetched) or blocked:
            rendered = await browser_client.render_html(target)
            if rendered and (not blocked or _is_real_page(rendered)):
                fetched.body = rendered
                rendered_with_browser = True
                if blocked:
                    # Le navigateur a franchi la protection : la page est réellement accessible.
                    fetched.reached = True
                    fetched.status_code = 200

    # Collection Method Analyzer : teste et VALIDE les méthodes (API → RSS → API interne →
    # scraping dynamique → scraping HTML) par la présence réelle de CVE, et choisit la meilleure.
    analysis = None
    if target:
        analysis = await analyze_source(
            target, page_fetched=fetched,
            rendered_body=fetched.body if rendered_with_browser else None,
        )

    # Le contrôle de cohérence technique connaît la méthode retenue et l'endpoint éventuel.
    technical_source = {**source}
    if analysis:
        technical_source["collection_method"] = analysis["collection_method"]
        technical_source["api_endpoint"] = analysis.get("api_endpoint")
    technical = verify_technical(technical_source, fetched)

    # L'analyse CVE (présence + dates + crédibilité) porte sur le contenu RÉEL de la méthode
    # retenue (ex. le JSON de l'API MSRC, ou le HTML rendu), pas sur la page d'accueil vide.
    analysis_fetched = _fetch_from_analysis(analysis, fetched, target)

    credibility = await verify_credibility(source, analysis_fetched, corroborator=corroborator)

    technical_score = technical["score"]
    credibility_score = credibility["score"]
    overall = round(TECHNICAL_WEIGHT * technical_score + CREDIBILITY_WEIGHT * credibility_score)
    recommendation = _recommendation(overall, technical_score, credibility["hard_reject"])

    # --- Logs détaillés : montre l'issue de CHAQUE étape (diagnostic des échecs) ---
    _log = logging.getLogger("cyberwatch.verification")
    _log.info("[verify] %s | host=%s reached=%s https=%s ssl_ok=%s%s",
              target, (fetched.host if fetched else None), bool(fetched and fetched.reached),
              bool(fetched and fetched.is_https), bool(fetched and fetched.ssl_ok),
              f" ({fetched.ssl_note})" if (fetched and fetched.ssl_note) else "")
    for _c in technical["checks"]:
        _log.info("[verify][technique] %s : %s%s", _c["label"],
                  {True: "OK", False: "ÉCHEC", None: "indéterminé"}[_c["passed"]],
                  f" — {_c['detail']}" if _c.get("detail") else "")
    for _c in credibility["checks"]:
        _log.info("[verify][crédibilité] %s : %s%s", _c["label"],
                  {True: "OK", False: "ÉCHEC", None: "indéterminé"}[_c["passed"]],
                  f" — {_c['detail']}" if _c.get("detail") else "")
    _log.info("[verify] SCORES technique=%d crédibilité=%d global=%d -> %s",
              technical_score, credibility_score, overall, DECISION_LABELS[recommendation])

    detection_dict = _detection_report(analysis)
    admin_indicators = _admin_indicators(
        fetched, credibility,
        analysis["collection_method"] if analysis else None,
        analysis_fetched,
    )

    return {
        "technical_score": technical_score,
        "credibility_score": credibility_score,
        "overall_score": overall,
        # Conservé pour la colonne « Score de confiance » de la liste des sources.
        "confidence_score": overall,
        "recommendation": recommendation,
        "decision": DECISION_LABELS[recommendation],
        "confidence_level": _confidence_level(overall),
        "summary": build_summary(recommendation, fetched, detection_dict, credibility),
        "detection": detection_dict,
        "technical": {"score": technical_score, "checks": technical["checks"]},
        "credibility": {"score": credibility_score, "checks": credibility["checks"]},
        # 3 indicateurs simplifiés affichés à l'admin (vérification de la source).
        "admin_indicators": admin_indicators,
        "rendered_with_browser": rendered_with_browser,
        "verified_at": utcnow(),
    }


def _fetch_from_analysis(analysis: dict | None, fetched: FetchResult | None, target: str | None) -> FetchResult | None:
    """Construit un FetchResult à partir du contenu de la méthode retenue par l'analyseur."""
    if not analysis:
        return fetched
    fr = FetchResult()
    fr.reached = True
    fr.status_code = 200
    fr.body = analysis.get("analysis_body") or ""
    fr.content_type = analysis.get("analysis_content_type")
    fr.final_url = analysis.get("analysis_url") or target
    fr.host = (urlparse(fr.final_url or "").hostname or "").lower() or None
    fr.is_https = (fr.final_url or "").startswith("https://")
    fr.ssl_ok = fr.is_https
    return fr


def _detection_report(analysis: dict | None) -> dict | None:
    """Version stockable/affichable de l'analyse (sans le corps volumineux)."""
    if not analysis:
        return None
    return {k: v for k, v in analysis.items() if k not in ("analysis_body", "analysis_content_type")}


def _admin_indicators(fetched: FetchResult | None, credibility: dict, collection_method: str | None,
                      analysis: FetchResult | None = None) -> dict:
    """Indicateurs pour l'écran admin : URL fiable / contient des CVE.

    NB : le contrôle « la source publie des CVE aujourd'hui (source active) » a été retiré
    de la vérification admin (affichage + exécution). Les autres niveaux (technique et
    crédibilité) restent inchangés, et la logique de collecte n'est pas concernée.
    """
    analysis = analysis or fetched
    body = analysis.body if analysis else ""

    # URL valide et fiable : joignable + HTTPS/TLS + crédibilité non rejetée (URL saisie).
    reachable = bool(fetched and (fetched.status_ok or fetched.status_code in (401, 403)))
    https_ok = bool(fetched and fetched.is_https and fetched.ssl_ok)
    url_reliable = reachable and https_ok and not credibility.get("hard_reject", False)

    cve_ids = extract_cve_ids(body)

    return {
        "url_reliable": url_reliable,
        "contains_cve": len(cve_ids) > 0,
        "cve_count": len(cve_ids),
    }


async def test_connection(source: dict) -> dict:
    """Sonde de connectivité réelle utilisée par le bouton « Tester la connexion »."""
    target = source.get("url")
    if not target:
        return {"success": False, "latency_ms": None, "message": "Échec : URL manquante."}

    fetched = await fetch(target)
    if not fetched.reached:
        return {"success": False, "latency_ms": None, "message": f"Échec : {fetched.error or 'injoignable'}"}

    # Une API protégée (401/403) répond : la connexion est établie même si l'accès est refusé.
    reachable = fetched.status_ok or fetched.status_code in (401, 403)
    return {
        "success": reachable,
        "latency_ms": fetched.latency_ms,
        "message": (
            f"Connexion établie — HTTP {fetched.status_code}"
            if reachable
            else f"Réponse HTTP {fetched.status_code} (non valide)"
        ),
    }
