"""Adaptateur LLM de l'assistant IA — Groq, Grok (xAI), Anthropic et OpenAI supportés.

NB : « Groq » (groq.com, clés « gsk_… ») et « Grok » (xAI, clés « xai-… ») sont deux
fournisseurs distincts aux noms quasi identiques. Les deux exposent une API compatible
OpenAI et sont servis ici par le même client HTTP ; seules l'URL de base et la clé changent.

DEUX modes d'utilisation, volontairement séparés :

1. ANCRÉ (`GROUNDING_SYSTEM`) — questions sur les CVE RÉELLEMENT collectées en base.
   Le LLM ne reçoit QUE le contexte extrait de MongoDB (champs CVE réels) et un prompt de
   bridage strict : reformuler naturellement, sans jamais inventer ni modifier une valeur
   (CVSS, versions, sources, statut d'exploitation…).

2. EXTERNE (`EXTERNAL_SYSTEM`) — questions générales de cybersécurité qui ne concernent pas
   le contenu de la base (définitions, méthodologie, bonnes pratiques, CVE absente de la
   base). La réponse est produite à partir des connaissances propres du modèle et elle est
   TOUJOURS étiquetée « hors base » par l'appelant (champ `scope: "external"`).

Si aucune clé n'est configurée, ou en cas d'erreur/timeout, `generate()` renvoie None et
l'appelant retombe sur la synthèse déterministe ancrée — donc jamais de régression ni de
dépendance dure à un LLM externe.

Aucune bibliothèque tierce : appel HTTP direct via httpx (déjà présent dans le projet).
"""
import logging

import httpx

from app.backend.core.config import settings

logger = logging.getLogger("cyberwatch.assistant.llm")

# URL de base par défaut de chaque fournisseur (sans le suffixe de version « /v1 »).
_DEFAULT_BASE = {
    "groq": "https://api.groq.com/openai",
    "xai": "https://api.x.ai",
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com",
}

# Fournisseurs exposant l'API « chat completions » compatible OpenAI.
_OPENAI_COMPATIBLE = {"groq", "xai", "openai"}

# Prompt système n° 1 : cadre de bridage anti-hallucination (données de la base UNIQUEMENT).
GROUNDING_SYSTEM = (
    "Tu es un analyste cybersécurité qui rédige des synthèses professionnelles en français. "
    "Tu dois t'appuyer EXCLUSIVEMENT sur les données JSON fournies (issues de la base interne "
    "CyberWatch AI). Règles STRICTES :\n"
    "- N'invente AUCUNE information : n'ajoute rien qui ne soit pas dans les données.\n"
    "- Ne modifie jamais une valeur (score CVSS, versions affectées, sources, statut "
    "d'exploitation, dates, solutions).\n"
    "- Si une information est absente (champ vide ou null), écris exactement : "
    "« Information non disponible dans la base de connaissances. »\n"
    "- Reformule naturellement et clairement ; ne recopie pas mot pour mot les champs bruts.\n"
    "- Respecte EXACTEMENT le format de sections Markdown demandé (titres ### inchangés).\n"
    "- Reste concis, factuel et professionnel."
)

# Prompt système n° 2 : questions EXTERNES (hors base). Les connaissances propres du modèle
# sont autorisées, mais l'honnêteté épistémique est imposée.
EXTERNAL_SYSTEM = (
    "Tu es l'assistant IA de CyberWatch AI, une plateforme de veille en vulnérabilités. "
    "Tu réponds ici à une question qui NE porte PAS sur le contenu de la base interne : tu "
    "utilises donc tes connaissances générales en cybersécurité. Règles :\n"
    "- Réponds en français, de manière claire, structurée et professionnelle.\n"
    "- Adopte le point de vue d'un analyste SOC / consultant en cybersécurité.\n"
    "- Sois précis et concret (exemples, commandes, standards, références) quand c'est utile.\n"
    "- Si tu n'es pas certain d'un fait (score CVSS exact, date, version corrigée), dis-le "
    "explicitement au lieu de deviner ; ne fabrique JAMAIS un identifiant CVE, un score, une "
    "date ou une URL.\n"
    "- Précise, quand c'est pertinent, que l'information doit être recoupée avec une source "
    "officielle (NVD, éditeur, CERT).\n"
    "- N'aide jamais à conduire une attaque contre un système tiers : reste sur la défense, "
    "la détection, la remédiation et la pédagogie.\n"
    "- Structure ta réponse en sections Markdown « ### Titre » quand elle dépasse quelques "
    "phrases ; reste synthétique (moins de 400 mots sauf demande explicite)."
)


def available() -> bool:
    """True si un fournisseur LLM est configuré (clé + provider)."""
    return settings.llm_enabled


def _base_url() -> str:
    """URL de base normalisée : un éventuel suffixe /v1 fourni par l'utilisateur est retiré."""
    base = (settings.LLM_BASE_URL or _DEFAULT_BASE.get(settings.llm_provider, "")).strip()
    base = base.rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    return base


async def generate(user_prompt: str, system: str = GROUNDING_SYSTEM,
                   max_tokens: int = 1200) -> str | None:
    """Retourne le texte produit par le LLM, ou None si indisponible (-> fallback ancré)."""
    if not settings.llm_enabled:
        return None
    try:
        return await _call(system, user_prompt, max_tokens)
    except Exception as exc:  # noqa: BLE001 - toute erreur réseau/API -> fallback silencieux
        logger.warning("Appel LLM (%s) échoué : %s", settings.llm_provider, str(exc)[:200])
        return None


async def _call(system: str, user: str, max_tokens: int) -> str | None:
    provider = settings.llm_provider
    if provider in _OPENAI_COMPATIBLE:
        return await _chat_completions(system, user, max_tokens)
    if provider == "anthropic":
        return await _anthropic(system, user, max_tokens)
    return None


async def _chat_completions(system: str, user: str, max_tokens: int) -> str | None:
    """Groq / Grok (xAI) / OpenAI — POST {base}/v1/chat/completions.

    `max_completion_tokens` est le paramètre moderne ; `max_tokens` reste envoyé pour les
    passerelles plus anciennes. Les modèles à raisonnement (GPT-OSS…) placent leur brouillon
    dans un champ séparé : seul `message.content` est retenu.
    """
    async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT) as client:
        resp = await client.post(
            f"{_base_url()}/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.LLM_API_KEY}",
                     "content-type": "application/json"},
            json={"model": settings.llm_model, "temperature": 0.2,
                  "max_tokens": max_tokens, "max_completion_tokens": max_tokens,
                  "messages": [{"role": "system", "content": system},
                               {"role": "user", "content": user}]})
        resp.raise_for_status()
        data = resp.json()
        text = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        return text.strip() or None


async def _anthropic(system: str, user: str, max_tokens: int) -> str | None:
    async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT) as client:
        resp = await client.post(
            f"{_base_url()}/v1/messages",
            headers={"x-api-key": settings.LLM_API_KEY, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": settings.llm_model, "max_tokens": max_tokens, "system": system,
                  "messages": [{"role": "user", "content": user}]})
        resp.raise_for_status()
        data = resp.json()
        parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
        text = "".join(parts).strip()
        return text or None


# --------------------------------------------------------------------------------------
# Diagnostic : vérifier la configuration SANS masquer l'erreur (utilisé par /health).
# --------------------------------------------------------------------------------------

async def ping() -> dict:
    """Teste réellement la connexion au fournisseur et retourne un diagnostic lisible."""
    status_out = {
        "enabled": settings.llm_enabled,
        "provider": settings.llm_provider or None,
        "provider_raw": settings.LLM_PROVIDER or None,
        "model": settings.llm_model if settings.llm_enabled else None,
        "base_url": _base_url() if settings.llm_enabled else None,
        "external_answers": settings.external_answers_enabled,
        "ok": False,
        "error": None,
    }
    if not settings.llm_enabled:
        status_out["error"] = (
            "LLM désactivé : renseignez LLM_PROVIDER=grok et LLM_API_KEY dans le fichier .env, "
            "puis redémarrez le backend.")
        return status_out
    try:
        # Budget volontairement large : les modèles à raisonnement (GPT-OSS, o-series, Grok
        # « thinking ») consomment des jetons de réflexion AVANT d'émettre le moindre contenu.
        # Un budget trop court renverrait une réponse vide et un faux diagnostic d'échec.
        text = await _call("Réponds par un seul mot.", "Dis « ok ».", 512)
        status_out["ok"] = bool(text)
        status_out["sample"] = (text or "")[:80]
        if not text:
            status_out["error"] = (
                "Le fournisseur a répondu sans contenu exploitable — modèle inconnu ou budget "
                f"de jetons insuffisant pour « {settings.llm_model} ».")
    except httpx.HTTPStatusError as exc:
        status_out["error"] = f"HTTP {exc.response.status_code} : {exc.response.text[:300]}"
    except Exception as exc:  # noqa: BLE001
        status_out["error"] = f"{type(exc).__name__} : {str(exc)[:300]}"
    return status_out
