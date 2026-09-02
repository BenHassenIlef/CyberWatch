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
import asyncio
import logging
import re
from dataclasses import dataclass

import httpx

from app.backend.core.config import settings

logger = logging.getLogger("cyberwatch.assistant.llm")


@dataclass(frozen=True)
class Reponse:
    """Texte produit par le modèle, ET l'information que la limite de longueur l'a interrompu.

    POURQUOI CE DRAPEAU EXISTE. Le fournisseur signale dans `finish_reason` qu'il a cessé
    d'écrire faute de jetons, et non parce qu'il avait fini. Cette distinction n'était pas
    lue : seul `message.content` était retenu, si bien qu'une réponse coupée en plein mot
    remontait jusqu'au consultant avec les mêmes atours qu'une réponse aboutie.

    C'est la pire des défaillances silencieuses. Une panne se voit et fait recommencer ;
    un plan de mise en conformité amputé de ses trois dernières étapes se lit, se cite et
    s'applique — l'absence n'a laissé aucune trace à l'écran.
    """

    texte: str | None
    tronquee: bool = False


_TITRE_RE = re.compile(r"\s*#{1,6}\s")
_FIN_PHRASE_RE = re.compile(r"[.!?…][\"'»)\]]?(?=\s|$)")


def _derniere_phrase(texte: str) -> str:
    """Texte ramené à sa dernière phrase achevée ; inchangé s'il n'en contient aucune."""
    fins = list(_FIN_PHRASE_RE.finditer(texte))
    return texte[: fins[-1].end()].rstrip() if fins else texte.rstrip()


def _refermer_marqueurs(texte: str) -> str:
    """Referme le balisage resté ouvert par la coupure.

    Un `**` orphelin ne se contente pas d'être laid : le lecteur Markdown cherche sa paire
    plus loin et met en gras tout ce qui suit, y compris l'avertissement d'incomplétude —
    la seule ligne qui devait rester lisible.
    """
    if texte.count("```") % 2:
        texte = texte.rstrip() + "\n```"
    if texte.count("**") % 2:
        position = texte.rfind("**")
        texte = texte[:position] + texte[position + 2:]
    return texte.rstrip()


def couper_proprement(texte: str) -> str:
    """Ramène un texte interrompu par le plafond de jetons à sa dernière unité COMPLÈTE.

    Le modèle s'arrête au milieu d'un mot : « … et désigner un ** ». Rendu tel quel, cela
    donne à lire une phrase FAUSSE là où il n'y avait qu'une phrase absente — et une phrase
    fausse, personne ne la signale, on la croit.

    On retire donc la dernière ligne, toujours interrompue, puis les titres devenus vides :
    un titre sans corps annonce une section que le lecteur cherchera en vain.
    """
    if not texte:
        return texte
    lignes = texte.split("\n")
    if len(lignes) > 1:
        if not texte.endswith("\n"):
            lignes = lignes[:-1]          # cette dernière ligne est celle qu'on a interrompue
        while lignes and (not lignes[-1].strip() or _TITRE_RE.match(lignes[-1])):
            lignes.pop()
        propre = "\n".join(lignes).rstrip()
    else:
        # Réponse d'un seul tenant : il n'y a pas de ligne à retirer, la coupure se fait
        # alors à la dernière phrase achevée.
        propre = ""
    return _refermer_marqueurs(propre or _derniere_phrase(texte))

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
    "La question posée ne porte PAS sur le contenu de la base interne : réponds-y avec tes "
    "connaissances générales. Règles :\n"
    # UNE QUESTION HORS SUJET MERITE UNE REPONSE, PAS UN RENVOI.
    #
    # Le consultant qui demande autre chose sait parfaitement ce qu'est cet outil. Lui
    # repondre « je suis un assistant cybersecurite » ne lui apprend rien, ne l'aide pas, et
    # transforme une question banale en mur. Repondre brievement coute quelques jetons et
    # laisse la conversation ouverte.
    "- Ta spécialité est la cybersécurité, mais tu réponds AUSSI aux questions d'un autre "
    "domaine ou de simple conversation. Une question hors sujet reçoit une réponse utile et "
    "brève — jamais un refus, jamais un renvoi vers la cybersécurité.\n"
    "- Réponds en français, de manière claire, structurée et professionnelle.\n"
    "- Sur un sujet de cybersécurité, adopte le point de vue d'un analyste SOC / consultant.\n"
    "- Sois précis et concret (exemples, commandes, standards, références) quand c'est utile.\n"
    "- Si tu n'es pas certain d'un fait (score CVSS exact, date, version corrigée), dis-le "
    "explicitement au lieu de deviner ; ne fabrique JAMAIS un identifiant CVE, un score, une "
    "date ou une URL.\n"
    "- Précise, quand c'est pertinent, que l'information doit être recoupée avec une source "
    "officielle (NVD, éditeur, CERT).\n"
    "- N'aide jamais à conduire une attaque contre un système tiers : reste sur la défense, "
    "la détection, la remédiation et la pédagogie.\n"
    "- Structure ta réponse en sections Markdown « ### Titre » quand elle dépasse quelques "
    "phrases ; reste synthétique (moins de 400 mots sauf demande explicite).\n"
    # Un tableau Markdown coûte beaucoup de jetons par ligne. Trois tableaux dans une même
    # réponse épuisaient le budget de rédaction et la réponse s'arrêtait en plein mot —
    # « 4. **Rec » s'affichait à l'écran. Une comparaison tient dans un seul tableau.
    "- Au plus UN tableau par réponse, et seulement pour une comparaison point par "
    "point. Exprime le reste en phrases ou en listes à puces.\n"
    "- TERMINE toujours ta réponse : mieux vaut être plus bref que t'interrompre en "
    "cours de phrase ou de liste."
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


# Reprises sur limite de debit. Le fournisseur repond « 429 Too Many Requests » des que le
# quota par minute est atteint ; sans reprise, l'appel etait simplement perdu et la
# fonctionnalite appelante retombait en mode degrade pour une raison purement transitoire.
MAX_TENTATIVES = 3
ATTENTE_PAR_DEFAUT = 12.0      # secondes, si le serveur n'indique pas de delai
# Plafond d'UNE attente. Volontairement inferieur a BUDGET_ATTENTE_TOTAL (voir plus bas) :
# un delai superieur au budget serait systematiquement refuse, et la reprise ne servirait
# alors plus jamais a rien. Le quota par minute se reconstituant en continu, une echeance
# au-dela de ce seuil signale un credit epuise plutot qu'un simple pic.
ATTENTE_MAX = 25.0


def _delai_avant_reprise(exc: Exception, tentative: int) -> float | None:
    """Secondes a patienter avant de reessayer, ou None si l'erreur n'est pas transitoire.

    Seules les erreurs de DEBIT (429) et les incidents serveur (5xx) sont reessayes. Une
    charge utile trop grande ou une cle invalide se reproduirait a l'identique : inutile.
    """
    reponse = getattr(exc, "response", None)
    if reponse is None:
        return None
    code = reponse.status_code
    if code != 429 and code < 500:
        return None
    entete = reponse.headers.get("retry-after")
    if entete:
        try:
            delai = float(entete)
        except (TypeError, ValueError):
            delai = None
        if delai is not None:
            # Un delai ANNONCE plus long que ce qu'on accepte d'attendre signale un quota
            # EPUISE (chez Groq : le plafond quotidien), pas un simple pic de trafic.
            # Reessayer echouerait a l'identique tout en bloquant l'appelant : on rend la
            # main tout de suite et la fonctionnalite retombe proprement sur son mode degrade.
            return delai if delai <= ATTENTE_MAX else None

    # ECHEANCE PRECISE annoncee par le fournisseur : le quota par minute se reconstitue en
    # continu, et l'en-tete dit exactement quand il redeviendra suffisant (« 915ms », « 24s »).
    # A defaut, on attendait 20 s puis 40 s a l'aveugle — la reprise arrivait longtemps apres
    # que le credit fut revenu, et une question banale prenait une demi-minute.
    fenetre = _secondes(reponse.headers.get("x-ratelimit-reset-tokens"))
    if fenetre is not None:
        # Meme regle que pour « retry-after » : une echeance plus lointaine que ce qu'on
        # accepte d'attendre signale un credit qui ne reviendra pas a temps. Plafonner
        # l'attente au lieu d'abandonner ferait patienter l'appelant 65 s a chaque tentative
        # pour un appel voue a echouer — trois fois de suite, et sur chaque question.
        return fenetre + 1.0 if fenetre <= ATTENTE_MAX else None   # +1 s de marge d'horloge
    return min(ATTENTE_PAR_DEFAUT * tentative, ATTENTE_MAX)


_DUREE_RE = re.compile(r"(?:(\d+(?:\.\d+)?)m(?!s))?(?:(\d+(?:\.\d+)?)s)?(?:(\d+(?:\.\d+)?)ms)?$")


def _secondes(valeur: str | None) -> float | None:
    """Convertit une duree du fournisseur (« 915ms », « 24s », « 2m52.8s ») en secondes."""
    if not valeur:
        return None
    correspondance = _DUREE_RE.match(valeur.strip())
    if not correspondance or not any(correspondance.groups()):
        return None
    minutes, secondes, millisecondes = correspondance.groups()
    return (float(minutes or 0) * 60) + float(secondes or 0) + (float(millisecondes or 0) / 1000)


# PLAFOND DUR sur l'attente CUMULEE d'un seul appel, toutes reprises confondues.
#
# Une latence bornee doit se PROUVER, pas s'esperer. Chaque garde-fou pris isolement semblait
# suffisant — trois tentatives au plus, chacune plafonnee — et pourtant une question a mis
# 2 000 secondes a repondre lors d'un enchainement rapide. Ce compteur unique rend la duree
# maximale independante du nombre de couches de reprise : passe ce budget, on rend la main et
# la reponse se rabat sur le mode ancre, qui reste exact.
#
# Mieux vaut une reponse non reformulee en 30 secondes qu'une reponse parfaite en une demi-heure.
BUDGET_ATTENTE_TOTAL = 30.0


async def generate(user_prompt: str, system: str = GROUNDING_SYSTEM,
                   max_tokens: int = 1200, effort: str | None = None) -> str | None:
    """Texte produit par le LLM, ou None si indisponible (-> repli deterministe ancre).

    Forme historique, conservee pour les appelants que la troncature n'expose pas : une
    traduction ou un resume court tiennent tres en deca de leur plafond. Les appelants dont
    la reponse s'affiche telle quelle au consultant emploient `generer()`, qui dit AUSSI si
    le modele a ete interrompu.
    """
    return (await generer(user_prompt, system, max_tokens, effort)).texte


async def generer(user_prompt: str, system: str = GROUNDING_SYSTEM,
                  max_tokens: int = 1200, effort: str | None = None) -> Reponse:
    """Retourne le texte produit par le LLM, ou None si indisponible (-> fallback ancre).

    `effort` regle la profondeur de raisonnement du modele (« low » / « medium » / « high »).
    Mesure sur cette installation : « low » divise le brouillon interne par neuf (73 jetons
    -> 8) et le cout total d'un tiers. Le fournisseur bornant le debit a 8 000 jetons par
    MINUTE, ces jetons de brouillon se payaient en attentes sur la question suivante.

    A n'employer que la ou la tache est de RESTITUER des faits deja etablis. Une question
    de methode ou de definition merite que le modele reflechisse : on laisse alors None.
    """
    if not settings.llm_enabled:
        return Reponse(None)
    attente_cumulee = 0.0
    for tentative in range(1, MAX_TENTATIVES + 1):
        try:
            return await _call(system, user_prompt, max_tokens, effort)
        except Exception as exc:  # noqa: BLE001 - toute erreur -> reprise puis fallback
            delai = _delai_avant_reprise(exc, tentative)
            if delai is None or tentative == MAX_TENTATIVES:
                logger.warning("Appel LLM (%s) echoue : %s",
                               settings.llm_provider, str(exc)[:200])
                return Reponse(None)
            if attente_cumulee + delai > BUDGET_ATTENTE_TOTAL:
                logger.warning(
                    "Debit LLM : reprise abandonnee (%.0fs deja attendues, %.0fs demandees, "
                    "budget %.0fs). Reponse rendue sans reformulation.",
                    attente_cumulee, delai, BUDGET_ATTENTE_TOTAL)
                return Reponse(None)
            attente_cumulee += delai
            logger.info("Debit LLM atteint, reprise dans %.0fs (tentative %d/%d)",
                        delai, tentative, MAX_TENTATIVES)
            await asyncio.sleep(delai)
    return Reponse(None)


async def _call(system: str, user: str, max_tokens: int,
                effort: str | None = None) -> Reponse:
    provider = settings.llm_provider
    if provider in _OPENAI_COMPATIBLE:
        return await _chat_completions(system, user, max_tokens, effort)
    if provider == "anthropic":
        return await _anthropic(system, user, max_tokens)
    return Reponse(None)


# Seuil d'alerte sur le budget par minute. En deçà, la requête suivante partira en « 429 » :
# mieux vaut le voir dans le journal que le découvrir par une réponse dégradée.
SEUIL_JETONS_RESTANTS = 2000


def _tracer_consommation(data: dict, entetes) -> None:
    """Journalise le coût réel d'un appel et l'état du quota. Aucune donnée, aucun secret.

    Le fournisseur borne le débit à quelques milliers de jetons PAR MINUTE. Sans cette
    mesure, un dépassement se manifeste par une réponse déterministe inexpliquée : on croit
    le modèle défaillant alors qu'on lui a simplement demandé trop de choses trop vite.
    """
    usage = data.get("usage") or {}
    total = usage.get("total_tokens")
    if total is None:
        return
    raisonnement = (usage.get("completion_tokens_details") or {}).get("reasoning_tokens")
    restants = entetes.get("x-ratelimit-remaining-tokens")
    message = ("Appel LLM : %s jetons (invite %s, réponse %s, dont %s de raisonnement)"
               % (total, usage.get("prompt_tokens"), usage.get("completion_tokens"),
                  raisonnement))
    if restants is not None:
        message += f" — reste {restants} jetons sur la minute"
        try:
            if int(restants) < SEUIL_JETONS_RESTANTS:
                logger.warning("%s : le prochain appel risque d'être refusé (429).", message)
                return
        except (TypeError, ValueError):
            pass
    logger.info("%s.", message)


def _corps(system: str, user: str, max_tokens: int, effort: str | None) -> dict:
    """Charge utile de la requete. `reasoning_effort` n'est envoye que s'il est demande :
    une passerelle qui ne le connait pas refuserait un champ inconnu."""
    corps = {"model": settings.llm_model, "temperature": 0.2,
             "max_tokens": max_tokens, "max_completion_tokens": max_tokens,
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": user}]}
    if effort:
        corps["reasoning_effort"] = effort
    return corps


async def _chat_completions(system: str, user: str, max_tokens: int,
                            effort: str | None = None) -> Reponse:
    """Groq / Grok (xAI) / OpenAI — POST {base}/v1/chat/completions.

    `max_completion_tokens` est le paramètre moderne ; `max_tokens` reste envoyé pour les
    passerelles plus anciennes. Les modèles à raisonnement (GPT-OSS…) placent leur brouillon
    dans un champ séparé : seul `message.content` est retenu.

    `finish_reason` vaut « length » quand le modèle a été interrompu par le plafond de
    jetons, et « stop » quand il a terminé de lui-même. Les deux cas rendent du texte : seul
    cet indicateur les distingue.
    """
    async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT) as client:
        resp = await client.post(
            f"{_base_url()}/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.LLM_API_KEY}",
                     "content-type": "application/json"},
            json=_corps(system, user, max_tokens, effort))
        resp.raise_for_status()
        data = resp.json()
        _tracer_consommation(data, resp.headers)
        choix = (data.get("choices") or [{}])[0]
        text = (choix.get("message") or {}).get("content") or ""
        tronquee = choix.get("finish_reason") == "length"
        if tronquee:
            logger.warning(
                "Reponse LLM interrompue par le plafond de %d jetons : elle est INCOMPLETE.",
                max_tokens)
        return Reponse(text.strip() or None, tronquee)


async def _anthropic(system: str, user: str, max_tokens: int) -> Reponse:
    """Anthropic — l'equivalent de `finish_reason: length` s'y nomme `stop_reason: max_tokens`."""
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
        tronquee = data.get("stop_reason") == "max_tokens"
        if tronquee:
            logger.warning(
                "Reponse LLM interrompue par le plafond de %d jetons : elle est INCOMPLETE.",
                max_tokens)
        return Reponse(text or None, tronquee)


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
        text = (await _call("Réponds par un seul mot.", "Dis « ok ».", 512)).texte
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
