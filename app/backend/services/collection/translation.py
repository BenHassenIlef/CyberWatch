"""AGENT DE TRADUCTION (anglais → français) des contenus de CVE.

Place dans le pipeline — après l'analyse/enrichissement, avant le stockage :

    Sources → Collecte → Vérification → Enrichissement → ★ TRADUCTION ★ → MongoDB
                                                                              ↓
                                                          Interface consultant + e-mails

RESPONSABILITÉ STRICTE : traduire du texte en langage naturel. L'agent n'analyse pas la
vulnérabilité, ne recalcule aucun score, ne modifie ni sévérité, ni produits, ni versions,
ni identifiants. Il n'invente ni ne supprime aucune information.

L'ORIGINAL N'EST JAMAIS ÉCRASÉ. Les champs canoniques (`title`, `description`, `impact`,
`solution`) restent la version d'origine ; la traduction est écrite dans des champs parallèles
`*_fr`. Renommer les champs d'origine casserait `content_hash()`, `completeness()`, le diff de
`storage`, les bulletins et le RAG de l'assistant — d'où ce choix, conforme au modèle existant.

RÉUTILISE l'intégration LLM existante (`services/assistant/llm.py`, fournisseur configuré par
`LLM_PROVIDER` : groq / grok-xai / openai / anthropic). Aucun second client n'est créé.

UN SEUL APPEL PAR CVE : tous les champs traduisibles partent dans une unique requête JSON.

TOLÉRANT AUX PANNES : si le LLM est indisponible, invalide ou trop lent, la CVE est enregistrée
telle quelle avec `translation_status = "failed"`. Une traduction ratée ne fait jamais échouer
la collecte et ne supprime jamais de donnée.
"""
import asyncio
import json
import logging
import re

from app.backend.services.assistant import llm
from app.backend.services.collection.schema import CVE_RE

logger = logging.getLogger("cyberwatch.collection.translation")

# Champs en langage naturel traduits. Volontairement limité : `vuln_type` contient le plus
# souvent un identifiant CWE (« CWE-787 »), et les listes de produits/versions sont techniques.
TRANSLATABLE_FIELDS = ("title", "description", "impact", "solution")

# États de traduction portés par chaque CVE (champ `translation_status`).
PENDING = "pending"
PROCESSING = "processing"
COMPLETED = "completed"
FAILED = "failed"
NOT_REQUIRED = "not_required"      # contenu déjà français, ou rien à traduire

MAX_CHARS = 4000                   # borne par champ (protège le budget de jetons)
# Les fournisseurs LLM plafonnent le DÉBIT (Groq renvoie HTTP 429 au-delà). Une concurrence
# élevée fait échouer des traductions pour rien : on reste prudent par défaut.
CONCURRENCY = 2
RETRY_BACKOFF = (2.0, 5.0)         # pause avant chaque nouvelle tentative (secondes)

# --------------------------------------------------------------------------------------
# Détection de langue (heuristique, sans dépendance)
# --------------------------------------------------------------------------------------

_EN_WORDS = re.compile(
    r"\b(the|is|are|was|were|this|that|which|allows?|could|would|may|an|of|to|in|on|for|with|"
    r"from|by|before|through|via|attacker|remote|vulnerability|issue|affected|prior)\b", re.I)
_FR_WORDS = re.compile(
    r"\b(le|la|les|des|une|un|est|sont|été|cette|ce|ces|qui|que|dont|permet|permettre|pourrait|"
    r"vulnérabilité|faille|attaquant|distant|avant|par|dans|sur|pour|avec|depuis|affecté)\b", re.I)


def looks_english(text: str | None) -> bool:
    """Le texte est-il vraisemblablement en anglais ? Heuristique par mots outils : ils sont
    trop fréquents pour qu'un texte technique y échappe, et discriminants entre FR et EN."""
    s = (text or "").strip()
    if len(s) < 25:
        return False
    return len(_EN_WORDS.findall(s)) > len(_FR_WORDS.findall(s))


# --------------------------------------------------------------------------------------
# Décision : faut-il traduire cette CVE ?
# --------------------------------------------------------------------------------------

def translatable_payload(rec: dict) -> dict:
    """Champs à traduire (non vides, vraisemblablement anglais), bornés en longueur."""
    out = {}
    for key in TRANSLATABLE_FIELDS:
        value = rec.get(key)
        if isinstance(value, str) and value.strip() and looks_english(value):
            out[key] = value.strip()[:MAX_CHARS]
    return out


def already_translated(rec: dict) -> bool:
    """CVE déjà traitée ? Évite de rappeler le LLM (base de ~10 000 CVE)."""
    status = rec.get("translation_status")
    if status == NOT_REQUIRED:
        return True
    if status != COMPLETED:
        return False
    # « completed » n'est fiable que si au moins un champ français est réellement présent.
    return any(rec.get(f"{k}_fr") for k in TRANSLATABLE_FIELDS)


def needs_translation(rec: dict) -> bool:
    if already_translated(rec):
        return False
    return bool(translatable_payload(rec))


# --------------------------------------------------------------------------------------
# Garde-fou : les informations TECHNIQUES doivent traverser la traduction intactes
# --------------------------------------------------------------------------------------

_CWE_RE = re.compile(r"CWE-\d+", re.I)
_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
_CVSS_VECTOR_RE = re.compile(r"CVSS:\d\.\d/[A-Z:/.\d]+")
_VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+){0,3}\b")
_CPE_RE = re.compile(r"cpe:2\.3:[^\s]+", re.I)


def _technical_tokens(text: str) -> set[str]:
    """Jetons techniques qui doivent se retrouver À L'IDENTIQUE dans la traduction."""
    tokens: set[str] = set()
    for rx in (CVE_RE, _CWE_RE, _URL_RE, _CVSS_VECTOR_RE, _CPE_RE, _VERSION_RE):
        tokens |= {m.group(0) for m in rx.finditer(text)}
    return tokens


def validate(source: str, translated: str) -> tuple[bool, list[str]]:
    """La traduction a-t-elle préservé les valeurs techniques ? Renvoie (valide, manquants).

    Un identifiant CVE/CWE, une URL, un vecteur CVSS ou un numéro de version PERDU ou ALTÉRÉ
    rend la traduction inexploitable : on la rejette plutôt que d'afficher une donnée fausse.
    """
    expected = _technical_tokens(source)
    if not expected:
        return True, []
    low = translated.lower()
    missing = [t for t in expected if t.lower() not in low]
    return (not missing), missing


# --------------------------------------------------------------------------------------
# Appel au LLM — UN SEUL par CVE, entrée et sortie JSON
# --------------------------------------------------------------------------------------

TRANSLATION_SYSTEM = (
    "Tu es un traducteur technique spécialisé en cybersécurité. Tu traduis de l'ANGLAIS vers le "
    "FRANÇAIS, et RIEN D'AUTRE.\n"
    "RÈGLES ABSOLUES :\n"
    "- Tu ne fais que TRADUIRE : tu n'analyses pas, tu n'expliques pas, tu ne résumes pas, tu "
    "n'ajoutes ni ne retires aucune information.\n"
    "- Tu laisses STRICTEMENT INCHANGÉS : les identifiants (CVE-…, CWE-…, GHSA-…), les scores et "
    "vecteurs CVSS, les numéros de version, les URL, les valeurs CPE, les dates, les noms "
    "d'éditeurs et de produits (Microsoft Outlook, Windows 11, Apache Tomcat…).\n"
    "- Tu conserves la terminologie technique consacrée en français (dépassement de tampon, "
    "exécution de code à distance, élévation de privilèges, injection SQL…).\n"
    "- Si un passage est DÉJÀ en français, tu le recopies tel quel.\n"
    "- Tu réponds UNIQUEMENT par un objet JSON valide, sans texte autour ni bloc de code."
)


def _build_prompt(payload: dict) -> str:
    return (
        "Traduis en français la valeur de chaque clé de l'objet JSON ci-dessous.\n\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
        + "\n\nRéponds par un objet JSON ayant EXACTEMENT les mêmes clés "
        f"({', '.join(payload)}), dont les valeurs sont les traductions françaises."
    )


def _parse_json(raw: str | None) -> dict | None:
    """Extrait l'objet JSON de la réponse (tolère un bloc ```json et du texte autour)."""
    if not raw:
        return None
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*(.+?)\s*```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    if not text.startswith("{"):
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            return None
        text = text[start:end + 1]
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


async def translate_record(rec: dict, retries: int = 1) -> dict:
    """Traduit UNE CVE. Renvoie les champs à écrire en base (`*_fr` + `translation_status`).

    Ne lève jamais : toute défaillance se traduit par `translation_status = "failed"`, la CVE
    d'origine restant intacte.
    """
    if already_translated(rec):
        return {}
    payload = translatable_payload(rec)
    if not payload:
        # Rien d'anglais à traduire : contenu déjà français, ou champs vides.
        return {"translation_status": NOT_REQUIRED}
    if not llm.available():
        return {"translation_status": FAILED,
                "translation_error": "Aucun modèle LLM configuré."}

    cve_id = rec.get("cve_id", "?")
    for attempt in range(retries + 1):
        if attempt:
            # Pause avant de réessayer : une réponse vide vient le plus souvent d'un
            # dépassement de débit (HTTP 429), que réessayer aussitôt ne ferait qu'aggraver.
            await asyncio.sleep(RETRY_BACKOFF[min(attempt - 1, len(RETRY_BACKOFF) - 1)])
        raw = await llm.generate(_build_prompt(payload), system=TRANSLATION_SYSTEM,
                                 max_tokens=2000)
        data = _parse_json(raw)
        if data is None:
            logger.warning("Traduction %s : réponse non exploitable (tentative %d/%d).",
                           cve_id, attempt + 1, retries + 1)
            continue

        updates, rejected = {}, []
        for key, source in payload.items():
            value = data.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            ok, missing = validate(source, value)
            if ok:
                updates[f"{key}_fr"] = value.strip()
            else:
                # Valeur technique perdue : on garde l'original pour ce champ (jamais de
                # donnée altérée affichée au consultant).
                rejected.append(f"{key} ({', '.join(missing[:3])})")

        if updates:
            out = {**updates, "translation_status": COMPLETED,
                   "translated_fields": sorted(k[:-3] for k in updates)}
            if rejected:
                out["translation_warning"] = "Champs écartés (technique altérée) : " + "; ".join(rejected)
                logger.info("Traduction %s : %s", cve_id, out["translation_warning"])
            return out

        if rejected:
            return {"translation_status": FAILED,
                    "translation_error": "Valeurs techniques altérées : " + "; ".join(rejected)}

    return {"translation_status": FAILED,
            "translation_error": "Réponse du modèle inexploitable après nouvelle tentative."}


async def translate_batch(records: list[dict], concurrency: int = CONCURRENCY) -> dict:
    """Traduit une liste de CVE EN PLACE (les champs sont fusionnés dans chaque dict).

    Renvoie un compte {traduites, non_requises, echecs, ignorees}. Best-effort : ne lève jamais.
    """
    stats = {"translated": 0, "not_required": 0, "failed": 0, "skipped": 0}
    todo = []
    for rec in records:
        if already_translated(rec):
            stats["skipped"] += 1
        else:
            todo.append(rec)
    if not todo:
        return stats

    sem = asyncio.Semaphore(max(1, concurrency))

    async def _one(rec: dict) -> None:
        async with sem:
            try:
                updates = await translate_record(rec)
            except Exception as exc:  # noqa: BLE001 - la traduction ne casse jamais la collecte
                logger.warning("Traduction %s : %s", rec.get("cve_id"), str(exc)[:150])
                updates = {"translation_status": FAILED, "translation_error": str(exc)[:200]}
            rec.update(updates)
            status = updates.get("translation_status")
            if status == COMPLETED:
                stats["translated"] += 1
            elif status == NOT_REQUIRED:
                stats["not_required"] += 1
            elif status == FAILED:
                stats["failed"] += 1

    await asyncio.gather(*[_one(r) for r in todo])
    return stats


# --------------------------------------------------------------------------------------
# Lecture : version française si disponible, original sinon (repli systématique)
# --------------------------------------------------------------------------------------

def localized(rec: dict, field: str) -> str | None:
    """Valeur à AFFICHER pour ce champ : le français s'il existe, l'original sinon.

    Un champ n'est JAMAIS vide du seul fait que la traduction a échoué.
    """
    return rec.get(f"{field}_fr") or rec.get(field)


def apply_localization(doc: dict) -> dict:
    """Remplace les champs traduisibles par leur version affichable, en conservant l'original
    sous `*_original` pour que l'interface puisse toujours le proposer."""
    out = dict(doc)
    for field in TRANSLATABLE_FIELDS:
        fr = doc.get(f"{field}_fr")
        if fr:
            out[f"{field}_original"] = doc.get(field)
            out[field] = fr
    return out
