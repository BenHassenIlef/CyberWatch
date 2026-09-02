"""Assistant IA cybersécurité (RAG + IA générative) — RÉSERVÉ AUX CONSULTANTS.

Deux portées de réponse, toujours distinguées par le champ `scope` :
  • "internal" : réponse ANCRÉE sur la base interne (CVE, historiques, bulletins, sources).
    Aucune information non étayée ; à défaut de document, message « non disponible ».
  • "external" : question générale de cybersécurité (hors base) déléguée au modèle configuré
    (Grok / xAI par défaut) et explicitement signalée comme provenant de l'extérieur.

Sauvegarde chaque conversation (question, réponse, sources, portée) pour la relire plus tard.
"""
from datetime import datetime

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.backend.core.config import settings
from app.backend.db.mongodb import get_database
from app.backend.dependencies.auth import require_role
from app.backend.services.assistant import conversation, llm
from app.backend.services.assistant import harness
from app.backend.utils import serialize_doc, utcnow

# Dépendance de rôle au niveau du routeur -> l'espace ADMIN n'y a PAS accès.
router = APIRouter(prefix="/consultant/assistant", tags=["assistant"],
                   dependencies=[Depends(require_role("consultant"))])


class AskIn(BaseModel):
    question: str = Field(min_length=2, max_length=1000)
    conversation_id: str | None = None
    # Force un résumé structuré : "executive" | "technical" | "changes" (boutons IA). Optionnel.
    mode: str | None = None


# Suggestions ANCRÉES : interrogent le contenu réellement collecté en base.
SUGGESTIONS_BASE = [
    "Affiche les CVE critiques d'aujourd'hui",
    "Quelles vulnérabilités Microsoft ont un CVSS supérieur à 9 ?",
    "Vulnérabilités affectant Apache ce mois-ci",
    "Combien de CVE ont affecté le noyau Linux cette année ?",
    "Vulnérabilités avec un exploit connu",
    "Quel éditeur a le plus de vulnérabilités cette année ?",
]

# Suggestions EXTERNES : proposées uniquement quand un modèle d'IA est configuré.
SUGGESTIONS_EXTERNAL = [
    "Qu'est-ce qu'une attaque par chaîne d'approvisionnement ?",
    "Comment prioriser la remédiation avec EPSS et le catalogue KEV ?",
    "Quelle est la différence entre CVE, CWE et CVSS ?",
    "Quelles bonnes pratiques pour durcir un serveur web exposé ?",
]


def _oid(raw: str) -> ObjectId:
    try:
        return ObjectId(raw)
    except InvalidId:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Identifiant invalide")


@router.get("/suggestions")
async def suggestions():
    items = list(SUGGESTIONS_BASE)
    if settings.external_answers_enabled:
        items += SUGGESTIONS_EXTERNAL
    return {"items": items, "external_answers": settings.external_answers_enabled}


@router.get("/health")
async def health():
    """Diagnostic de l'agent IA : fournisseur, modèle, et test réel de connexion à l'API."""
    return await llm.ping()


@router.get("/harness")
async def harness_capabilities():
    """Capacités du harness : agents déclarés et outils que CHACUN a le droit d'appeler.

    Lecture seule et sans secret : ni clé, ni prompt système, ni fonction exécutable. Sert à
    vérifier les permissions depuis l'extérieur — un tableau de permissions qu'on ne peut pas
    consulter est un tableau que personne ne relit.
    """
    return {
        "agents": [
            {"nom": a.nom, "role": a.role,
             "outils": harness.agents.outils_autorises(a.nom)}
            for a in harness.agents.AGENTS.values()
        ],
        "outils": harness.outils.catalogue(),
        "limites": {"reprises_max": harness.MAX_REPRISES,
                    "budget_outils_s": harness.BUDGET_OUTILS_S,
                    "question_max_caracteres": harness.securite.MAX_QUESTION},
    }


@router.post("/ask")
async def ask(payload: AskIn, user: dict = Depends(require_role("consultant"))):
    db = get_database()
    question = payload.question.strip()

    # Conversation (créée si absente). Résolue AVANT la réponse : les échanges précédents
    # servent à comprendre une question de suivi (« et pour Microsoft ? »), qui sans eux
    # arrivait au moteur dépouillée de son sujet.
    now = utcnow()
    historique: list[dict] = []
    if payload.conversation_id:
        conv = await db.assistant_conversations.find_one(
            {"_id": _oid(payload.conversation_id), "consultant_id": user["_id"]})
        if conv is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversation introuvable")
        conv_id = conv["_id"]
        historique = await db.assistant_messages.find(
            {"conversation_id": conv_id},
            {"question": 1, "answer": 1},
        ).sort("created_at", -1).to_list(conversation.MAX_ECHANGES)
        historique.reverse()          # du plus ancien au plus récent
        await db.assistant_conversations.update_one({"_id": conv_id}, {"$set": {"updated_at": now}})
    else:
        conv_id = (await db.assistant_conversations.insert_one({
            "consultant_id": user["_id"], "title": question[:70],
            "created_at": now, "updated_at": now})).inserted_id

    # HARNESS — contrôleur d'exécution placé AUTOUR de l'assistant existant.
    #
    # Le contrat de cette route ne change pas : mêmes paramètres, mêmes champs en retour.
    # Ce qui change est le TRAJET interne — planification de l'agent, permissions d'outils,
    # délais, reprises bornées, validation, assainissement de la sortie — avant que
    # `rag.answer_question` ne rédige, comme il le faisait déjà, la réponse finale.
    try:
        result = await harness.repondre(db, question, historique=historique, mode=payload.mode)
    except harness.HarnessIndisponible as exc:
        # Entrée refusée (vide, démesurée) : on le dit franchement plutôt que de renvoyer une
        # erreur technique que le consultant ne saurait pas corriger.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    await db.assistant_messages.insert_one({
        "conversation_id": conv_id, "consultant_id": user["_id"],
        "question": question, "answer": result["answer"],
        # Question réellement traitée après réécriture d'un suivi — conservée pour que
        # l'historique reste relisible : sans elle, « et pour Microsoft ? » suivi d'une
        # réponse sur Microsoft paraîtrait sortir de nulle part.
        "rewritten_question": result.get("rewritten_question"),
        "sources": result.get("sources", []), "confidence": result.get("confidence"),
        "results": result.get("results", []), "count": result.get("count", 0),
        "sections": result.get("sections", []), "style": result.get("style"),
        "generated_by": result.get("generated_by"),
        "scope": result.get("scope", "internal"),
        # TRACE D'ORCHESTRATION : agent retenu, outils appelés, statuts, reprises, durée.
        # Ne porte ni question, ni réponse, ni secret — de quoi diagnostiquer une réponse
        # décevante des semaines plus tard, sans conserver de données sensibles.
        "harness": result.get("harness"),
        "tools_used": result.get("tools_used", []),
        "created_at": now,
    })
    return {**result, "conversation_id": str(conv_id)}


@router.get("/conversations")
async def list_conversations(user: dict = Depends(require_role("consultant"))):
    db = get_database()
    convs = await db.assistant_conversations.find(
        {"consultant_id": user["_id"]}).sort("updated_at", -1).to_list(100)
    return {"items": [serialize_doc(c) for c in convs]}


@router.get("/conversations/{conv_id}")
async def get_conversation(conv_id: str, user: dict = Depends(require_role("consultant"))):
    db = get_database()
    conv = await db.assistant_conversations.find_one(
        {"_id": _oid(conv_id), "consultant_id": user["_id"]})
    if conv is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversation introuvable")
    msgs = await db.assistant_messages.find(
        {"conversation_id": conv["_id"]}).sort("created_at", 1).to_list(500)
    return {"conversation": serialize_doc(conv), "items": [serialize_doc(m) for m in msgs]}


@router.delete("/conversations/{conv_id}")
async def delete_conversation(conv_id: str, user: dict = Depends(require_role("consultant"))):
    db = get_database()
    oid = _oid(conv_id)
    conv = await db.assistant_conversations.find_one({"_id": oid, "consultant_id": user["_id"]})
    if conv is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversation introuvable")
    await db.assistant_messages.delete_many({"conversation_id": oid})
    await db.assistant_conversations.delete_one({"_id": oid})
    return {"ok": True}
