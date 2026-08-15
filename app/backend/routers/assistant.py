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
from app.backend.services.assistant import llm, rag
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


@router.post("/ask")
async def ask(payload: AskIn, user: dict = Depends(require_role("consultant"))):
    db = get_database()
    question = payload.question.strip()

    # RAG : récupération en base + synthèse ancrée (mode = résumé structuré éventuel).
    result = await rag.answer_question(db, question, mode=payload.mode)

    # Conversation (créée si absente).
    now = utcnow()
    if payload.conversation_id:
        conv = await db.assistant_conversations.find_one(
            {"_id": _oid(payload.conversation_id), "consultant_id": user["_id"]})
        if conv is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversation introuvable")
        conv_id = conv["_id"]
        await db.assistant_conversations.update_one({"_id": conv_id}, {"$set": {"updated_at": now}})
    else:
        conv_id = (await db.assistant_conversations.insert_one({
            "consultant_id": user["_id"], "title": question[:70],
            "created_at": now, "updated_at": now})).inserted_id

    await db.assistant_messages.insert_one({
        "conversation_id": conv_id, "consultant_id": user["_id"],
        "question": question, "answer": result["answer"],
        "sources": result.get("sources", []), "confidence": result.get("confidence"),
        "results": result.get("results", []), "count": result.get("count", 0),
        "sections": result.get("sections", []), "style": result.get("style"),
        "generated_by": result.get("generated_by"),
        "scope": result.get("scope", "internal"),
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
