"""Messagerie interne (Admin ⇄ Consultant) — REST + WebSocket temps réel.

Modèle : chaque CONSULTANT possède UNE conversation avec l'équipe des ADMINISTRATEURS.
- Un consultant ne voit QUE sa conversation.
- Un administrateur voit TOUTES les conversations et peut répondre à chacune.

Sécurité : JWT (même système que le reste de l'app), autorisation par rôle/propriété,
longueur de message bornée, contenu stocké tel quel puis échappé à l'affichage (React
n'injecte jamais de HTML → pas de XSS). Extensible (groupes, pièces jointes, réactions…).
"""
import asyncio
import json
import logging
from datetime import datetime

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import (APIRouter, Depends, HTTPException, Query, WebSocket,
                     WebSocketDisconnect, status)
from pydantic import BaseModel, Field

from app.backend.core.security import decode_access_token
from app.backend.db.mongodb import get_database
from app.backend.dependencies.auth import get_current_user
from app.backend.utils import serialize_doc, utcnow

logger = logging.getLogger("cyberwatch.chat")
router = APIRouter(prefix="/chat", tags=["chat"])

MAX_MESSAGE_LEN = 4000


def _json_default(o):
    """Encodeur JSON tolérant aux datetime (WebSocket send_json ne les gère pas)."""
    if isinstance(o, datetime):
        return o.isoformat()
    return str(o)


class MessageIn(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_MESSAGE_LEN)


# --------------------------------------------------------------------------------------
# Gestionnaire de connexions WebSocket (livraison temps réel)
# --------------------------------------------------------------------------------------

class ConnectionManager:
    """Diffusion via des FILES par connexion : chaque WebSocket est SEUL à faire `send` (sa tâche
    d'envoi lit sa file). Les autres tâches (ex. POST d'un message) ne touchent jamais le socket ;
    elles déposent l'événement dans les files -> pas d'envoi concurrent sur un même socket."""
    def __init__(self):
        self.queues: dict[str, set["asyncio.Queue"]] = {}   # user_id -> files
        self.roles: dict[str, str] = {}                       # user_id -> rôle

    def register(self, user_id: str, role: str) -> "asyncio.Queue":
        q: asyncio.Queue = asyncio.Queue()
        self.queues.setdefault(user_id, set()).add(q)
        self.roles[user_id] = role
        return q

    def unregister(self, user_id: str, q: "asyncio.Queue"):
        s = self.queues.get(user_id)
        if s:
            s.discard(q)
            if not s:
                self.queues.pop(user_id, None)
                self.roles.pop(user_id, None)

    async def send_to_user(self, user_id: str, data: dict):
        for q in list(self.queues.get(user_id, ())):
            q.put_nowait(data)

    async def send_to_admins(self, data: dict):
        for uid, role in list(self.roles.items()):
            if role == "admin":
                for q in list(self.queues.get(uid, ())):
                    q.put_nowait(data)

    def is_online(self, user_id: str) -> bool:
        return user_id in self.queues


manager = ConnectionManager()


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

def _oid(raw: str) -> ObjectId:
    try:
        return ObjectId(raw)
    except InvalidId:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Identifiant invalide")


def _msg_out(m: dict) -> dict:
    d = serialize_doc(m)
    d["conversation_id"] = str(m.get("conversation_id"))
    d["sender_id"] = str(m.get("sender_id"))
    return d


async def _get_or_create_conversation(db, consultant: dict) -> dict:
    conv = await db.chat_conversations.find_one({"consultant_id": consultant["_id"]})
    if conv:
        return conv
    now = utcnow()
    doc = {
        "consultant_id": consultant["_id"],
        "consultant_name": consultant.get("full_name") or consultant.get("email"),
        "created_at": now, "updated_at": now,
        "last_message": None, "last_message_at": None, "last_sender_role": None,
    }
    doc["_id"] = (await db.chat_conversations.insert_one(doc)).inserted_id
    return doc


async def _conversation_or_403(db, conv_id: ObjectId, user: dict) -> dict:
    conv = await db.chat_conversations.find_one({"_id": conv_id})
    if conv is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversation introuvable")
    # Un consultant n'accède QU'À sa propre conversation ; un admin accède à tout.
    if user["role"] != "admin" and conv["consultant_id"] != user["_id"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Accès refusé")
    return conv


async def _unread_for(db, user: dict) -> int:
    if user["role"] == "admin":
        return await db.chat_messages.count_documents({"sender_role": "consultant", "read": False})
    conv = await db.chat_conversations.find_one({"consultant_id": user["_id"]}, {"_id": 1})
    if not conv:
        return 0
    return await db.chat_messages.count_documents(
        {"conversation_id": conv["_id"], "sender_role": "admin", "read": False})


def _conv_out(conv: dict, unread: int) -> dict:
    d = serialize_doc(conv)
    d["consultant_id"] = str(conv.get("consultant_id"))
    d["unread"] = unread
    return d


# --------------------------------------------------------------------------------------
# REST — Conversations
# --------------------------------------------------------------------------------------

@router.get("/conversations")
async def list_conversations(q: str | None = Query(None), user: dict = Depends(get_current_user)):
    db = get_database()
    if user["role"] == "admin":
        query: dict = {}
        if q:
            query["consultant_name"] = {"$regex": q, "$options": "i"}
        convs = await db.chat_conversations.find(query).sort("updated_at", -1).to_list(500)
        out = []
        for c in convs:
            unread = await db.chat_messages.count_documents(
                {"conversation_id": c["_id"], "sender_role": "consultant", "read": False})
            out.append(_conv_out(c, unread))
        return {"items": out}
    # Consultant : sa conversation (créée si absente).
    conv = await _get_or_create_conversation(db, user)
    unread = await db.chat_messages.count_documents(
        {"conversation_id": conv["_id"], "sender_role": "admin", "read": False})
    return {"items": [_conv_out(conv, unread)]}


@router.post("/conversations", status_code=status.HTTP_201_CREATED)
async def ensure_conversation(user: dict = Depends(get_current_user)):
    """Le consultant s'assure que sa conversation existe (pour démarrer un échange)."""
    if user["role"] != "consultant":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Réservé aux consultants")
    db = get_database()
    conv = await _get_or_create_conversation(db, user)
    return _conv_out(conv, 0)


@router.get("/conversations/{conv_id}/messages")
async def get_messages(conv_id: str, user: dict = Depends(get_current_user)):
    db = get_database()
    conv = await _conversation_or_403(db, _oid(conv_id), user)
    msgs = await db.chat_messages.find({"conversation_id": conv["_id"]}).sort("created_at", 1).to_list(2000)

    # Ouvrir la conversation = marquer LUS les messages de l'autre partie.
    other = "consultant" if user["role"] == "admin" else "admin"
    res = await db.chat_messages.update_many(
        {"conversation_id": conv["_id"], "sender_role": other, "read": False},
        {"$set": {"read": True, "read_at": utcnow()}})
    if res.modified_count:
        # Accusé de lecture temps réel vers l'expéditeur (indicateur « lu »).
        payload = {"type": "read", "conversation_id": conv_id, "by_role": user["role"]}
        if user["role"] == "admin":
            await manager.send_to_user(str(conv["consultant_id"]), payload)
        else:
            await manager.send_to_admins(payload)

    return {"conversation": _conv_out(conv, 0), "items": [_msg_out(m) for m in msgs]}


@router.post("/conversations/{conv_id}/messages", status_code=status.HTTP_201_CREATED)
async def send_message(conv_id: str, payload: MessageIn, user: dict = Depends(get_current_user)):
    db = get_database()
    conv = await _conversation_or_403(db, _oid(conv_id), user)
    content = payload.content.strip()
    if not content:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Message vide")

    now = utcnow()
    sender_role = user["role"]
    receiver_role = "consultant" if sender_role == "admin" else "admin"
    msg = {
        "conversation_id": conv["_id"],
        "sender_id": user["_id"],
        "sender_name": user.get("full_name") or user.get("email"),
        "sender_role": sender_role,
        "receiver_role": receiver_role,
        "receiver_id": conv["consultant_id"] if sender_role == "admin" else None,
        "content": content,               # stocké tel quel ; échappé à l'affichage (React)
        "created_at": now,
        "read": False,
        "edited": False,
    }
    msg["_id"] = (await db.chat_messages.insert_one(msg)).inserted_id
    await db.chat_conversations.update_one(
        {"_id": conv["_id"]},
        {"$set": {"updated_at": now, "last_message": content[:120],
                  "last_message_at": now, "last_sender_role": sender_role}})

    out = _msg_out(msg)
    event = {"type": "message", "conversation_id": conv_id, "message": out}
    # Livraison temps réel : au consultant concerné + à tous les admins connectés.
    await manager.send_to_user(str(conv["consultant_id"]), event)
    await manager.send_to_admins(event)
    return out


@router.patch("/messages/{msg_id}")
async def edit_message(msg_id: str, payload: MessageIn, user: dict = Depends(get_current_user)):
    db = get_database()
    m = await db.chat_messages.find_one({"_id": _oid(msg_id)})
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Message introuvable")
    if m["sender_id"] != user["_id"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "On ne peut modifier que ses propres messages")
    content = payload.content.strip()
    await db.chat_messages.update_one({"_id": m["_id"]},
                                      {"$set": {"content": content, "edited": True, "edited_at": utcnow()}})
    m.update(content=content, edited=True)
    event = {"type": "edit", "conversation_id": str(m["conversation_id"]), "message": _msg_out(m)}
    conv = await db.chat_conversations.find_one({"_id": m["conversation_id"]}, {"consultant_id": 1})
    await manager.send_to_user(str(conv["consultant_id"]), event)
    await manager.send_to_admins(event)
    return _msg_out(m)


@router.delete("/messages/{msg_id}")
async def delete_message(msg_id: str, user: dict = Depends(get_current_user)):
    db = get_database()
    m = await db.chat_messages.find_one({"_id": _oid(msg_id)})
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Message introuvable")
    # Admin peut supprimer un message inapproprié ; un consultant, seulement le sien.
    if user["role"] != "admin" and m["sender_id"] != user["_id"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Accès refusé")
    await db.chat_messages.delete_one({"_id": m["_id"]})
    event = {"type": "delete", "conversation_id": str(m["conversation_id"]), "message_id": msg_id}
    conv = await db.chat_conversations.find_one({"_id": m["conversation_id"]}, {"consultant_id": 1})
    if conv:
        await manager.send_to_user(str(conv["consultant_id"]), event)
    await manager.send_to_admins(event)
    return {"ok": True}


@router.get("/unread-count")
async def unread_count(user: dict = Depends(get_current_user)):
    db = get_database()
    return {"count": await _unread_for(db, user)}


@router.get("/search")
async def search_messages(q: str = Query(..., min_length=1), date_from: str | None = Query(None),
                          date_to: str | None = Query(None), user: dict = Depends(get_current_user)):
    """Recherche par mot-clé (+ plage de dates). Un consultant ne fouille QUE sa conversation."""
    db = get_database()
    query: dict = {"content": {"$regex": q, "$options": "i"}}
    if user["role"] != "admin":
        conv = await db.chat_conversations.find_one({"consultant_id": user["_id"]}, {"_id": 1})
        query["conversation_id"] = conv["_id"] if conv else ObjectId()
    rng: dict = {}
    for key, val in (("$gte", date_from), ("$lte", date_to)):
        if val:
            try:
                rng[key] = datetime.strptime(val[:10], "%Y-%m-%d")
            except ValueError:
                pass
    if rng:
        query["created_at"] = rng
    msgs = await db.chat_messages.find(query).sort("created_at", -1).to_list(200)
    return {"total": len(msgs), "items": [_msg_out(m) for m in msgs]}


# --------------------------------------------------------------------------------------
# WebSocket — temps réel
# --------------------------------------------------------------------------------------

@router.websocket("/ws")
async def chat_ws(ws: WebSocket, token: str = Query(...)):
    payload = decode_access_token(token)
    if payload is None:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    try:
        user = await get_database().users.find_one({"_id": ObjectId(payload["sub"])})
    except (InvalidId, KeyError):
        user = None
    if user is None:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws.accept()
    uid = str(user["_id"])
    q = manager.register(uid, user["role"])
    await manager.send_to_admins({"type": "presence", "user_id": uid, "online": True})

    async def _sender():
        # Seule tâche à écrire sur ce socket : elle vide la file de l'utilisateur.
        try:
            while True:
                item = await q.get()
                await ws.send_text(json.dumps(item, default=_json_default))
        except Exception:  # noqa: BLE001 - socket fermé
            pass

    sender_task = asyncio.create_task(_sender())
    try:
        while True:
            data = await ws.receive_json()
            # Indicateur de saisie (optionnel) : relayé à l'autre partie.
            if data.get("type") == "typing" and data.get("conversation_id"):
                evt = {"type": "typing", "conversation_id": data["conversation_id"], "role": user["role"]}
                conv = await get_database().chat_conversations.find_one(
                    {"_id": ObjectId(data["conversation_id"])}, {"consultant_id": 1})
                if conv:
                    if user["role"] == "admin":
                        await manager.send_to_user(str(conv["consultant_id"]), evt)
                    else:
                        await manager.send_to_admins(evt)
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.info("WS fermé (%s) : %s", uid, str(exc)[:80])
    finally:
        sender_task.cancel()
        manager.unregister(uid, q)
        await manager.send_to_admins({"type": "presence", "user_id": uid, "online": False})
