import { useEffect, useMemo, useRef, useState } from "react";
import { MessageCircle, X, Send, ArrowLeft, Search } from "lucide-react";
import api from "../api/axios";
import { useAuth } from "../context/AuthContext";

const WS_BASE = (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(/^http/, "ws");
const fmtTime = (d) => (d ? new Date(d).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" }) : "");

// Widget de messagerie flottant (façon Messenger) — présent en bas à droite de toutes les pages.
export default function ChatWidget() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const myId = user?.id;

  const [open, setOpen] = useState(false);
  const [unread, setUnread] = useState(0);
  const [conversations, setConversations] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [draft, setDraft] = useState("");
  const [view, setView] = useState(isAdmin ? "list" : "chat"); // admin : liste -> chat
  const [search, setSearch] = useState("");
  const [typing, setTyping] = useState(false);

  const wsRef = useRef(null);
  const openRef = useRef(false);
  const activeIdRef = useRef(null);
  const bottomRef = useRef(null);

  const isMine = (m) => (myId ? String(m.sender_id) === String(myId) : m.sender_role === user?.role);

  // --- API ---
  const refreshUnread = () => api.get("/chat/unread-count").then((r) => setUnread(r.data.count)).catch(() => {});

  const loadConversations = async (autoSelect = false) => {
    const { data } = await api.get("/chat/conversations");
    setConversations(data.items);
    if (autoSelect && !isAdmin && data.items[0]) selectConversation(data.items[0].id);
    return data.items;
  };

  const loadMessages = async (id) => {
    const { data } = await api.get(`/chat/conversations/${id}/messages`);
    setMessages(data.items);
    setConversations((cs) => cs.map((c) => (c.id === id ? { ...c, unread: 0 } : c)));
    refreshUnread();
  };

  const selectConversation = (id) => {
    setActiveId(id);
    activeIdRef.current = id;
    setView("chat");
    loadMessages(id);
  };

  // --- Ouverture du panneau ---
  const togglePanel = async () => {
    const next = !open;
    setOpen(next);
    openRef.current = next;
    if (next) {
      const items = await loadConversations(true);
      if (isAdmin) setView("list");
      else if (items[0]) selectConversation(items[0].id);
    }
  };

  // --- Non-lus (poll de secours) + WebSocket temps réel ---
  useEffect(() => {
    if (!user) return;
    refreshUnread();
    const poll = setInterval(refreshUnread, 15000);

    const token = localStorage.getItem("cyberwatch_token");
    const ws = new WebSocket(`${WS_BASE}/chat/ws?token=${token}`);
    wsRef.current = ws;
    ws.onmessage = (ev) => {
      let data;
      try { data = JSON.parse(ev.data); } catch { return; }
      const openId = activeIdRef.current;
      if (data.type === "message") {
        const m = data.message;
        const active = openRef.current && data.conversation_id === openId;
        if (active) {
          setMessages((ms) => (ms.some((x) => x.id === m.id) ? ms : [...ms, m]));
          if (!isMine(m)) loadMessages(openId); // marque lu côté serveur
        } else if (!isMine(m)) {
          setUnread((u) => u + 1);
        }
        setConversations((cs) => {
          const i = cs.findIndex((c) => c.id === data.conversation_id);
          if (i === -1) { loadConversations(); return cs; }
          const c = { ...cs[i], last_message: m.content?.slice(0, 120), last_message_at: m.created_at };
          if (!active && !isMine(m)) c.unread = (c.unread || 0) + 1;
          return [c, ...cs.filter((_, k) => k !== i)];
        });
      } else if (data.type === "read" && data.conversation_id === openId) {
        setMessages((ms) => ms.map((x) => (isMine(x) ? { ...x, read: true } : x)));
      } else if (data.type === "typing" && data.conversation_id === openId && data.role !== user.role) {
        setTyping(true);
        clearTimeout(ws._tt);
        ws._tt = setTimeout(() => setTyping(false), 2500);
      }
    };
    return () => { clearInterval(poll); try { ws.close(); } catch { /* noop */ } };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages, typing, open]);

  const send = async () => {
    const content = draft.trim();
    if (!content || !activeId) return;
    setDraft("");
    const { data } = await api.post(`/chat/conversations/${activeId}/messages`, { content });
    setMessages((ms) => (ms.some((x) => x.id === data.id) ? ms : [...ms, data]));
  };

  const notifyTyping = () => {
    if (wsRef.current?.readyState === 1 && activeId)
      wsRef.current.send(JSON.stringify({ type: "typing", conversation_id: activeId }));
  };

  const filteredConvs = useMemo(() => {
    if (!search.trim()) return conversations;
    const s = search.toLowerCase();
    return conversations.filter((c) => (c.consultant_name || "").toLowerCase().includes(s));
  }, [conversations, search]);

  const activeConv = conversations.find((c) => c.id === activeId);

  if (!user) return null;

  return (
    <>
      {/* Bouton flottant */}
      <button
        onClick={togglePanel}
        className="fixed bottom-5 right-5 z-50 flex h-14 w-14 items-center justify-center rounded-full bg-gradient-to-br from-brand-600 to-brand-700 text-white shadow-lg transition hover:scale-105"
        title="Messagerie"
      >
        {open ? <X size={24} /> : <MessageCircle size={24} />}
        {!open && unread > 0 && (
          <span className="absolute -right-1 -top-1 inline-flex h-5 min-w-[1.25rem] items-center justify-center rounded-full bg-rose-500 px-1.5 text-xs font-bold text-white">
            {unread > 99 ? "99+" : unread}
          </span>
        )}
      </button>

      {/* Fenêtre de chat */}
      {open && (
        <div className="fixed bottom-24 right-5 z-50 flex h-[32rem] w-[23rem] max-w-[calc(100vw-2.5rem)] flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-2xl">
          {/* En-tête */}
          <div className="flex items-center gap-2 bg-gradient-to-r from-brand-600 to-brand-700 px-4 py-3 text-white">
            {isAdmin && view === "chat" && (
              <button onClick={() => setView("list")} className="rounded p-0.5 hover:bg-white/20"><ArrowLeft size={18} /></button>
            )}
            <MessageCircle size={18} />
            <span className="flex-1 truncate text-sm font-semibold">
              {isAdmin ? (view === "chat" ? activeConv?.consultant_name || "Conversation" : "Messagerie") : "Administration"}
            </span>
            <button onClick={togglePanel} className="rounded p-0.5 hover:bg-white/20"><X size={18} /></button>
          </div>

          {/* Corps */}
          {isAdmin && view === "list" ? (
            <div className="flex flex-1 flex-col overflow-hidden">
              <div className="border-b border-slate-100 p-2">
                <div className="flex items-center gap-2 rounded-lg bg-slate-50 px-2.5 py-1.5">
                  <Search size={14} className="text-slate-400" />
                  <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Rechercher…"
                    className="w-full bg-transparent text-sm focus:outline-none" />
                </div>
              </div>
              <div className="flex-1 overflow-y-auto">
                {filteredConvs.length === 0 && <p className="p-4 text-sm text-slate-400">Aucune conversation.</p>}
                {filteredConvs.map((c) => (
                  <button key={c.id} onClick={() => selectConversation(c.id)}
                    className="flex w-full items-center gap-3 border-b border-slate-50 px-3 py-2.5 text-left hover:bg-slate-50">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-brand-100 text-xs font-semibold text-brand-700">
                      {(c.consultant_name || "?").slice(0, 1).toUpperCase()}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex justify-between gap-2">
                        <span className="truncate text-sm font-semibold text-slate-700">{c.consultant_name}</span>
                        <span className="shrink-0 text-[10px] text-slate-400">{fmtTime(c.last_message_at)}</span>
                      </div>
                      <p className="truncate text-xs text-slate-400">{c.last_message || "Nouvelle conversation"}</p>
                    </div>
                    {c.unread > 0 && <span className="inline-flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-brand-600 px-1 text-[10px] font-semibold text-white">{c.unread}</span>}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <>
              <div className="flex-1 space-y-2 overflow-y-auto bg-slate-50/60 px-3 py-3">
                {messages.map((m) => {
                  const mine = isMine(m);
                  return (
                    <div key={m.id} className={`flex ${mine ? "justify-end" : "justify-start"}`}>
                      <div className={`max-w-[80%] rounded-2xl px-3 py-1.5 text-sm ${mine ? "bg-brand-600 text-white" : "bg-white text-slate-700 shadow-sm"}`}>
                        {!mine && isAdmin && <div className="mb-0.5 text-[10px] font-semibold text-brand-600">{m.sender_name}</div>}
                        <div className="whitespace-pre-wrap break-words">{m.content}</div>
                        <div className={`mt-0.5 flex items-center justify-end gap-1 text-[9px] ${mine ? "text-brand-100" : "text-slate-400"}`}>
                          {m.edited && <span>(modifié)</span>}
                          <span>{fmtTime(m.created_at)}</span>
                          {mine && <span>{m.read ? "✓✓" : "✓"}</span>}
                        </div>
                      </div>
                    </div>
                  );
                })}
                {typing && <div className="text-xs italic text-slate-400">en train d'écrire…</div>}
                <div ref={bottomRef} />
              </div>
              <div className="flex items-center gap-2 border-t border-slate-100 p-2">
                <input
                  value={draft}
                  onChange={(e) => { setDraft(e.target.value); notifyTyping(); }}
                  onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
                  maxLength={4000}
                  placeholder="Écrire un message…"
                  className="flex-1 rounded-xl border border-slate-200 px-3 py-2 text-sm focus:border-brand-400 focus:outline-none focus:ring-2 focus:ring-brand-100"
                />
                <button onClick={send} disabled={!draft.trim()}
                  className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-600 text-white transition hover:bg-brand-700 disabled:opacity-40">
                  <Send size={16} />
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </>
  );
}
