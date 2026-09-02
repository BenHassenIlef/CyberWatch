import { useEffect, useRef, useState } from "react";
import { useSearchParams, useNavigate, Link } from "react-router-dom";
import { Sparkles, Send, Plus, MessageSquare, ShieldAlert, ExternalLink, Trash2, Globe, Database } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import AiSummaryButtons from "../../components/ui/AiSummaryButtons";
import Markdown from "../../components/ui/Markdown";
import api from "../../api/axios";
import { useConsultantNavItems } from "./navItems";
import { SEVERITY_LABELS, SEVERITY_STYLES } from "./cveConstants";

const CONF_LABEL = { high: "élevée", medium: "moyenne", low: "faible", none: "aucune", external: "hors base" };
const CONF_STYLE = {
  high: "bg-emerald-100 text-emerald-700", medium: "bg-amber-100 text-amber-700",
  low: "bg-slate-100 text-slate-600", none: "bg-rose-100 text-rose-700",
  external: "bg-violet-100 text-violet-700",
};

// Origine de la réponse : base interne (ancrée) ou connaissances générales du modèle.
const ORIGIN = {
  llm_external: { label: "Connaissances IA — hors base", style: "bg-violet-100 text-violet-700", Icon: Globe },
  llm: { label: "Base interne · reformulé par IA", style: "bg-brand-100 text-brand-700", Icon: Database },
  grounded: { label: "Base interne · synthèse ancrée", style: "bg-slate-100 text-slate-500", Icon: Database },
  unavailable: { label: "IA non configurée", style: "bg-rose-100 text-rose-700", Icon: ShieldAlert },
};

export default function Assistant() {
  const navItems = useConsultantNavItems();
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const [messages, setMessages] = useState([]); // {role, question|answer, sources, results, confidence, count}
  const [draft, setDraft] = useState("");
  const [loading, setLoading] = useState(false);
  const [suggestions, setSuggestions] = useState([]);
  const [conversations, setConversations] = useState([]);
  const [convId, setConvId] = useState(null);
  const bottomRef = useRef(null);
  const askedInitial = useRef(false);

  const loadConversations = () =>
    api.get("/consultant/assistant/conversations").then((r) => setConversations(r.data.items));

  useEffect(() => {
    api.get("/consultant/assistant/suggestions").then((r) => setSuggestions(r.data.items));
    loadConversations();
    const q = params.get("q");
    const mode = params.get("mode");
    if (q && !askedInitial.current) { askedInitial.current = true; setParams({}, { replace: true }); ask(q, mode); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages, loading]);

  const ask = async (question, mode) => {
    const q = (question ?? draft).trim();
    if (!q || loading) return;
    setDraft("");
    setMessages((m) => [...m, { role: "user", question: q }]);
    setLoading(true);
    try {
      const { data } = await api.post("/consultant/assistant/ask", { question: q, conversation_id: convId, mode });
      setConvId(data.conversation_id);
      setMessages((m) => [...m, { role: "assistant", ...data }]);
      loadConversations();
    } catch {
      setMessages((m) => [...m, { role: "assistant", answer: "Une erreur est survenue.", confidence: "none", results: [], sources: [] }]);
    } finally {
      setLoading(false);
    }
  };

  const openConversation = async (id) => {
    const { data } = await api.get(`/consultant/assistant/conversations/${id}`);
    const msgs = [];
    for (const m of data.items) {
      msgs.push({ role: "user", question: m.question });
      msgs.push({ role: "assistant", answer: m.answer, sources: m.sources, results: m.results, confidence: m.confidence, count: m.count, sections: m.sections, style: m.style, generated_by: m.generated_by, scope: m.scope, rewritten_question: m.rewritten_question });
    }
    setMessages(msgs);
    setConvId(id);
  };

  const newConversation = () => { setMessages([]); setConvId(null); };

  const removeConversation = async (id, e) => {
    e.stopPropagation();
    await api.delete(`/consultant/assistant/conversations/${id}`);
    if (id === convId) newConversation();
    loadConversations();
  };

  return (
    <Layout role="consultant" homeLabel="Espace Consultant" navItems={navItems}>
      <PageHeader title="Assistant IA Cyber" subtitle="Interrogez la base CyberWatch AI (CVE, bulletins, historiques) ou posez une question générale de cybersécurité" />

      <div className="flex h-[calc(100vh-11rem)] gap-4">
        {/* Historique des conversations */}
        <div className="hidden w-60 shrink-0 flex-col rounded-2xl border border-slate-200 bg-white lg:flex">
          <button onClick={newConversation}
            className="m-2 flex items-center justify-center gap-2 rounded-xl bg-brand-600 px-3 py-2 text-sm font-medium text-white hover:bg-brand-700">
            <Plus size={16} /> Nouvelle conversation
          </button>
          <div className="flex-1 overflow-y-auto px-1">
            {conversations.map((c) => (
              <button key={c.id} onClick={() => openConversation(c.id)}
                className={`group flex w-full items-center gap-2 rounded-lg px-2 py-2 text-left text-sm ${
                  c.id === convId ? "bg-brand-50 text-brand-700" : "text-slate-600 hover:bg-slate-50"}`}>
                <MessageSquare size={14} className="shrink-0" />
                <span className="flex-1 truncate">{c.title}</span>
                <Trash2 size={13} className="shrink-0 opacity-0 hover:text-rose-600 group-hover:opacity-100"
                  onClick={(e) => removeConversation(c.id, e)} />
              </button>
            ))}
          </div>
        </div>

        {/* Zone de discussion */}
        <div className="flex min-w-0 flex-1 flex-col rounded-2xl border border-slate-200 bg-white">
          <div className="flex-1 space-y-4 overflow-y-auto p-5">
            {messages.length === 0 && (
              <div className="mx-auto max-w-2xl pt-8 text-center">
                <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-brand-100 text-brand-600">
                  <Sparkles size={24} />
                </div>
                <h3 className="text-lg font-semibold text-slate-700">Posez une question sur vos vulnérabilités</h3>
                <p className="mt-1 text-sm text-slate-400">
                  Les questions sur vos CVE sont répondues à partir de la base CyberWatch AI.
                  Les questions générales de cybersécurité sont traitées par l'IA et signalées « hors base ».
                </p>
                <div className="mt-5 grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {suggestions.map((s) => (
                    <button key={s} onClick={() => ask(s)}
                      className="rounded-xl border border-slate-200 px-3 py-2 text-left text-sm text-slate-600 transition hover:border-brand-300 hover:bg-brand-50">
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {messages.map((m, i) =>
              m.role === "user" ? (
                <div key={i} className="flex justify-end">
                  <div className="max-w-[80%] rounded-2xl bg-brand-600 px-4 py-2 text-sm text-white">{m.question}</div>
                </div>
              ) : (
                <div key={i} className="flex justify-start">
                  <div className="max-w-[85%] space-y-3">
                    <div className={`rounded-2xl px-4 py-3 text-sm text-slate-700 shadow-sm ${
                      m.scope === "external" ? "border border-violet-200 bg-violet-50/60" : "bg-slate-50"}`}>
                      <div className="mb-2 flex items-center gap-2">
                        <Sparkles size={15} className="text-brand-600" />
                        <span className="text-xs font-semibold text-brand-600">Assistant</span>
                        {m.confidence && (
                          <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${CONF_STYLE[m.confidence]}`}>
                            Confiance : {CONF_LABEL[m.confidence]}
                          </span>
                        )}
                        {ORIGIN[m.generated_by] && (
                          <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium ${ORIGIN[m.generated_by].style}`}>
                            {(() => { const I = ORIGIN[m.generated_by].Icon; return <I size={11} />; })()}
                            {ORIGIN[m.generated_by].label}
                          </span>
                        )}
                      </div>

                      {/* QUESTION DE SUIVI RÉÉCRITE : « et pour Microsoft ? » a été complétée
                          à partir des échanges précédents. Le consultant doit voir ce que
                          l'assistant a compris — sinon une mémoire qui se trompe donne une
                          réponse cohérente à une question qu'il n'a jamais posée, sans
                          qu'aucun élément à l'écran ne permette de s'en apercevoir. */}
                      {m.rewritten_question && (
                        <p className="mb-2 rounded-lg bg-white/70 px-3 py-1.5 text-xs italic text-slate-500">
                          Question interprétée d’après le contexte :{" "}
                          <span className="not-italic font-medium text-slate-600">{m.rewritten_question}</span>
                        </p>
                      )}

                      {/* RENDU DU MARKDOWN. Le texte etait affiche brut (`whitespace-pre-wrap`) :
                          une reponse comparative arrivait sous forme de « | Aspect | Description | »
                          et de « **Definition** » en clair, illisible. Le composant Markdown ne
                          produit que des elements React — jamais du HTML injecte — de sorte qu'une
                          reponse construite a partir de contenus externes ne peut rien executer. */}
                      {m.sections?.length > 0 ? (
                        <div className="space-y-4">
                          {m.sections.map((s, si) => (
                            <div key={si}>
                              <h4 className="mb-1 text-xs font-bold uppercase tracking-wide text-brand-700">{s.title}</h4>
                              <Markdown texte={s.body} className="text-slate-700" />
                            </div>
                          ))}
                        </div>
                      ) : (
                        <Markdown texte={m.answer} />
                      )}

                      {m.results?.length > 0 && (
                        <div className="mt-3 space-y-1.5 border-t border-slate-200 pt-2">
                          {m.results.slice(0, 12).map((r) => (
                            <Link key={r.cve_id} to={r.id ? `/consultant/cves/${r.id}` : "#"}
                              className="flex items-center gap-2 rounded-lg px-2 py-1 text-xs hover:bg-white">
                              <span className="font-semibold text-brand-700">{r.cve_id}</span>
                              {r.severity && (
                                <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${SEVERITY_STYLES[r.severity]}`}>
                                  {SEVERITY_LABELS[r.severity]}
                                </span>
                              )}
                              {r.cvss_score != null && <span className="text-slate-500">CVSS {Number(r.cvss_score).toFixed(1)}</span>}
                              <span className="truncate text-slate-400">{r.product || r.vendor}</span>
                            </Link>
                          ))}
                          {m.count > 12 && <p className="px-2 text-[11px] text-slate-400">…et {m.count - 12} autre(s).</p>}
                        </div>
                      )}

                      {m.sources?.length > 0 && (
                        <div className="mt-3 flex flex-wrap items-center gap-1.5 border-t border-slate-200 pt-2">
                          <span className="text-[11px] font-semibold text-slate-400">Sources :</span>
                          {m.sources.map((s) => (
                            <span key={s} className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] text-slate-600">{s}</span>
                          ))}
                        </div>
                      )}

                      {m.results?.length === 1 && m.results[0].cve_id && (
                        <div className="mt-3 border-t border-slate-200 pt-2">
                          <AiSummaryButtons subject={m.results[0].cve_id} size="sm" />
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )
            )}
            {loading && (
              <div className="flex items-center gap-2 text-sm text-slate-400">
                <Sparkles size={15} className="animate-pulse text-brand-500" /> Analyse en cours…
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          <div className="flex items-center gap-2 border-t border-slate-100 p-3">
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); ask(); } }}
              placeholder="Ex. « CVE Microsoft critiques ce mois-ci » ou « Qu'est-ce que le catalogue KEV ? »…"
              className="flex-1 rounded-xl border border-slate-200 px-4 py-2.5 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100"
            />
            <button onClick={() => ask()} disabled={!draft.trim() || loading}
              className="inline-flex items-center gap-1.5 rounded-xl bg-brand-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-brand-700 disabled:opacity-40">
              <Send size={16} /> Envoyer
            </button>
          </div>
        </div>
      </div>
    </Layout>
  );
}
