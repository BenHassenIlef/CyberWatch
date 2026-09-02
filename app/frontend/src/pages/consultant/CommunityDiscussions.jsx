import { useEffect, useState } from "react";
import { MessageSquare, Info, RefreshCw, ExternalLink, AlertTriangle,
         CheckCircle2, Settings } from "lucide-react";
import Card from "../../components/ui/Card";
import api from "../../api/axios";

// DISCUSSIONS COMMUNAUTAIRES d'une CVE.
//
// Couche d'ENRICHISSEMENT, jamais une source officielle. Le contraste visuel est délibéré :
// l'information officielle occupe les cartes blanches du haut de page, la communauté cette
// section ambrée, précédée d'un avertissement. Un consultant doit voir d'un coup d'œil ce
// qui engage l'éditeur et ce qui n'engage que des participants à un forum.

const STYLES_PERTINENCE = {
  HIGH: { texte: "Élevée", classe: "bg-emerald-100 text-emerald-700" },
  MEDIUM: { texte: "Moyenne", classe: "bg-amber-100 text-amber-700" },
  LOW: { texte: "Faible", classe: "bg-slate-100 text-slate-600" },
};

const fmtDate = (d) => {
  if (!d) return null;
  const dt = new Date(d);
  return isNaN(dt) ? null : dt.toLocaleDateString("fr-FR");
};

export default function CommunityDiscussions({ cveId }) {
  const [data, setData] = useState(null);
  const [chargement, setChargement] = useState(true);
  const [erreur, setErreur] = useState("");

  const charger = (refresh = false) => {
    setChargement(true);
    setErreur("");
    api
      .get(`/consultant/cves/${encodeURIComponent(cveId)}/community-discussions`,
           { params: refresh ? { refresh: true } : {} })
      .then((res) => setData(res.data))
      .catch(() => setErreur("Les discussions communautaires n'ont pas pu être chargées."))
      .finally(() => setChargement(false));
  };

  useEffect(() => { charger(false); /* eslint-disable-next-line */ }, [cveId]);

  const discussions = data?.discussions || [];

  return (
    <Card className="mt-4 border-amber-200 bg-amber-50/40 p-6">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-amber-700">
          <MessageSquare size={16} /> Discussions communautaires
        </h2>
        <button
          type="button"
          onClick={() => charger(true)}
          disabled={chargement}
          className="flex items-center gap-1.5 rounded-lg border border-amber-200 bg-white px-3 py-1.5
                     text-xs font-medium text-amber-800 transition hover:bg-amber-50 disabled:opacity-50"
        >
          <RefreshCw size={13} className={chargement ? "animate-spin" : ""} />
          {chargement ? "Recherche…" : "Actualiser"}
        </button>
      </div>

      {/* Avertissement TOUJOURS visible : ces propos n'engagent pas l'éditeur. */}
      <p className="mb-4 flex items-start gap-2 rounded-lg bg-white/70 p-3 text-xs leading-relaxed text-slate-600">
        <Info size={14} className="mt-0.5 shrink-0 text-amber-600" />
        Les informations ci-dessous proviennent de discussions publiques et ne remplacent pas
        les recommandations officielles de l'éditeur.
      </p>

      {erreur && <p className="text-sm text-rose-600">{erreur}</p>}

      {!erreur && chargement && !data && (
        <p className="text-sm italic text-slate-500">Recherche des discussions publiques…</p>
      )}

      {!erreur && data && (
        <>
          {/* Synthèse — explicitement présentée comme un RAPPORT de propos. */}
          <p className="mb-4 border-l-4 border-amber-300 bg-white/70 py-2 pl-3 text-sm leading-relaxed text-slate-700">
            <span className="font-semibold text-amber-800">Analyse de la communauté : </span>
            {data.community_summary}
          </p>

          {/* ÉTAT DE CHAQUE SOURCE — trois situations qu'il ne faut jamais confondre.
              « Aucun résultat » dit quelque chose de la communauté ; « indisponible » et
              « non configurée » ne disent rien d'elle, seulement de l'application. Les
              afficher pareillement laisserait croire que personne n'a discuté de la faille. */}
          {(data.sources || []).length > 0 && (
            <ul className="mb-4 space-y-1">
              {data.sources.map((s) => (
                <li key={s.source} className="flex items-start gap-2 text-xs text-slate-600">
                  {s.status === "completed" ? (
                    <>
                      <CheckCircle2 size={13} className="mt-0.5 shrink-0 text-emerald-600" />
                      <span>
                        <b>{s.source}</b> — recherche effectuée
                        {s.results ? ` : ${s.results} discussion${s.results > 1 ? "s" : ""} retenue${s.results > 1 ? "s" : ""}.`
                                   : " : aucune discussion pertinente trouvée."}
                      </span>
                    </>
                  ) : s.status === "unconfigured" ? (
                    <>
                      <Settings size={13} className="mt-0.5 shrink-0 text-slate-500" />
                      <span>
                        <b>{s.source}</b> — source non configurée. Des identifiants d'accès
                        sont nécessaires pour interroger cette communauté.
                      </span>
                    </>
                  ) : (
                    <>
                      <AlertTriangle size={13} className="mt-0.5 shrink-0 text-amber-600" />
                      <span>
                        <b>{s.source}</b> — source momentanément indisponible. La recherche
                        n'a pas pu aboutir ; d'autres discussions existent peut-être.
                      </span>
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}

          {/* AUCUNE DISCUSSION : il faut le dire. Une liste vide sans un mot laisse croire
              à un chargement inachevé, et le consultant attend une réponse qui ne vient pas. */}
          {discussions.length === 0 && (
            <p className="rounded-lg border border-amber-100 bg-white p-4 text-sm text-slate-600">
              Aucune discussion publique citant cette vulnérabilité n’a été retenue. Les
              communautés interrogées sont listées ci-dessus avec le résultat de chaque
              recherche.
            </p>
          )}

          <div className="space-y-3">
            {discussions.map((d) => {
              const p = STYLES_PERTINENCE[d.relevance_level] || STYLES_PERTINENCE.LOW;
              const date = fmtDate(d.published_at);
              return (
                <div key={d._id || d.url} className="rounded-xl border border-amber-100 bg-white p-4">
                  <div className="mb-1 flex flex-wrap items-center gap-2">
                    <span className="text-xs font-semibold text-slate-700">
                      {d.source}{d.community ? ` – ${d.community}` : ""}
                    </span>
                    <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${p.classe}`}>
                      Pertinence {p.texte}
                    </span>
                    {date && <span className="text-xs text-slate-400">{date}</span>}
                    {d.author && <span className="text-xs text-slate-400">· {d.author}</span>}
                  </div>
                  {/* Un COMMENTAIRE et un BILLET ne se lisent pas pareil : le premier est
                      un avis dans un fil, le second un sujet soumis à la communauté. */}
                  {d.is_comment && (
                    <span className="mb-1 inline-block rounded bg-slate-100 px-1.5 py-0.5 text-[10px]
                                     font-semibold uppercase tracking-wide text-slate-600">
                      Commentaire
                    </span>
                  )}
                  <p className="text-sm font-medium text-slate-800">{d.title}</p>
                  {d.summary && (
                    <p className="mt-1 line-clamp-3 text-xs leading-relaxed text-slate-600">
                      {d.summary}
                    </p>
                  )}
                  <a href={d.url} target="_blank" rel="noreferrer"
                     className="mt-2 inline-flex items-center gap-1 text-xs font-medium text-brand-700 hover:underline">
                    Voir la discussion <ExternalLink size={12} />
                  </a>
                </div>
              );
            })}
          </div>
        </>
      )}
    </Card>
  );
}
