import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Wrench, LinkIcon, FileText } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Card from "../../components/ui/Card";
import Button from "../../components/ui/Button";
import AiSummaryButtons from "../../components/ui/AiSummaryButtons";
import api from "../../api/axios";
import CommunityDiscussions from "./CommunityDiscussions";
import { useConsultantNavItems } from "./navItems";
import { useNotifications } from "../../context/NotificationsContext";
import { SEVERITY_LABELS, SEVERITY_STYLES, EXPLOIT_STYLES } from "./cveConstants";

const NA = "Non disponible";
const fmtDate = (d) => (d ? new Date(d).toLocaleDateString("fr-FR") : NA);
const fmtDateTime = (d) => (d ? new Date(d).toLocaleString("fr-FR") : NA);

// Libellés FR des champs (journal des modifications).
const FIELD_FR = {
  cvss_score: "Score CVSS", cvss_vector: "Vecteur CVSS", severity: "Sévérité", cwe: "CWE",
  vuln_type: "Type", solution: "Solution", references: "Références", vendor: "Éditeur",
  product: "Produit", affected_products: "Produits affectés", affected_systems: "Systèmes affectés",
  affected_versions: "Versions affectées", description: "Description", patch_links: "Correctifs",
};

// Temps relatif (« il y a 2 h », « hier »…) pour l'affichage type OpenCVE.
const fmtRelative = (d) => {
  if (!d) return null;
  const s = (Date.now() - new Date(d).getTime()) / 1000;
  if (s < 0) return null;
  if (s < 60) return "à l'instant";
  if (s < 3600) return `il y a ${Math.round(s / 60)} min`;
  if (s < 86400) return `il y a ${Math.round(s / 3600)} h`;
  const j = Math.round(s / 86400);
  if (j === 1) return "hier";
  if (j < 30) return `il y a ${j} j`;
  return null;
};

// Rend CLIQUABLES les URL contenues dans un texte libre (solution, remediation).
// On decoupe la chaine plutot que d'injecter du HTML : aucun risque d'injection depuis
// le contenu collecte, contrairement a dangerouslySetInnerHTML.
const URL_RE = /(https?:\/\/[^\s<>"')\]]+)/g;

// Version NON globale pour les tests : `.test()` sur une regex /g fait avancer `lastIndex`
// et renvoie alternativement true/false sur la meme chaine. Piege classique, evite ici.
const IS_URL = /^https?:\/\/[^\s<>"')\]]+$/;

function TextWithLinks({ value }) {
  if (!value) return null;
  return (
    <>
      {String(value).split(URL_RE).map((part, i) =>
        IS_URL.test(part) ? (
          <a key={i} href={part} target="_blank" rel="noreferrer"
             className="break-all text-brand-700 hover:underline">{part}</a>
        ) : (
          <span key={i}>{part}</span>
        )
      )}
    </>
  );
}

// Champ (libellé + valeur) réutilisable, affiche « Non disponible » si vide.
function Field({ label, children, full }) {
  const empty = children === null || children === undefined || children === "";
  return (
    <div className={full ? "col-span-2" : ""}>
      <dt className="font-semibold text-slate-500">{label}</dt>
      <dd className={`mt-1 ${empty ? "italic text-slate-400" : "text-slate-700"}`}>{empty ? NA : children}</dd>
    </div>
  );
}

export default function ConsultantCveDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const navItems = useConsultantNavItems();
  const { refresh } = useNotifications();
  const [cve, setCve] = useState(null);
  // Synthèse approfondie : lecture des pages sources (opération coûteuse, à la demande).
  const [synth, setSynth] = useState(null);
  const [synthLoading, setSynthLoading] = useState(false);

  const runSynthesis = async (refresh = false) => {
    setSynthLoading(true);
    try {
      const { data } = await api.post(
        `/consultant/cves/${id}/deep-synthesis${refresh ? "?refresh=true" : ""}`);
      setSynth(data);
    } catch {
      setSynth({ status: "failed", error: "La synthèse a échoué. Réessayez dans un instant." });
    } finally {
      setSynthLoading(false);
    }
  };

  useEffect(() => {
    api.get(`/consultant/cves/${id}`).then((res) => {
      setCve(res.data);
      refresh(); // la consultation a marqué la CVE comme lue -> met à jour le badge
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  if (!cve) {
    return (
      <Layout role="consultant" homeLabel="Espace Consultant" navItems={navItems}>
        <p className="text-slate-400">Chargement…</p>
      </Layout>
    );
  }

  const product = cve.product || (cve.affected_products || []).join(", ");
  const systems = (cve.affected_systems || []).join(", ");
  const references = cve.references || [];

  return (
    <Layout role="consultant" homeLabel="Espace Consultant" navItems={navItems}>
      <PageHeader
        title={cve.cve_id}
        subtitle={cve.title}
        action={
          <div className="flex items-center gap-3">
            <span className={`rounded-full px-3 py-1 text-sm font-semibold ${SEVERITY_STYLES[cve.severity]}`}>
              {SEVERITY_LABELS[cve.severity]}
            </span>
            <Button onClick={() => navigate(`/consultant/cves/${id}/bulletin`)}>
              <FileText size={16} /> Bulletin de sécurité
            </Button>
          </div>
        }
      />

      {/* Résumés IA ancrés (reformulation LLM si configurée, sinon synthèse déterministe). */}
      <Card className="mb-4 p-4">
        <AiSummaryButtons subject={`la vulnérabilité ${cve.cve_id}`} />
        <div className="mt-3 border-t border-slate-100 pt-3">
          <Button variant="secondary" onClick={() => runSynthesis(false)} disabled={synthLoading}>
            <FileText size={16} />
            {synthLoading ? "Lecture des pages sources…" : "Synthèse approfondie (pages sources)"}
          </Button>
          <p className="mt-1.5 text-xs text-slate-400">
            Lit les pages officielles référencées par cette CVE et en extrait un résumé ainsi que
            la meilleure solution disponible, avec sa source.
          </p>
        </div>
      </Card>

      {synth && (
        <Card className="mb-4 p-5">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">
            Synthèse approfondie
          </h2>

          {synth.status === "completed" ? (
            <div className="space-y-4 text-sm">
              {synth.summary && (
                <div>
                  <h3 className="mb-1 font-semibold text-slate-700">Résumé</h3>
                  <p className="whitespace-pre-wrap leading-relaxed text-slate-700">{synth.summary}</p>
                </div>
              )}

              {/* La solution est TOUJOURS présentée avec sa source : un consultant doit savoir
                  qui prescrit la remédiation avant de l'appliquer sur un système réel. */}
              {synth.solution && (
                <div className="rounded-xl border border-emerald-200 bg-emerald-50/60 p-3">
                  <h3 className="mb-1 font-semibold text-emerald-800">Solution recommandée</h3>
                  <p className="whitespace-pre-wrap leading-relaxed text-slate-700">{synth.solution}</p>
                  {synth.solution_source?.url && (
                    <p className="mt-2 text-xs text-slate-500">
                      Source : <b>{synth.solution_source.name}</b>{" "}
                      <a href={synth.solution_source.url} target="_blank" rel="noreferrer"
                         className="break-all text-brand-700 hover:underline">
                        {synth.solution_source.url}
                      </a>
                    </p>
                  )}
                </div>
              )}

              {synth.conflicts?.length > 0 && (
                <div className="rounded-xl border border-amber-200 bg-amber-50/60 p-3">
                  <h3 className="mb-1 font-semibold text-amber-800">Divergences entre sources</h3>
                  <ul className="list-disc pl-5 text-slate-700">
                    {synth.conflicts.map((c, i) => <li key={i}>{c}</li>)}
                  </ul>
                </div>
              )}

              {synth.pages_read?.length > 0 && (
                <div className="border-t border-slate-100 pt-2 text-xs text-slate-500">
                  <span className="font-semibold">Pages lues ({synth.pages_read.length}) : </span>
                  {synth.pages_read.map((p) => p.source).join(" · ")}
                </div>
              )}
            </div>
          ) : (
            <p className="text-sm text-slate-500">
              {synth.error || "Aucune information exploitable n'a pu être extraite des pages sources."}
            </p>
          )}

          <button onClick={() => runSynthesis(true)} disabled={synthLoading}
                  className="mt-3 text-xs font-medium text-brand-600 hover:underline disabled:opacity-40">
            Recalculer
          </button>
        </Card>
      )}

      {/* Suivi de synchronisation incrémentale (complétude, publication, mise à jour) */}
      <Card className="mb-4 p-4">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-slate-500">Complétude</span>
            <div className="h-2 w-32 rounded-full bg-slate-100">
              <div className="h-2 rounded-full bg-emerald-500" style={{ width: `${cve.information_completeness || 0}%` }} />
            </div>
            <span className="font-semibold text-slate-700">{cve.information_completeness ?? 0}%</span>
          </div>
          {/* UNIQUEMENT `published_at`, la date officielle de la CVE. Le repli sur
              `first_published` a ete retire : ce champ peut contenir une date d'avis, qui
              reapparaitrait alors que la migration l'a precisement ecartee. */}
          <div className="text-slate-500">
            CVE publiee :{" "}
            <span className={cve.published_at ? "text-slate-700" : "italic text-slate-400"}>
              {cve.published_at
                ? (fmtRelative(cve.published_at) || fmtDate(cve.published_at))
                : "date non disponible"}
            </span>
          </div>
          {cve.is_updated && (
            <div className="font-medium text-amber-700">
              Mise à jour {fmtRelative(cve.last_important_update || cve.updated_at) || fmtDate(cve.updated_at)}
            </div>
          )}
          <div className="text-xs text-slate-400">
            Collectée {fmtRelative(cve.last_collected || cve.collected_at) || fmtDate(cve.collected_at)}
          </div>
        </div>
        {cve.is_updated && (cve.change_summary || []).length > 0 && (
          <div className="mt-2 text-xs text-amber-700">Enrichissements : {(cve.change_summary || []).join(" · ")}</div>
        )}
      </Card>

      {/* Journal des modifications (historique permanent) */}
      {(cve.history || []).length > 0 && (
        <Card className="mb-4 p-6">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">
            Journal des modifications
          </h2>
          <ul className="space-y-2 text-sm">
            {[...cve.history].reverse().map((h, i) => (
              <li key={i} className="flex gap-3">
                <span className="whitespace-nowrap text-xs text-slate-400">{fmtDateTime(h.ts)}</span>
                <span className="text-slate-700">
                  {Object.keys(h.changes || {}).map((k) => FIELD_FR[k] || k).join(", ") || "Modifiée"}
                </span>
              </li>
            ))}
            <li className="flex gap-3">
              {/* Entree d'HISTORIQUE : il s'agit de l'arrivee en base, donc `collected_at`.
                  `first_published` a ete retire ici : il peut porter une date d'avis. */}
              <span className="whitespace-nowrap text-xs text-slate-400">{fmtDate(cve.collected_at)}</span>
              <span className="text-slate-500">Collectée par CyberWatch AI</span>
            </li>
          </ul>
        </Card>
      )}

      <div className="space-y-4">
          <Card className="p-6">
            <div className="mb-5 flex items-center gap-4">
              <div className="text-4xl font-bold text-slate-800">{cve.cvss_score?.toFixed(1) ?? "—"}</div>
              <div>
                <span className={`rounded-full px-3 py-1 text-sm font-semibold ${SEVERITY_STYLES[cve.severity]}`}>
                  {SEVERITY_LABELS[cve.severity]}
                </span>
                <p className="mt-1 text-xs text-slate-400">Score CVSS</p>
              </div>
            </div>

            <dl className="space-y-4 text-sm">
              <Field label="Description" full>{cve.description}</Field>
              <div className="grid grid-cols-2 gap-4">
                <Field label="Produit">{product}</Field>
                <Field label="Éditeur (vendor)">{cve.vendor}</Field>
                <Field label="Type de vulnérabilité">{cve.vuln_type || cve.category}</Field>
                <Field label="CWE">{cve.cwe}</Field>
                <Field label="Vecteur CVSS" full>{cve.cvss_vector}</Field>
                <Field label="Impact" full>{cve.impact}</Field>
                <Field label="Versions affectées">{cve.affected_versions}</Field>
                <Field label="Version corrigée">{cve.fixed_version}</Field>
                <Field label="Plateforme">{cve.platform}</Field>
                <Field label="Systèmes affectés" full>{systems}</Field>
                {cve.advisory_id && <Field label="Identifiant d'avis (CERT)">{cve.advisory_id}</Field>}
                {(cve.associated_cves || []).length > 1 && (
                  <Field label="CVE associées à l'avis" full>{(cve.associated_cves || []).join(", ")}</Field>
                )}
                <Field label="Statut de l'exploit">
                  {cve.exploit_status ? (
                    <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${EXPLOIT_STYLES[cve.exploit_status] || "bg-slate-100 text-slate-500"}`}>
                      {cve.exploit_status}
                    </span>
                  ) : null}
                </Field>
                <Field label="Source(s)">
                  {(cve.sources && cve.sources.length
                    ? cve.sources.map((s) => s.name).join(", ")
                    : cve.source)}
                </Field>
                <Field label="Sources ayant confirmé">{(cve.confirmed_sources || []).join(", ")}</Field>
                <Field label="Page d'origine" full>
                  {cve.detail_url ? (
                    <a href={cve.detail_url} target="_blank" rel="noreferrer" className="break-all text-brand-700 hover:underline">
                      {cve.detail_url}
                    </a>
                  ) : null}
                </Field>
                {/* Libellés EXPLICITES : trois dates de natures différentes coexistent.
                    Une date d'avis ou de collecte ne doit jamais être lue comme la date de
                    publication de la vulnérabilité. */}
                <Field label="Date de publication de la CVE">
                  {cve.published_at ? fmtDate(cve.published_at) : "Non disponible"}
                </Field>
                {cve.advisory_published_at && (
                  <Field label="Date de publication de l'avis">
                    {fmtDate(cve.advisory_published_at)}
                    {cve.advisory_id ? ` (${cve.advisory_id})` : ""}
                  </Field>
                )}
                <Field label="Dernière mise à jour de la CVE">
                  {cve.updated_at ? fmtDate(cve.updated_at) : "Non disponible"}
                </Field>
                <Field label="Date de collecte">{fmtDate(cve.collected_at)}</Field>
                <Field label="Date de mise à jour">{fmtDate(cve.updated_at)}</Field>
                <Field label="Collectée le (technique)" full>
                  <span className="text-xs text-slate-400">
                    {cve.collected_at ? new Date(cve.collected_at).toLocaleString("fr-FR") : ""}
                  </span>
                </Field>
              </div>
            </dl>
          </Card>

          {/* Solution / Correctif */}
          <Card className="p-6">
            <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-emerald-600">
              <Wrench size={16} /> Solution / Correctif
            </h2>
            {(() => {
              // La solution RESOLUE (lue sur les pages officielles) prime sur celle
              // recopiee d'un avis : elle est attribuee a la source qui la prescrit.
              const synthese = cve.deep_synthesis || {};
              const resolue = synthese.solution;
              const src = synthese.solution_source || {};
              const texte = resolue || cve.solution;
              if (!texte) {
                // UNE DONNÉE ABSENTE N'EST PAS UNE DONNÉE NÉGATIVE.
                //
                // Affirmer « aucune source officielle ne prescrit de remédiation » suppose
                // d'avoir LU ces sources. Tant que la synthèse approfondie n'a pas abouti,
                // l'application ne sait rien : elle doit dire que l'information manque, et
                // non qu'il n'existe pas de correctif — un consultant renoncerait à en
                // chercher un qui existe.
                const lecturePotentiellementAboutie = synthese.status === "completed";
                return (
                  <p className="text-sm italic text-slate-500">
                    {lecturePotentiellementAboutie
                      ? "Aucun correctif ou mesure de remédiation officielle identifié."
                      : "Les informations de remédiation n'ont pas pu être extraites de manière fiable."}
                  </p>
                );
              }
              return (
                <>
                  <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-700">
                    <TextWithLinks value={texte} />
                  </p>
                  {resolue && src.url && (
                    <p className="mt-3 border-t border-slate-100 pt-2 text-xs text-slate-500">
                      Prescrite par <b>{src.name}</b>{" "}
                      <a href={src.url} target="_blank" rel="noreferrer"
                         className="break-all text-brand-700 hover:underline">{src.url}</a>
                    </p>
                  )}
                  {!resolue && (
                    <p className="mt-3 border-t border-slate-100 pt-2 text-xs text-amber-700">
                      Remédiation reprise de la page de collecte, non confirmée par un avis
                      officiel. Lancez la synthèse approfondie pour la vérifier.
                    </p>
                  )}
                </>
              );
            })()}
          </Card>

          {/* Correctifs / liens de téléchargement */}
          {(cve.patch_links || []).length > 0 && (
            <Card className="p-6">
              <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-emerald-600">
                <Wrench size={16} /> Correctifs / Téléchargement
              </h2>
              <ul className="space-y-1.5">
                {cve.patch_links.map((ref) => (
                  <li key={ref}>
                    <a href={ref} target="_blank" rel="noreferrer" className="break-all text-sm text-brand-700 hover:underline">
                      {ref}
                    </a>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          {/* Références */}
          <Card className="p-6">
            <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-500">
              <LinkIcon size={16} /> Références
            </h2>
            {references.length ? (
              <ul className="space-y-1.5">
                {references.map((ref) => (
                  <li key={ref}>
                    <a href={ref} target="_blank" rel="noreferrer" className="break-all text-sm text-brand-700 hover:underline">
                      {ref}
                    </a>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-slate-400">Aucune référence disponible.</p>
            )}
          </Card>
      </div>

      {/* DISCUSSIONS COMMUNAUTAIRES — placées APRÈS toute l'information officielle, et
          visuellement distinctes. Cette couche enrichit l'analyse ; elle ne fait autorité
          sur aucun champ de la fiche. */}
      <CommunityDiscussions cveId={cve.cve_id} />

      <div className="mt-4">
        <Button variant="ghost" onClick={() => navigate("/consultant/cves")}>
          ← Retour à la liste
        </Button>
      </div>
    </Layout>
  );
}
