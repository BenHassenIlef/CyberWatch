import { useEffect, useState } from "react";
import { useParams, useNavigate, useSearchParams } from "react-router-dom";
import { Download } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Card from "../../components/ui/Card";
import Button from "../../components/ui/Button";
import Table from "../../components/ui/Table";
import AiSummaryButtons from "../../components/ui/AiSummaryButtons";
import api from "../../api/axios";
import { useConsultantNavItems } from "./navItems";
import { SEVERITY_LABELS, SEVERITY_STYLES } from "./cveConstants";
import { bulletinTableHTML, aiSummaryHTML, downloadBulletinPdf } from "./bulletin";
import { bornesDuMode, formatCourt } from "./PeriodPicker";

// Valeur manquante : on l'ÉCRIT. Un tiret laisse croire à un oubli d'affichage, et surtout
// il ne faut jamais combler le vide avec la donnée d'une autre CVE.
const na = (v) =>
  v === null || v === undefined || v === "" || (Array.isArray(v) && v.length === 0)
    ? "Non disponible"
    : v;

// Bulletin de sécurité GROUPÉ d'un éditeur (rendu identique au modèle Advancia + tableau des CVE).
export default function ProductBulletinDetail() {
  const { vendor } = useParams();
  const navigate = useNavigate();
  const navItems = useConsultantNavItems();
  // Période héritée de la liste (?start=&end=) : le détail porte sur la MÊME période,
  // sinon la carte annonce N CVE et le bulletin en affiche un autre nombre.
  const [params] = useSearchParams();
  const defaut = bornesDuMode("last3");
  const start = params.get("start") || defaut.start;
  const end = params.get("end") || defaut.end;
  const [b, setB] = useState(null);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState("");
  const [downloadingDetail, setDownloadingDetail] = useState(false);

  // Téléchargement du DÉTAIL SEUL : document distinct du bulletin de synthèse. Les deux
  // répondent à des usages différents — transmettre une alerte, ou travailler ligne à ligne.
  const handleDownloadDetail = async () => {
    setDownloadingDetail(true);
    setDownloadError("");
    try {
      await downloadBulletinPdf(
        api,
        `/consultant/product-bulletins/${encodeURIComponent(vendor)}/details.pdf?start=${start}&end=${end}`,
        "Detail_vulnerabilites.pdf");
    } catch {
      setDownloadError("Le téléchargement du détail a échoué. Réessayez dans un instant.");
    } finally {
      setDownloadingDetail(false);
    }
  };

  const handleDownload = async () => {
    setDownloading(true);
    setDownloadError("");
    try {
      await downloadBulletinPdf(
        api, `/consultant/product-bulletins/${encodeURIComponent(vendor)}/bulletin.pdf?start=${start}&end=${end}`);
    } catch {
      setDownloadError("Le téléchargement du PDF a échoué. Réessayez dans un instant.");
    } finally {
      setDownloading(false);
    }
  };

  // Score maximal RÉELLEMENT présent dans le tableau. Calculé ici, et non repris de l'en-tête :
  // le bulletin est plafonné à 80 CVE, si bien que l'agrégat pourrait désigner un score qui ne
  // figure sur aucune ligne — et aucune ne serait alors mise en évidence.
  const scoreMax = (b?.vulnerabilities || []).reduce(
    (m, v) => (typeof v.cvss_score === "number" && v.cvss_score > m ? v.cvss_score : m), -1);
  const estLaPlusGrave = (r) => scoreMax > 0 && r.cvss_score === scoreMax;

  useEffect(() => {
    setB(null);
    setError("");
    api
      .get(`/consultant/product-bulletins/${encodeURIComponent(vendor)}`, { params: { start, end } })
      .then((res) => setB(res.data))
      .catch((e) => setError(e.response?.data?.detail || "Bulletin introuvable."));
  }, [vendor, start, end]);

  return (
    <Layout role="consultant" homeLabel="Espace Consultant" navItems={navItems}>
      <PageHeader
        title={b ? b.title : "Bulletin de sécurité"}
        subtitle={b ? `${b.cve_count} CVE · période du ${formatCourt(start)} au ${formatCourt(end)}` : "Chargement…"}
        action={b && (
          <Button onClick={handleDownload} disabled={downloading}>
            <Download size={16} /> {downloading ? "Génération du PDF…" : "Télécharger le PDF"}
          </Button>
        )}
      />

      {downloadError && (
        <Card className="mb-4 p-4"><p className="text-sm text-rose-600">{downloadError}</p></Card>
      )}

      {error ? (
        <Card className="p-6"><p className="text-sm text-rose-600">{error}</p></Card>
      ) : !b ? (
        <Card className="p-6"><p className="text-sm text-slate-400">Génération du bulletin…</p></Card>
      ) : (
        <div className="space-y-4">
          {/* En-tête : le produit, son éditeur et la PÉRIODE réellement appliquée. Le nombre
              de CVE et le CVSS maximal ci-dessous portent sur cette période seule. */}
          <Card className="p-5">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm md:grid-cols-5">
              <div>
                <dt className="text-xs font-semibold uppercase tracking-wide text-slate-400">Produit</dt>
                <dd className="font-medium text-slate-800">{na(b.vendor)}</dd>
              </div>
              <div>
                <dt className="text-xs font-semibold uppercase tracking-wide text-slate-400">Éditeur</dt>
                <dd className="text-slate-700">{na(b.official_source?.name)}</dd>
              </div>
              <div>
                <dt className="text-xs font-semibold uppercase tracking-wide text-slate-400">Période</dt>
                <dd className="text-slate-700">{formatCourt(start)} → {formatCourt(end)}</dd>
              </div>
              <div>
                <dt className="text-xs font-semibold uppercase tracking-wide text-slate-400">Nombre de CVE</dt>
                <dd className="font-medium text-slate-800">{b.cve_count}</dd>
              </div>
              <div>
                <dt className="text-xs font-semibold uppercase tracking-wide text-slate-400">CVSS maximal</dt>
                <dd className="font-medium text-slate-800">
                  {b.cvss_score != null ? Number(b.cvss_score).toFixed(1) : "Non disponible"}
                </dd>
              </div>
            </dl>
          </Card>

          <Card className="p-4">
            <AiSummaryButtons subject={`les vulnérabilités ${b.vendor || vendor}`} group />
          </Card>
          <Card className="p-6">
            {b.ai_summary && (
              <div className="overflow-x-auto" dangerouslySetInnerHTML={{ __html: aiSummaryHTML(b) }} />
            )}
            <div className="overflow-x-auto" dangerouslySetInnerHTML={{ __html: bulletinTableHTML(b, { showReferences: false }) }} />
          </Card>

          {/* Détail par CVE (structure vulnerabilities[]) */}
          <Card className="p-6">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">
                Détail des vulnérabilités ({b.vulnerabilities?.length || 0})
              </h2>
              <Button variant="ghost" onClick={handleDownloadDetail} disabled={downloadingDetail}>
                <Download size={15} />
                {downloadingDetail ? "Génération…" : "Télécharger ce tableau (PDF)"}
              </Button>
            </div>
            {/* La ou les CVE portant le score le PLUS ÉLEVÉ de ce bulletin sont signalées en
                rouge : c'est par elles qu'un consultant commence. Le maximum est recalculé
                sur les seules vulnérabilités affichées, donc sur la période choisie. */}
            {/* UNE LIGNE = UNE CVE. Chaque cellule lit `r`, c'est-à-dire LA vulnérabilité de
                cette ligne — jamais une valeur agrégée du bulletin. Deux CVE d'un même
                produit ont des dates, des scores et des correctifs différents ; les
                confondre conduirait un consultant à appliquer le correctif du voisin. */}
            <Table
              columns={[
                {
                  key: "cve_id",
                  label: "CVE",
                  render: (r) => (
                    <div className="min-w-[8rem]">
                      <span className={estLaPlusGrave(r)
                        ? "font-bold text-rose-700"
                        : "font-medium text-brand-700"}>
                        {r.cve_id}
                      </span>
                      {estLaPlusGrave(r) && (
                        <span className="ml-2 rounded-full bg-rose-100 px-2 py-0.5 text-[10px] font-semibold uppercase text-rose-700">
                          Score le plus élevé
                        </span>
                      )}
                      <div className="text-xs text-slate-400">
                        Publiée : {r.published_at ? formatCourt(String(r.published_at).slice(0, 10)) : "Non disponible"}
                      </div>
                      <div className="text-xs text-slate-400">
                        Détectée : {r.detected_at ? formatCourt(String(r.detected_at).slice(0, 10)) : "Non disponible"}
                      </div>
                    </div>
                  ),
                },
                {
                  key: "updated_at",
                  label: "Dernière mise à jour",
                  // Date de RÉVISION de la CVE chez l'autorité qui la publie. Une fiche
                  // révisée voit son score ou son correctif changer sans être republiée :
                  // sans cette colonne, le consultant ne voyait pas qu'elle avait bougé.
                  render: (r) => (r.updated_at
                    ? <span className="whitespace-nowrap text-xs">{formatCourt(String(r.updated_at).slice(0, 10))}</span>
                    : <span className="whitespace-nowrap text-xs text-slate-400">Non disponible</span>),
                },
                { key: "description", label: "Résumé", render: (r) => <span className="line-clamp-3 block max-w-[18rem] text-xs">{na(r.description)}</span> },
                { key: "impact", label: "Impact", render: (r) => <span className="line-clamp-3 block max-w-[12rem] text-xs">{na(r.impact)}</span> },
                { key: "cvss_score", label: "CVSS", render: (r) => (r.cvss_score != null ? Number(r.cvss_score).toFixed(1) : "Non disponible") },
                {
                  key: "severity",
                  label: "Sévérité",
                  render: (r) => (r.severity ? (
                    <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${SEVERITY_STYLES[r.severity]}`}>
                      {SEVERITY_LABELS[r.severity]}
                    </span>
                  ) : <span className="text-xs text-slate-400">Non disponible</span>),
                },
                {
                  key: "affected_systems",
                  label: "Systèmes affectés",
                  render: (r) => {
                    const liste = (r.affected_systems?.length ? r.affected_systems : r.affected_products) || [];
                    if (!liste.length) return <span className="text-xs text-slate-400">{na(r.affected_versions)}</span>;
                    return <span className="line-clamp-3 block max-w-[12rem] text-xs">{liste.join(" · ")}</span>;
                  },
                },
                {
                  key: "solution",
                  label: "Solution",
                  render: (r) => (r.solution
                    ? <span className="line-clamp-3 block max-w-[14rem] text-xs">{r.solution}</span>
                    // Une remédiation absente n'est pas une absence de correctif : le backend
                    // distingue les deux, on restitue son verdict tel quel.
                    : <span className="block max-w-[14rem] text-xs italic text-slate-400">
                        {r.solution_message || "Non disponible"}
                      </span>),
                },
                {
                  key: "official_source",
                  label: "Site officiel",
                  render: (r) => {
                    const src = r.official_source || {};
                    if (!src.url) return <span className="text-xs text-slate-400">Non identifié</span>;
                    return (
                      <a href={src.url} target="_blank" rel="noreferrer"
                         className="line-clamp-2 block max-w-[12rem] text-xs text-brand-700 hover:underline">
                        {src.name || src.url}
                      </a>
                    );
                  },
                },
              ]}
              rows={b.vulnerabilities || []}
              emptyLabel="Aucune vulnérabilité sur cette période"
            />
          </Card>
        </div>
      )}

      <div className="mt-4">
        <Button variant="ghost" onClick={() => navigate(`/consultant/product-bulletins?start=${start}&end=${end}`)}>
          ← Retour aux bulletins
        </Button>
      </div>
    </Layout>
  );
}
