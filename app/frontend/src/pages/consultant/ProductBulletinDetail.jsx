import { useEffect, useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
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

const na = (v) => (v === null || v === undefined || v === "" ? "—" : v);

// Bulletin de sécurité GROUPÉ d'un éditeur (rendu identique au modèle Advancia + tableau des CVE).
export default function ProductBulletinDetail() {
  const { vendor } = useParams();
  const navigate = useNavigate();
  const navItems = useConsultantNavItems();
  const [b, setB] = useState(null);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState("");

  const handleDownload = async () => {
    setDownloading(true);
    setDownloadError("");
    try {
      await downloadBulletinPdf(
        api, `/consultant/product-bulletins/${encodeURIComponent(vendor)}/bulletin.pdf`);
    } catch {
      setDownloadError("Le téléchargement du PDF a échoué. Réessayez dans un instant.");
    } finally {
      setDownloading(false);
    }
  };

  useEffect(() => {
    setB(null);
    setError("");
    api
      .get(`/consultant/product-bulletins/${encodeURIComponent(vendor)}`)
      .then((res) => setB(res.data))
      .catch((e) => setError(e.response?.data?.detail || "Bulletin introuvable."));
  }, [vendor]);

  return (
    <Layout role="consultant" homeLabel="Espace Consultant" navItems={navItems}>
      <PageHeader
        title={b ? b.title : "Bulletin de sécurité"}
        subtitle={b ? `${b.cve_count} CVE regroupées` : "Chargement…"}
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
          <Card className="p-4">
            <AiSummaryButtons subject={`les vulnérabilités ${b.vendor || vendor}`} group />
          </Card>
          <Card className="p-6">
            {b.ai_summary && (
              <div className="overflow-x-auto" dangerouslySetInnerHTML={{ __html: aiSummaryHTML(b) }} />
            )}
            <div className="overflow-x-auto" dangerouslySetInnerHTML={{ __html: bulletinTableHTML(b) }} />
          </Card>

          {/* Détail par CVE (structure vulnerabilities[]) */}
          <Card className="p-6">
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">
              Détail des vulnérabilités ({b.vulnerabilities?.length || 0})
            </h2>
            <Table
              columns={[
                {
                  key: "cve_id",
                  label: "CVE",
                  render: (r) => (
                    <span className="font-medium text-brand-700">{r.cve_id}</span>
                  ),
                },
                { key: "cvss_score", label: "CVSS", render: (r) => (r.cvss_score != null ? Number(r.cvss_score).toFixed(1) : "—") },
                {
                  key: "severity",
                  label: "Criticité",
                  render: (r) => (r.severity ? (
                    <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${SEVERITY_STYLES[r.severity]}`}>
                      {SEVERITY_LABELS[r.severity]}
                    </span>
                  ) : "—"),
                },
                { key: "vulnerability_type", label: "Type", render: (r) => <span className="line-clamp-1 max-w-[10rem]">{na(r.vulnerability_type)}</span> },
                { key: "affected_versions", label: "Versions affectées", render: (r) => <span className="line-clamp-1 max-w-[16rem]">{na(r.affected_versions)}</span> },
              ]}
              rows={b.vulnerabilities || []}
              emptyLabel="Aucune vulnérabilité"
            />
          </Card>
        </div>
      )}

      <div className="mt-4">
        <Button variant="ghost" onClick={() => navigate("/consultant/product-bulletins")}>
          ← Retour aux bulletins
        </Button>
      </div>
    </Layout>
  );
}
