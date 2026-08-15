import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Download, ArrowLeft } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Card from "../../components/ui/Card";
import Button from "../../components/ui/Button";
import AiSummaryButtons from "../../components/ui/AiSummaryButtons";
import api from "../../api/axios";
import { useConsultantNavItems } from "./navItems";
import { bulletinTableHTML, aiSummaryHTML, downloadBulletinPdf } from "./bulletin";

// Page INDÉPENDANTE du bulletin de sécurité Advancia (modèle normalisé, moteur générique).
export default function CveBulletin() {
  const { id } = useParams();
  const navigate = useNavigate();
  const navItems = useConsultantNavItems();
  const [bulletin, setBulletin] = useState(null);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState("");

  const handleDownload = async () => {
    setDownloading(true);
    setDownloadError("");
    try {
      await downloadBulletinPdf(api, `/consultant/cves/${id}/bulletin.pdf`);
    } catch {
      setDownloadError("Le téléchargement du PDF a échoué. Réessayez dans un instant.");
    } finally {
      setDownloading(false);
    }
  };

  useEffect(() => {
    setBulletin(null);
    setError("");
    api
      .get(`/consultant/cves/${id}/bulletin`)
      .then((res) => setBulletin(res.data))
      .catch((e) =>
        setError(e.response?.data?.detail || "Impossible de générer le bulletin de cette CVE."));
  }, [id]);

  const subtitle = bulletin ? (bulletin.cves || [])[0] || bulletin.reference || "" : "Génération en cours…";

  return (
    <Layout role="consultant" homeLabel="Espace Consultant" navItems={navItems}>
      <PageHeader
        title="Bulletin de sécurité"
        subtitle={subtitle}
        action={
          bulletin && (
            <Button onClick={handleDownload} disabled={downloading}>
              <Download size={16} /> {downloading ? "Génération du PDF…" : "Télécharger le PDF"}
            </Button>
          )
        }
      />

      {downloadError && (
        <Card className="mb-4 p-4">
          <p className="text-sm text-rose-600">{downloadError}</p>
        </Card>
      )}

      {error ? (
        <Card className="p-6">
          <p className="text-sm text-rose-600">{error}</p>
        </Card>
      ) : !bulletin ? (
        <Card className="p-6">
          <p className="text-sm text-slate-400">
            Génération du bulletin (analyse de la page d'avis, normalisation et complétion multi-sources)…
          </p>
        </Card>
      ) : (
        <>
        {(bulletin.cves || [])[0] && (
          <Card className="mb-4 p-4">
            <AiSummaryButtons subject={`la vulnérabilité ${(bulletin.cves || [])[0]}`} />
          </Card>
        )}
        <Card className="p-6">
          {bulletin.ai_summary && (
            <div className="overflow-x-auto" dangerouslySetInnerHTML={{ __html: aiSummaryHTML(bulletin) }} />
          )}
          <div className="overflow-x-auto" dangerouslySetInnerHTML={{ __html: bulletinTableHTML(bulletin) }} />
        </Card>
        </>
      )}

      <div className="mt-4">
        <Button variant="ghost" onClick={() => navigate(`/consultant/cves/${id}`)}>
          <ArrowLeft size={16} /> Retour à la fiche CVE
        </Button>
      </div>
    </Layout>
  );
}
