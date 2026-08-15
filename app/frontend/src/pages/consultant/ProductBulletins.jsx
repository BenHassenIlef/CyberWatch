import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { FileText, ShieldAlert, ChevronRight } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Card from "../../components/ui/Card";
import SearchInput from "../../components/ui/SearchInput";
import api from "../../api/axios";
import { useConsultantNavItems } from "./navItems";
import { SEVERITY_LABELS, SEVERITY_STYLES } from "./cveConstants";

const DAYS_OPTIONS = [
  { value: 3, label: "3 jours" },
  { value: 7, label: "1 semaine" },
  { value: 14, label: "2 semaines" },
  { value: 30, label: "30 jours" },
  { value: 45, label: "45 jours" },
  { value: 90, label: "90 jours" },
  { value: 365, label: "1 an" },
];

// Liste des bulletins de sécurité GROUPÉS PAR ÉDITEUR / PRODUIT (vue CERT).
export default function ProductBulletins() {
  const navItems = useConsultantNavItems();
  const [data, setData] = useState({ total: 0, items: [] });
  const [loading, setLoading] = useState(true);
  const [days, setDays] = useState(90);
  const [q, setQ] = useState("");

  useEffect(() => {
    setLoading(true);
    const params = { days, limit: 60 };
    if (q.trim()) params.q = q.trim();
    api.get("/consultant/product-bulletins", { params }).then((res) => {
      setData(res.data);
      setLoading(false);
    });
  }, [days, q]);

  const selectClass =
    "rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100";

  return (
    <Layout role="consultant" homeLabel="Espace Consultant" navItems={navItems}>
      <PageHeader
        title="Bulletins de sécurité par produit"
        subtitle="Vulnérabilités regroupées par éditeur / technologie, comme un bulletin CERT"
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <SearchInput value={q} onChange={setQ} placeholder="Rechercher un éditeur (Mozilla, Microsoft…)" />
        <select value={days} onChange={(e) => setDays(Number(e.target.value))} className={selectClass} title="Fenêtre">
          {DAYS_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>Fenêtre : {o.label}</option>
          ))}
        </select>
        <span className="text-sm text-slate-400">{data.total} éditeur(s)</span>
      </div>

      {loading ? (
        <p className="text-slate-400">Chargement…</p>
      ) : data.items.length === 0 ? (
        <Card className="p-6"><p className="text-sm text-slate-400">Aucun bulletin sur cette période.</p></Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {data.items.map((b) => (
            <Link key={b.vendor_key} to={`/consultant/product-bulletins/${encodeURIComponent(b.vendor_key)}`}>
              <Card className="h-full p-5 transition hover:border-brand-300 hover:shadow-md">
                <div className="mb-2 flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <FileText size={18} className="text-brand-600" />
                    <h3 className="font-semibold text-slate-800">{b.vendor}</h3>
                  </div>
                  {b.severity && (
                    <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${SEVERITY_STYLES[b.severity]}`}>
                      {SEVERITY_LABELS[b.severity]}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-4 text-sm text-slate-500">
                  <span className="flex items-center gap-1"><ShieldAlert size={14} /> {b.cve_count} CVE</span>
                  {b.cvss_score != null && <span>CVSS max {Number(b.cvss_score).toFixed(1)}</span>}
                </div>
                {b.products?.length > 0 && (
                  <p className="mt-3 line-clamp-2 text-xs text-slate-400">{b.products.join(" · ")}</p>
                )}
                <div className="mt-3 flex items-center gap-1 text-sm font-medium text-brand-600">
                  Voir le bulletin <ChevronRight size={15} />
                </div>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </Layout>
  );
}
