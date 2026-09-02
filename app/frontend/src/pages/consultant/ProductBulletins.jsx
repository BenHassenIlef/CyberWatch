import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { FileText, ShieldAlert, ChevronRight } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Card from "../../components/ui/Card";
import SearchInput from "../../components/ui/SearchInput";
import api from "../../api/axios";
import { useConsultantNavItems } from "./navItems";
import { SEVERITY_LABELS, SEVERITY_STYLES } from "./cveConstants";
import PeriodPicker, { bornesDuMode, formatCourt } from "./PeriodPicker";

// Période proposée par défaut : les trois derniers jours. Elle est recalculee a chaque
// affichage — aucune date n'est figee dans le code.
const PERIODE_PAR_DEFAUT = () => bornesDuMode("last3");

// Liste des bulletins de sécurité GROUPÉS PAR ÉDITEUR / PRODUIT (vue CERT).
export default function ProductBulletins() {
  const navItems = useConsultantNavItems();
  const [data, setData] = useState({ total: 0, items: [] });
  const [loading, setLoading] = useState(true);
  // La période vit dans l'URL (?start=&end=), pas dans un état local : elle survit ainsi à
  // l'aller-retour vers le détail d'un produit et reste partageable par lien.
  const [params, setParams] = useSearchParams();
  const defaut = PERIODE_PAR_DEFAUT();
  const start = params.get("start") || defaut.start;
  const end = params.get("end") || defaut.end;
  const appliquerPeriode = ({ start: s, end: e }) =>
    setParams((p) => { p.set("start", s); p.set("end", e); return p; }, { replace: true });
  const [q, setQ] = useState("");

  useEffect(() => {
    setLoading(true);
    // Le FILTRAGE EST FAIT PAR LE SERVEUR : les compteurs et le CVSS maximal des cartes
    // portent donc bien sur la période choisie, et non sur un sous-ensemble masqué a
    // l'affichage.
    const query = { start, end, limit: 60 };
    if (q.trim()) query.q = q.trim();
    api.get("/consultant/product-bulletins", { params: query }).then((res) => {
      setData(res.data);
      setLoading(false);
    });
  }, [start, end, q]);

  return (
    <Layout role="consultant" homeLabel="Espace Consultant" navItems={navItems}>
      <PageHeader
        title="Bulletins de sécurité par produit"
        subtitle="Vulnérabilités regroupées par produit surveillé, comme un bulletin CERT"
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <SearchInput value={q} onChange={setQ} placeholder="Rechercher un produit surveillé…" />
        <PeriodPicker start={start} end={end} onApply={appliquerPeriode} />
        <span className="text-sm text-slate-400">
          {formatCourt(start)} → {formatCourt(end)} · {data.total} produit(s) concerné(s)
        </span>
      </div>

      {loading ? (
        <p className="text-slate-400">Chargement…</p>
      ) : data.items.length === 0 ? (
        <Card className="p-6"><p className="text-sm text-slate-400">Aucune vulnérabilité sur les produits surveillés pour cette période.</p></Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {data.items.map((b) => (
            <Link key={b.vendor_key} to={`/consultant/product-bulletins/${encodeURIComponent(b.vendor_key)}?start=${start}&end=${end}`}>
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
