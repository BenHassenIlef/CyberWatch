import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Bell, CheckCheck } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Card from "../../components/ui/Card";
import Button from "../../components/ui/Button";
import api from "../../api/axios";
import { useConsultantNavItems } from "./navItems";
import { useNotifications } from "../../context/NotificationsContext";
import { SEVERITY_LABELS, SEVERITY_STYLES } from "./cveConstants";

const fmtDateTime = (d) => (d ? new Date(d).toLocaleString("fr-FR") : "");

export default function ConsultantNotifications() {
  const navItems = useConsultantNavItems();
  const navigate = useNavigate();
  const { refresh, markAllRead } = useNotifications();
  const [items, setItems] = useState(null);

  const load = async () => {
    const { data } = await api.get("/consultant/notifications");
    setItems(data.items);
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleMarkAll = async () => {
    await markAllRead();
    load();
  };

  return (
    <Layout role="consultant" homeLabel="Espace Consultant" navItems={navItems}>
      <PageHeader
        title="Notifications"
        subtitle="Nouvelles CVE détectées par les agents de collecte"
        action={
          items?.length ? (
            <Button variant="secondary" onClick={handleMarkAll}>
              <CheckCheck size={16} /> Tout marquer comme lu
            </Button>
          ) : null
        }
      />

      {items === null ? (
        <p className="text-slate-400">Chargement…</p>
      ) : items.length === 0 ? (
        <Card className="flex flex-col items-center gap-2 p-10 text-center">
          <Bell size={28} className="text-slate-300" />
          <p className="text-sm text-slate-500">Aucune nouvelle notification.</p>
          <p className="text-xs text-slate-400">Les nouvelles CVE collectées apparaîtront ici.</p>
        </Card>
      ) : (
        <div className="space-y-3">
          {items.map((n) => (
            <div
              key={n.id}
              onClick={() => navigate(`/consultant/cves/${n.id}`)}
              className="cursor-pointer transition-shadow hover:shadow-md rounded-2xl"
            >
              <Card className="flex items-center gap-4 p-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-50 text-brand-600">
                  <Bell size={18} />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-slate-800">
                    {n.type === "update" ? "🔄 Mise à jour de CVE — " : "🔔 Nouvelle CVE détectée — "}
                    <span className="text-brand-700">{n.cve_id}</span>
                  </p>
                  <p className="mt-0.5 truncate text-xs text-slate-500">
                    Produit : {n.product || "—"} · Source : {n.source || "—"}
                    {n.published_at ? ` · Publiée le ${new Date(n.published_at).toLocaleDateString("fr-FR")}` : ""}
                    <span className="text-slate-400"> · détectée le {fmtDateTime(n.collected_at)}</span>
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <span className="text-sm font-semibold text-slate-700">CVSS {n.cvss_score?.toFixed(1) ?? "—"}</span>
                  <span className={`rounded-full px-3 py-1 text-xs font-semibold ${SEVERITY_STYLES[n.severity]}`}>
                    {SEVERITY_LABELS[n.severity]}
                  </span>
                </div>
              </Card>
            </div>
          ))}
        </div>
      )}
    </Layout>
  );
}
