import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Plus, RefreshCw, Pencil, Trash2, ShieldCheck, ShieldQuestion, ShieldX, ShieldOff, Lock } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Table from "../../components/ui/Table";
import Button from "../../components/ui/Button";
import StatCard from "../../components/ui/StatCard";
import SearchInput from "../../components/ui/SearchInput";
import api from "../../api/axios";
import { useAdminNavItems } from "./navItems";
import { COLLECTION_METHOD_LABELS, SOURCE_STATUS_LABELS, SOURCE_STATUS_STYLES } from "./sourceConstants";

export default function Sources() {
  const navItems = useAdminNavItems();
  const navigate = useNavigate();
  const [sources, setSources] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  const load = async () => {
    setLoading(true);
    const [sourcesRes, statsRes] = await Promise.all([api.get("/admin/sources"), api.get("/admin/sources/stats")]);
    setSources(sourcesRes.data);
    setStats(statsRes.data);
    setLoading(false);
  };

  useEffect(() => {
    load();
  }, []);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return sources;
    return sources.filter(
      (s) => s.name.toLowerCase().includes(q) || (s.collection_method || "").toLowerCase().includes(q)
    );
  }, [sources, search]);

  const handleToggleStatus = async (source) => {
    const next = source.status === "validated" ? "disabled" : "validated";
    await api.put(`/admin/sources/${source.id}`, { status: next });
    load();
  };

  const handleTrigger = async (source) => {
    await api.post(`/admin/sources/${source.id}/trigger-collection`);
    load();
  };

  const handleDelete = async (source) => {
    if (!confirm("Êtes-vous sûr de vouloir supprimer cette source ? Cette action est irréversible.")) return;
    await api.delete(`/admin/sources/${source.id}`);
    load();
  };

  return (
    <Layout role="admin" homeLabel="Espace Admin" navItems={navItems}>
      <PageHeader
        title="Sources CVE"
        subtitle="Gestion des sources fiables de collecte de CVE"
        action={
          <Button onClick={() => navigate("/admin/sources/new")}>
            <Plus size={16} /> Nouvelle source
          </Button>
        }
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Sources totales" value={stats?.total ?? "—"} icon={ShieldQuestion} accent="from-slate-500 to-slate-700" />
        <StatCard label="Validées" value={stats?.validated ?? "—"} icon={ShieldCheck} accent="from-emerald-500 to-teal-600" />
        <StatCard label="En attente" value={stats?.pending ?? "—"} icon={ShieldQuestion} accent="from-amber-400 to-orange-500" />
        <StatCard label="Rejetées" value={stats?.rejected ?? "—"} icon={ShieldX} accent="from-rose-500 to-brand-700" />
      </div>

      <div className="mb-4">
        <SearchInput value={search} onChange={setSearch} placeholder="Rechercher une source…" />
      </div>

      <Table
        columns={[
          { key: "name", label: "Nom", render: (r) => <Link to={`/admin/sources/${r.id}`} className="font-medium text-brand-700 hover:underline">{r.name}</Link> },
          {
            key: "collection_method",
            label: "Méthode",
            render: (r) => (
              <span className="inline-flex items-center gap-1.5">
                {COLLECTION_METHOD_LABELS[r.collection_method] || r.collection_method || "—"}
                {r.authentication_required && (
                  <Lock
                    size={13}
                    className={r.authentication_status === "configured" ? "text-emerald-500" : "text-amber-500"}
                    title={r.authentication_status === "configured" ? "Authentification configurée" : "Configuration requise"}
                  />
                )}
              </span>
            ),
          },
          {
            key: "status",
            label: "Statut",
            render: (r) => (
              <span className={`rounded-full px-3 py-1 text-xs font-semibold ${SOURCE_STATUS_STYLES[r.status]}`}>
                {SOURCE_STATUS_LABELS[r.status]}
              </span>
            ),
          },
          {
            key: "confidence_score",
            label: "Score de confiance",
            render: (r) => (r.confidence_score != null ? `${r.confidence_score}/100` : "—"),
          },
          {
            key: "last_sync_at",
            label: "Dernière collecte",
            render: (r) => (r.last_sync_at ? new Date(r.last_sync_at).toLocaleString("fr-FR") : "Jamais"),
          },
          {
            key: "actions",
            label: "",
            render: (r) => (
              <div className="flex justify-end gap-2">
                <button onClick={() => handleTrigger(r)} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100" title="Relancer la collecte">
                  <RefreshCw size={16} />
                </button>
                {(r.status === "validated" || r.status === "disabled") && (
                  <button
                    onClick={() => handleToggleStatus(r)}
                    className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
                    title={r.status === "validated" ? "Désactiver" : "Activer"}
                  >
                    <ShieldOff size={16} />
                  </button>
                )}
                <button onClick={() => navigate(`/admin/sources/${r.id}`)} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100" title="Modifier">
                  <Pencil size={16} />
                </button>
                <button onClick={() => handleDelete(r)} className="rounded-lg p-2 text-rose-500 hover:bg-rose-50" title="Supprimer">
                  <Trash2 size={16} />
                </button>
              </div>
            ),
          },
        ]}
        rows={loading ? [] : filtered}
        emptyLabel={loading ? "Chargement…" : "Aucune source pour le moment"}
      />
    </Layout>
  );
}
