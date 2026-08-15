import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Card from "../../components/ui/Card";
import Button from "../../components/ui/Button";
import AdminVerification from "../../components/ui/AdminVerification";
import api from "../../api/axios";
import { useAdminNavItems } from "./navItems";

const EMPTY_FORM = { name: "", url: "", description: "" };

export default function SourceNew() {
  const navItems = useAdminNavItems();
  const navigate = useNavigate();
  const [form, setForm] = useState(EMPTY_FORM);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [createdId, setCreatedId] = useState(null);
  const [verification, setVerification] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const payload = { ...form, description: form.description || null };
      const { data } = await api.post("/admin/sources", payload);
      setCreatedId(data.id);
      const verifyRes = await api.post(`/admin/sources/${data.id}/verify`);
      setVerification(verifyRes.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Une erreur est survenue");
    } finally {
      setLoading(false);
    }
  };

  const decide = async (status) => {
    await api.put(`/admin/sources/${createdId}`, { status });
    navigate(`/admin/sources/${createdId}`);
  };

  return (
    <Layout role="admin" homeLabel="Espace Admin" navItems={navItems}>
      <PageHeader title="Nouvelle source" subtitle="Ajouter et vérifier une source CVE" />

      {!verification ? (
        <Card className="max-w-2xl p-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && <p className="rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-600">{error}</p>}
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-600">Nom</label>
              <input
                required
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-600">URL</label>
              <input
                required
                type="url"
                placeholder="https://…"
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-600">Description</label>
              <textarea
                rows={3}
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100"
              />
            </div>
            <p className="rounded-lg bg-brand-50 px-3 py-2 text-xs text-brand-700">
              La méthode de collecte (API / RSS / Scraping) et l'authentification sont détectées automatiquement.
              La planification de la collecte se configure dans l'espace Consultant.
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="ghost" onClick={() => navigate("/admin/sources")}>
                Annuler
              </Button>
              <Button type="submit" disabled={loading}>
                <ShieldCheck size={16} /> {loading ? "Vérification…" : "Créer et vérifier"}
              </Button>
            </div>
          </form>
        </Card>
      ) : (
        <Card className="max-w-2xl p-6">
          <h2 className="mb-5 text-lg font-semibold text-slate-800">Résultat de la vérification</h2>

          <AdminVerification verification={verification} />

          <div className="mt-6 flex flex-wrap justify-end gap-2 border-t border-slate-100 pt-4">
            <Button variant="ghost" onClick={() => navigate(`/admin/sources/${createdId}`)}>
              Décider plus tard
            </Button>
            <Button variant="danger" onClick={() => decide("rejected")}>
              Refuser
            </Button>
            <Button onClick={() => decide("validated")}>Valider</Button>
          </div>
        </Card>
      )}
    </Layout>
  );
}
