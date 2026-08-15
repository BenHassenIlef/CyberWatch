import { useEffect, useMemo, useState } from "react";
import { Plus, Pencil, Trash2, Power, Boxes, Layers, ShieldCheck, CheckCircle2 } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Button from "../../components/ui/Button";
import Card from "../../components/ui/Card";
import Modal from "../../components/ui/Modal";
import StatCard from "../../components/ui/StatCard";
import SearchInput from "../../components/ui/SearchInput";
import api from "../../api/axios";
import { useConsultantNavItems } from "./navItems";

const EMPTY = { name: "", vendor: "", domain: "" };
const field = "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm focus:border-brand-400 focus:outline-none focus:ring-2 focus:ring-brand-100";

export default function Monitoring() {
  const navItems = useConsultantNavItems();
  const [products, setProducts] = useState([]);
  const [domains, setDomains] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [domainFilter, setDomainFilter] = useState("");
  const [modal, setModal] = useState(false);
  const [editing, setEditing] = useState(null); // id en cours d'édition, ou null pour un ajout
  const [form, setForm] = useState(EMPTY);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [flash, setFlash] = useState("");

  const load = async () => {
    setLoading(true);
    const [p, d] = await Promise.all([
      api.get("/consultant/monitoring/products"),
      api.get("/consultant/monitoring/domains"),
    ]);
    setProducts(p.data);
    setDomains(d.data);
    setLoading(false);
  };
  useEffect(() => { load(); }, []);

  const notify = (msg) => { setFlash(msg); setTimeout(() => setFlash(""), 3500); };

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return products.filter((p) => {
      if (domainFilter && p.domain !== domainFilter) return false;
      if (!q) return true;
      return [p.name, p.vendor].filter(Boolean).some((s) => s.toLowerCase().includes(q));
    });
  }, [products, search, domainFilter]);

  const grouped = useMemo(() => {
    const map = new Map();
    filtered.forEach((p) => { if (!map.has(p.domain)) map.set(p.domain, []); map.get(p.domain).push(p); });
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [filtered]);

  const activeCount = products.filter((p) => p.enabled).length;

  const openCreate = () => { setEditing(null); setForm({ ...EMPTY, domain: domainFilter || domains[0]?.name || "" }); setError(""); setModal(true); };
  const openEdit = (p) => { setEditing(p.id); setForm({ name: p.name, vendor: p.vendor || "", domain: p.domain }); setError(""); setModal(true); };

  const save = async () => {
    setSaving(true); setError("");
    const payload = { name: form.name.trim(), vendor: form.vendor.trim(), domain: form.domain.trim() };
    try {
      if (editing) {
        await api.put(`/consultant/monitoring/products/${editing}`, payload);
        notify("Produit modifié avec succès.");
      } else {
        await api.post("/consultant/monitoring/products", payload);
        notify("Produit ajouté avec succès.");
      }
      setModal(false);
      await load();
    } catch (e) {
      setError(e.response?.data?.detail || "Échec de l'enregistrement.");
    } finally { setSaving(false); }
  };

  const toggle = async (p) => {
    await api.post(`/consultant/monitoring/products/${p.id}/toggle`);
    notify(p.enabled ? "Surveillance désactivée." : "Surveillance activée.");
    load();
  };
  const remove = async (p) => {
    if (!confirm(`Êtes-vous sûr de vouloir supprimer ce produit ? (« ${p.name} ». Les CVE déjà collectées sont conservées.)`)) return;
    await api.delete(`/consultant/monitoring/products/${p.id}`);
    notify("Produit supprimé.");
    load();
  };

  return (
    <Layout role="consultant" homeLabel="Espace Consultant" navItems={navItems}>
      <PageHeader
        title="Produits surveillés"
        subtitle="Domaines et produits suivis — pris en compte automatiquement à la prochaine collecte"
        action={<Button onClick={openCreate}><Plus size={16} /> Ajouter un produit</Button>}
      />

      {flash && (
        <div className="mb-4 flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-2.5 text-sm font-medium text-emerald-700">
          <CheckCircle2 size={16} /> {flash}
        </div>
      )}

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-3">
        <StatCard label="Domaines" value={domains.length || "—"} icon={Layers} accent="from-slate-500 to-slate-700" />
        <StatCard label="Produits surveillés" value={products.length || "—"} icon={Boxes} accent="from-brand-500 to-brand-700" />
        <StatCard label="Surveillance active" value={activeCount || "—"} icon={ShieldCheck} accent="from-emerald-500 to-teal-600" />
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="min-w-[240px] flex-1"><SearchInput value={search} onChange={setSearch} placeholder="Rechercher un produit…" /></div>
        <select className={`${field} max-w-xs`} value={domainFilter} onChange={(e) => setDomainFilter(e.target.value)}>
          <option value="">Tous les domaines</option>
          {domains.map((d) => <option key={d.id} value={d.name}>{d.name} ({d.product_count})</option>)}
        </select>
      </div>

      {loading ? (
        <p className="text-sm text-slate-500">Chargement…</p>
      ) : grouped.length === 0 ? (
        <p className="text-sm text-slate-500">Aucun produit trouvé.</p>
      ) : (
        <div className="space-y-6">
          {grouped.map(([domain, items]) => (
            <Card key={domain} className="overflow-hidden">
              <div className="flex items-center justify-between border-b border-slate-100 bg-slate-50/60 px-5 py-3">
                <h3 className="font-semibold text-slate-800">Domaine : {domain}</h3>
                <span className="text-xs text-slate-500">{items.length} produit(s)</span>
              </div>
              <ul className="divide-y divide-slate-100">
                {items.map((p) => (
                  <li key={p.id} className="flex items-center justify-between gap-4 px-5 py-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-slate-800">{p.name}</span>
                        {p.vendor && <span className="text-xs text-slate-400">· {p.vendor}</span>}
                        <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${p.enabled ? "bg-emerald-100 text-emerald-700" : "bg-slate-200 text-slate-500"}`}>
                          {p.enabled ? "Surveillance active" : "Désactivé"}
                        </span>
                        <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${p.is_default ? "bg-slate-100 text-slate-500" : "bg-brand-50 text-brand-600"}`}>
                          {p.is_default ? "Par défaut" : "Personnalisé"}
                        </span>
                      </div>
                      {typeof p.cve_count === "number" && p.cve_count > 0 && (
                        <div className="mt-0.5 text-xs text-slate-400">{p.cve_count} CVE associée(s)</div>
                      )}
                    </div>
                    <div className="flex shrink-0 gap-2">
                      <button onClick={() => toggle(p)} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100" title={p.enabled ? "Désactiver la surveillance" : "Activer la surveillance"}><Power size={16} /></button>
                      <button onClick={() => openEdit(p)} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100" title="Modifier"><Pencil size={16} /></button>
                      <button onClick={() => remove(p)} className="rounded-lg p-2 text-rose-500 hover:bg-rose-50" title="Supprimer"><Trash2 size={16} /></button>
                    </div>
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
      )}

      <Modal open={modal} onClose={() => setModal(false)} title={editing ? "Modifier le produit" : "Ajouter un produit"}>
        <div className="space-y-4">
          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-600">Nom du produit</label>
            <input className={field} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="ex. SonicWall Firewall" autoFocus />
          </div>
          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-600">Fabricant / Éditeur</label>
            <input className={field} value={form.vendor} onChange={(e) => setForm({ ...form, vendor: e.target.value })} placeholder="ex. SonicWall" />
          </div>
          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-600">Domaine</label>
            <select className={field} value={form.domain} onChange={(e) => setForm({ ...form, domain: e.target.value })}>
              <option value="">Sélectionner un domaine</option>
              {domains.map((d) => <option key={d.id} value={d.name}>{d.name}</option>)}
            </select>
          </div>
          {error && <p className="text-sm text-rose-600">{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <Button variant="secondary" onClick={() => setModal(false)}>Annuler</Button>
            <Button onClick={save} disabled={saving || !form.name.trim() || !form.domain.trim()}>
              {saving ? "Enregistrement…" : editing ? "Enregistrer" : "Ajouter"}
            </Button>
          </div>
        </div>
      </Modal>
    </Layout>
  );
}
