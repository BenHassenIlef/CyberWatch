import { useEffect, useState } from "react";
import { Clock } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Card from "../../components/ui/Card";
import Button from "../../components/ui/Button";
import api from "../../api/axios";
import { useConsultantNavItems } from "./navItems";

const FREQUENCIES = [
  { value: "hourly", label: "Toutes les heures" },
  { value: "every_6h", label: "Toutes les 6 heures" },
  { value: "daily", label: "Tous les jours" },
  { value: "weekly", label: "Toutes les semaines" },
];

const inputClass =
  "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100";

export default function Schedule() {
  const navItems = useConsultantNavItems();
  const [form, setForm] = useState(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api.get("/consultant/collection-schedule").then((res) => setForm(res.data));
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const { data } = await api.put("/consultant/collection-schedule", {
      frequency: form.frequency,
      hour: Number(form.hour),
      minute: Number(form.minute),
    });
    setForm(data);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  if (!form) {
    return (
      <Layout role="consultant" homeLabel="Espace Consultant" navItems={navItems}>
        <p className="text-slate-400">Chargement…</p>
      </Layout>
    );
  }

  const perDay = form.frequency === "daily" || form.frequency === "weekly";

  return (
    <Layout role="consultant" homeLabel="Espace Consultant" navItems={navItems}>
      <PageHeader title="Planification de la collecte" subtitle="Configurer quand la collecte des CVE s'exécute" />

      <Card className="max-w-xl p-6">
        <div className="mb-5 flex items-center gap-2 text-brand-600">
          <Clock size={18} />
          <span className="text-sm font-semibold uppercase tracking-wide">Fréquence & horaire</span>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-600">Fréquence de collecte</label>
            <select value={form.frequency} onChange={(e) => setForm({ ...form, frequency: e.target.value })} className={inputClass}>
              {FREQUENCIES.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-600">Heure d'exécution</label>
              <input
                type="number"
                min={0}
                max={23}
                value={form.hour}
                onChange={(e) => setForm({ ...form, hour: e.target.value })}
                className={inputClass}
                disabled={!perDay && form.frequency === "hourly"}
              />
              <p className="mt-1 text-xs text-slate-400">0 à 23</p>
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-600">Minute d'exécution</label>
              <input
                type="number"
                min={0}
                max={59}
                value={form.minute}
                onChange={(e) => setForm({ ...form, minute: e.target.value })}
                className={inputClass}
              />
              <p className="mt-1 text-xs text-slate-400">0 à 59</p>
            </div>
          </div>

          <div className="flex items-center gap-3 pt-2">
            <Button type="submit">Enregistrer la planification</Button>
            {saved && <span className="text-sm text-emerald-600">Enregistré ✓</span>}
          </div>
        </form>
      </Card>
    </Layout>
  );
}
