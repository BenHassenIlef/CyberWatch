import { useEffect, useState } from "react";
import { Clock, PlayCircle, CheckCircle2, AlertTriangle } from "lucide-react";
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
  const [etat, setEtat] = useState(null);
  const [lancement, setLancement] = useState(false);
  const [message, setMessage] = useState("");

  const chargerEtat = () =>
    api.get("/consultant/collection-status").then((r) => setEtat(r.data)).catch(() => {});

  useEffect(() => {
    api.get("/consultant/collection-schedule").then((res) => setForm(res.data));
    chargerEtat();
  }, []);

  // Une collecte dure plusieurs minutes : on interroge l etat regulierement tant qu elle
  // tourne, pour que le consultant voie son avancement sans recharger la page.
  useEffect(() => {
    if (!etat?.running) return;
    const t = setInterval(chargerEtat, 15000);
    return () => clearInterval(t);
  }, [etat?.running]);

  const relancer = async () => {
    setLancement(true);
    setMessage("");
    try {
      const { data } = await api.post("/consultant/collection/run");
      setMessage(data.message);
      setTimeout(chargerEtat, 2000);
    } catch (e) {
      setMessage(e.response?.status === 409
        ? "Une collecte est deja en cours. Patientez quelques minutes."
        : "Le lancement a echoue. Reessayez dans un instant.");
    } finally {
      setLancement(false);
    }
  };

  const fmtHeure = (d) => (d ? new Date(d).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" }) : null);

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

      {/* VEILLE DU JOUR — etat reel, puis relance a la demande.
          L execution planifiee peut echouer : machine eteinte a l heure dite, reseau
          indisponible, portail injoignable. Sans ce bouton, le consultant devait attendre
          le lendemain pour disposer de sa veille. */}
      {etat && (
        <Card className="mb-4 max-w-xl p-5">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              {etat.running ? (
                <PlayCircle size={18} className="animate-pulse text-brand-600" />
              ) : etat.ran_today ? (
                <CheckCircle2 size={18} className="text-emerald-600" />
              ) : (
                <AlertTriangle size={18} className="text-amber-600" />
              )}
              <span className="text-sm font-semibold uppercase tracking-wide text-slate-600">
                Collecte du jour
              </span>
            </div>
            <Button onClick={relancer} disabled={lancement || etat.running}>
              <PlayCircle size={16} />
              {etat.running ? "Collecte en cours…" : lancement ? "Lancement…" : "Lancer la collecte"}
            </Button>
          </div>

          <p className="text-sm text-slate-600">
            {etat.running
              ? "Une collecte est en cours. Les résultats apparaîtront dans quelques minutes."
              : etat.ran_today ? (
                <>
                  Exécutée à <b>{fmtHeure(etat.started_at)}</b> — {etat.new_saved ?? 0} nouvelle(s),{" "}
                  {etat.updated ?? 0} mise(s) à jour, {etat.sources_ok}/{etat.sources_total} source(s) aboutie(s).
                </>
              ) : (
                <>Aucune collecte aujourd'hui. Elle est prévue à <b>{etat.scheduled_at}</b>.</>
              )}
          </p>

          {/* POURQUOI IL N'Y A RIEN. Un « 0 nouvelle » sec ne dit pas si la journée a été
              calme ou si la collecte a échoué — et le consultant conclut naturellement à la
              panne. En rappelant combien de vulnérabilités ont paru dans le monde, on rend
              le résultat interprétable : « 36 parues, aucune sur vos produits » est une
              réponse ; « 0 » n'en est pas une. */}
          {etat.ran_today && !etat.running && !etat.new_saved && (
            <p className="mt-2 rounded-lg bg-slate-50 px-3 py-2 text-sm text-slate-600">
              {etat.published_today > 0 ? (
                <>
                  <b>{etat.published_today}</b> vulnérabilité(s) ont été publiées aujourd’hui
                  toutes sources confondues, mais aucune ne concerne vos produits surveillés.
                  La veille a bien fonctionné : votre parc n’est pas touché.
                </>
              ) : etat.sources_ok === 0 ? (
                <>
                  Aucune source n’a abouti : le résultat n’est pas exploitable. Vérifiez la
                  connexion réseau, puis relancez la collecte.
                </>
              ) : (
                <>
                  Aucune vulnérabilité n’a été publiée aujourd’hui par les sources consultées
                  ({etat.cve_detected ?? 0} entrée(s) examinée(s)). C’est fréquent le week-end.
                </>
              )}
            </p>
          )}
          {message && <p className="mt-2 text-sm text-brand-700">{message}</p>}
        </Card>
      )}

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
