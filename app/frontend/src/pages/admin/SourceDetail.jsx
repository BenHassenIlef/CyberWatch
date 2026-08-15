import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Wifi, RefreshCw, ShieldCheck, Lock, KeyRound, Trash2, CheckCircle2, XCircle, MinusCircle } from "lucide-react";
// Trash2 used for both credential removal and source deletion.
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Card from "../../components/ui/Card";
import Button from "../../components/ui/Button";
import AdminVerification from "../../components/ui/AdminVerification";
import api from "../../api/axios";
import { useAdminNavItems } from "./navItems";
import {
  SOURCE_STATUS_LABELS,
  SOURCE_STATUS_STYLES,
  COLLECTION_METHOD_LABELS,
  AUTH_TYPES,
  authLabel,
  methodLabel,
  backupLabel,
} from "./sourceConstants";

export default function SourceDetail() {
  const navItems = useAdminNavItems();
  const { id } = useParams();
  const navigate = useNavigate();
  const [source, setSource] = useState(null);
  const [form, setForm] = useState(null);
  const [saved, setSaved] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [triggerMsg, setTriggerMsg] = useState(null);
  const [cred, setCred] = useState({ auth_type: "api_key", secret: "", username: "" });

  const load = async () => {
    const { data } = await api.get(`/admin/sources/${id}`);
    setSource(data);
    setForm({
      name: data.name,
      url: data.url || "",
      description: data.description || "",
    });
  };

  useEffect(() => {
    load();
  }, [id]);

  const handleSave = async (e) => {
    e.preventDefault();
    await api.put(`/admin/sources/${id}`, { ...form, description: form.description || null });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
    load();
  };

  const handleVerify = async () => {
    setVerifying(true);
    const { data } = await api.post(`/admin/sources/${id}/verify`);
    setVerifying(false);
    load();
    setSource((s) => ({ ...s, verification: data }));
  };

  const decide = async (status) => {
    await api.put(`/admin/sources/${id}`, { status });
    load();
  };

  const handleTestConnection = async () => {
    setTesting(true);
    const { data } = await api.post(`/admin/sources/${id}/test-connection`);
    setTestResult(data);
    setTesting(false);
  };

  const handleToggleStatus = async () => {
    const next = source.status === "validated" ? "disabled" : "validated";
    await decide(next);
  };

  const handleTrigger = async () => {
    const { data } = await api.post(`/admin/sources/${id}/trigger-collection`);
    setTriggerMsg(data.ok ? null : data.message);
    load();
  };

  const handleSaveCredential = async (e) => {
    e.preventDefault();
    const payload = { auth_type: cred.auth_type, secret: cred.secret };
    if (cred.auth_type === "basic" && cred.username) payload.username = cred.username;
    await api.put(`/admin/sources/${id}/credentials`, payload);
    setCred({ auth_type: "api_key", secret: "", username: "" });
    load();
  };

  const handleDeleteSource = async () => {
    if (!confirm("Êtes-vous sûr de vouloir supprimer cette source ? Cette action est irréversible.")) return;
    await api.delete(`/admin/sources/${id}`);
    navigate("/admin/sources");
  };

  const handleDeleteCredential = async () => {
    await api.delete(`/admin/sources/${id}/credentials`);
    load();
  };

  if (!source || !form) {
    return (
      <Layout role="admin" homeLabel="Espace Admin" navItems={navItems}>
        <p className="text-slate-400">Chargement…</p>
      </Layout>
    );
  }

  const verification = source.verification;
  const needsConfig = source.authentication_required && source.authentication_status !== "configured";

  return (
    <Layout role="admin" homeLabel="Espace Admin" navItems={navItems}>
      <PageHeader
        title={source.name}
        subtitle="Détails, vérification et configuration de la source"
        action={
          <span className={`rounded-full px-3 py-1 text-sm font-semibold ${SOURCE_STATUS_STYLES[source.status]}`}>
            {SOURCE_STATUS_LABELS[source.status]}
          </span>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="space-y-4">
          {/* Méthode de collecte + authentification (détectées automatiquement) */}
          <Card className="p-6">
            <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-500">Collecte</h2>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="rounded-xl border border-slate-100 bg-slate-50 px-4 py-3">
                <p className="text-xs uppercase tracking-wide text-slate-400">Méthode détectée</p>
                <p className="mt-1 font-semibold text-slate-700">
                  {methodLabel(source.collection_method)}
                  {COLLECTION_METHOD_LABELS[source.collection_method] &&
                    methodLabel(source.collection_method) !== COLLECTION_METHOD_LABELS[source.collection_method] && (
                      <span className="ml-1 text-xs font-normal text-slate-400">
                        ({COLLECTION_METHOD_LABELS[source.collection_method]})
                      </span>
                    )}
                </p>
              </div>
              <div className="rounded-xl border border-slate-100 bg-slate-50 px-4 py-3">
                <p className="text-xs uppercase tracking-wide text-slate-400">Authentication</p>
                <p className={`mt-1 font-semibold ${needsConfig ? "text-amber-600" : "text-slate-700"}`}>{authLabel(source)}</p>
              </div>
              {source.api_endpoint && (
                <div className="col-span-2 rounded-xl border border-slate-100 bg-slate-50 px-4 py-3">
                  <p className="text-xs uppercase tracking-wide text-slate-400">API Endpoint</p>
                  <p className="mt-1 break-all font-mono text-xs text-slate-600">{source.api_endpoint}</p>
                </div>
              )}
              {source.data_format && (
                <div className="rounded-xl border border-slate-100 bg-slate-50 px-4 py-3">
                  <p className="text-xs uppercase tracking-wide text-slate-400">Data Format</p>
                  <p className="mt-1 font-semibold uppercase text-slate-700">{source.data_format}</p>
                </div>
              )}
              <div className="rounded-xl border border-slate-100 bg-slate-50 px-4 py-3">
                <p className="text-xs uppercase tracking-wide text-slate-400">Méthode de repli</p>
                <p className="mt-1 font-semibold text-slate-700">{backupLabel(source.backup_method)}</p>
              </div>
              {typeof source.validation_score === "number" && (
                <div className="col-span-2 rounded-xl border border-slate-100 bg-slate-50 px-4 py-3">
                  <p className="text-xs uppercase tracking-wide text-slate-400">Validation de la méthode</p>
                  <p className={`mt-1 font-semibold ${source.contains_cve ? "text-emerald-600" : "text-rose-600"}`}>
                    {source.contains_cve ? "Réussie" : "Échec"}
                    <span className="ml-1 text-xs font-normal text-slate-400">
                      — {source.cve_count ?? 0} CVE trouvées · score {source.validation_score}/100
                    </span>
                  </p>
                </div>
              )}
            </div>

            {source.detection_reason && (
              <div className="mt-3 rounded-xl border border-slate-100 bg-slate-50 px-4 py-3 text-sm">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">Décision / Explication</p>
                <p className="mt-1 text-slate-600">{source.detection_reason}</p>
                {source.detection_alternatives?.length > 0 && (
                  <p className="mt-2 text-xs text-slate-400">
                    Méthodes alternatives : {source.detection_alternatives.join(" / ")} en cas d'indisponibilité.
                  </p>
                )}
              </div>
            )}

            {source.detection_candidates?.length > 0 && (
              <div className="mt-3 rounded-xl border border-slate-100 bg-slate-50 px-4 py-3">
                <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">Méthodes testées</p>
                <ul className="space-y-1.5">
                  {source.detection_candidates.map((c) => {
                    const Icon = c.validated ? CheckCircle2 : c.available ? XCircle : MinusCircle;
                    const color = c.validated ? "text-emerald-500" : c.available ? "text-rose-500" : "text-slate-300";
                    return (
                      <li key={c.method} className="flex items-start gap-2 text-sm">
                        <Icon size={15} className={`mt-0.5 shrink-0 ${color}`} />
                        <span className="text-slate-600">
                          <span className="font-medium text-slate-700">{c.label}</span>
                          {c.available && (
                            <span className="text-xs text-slate-400"> — {c.cve_count} CVE, score {c.score}</span>
                          )}
                          <span className="block text-xs text-slate-400">{c.reason}</span>
                        </span>
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}

            {needsConfig && (
              <div className="mt-3 flex items-center gap-2 rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-sm font-medium text-amber-700">
                <Lock size={15} /> Configuration Required — cette API nécessite une authentification pour collecter.
              </div>
            )}

            {source.authentication_required && (
              <div className="mt-4 rounded-xl border border-slate-100 bg-slate-50 p-3">
                <p className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
                  <KeyRound size={14} /> Authentification
                </p>
                {source.api_key_configured ? (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-emerald-600">✓ Secret configuré (chiffré, jamais affiché)</span>
                    <button onClick={handleDeleteCredential} className="rounded-lg p-2 text-rose-500 hover:bg-rose-50" title="Supprimer">
                      <Trash2 size={16} />
                    </button>
                  </div>
                ) : (
                  <form onSubmit={handleSaveCredential} className="space-y-3">
                    <div>
                      <label className="mb-1 block text-sm font-medium text-slate-600">Type d'authentification</label>
                      <select
                        value={cred.auth_type}
                        onChange={(e) => setCred({ ...cred, auth_type: e.target.value })}
                        className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100"
                      >
                        {AUTH_TYPES.map((t) => (
                          <option key={t.value} value={t.value}>
                            {t.label}
                          </option>
                        ))}
                      </select>
                    </div>
                    {cred.auth_type === "basic" && (
                      <div>
                        <label className="mb-1 block text-sm font-medium text-slate-600">Nom d'utilisateur</label>
                        <input
                          value={cred.username}
                          onChange={(e) => setCred({ ...cred, username: e.target.value })}
                          className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100"
                        />
                      </div>
                    )}
                    <div>
                      <label className="mb-1 block text-sm font-medium text-slate-600">
                        {cred.auth_type === "api_key" ? "Clé API" : cred.auth_type === "basic" ? "Mot de passe" : "Token"}
                      </label>
                      <input
                        required
                        type="password"
                        value={cred.secret}
                        onChange={(e) => setCred({ ...cred, secret: e.target.value })}
                        placeholder="Stocké chiffré, jamais renvoyé"
                        className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm font-mono focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100"
                      />
                    </div>
                    <Button type="submit" className="px-3 py-1.5 text-xs">
                      Enregistrer le secret
                    </Button>
                  </form>
                )}
              </div>
            )}
          </Card>

          {/* Informations éditables */}
          <Card className="p-6">
            <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-500">Informations</h2>
            <form onSubmit={handleSave} className="space-y-4">
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
                  type="url"
                  value={form.url}
                  onChange={(e) => setForm({ ...form, url: e.target.value })}
                  className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100"
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-600">Description</label>
                <textarea
                  rows={2}
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100"
                />
              </div>
              <div className="flex items-center gap-3 pt-2">
                <Button type="submit">Enregistrer</Button>
                {saved && <span className="text-sm text-emerald-600">Enregistré ✓</span>}
              </div>
            </form>

            <div className="mt-6 flex flex-wrap gap-2 border-t border-slate-100 pt-4">
              <Button variant="secondary" onClick={handleTestConnection} disabled={testing}>
                <Wifi size={16} /> {testing ? "Test en cours…" : "Tester la connexion"}
              </Button>
              {(source.status === "validated" || source.status === "disabled") && (
                <Button variant="secondary" onClick={handleToggleStatus}>
                  {source.status === "validated" ? "Désactiver la collecte" : "Activer la collecte"}
                </Button>
              )}
              <Button variant="secondary" onClick={handleTrigger}>
                <RefreshCw size={16} /> Relancer la collecte
              </Button>
            </div>

            {testResult && (
              <p className={`mt-3 rounded-lg px-3 py-2 text-sm ${testResult.success ? "bg-emerald-50 text-emerald-700" : "bg-rose-50 text-rose-700"}`}>
                {testResult.message}
                {testResult.latency_ms != null && ` (${testResult.latency_ms} ms)`}
              </p>
            )}
            {triggerMsg && <p className="mt-3 rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700">{triggerMsg}</p>}
          </Card>
        </div>

        <div className="space-y-4">
          <Card className="p-6">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">Vérification</h2>
              <Button variant="secondary" onClick={handleVerify} disabled={verifying} className="px-3 py-1.5 text-xs">
                <ShieldCheck size={14} /> {verifying ? "…" : "Relancer"}
              </Button>
            </div>

            {!verification || !verification.admin_indicators ? (
              <p className="text-sm text-slate-400">
                Aucune vérification effectuée. Cliquez sur « Relancer » pour lancer l'agent.
              </p>
            ) : (
              <>
                <AdminVerification verification={verification} />
                {source.status === "pending" && (
                  <div className="mt-4 flex justify-end gap-2 border-t border-slate-100 pt-4">
                    <Button variant="danger" onClick={() => decide("rejected")} className="px-3 py-1.5 text-xs">
                      Refuser
                    </Button>
                    <Button onClick={() => decide("validated")} className="px-3 py-1.5 text-xs">
                      Valider
                    </Button>
                  </div>
                )}
              </>
            )}
          </Card>
        </div>
      </div>

      <div className="mt-4 flex items-center justify-between">
        <Button variant="ghost" onClick={() => navigate("/admin/sources")}>
          ← Retour à la liste
        </Button>
        <Button variant="danger" onClick={handleDeleteSource}>
          <Trash2 size={16} /> Supprimer la source
        </Button>
      </div>
    </Layout>
  );
}
