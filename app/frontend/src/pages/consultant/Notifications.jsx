import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Bell, RefreshCw, CheckCheck, MailWarning, MailCheck, Send } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Card from "../../components/ui/Card";
import Button from "../../components/ui/Button";
import api from "../../api/axios";
import { useConsultantNavItems } from "./navItems";
import { useNotifications } from "../../context/NotificationsContext";
import { SEVERITY_LABELS, SEVERITY_STYLES } from "./cveConstants";

const fmtDateTime = (d) => (d ? new Date(d).toLocaleString("fr-FR") : "");

function BoutonEssai({ onClick, enCours }) {
  return (
    <button onClick={onClick} disabled={enCours}
      className="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:opacity-50">
      <Send size={13} />
      {enCours ? "Envoi en cours…" : "Envoyer un message d’essai"}
    </button>
  );
}

function ResultatEssai({ essai }) {
  if (!essai) return null;
  return (
    <p className={`mt-2 rounded-lg px-3 py-2 text-xs ${
      essai.envoye ? "bg-emerald-100 text-emerald-800" : "bg-rose-100 text-rose-800"}`}>
      {essai.detail}
    </p>
  );
}

export default function ConsultantNotifications() {
  const navItems = useConsultantNavItems();
  const navigate = useNavigate();
  const { refresh, markAllRead } = useNotifications();
  const [items, setItems] = useState(null);
  const [courriel, setCourriel] = useState(null);
  const [essai, setEssai] = useState(null);      // resultat du dernier essai de remise
  const [essaiEnCours, setEssaiEnCours] = useState(false);

  const load = async () => {
    const { data } = await api.get("/consultant/notifications");
    setItems(data.items);
  };

  // ETAT DE LA REMISE PAR COURRIEL. Un consultant qui ne recoit rien n'avait aucun moyen
  // de savoir pourquoi : le diagnostic n'existait que dans les journaux du serveur. Il en
  // concluait a une panne, alors qu'il manque le plus souvent une seule ligne de
  // configuration — et personne ne s'en apercevait tant que rien ne l'affichait.
  const chargerEtatCourriel = async () => {
    try {
      const { data } = await api.get("/consultant/notifications/email-status");
      setCourriel(data);
    } catch {
      setCourriel(null);   // l'etat est un complement : son absence ne casse pas la page
    }
  };

  useEffect(() => {
    load();
    chargerEtatCourriel();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleMarkAll = async () => {
    await markAllRead();
    load();
  };

  // ESSAI DE REMISE : valider la configuration sans attendre la collecte du lendemain.
  // Le message part vers SA PROPRE adresse — jamais une adresse saisie, ce qui ferait de
  // ce bouton un relais d'envoi vers un tiers.
  const testerEnvoi = async () => {
    setEssaiEnCours(true);
    setEssai(null);
    try {
      const { data } = await api.post("/consultant/notifications/email-test");
      setEssai(data);
      chargerEtatCourriel();
    } catch (e) {
      setEssai({ envoye: false, detail: e?.response?.data?.detail || "L'essai n'a pas abouti." });
    } finally {
      setEssaiEnCours(false);
    }
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

      {/* Pourquoi vous ne recevez pas (ou recevez) la veille par courriel. */}
      {courriel && !courriel.operationnel && (
        <div className="mb-4 flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3">
          <MailWarning size={20} className="mt-0.5 shrink-0 text-amber-600" />
          <div className="text-sm">
            <p className="font-semibold text-amber-800">
              Les notifications par courriel ne peuvent pas être envoyées
            </p>
            <p className="mt-1 text-amber-700">{courriel.detail}</p>
            <p className="mt-1.5 text-xs text-amber-700">
              Les alertes restent visibles ici, dans l’application. Signalez ce point à votre
              administrateur : la correction se fait dans la configuration du serveur.
            </p>
            <BoutonEssai onClick={testerEnvoi} enCours={essaiEnCours} />
            <ResultatEssai essai={essai} />
          </div>
        </div>
      )}
      {courriel?.operationnel && courriel.je_suis_destinataire && (
        <div className="mb-4 flex items-center gap-3 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-2.5 text-sm">
          <MailCheck size={18} className="shrink-0 text-emerald-600" />
          <div className="flex-1">
            <p className="text-emerald-800">
              La veille quotidienne vous est envoyée à <b>{courriel.mon_adresse}</b>.
            </p>
            <ResultatEssai essai={essai} />
          </div>
          <BoutonEssai onClick={testerEnvoi} enCours={essaiEnCours} />
        </div>
      )}
      {courriel?.operationnel && !courriel.je_suis_destinataire && (
        <div className="mb-4 flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm">
          <MailWarning size={20} className="mt-0.5 shrink-0 text-amber-600" />
          <p className="text-amber-800">
            L’envoi par courriel fonctionne, mais <b>votre adresse ne figure pas</b> parmi les
            destinataires de la veille quotidienne. Demandez à votre administrateur de vous y ajouter.
          </p>
        </div>
      )}

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
              <Card className={`flex items-center gap-4 p-4 ${
                n.type === "update" ? "border-l-4 border-l-amber-400" : ""}`}>
                {/* Repere visuel distinct : une mise a jour et une decouverte n appellent
                    pas la meme lecture — l une concerne une fiche deja traitee. */}
                <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full ${
                  n.type === "update" ? "bg-amber-50 text-amber-600" : "bg-brand-50 text-brand-600"}`}>
                  {n.type === "update" ? <RefreshCw size={18} /> : <Bell size={18} />}
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

                  {/* CE QUI A CHANGE. « Mise a jour de CVE » seul n aide pas : un score
                      reevalue, un correctif paru et une exploitation confirmee n appellent
                      pas la meme reaction. Les valeurs sont restituees telles qu elles ont
                      change, jamais interpretees. */}
                  {n.type === "update" && (n.changes || []).length > 0 && (
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      {n.changes.map((c, i) => (
                        <span key={i}
                              className="rounded-md bg-amber-50 px-2 py-0.5 text-[11px] font-medium text-amber-800">
                          {c}
                        </span>
                      ))}
                    </div>
                  )}
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
