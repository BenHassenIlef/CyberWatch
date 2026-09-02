import { CheckCircle2, XCircle, MinusCircle } from "lucide-react";
import { DECISION_STYLES } from "../../pages/admin/sourceConstants";

// Ligne d'indicateur à 3 états (réussi / échoué / indéterminé), avec détail optionnel.
function Row({ state, label, detail }) {
  let Icon = MinusCircle;
  let color = "text-amber-500";
  let text = "text-slate-500";
  if (state === true) {
    Icon = CheckCircle2;
    color = "text-emerald-500";
    text = "text-slate-700";
  } else if (state === false) {
    Icon = XCircle;
    color = "text-rose-500";
    text = "text-slate-600";
  }
  return (
    <li className="text-sm">
      <div className="flex items-center gap-2">
        <Icon size={16} className={`shrink-0 ${color}`} />
        <span className={text}>{label}</span>
      </div>
      {detail && <p className="ml-6 mt-0.5 text-xs text-slate-400">{detail}</p>}
    </li>
  );
}

const CONCLUSIONS = {
  FIABLE: "Cette source est fiable, active et peut être utilisée pour alimenter automatiquement la plateforme de veille cyber.",
  "À SURVEILLER": "Cette source présente des points à surveiller avant d'être utilisée pour alimenter la plateforme.",
  "NON FIABLE": "Cette source n'est pas suffisamment fiable pour alimenter la plateforme de veille cyber.",
};

// Affichage de vérification admin simplifié : uniquement les informations utiles à la décision.
export default function AdminVerification({ verification }) {
  const ind = verification.admin_indicators || {};
  const tech = verification.technical?.checks || [];
  const cred = verification.credibility?.checks || [];
  const auth = verification.authenticity;
  const authChecks = auth?.checks || [];
  const alertes = auth?.alertes || [];

  const techFind = (kw) => tech.find((c) => c.label.toLowerCase().includes(kw));
  const credFind = (kw) => cred.find((c) => c.label.toLowerCase().includes(kw));

  const urlAccessible = techFind("accessible");
  const httpsCheck = techFind("https") || techFind("sécuris");
  const contentCheck = techFind("contenu");
  const urlProvided = techFind("renseign");

  const officialCheck = credFind("officielle");
  const reputationCheck = credFind("réputation");
  const cvePresenceCheck = credFind("identifiant cve");

  const whitelisted = reputationCheck?.passed === true; // « liste blanche »

  return (
    <div className="space-y-6">
      {/* En-tête : date + verdict */}
      <div className="flex items-center justify-between">
        <div>
          {verification.verified_at && (
            <p className="text-xs text-slate-400">
              Vérifié le {new Date(verification.verified_at).toLocaleString("fr-FR")}
            </p>
          )}
          <p className="mt-1 text-sm font-semibold uppercase tracking-wide text-slate-500">Verdict</p>
        </div>
        {verification.decision && (
          <span className={`rounded-full px-3 py-1 text-sm font-semibold ${DECISION_STYLES[verification.decision]}`}>
            {verification.decision}
          </span>
        )}
      </div>

      {/* Résumé */}
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Résumé</h3>
        <ul className="space-y-2 rounded-xl border border-slate-100 bg-slate-50 px-4 py-3">
          <Row state={!!urlAccessible?.passed} label="URL valide et accessible" />
          <Row state={officialCheck ? officialCheck.passed : null} label="Domaine officiel reconnu" />
          <Row state={whitelisted} label="Domaine présent dans la liste blanche" />
          <Row state={!!httpsCheck?.passed} label="Connexion sécurisée (HTTPS/TLS)" />
          <Row state={!!ind.contains_cve} label="La source contient des CVE" />
          {auth && (
            <Row
              state={auth.usurpation ? false : alertes.length ? null : true}
              label={
                auth.usurpation
                  ? "Lien authentique — usurpation détectée"
                  : alertes.length
                  ? `Lien authentique — ${alertes.length} point${alertes.length > 1 ? "s" : ""} de vigilance`
                  : "Lien authentique (aucun indice de contrefaçon)"
              }
            />
          )}
        </ul>
      </div>

      {/* Usurpation : signalée séparément, car ce n’est pas une nuance de score */}
      {auth?.usurpation && (
        <div className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3">
          <p className="text-sm font-semibold text-rose-700">Lien potentiellement contrefait</p>
          <p className="mt-1 text-sm text-rose-600">
            Cette adresse présente les caractéristiques d’une usurpation de source officielle.
            Elle ne doit pas alimenter la veille sans vérification auprès de l’organisme concerné.
          </p>
          <ul className="mt-2 space-y-1">
            {alertes.map((a, i) => (
              <li key={i} className="text-xs text-rose-700">• {a}</li>
            ))}
          </ul>
        </div>
      )}
      {!auth?.usurpation && alertes.length > 0 && (
        <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3">
          <p className="text-sm font-semibold text-amber-700">Points de vigilance sur l’adresse</p>
          <p className="mt-1 text-xs text-amber-700">
            Aucun ne suffit à conclure à une contrefaçon ; ensemble, ils justifient un examen.
          </p>
          <ul className="mt-2 space-y-1">
            {alertes.map((a, i) => (
              <li key={i} className="text-xs text-amber-800">• {a}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Score global uniquement */}
      <div className="flex items-center gap-3">
        <span className="text-3xl font-bold text-slate-800">{verification.overall_score}</span>
        <span className="text-sm text-slate-500">Score global / 100</span>
      </div>

      {/* Conclusion */}
      {verification.decision && (
        <div>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Conclusion</h3>
          <p className="text-sm text-slate-600">{CONCLUSIONS[verification.decision]}</p>
        </div>
      )}

      {/* Détails — Niveau 1 : technique */}
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
          Niveau 1 — Vérification technique
        </h3>
        <ul className="space-y-2">
          <Row state={urlProvided ? urlProvided.passed : null} label="URL renseignée" />
          <Row state={urlAccessible ? urlAccessible.passed : null} label="URL accessible (HTTP 200)" />
          <Row state={httpsCheck ? httpsCheck.passed : null} label="Connexion sécurisée (HTTPS/TLS)" />
          <Row state={contentCheck ? contentCheck.passed : null} label="Contenu compatible avec la méthode de collecte" />
        </ul>
      </div>

      {/* Détails — Niveau 2 : crédibilité */}
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
          Niveau 2 — Vérification de crédibilité
        </h3>
        <ul className="space-y-2">
          <Row state={officialCheck ? officialCheck.passed : null} label="Domaine d'une organisation officielle reconnue" />
          <Row state={whitelisted} label="Domaine présent dans la liste blanche" />
          <Row state={!!ind.contains_cve} label="Présence de CVE" />
        </ul>
      </div>

      {/* Détails — Niveau 3 : authenticité du lien */}
      {authChecks.length > 0 && (
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
            Niveau 3 — Authenticité du lien
          </h3>
          <ul className="space-y-2">
            {authChecks.map((c, i) => (
              <Row key={i} state={c.passed} label={c.label} detail={c.detail} />
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
