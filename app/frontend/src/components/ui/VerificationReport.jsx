import { ShieldAlert, ShieldCheck } from "lucide-react";
import CheckList from "./CheckList";
import { COLLECTION_METHOD_LABELS, AUTH_TYPE_LABELS, DECISION_STYLES, CONFIDENCE_STYLES } from "../../pages/admin/sourceConstants";

function ScoreBadge({ label, score }) {
  const color = score >= 70 ? "text-emerald-600" : score >= 40 ? "text-amber-600" : "text-rose-600";
  return (
    <div className="rounded-xl border border-slate-100 bg-slate-50 px-4 py-3 text-center">
      <div className={`text-2xl font-bold ${color}`}>{score}</div>
      <div className="text-xs text-slate-500">{label}</div>
    </div>
  );
}

function detectionAuthText(detection) {
  if (!detection?.authentication_required) return "Aucune";
  const type = detection.authentication_type ? AUTH_TYPE_LABELS[detection.authentication_type] : "Authentification";
  return `${type} requise`;
}

// Bandeau d'authenticité : un lien contrefait est un problème d'une autre nature qu'un score
// faible, et il ne doit pas se lire comme une nuance au milieu d'une liste de contrôles.
function AuthenticityBanner({ authenticity }) {
  const alertes = authenticity?.alertes || [];
  if (authenticity?.usurpation) {
    return (
      <div className="flex items-start gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3">
        <ShieldAlert size={20} className="mt-0.5 shrink-0 text-rose-600" />
        <div>
          <p className="text-sm font-semibold text-rose-700">Lien potentiellement contrefait</p>
          <p className="mt-1 text-sm text-rose-600">
            Cette adresse présente les caractéristiques d’une usurpation. Elle ne doit pas alimenter
            la veille sans vérification humaine auprès de l’organisme concerné.
          </p>
          <ul className="mt-2 space-y-1">
            {alertes.map((a, i) => (
              <li key={i} className="text-xs text-rose-700">• {a}</li>
            ))}
          </ul>
        </div>
      </div>
    );
  }
  if (alertes.length) {
    return (
      <div className="flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3">
        <ShieldAlert size={20} className="mt-0.5 shrink-0 text-amber-600" />
        <div>
          <p className="text-sm font-semibold text-amber-700">
            {alertes.length} point{alertes.length > 1 ? "s" : ""} de vigilance sur l’adresse
          </p>
          <p className="mt-1 text-xs text-amber-700">
            Aucun ne suffit à conclure à une contrefaçon ; ensemble, ils justifient un examen.
          </p>
          <ul className="mt-2 space-y-1">
            {alertes.map((a, i) => (
              <li key={i} className="text-xs text-amber-800">• {a}</li>
            ))}
          </ul>
        </div>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-3 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3">
      <ShieldCheck size={20} className="shrink-0 text-emerald-600" />
      <p className="text-sm text-emerald-700">
        Aucun indice de contrefaçon : le domaine n’imite aucune source officielle et ne présente
        aucun procédé de dissimulation.
      </p>
    </div>
  );
}

// Rapport de vérification à trois niveaux (technique + crédibilité + authenticité) + verdict.
export default function VerificationReport({ verification }) {
  const technical = verification.technical?.checks || [];
  const credibility = verification.credibility?.checks || [];
  const authenticity = verification.authenticity;
  const detection = verification.detection;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-4xl font-bold text-slate-800">{verification.overall_score}</span>
          <span className="text-sm text-slate-500">
            Score global
            <br />
            sur 100
          </span>
        </div>
        <div className="text-right">
          {verification.decision && (
            <span className={`rounded-full px-3 py-1 text-sm font-semibold ${DECISION_STYLES[verification.decision]}`}>
              {verification.decision}
            </span>
          )}
          {verification.confidence_level && (
            <p className={`mt-1 text-xs font-semibold ${CONFIDENCE_STYLES[verification.confidence_level]}`}>
              Confiance : {verification.confidence_level}
            </p>
          )}
        </div>
      </div>

      {verification.summary && (
        <p className="rounded-xl border border-slate-100 bg-slate-50 px-4 py-3 text-sm text-slate-600">
          {verification.summary}
        </p>
      )}

      <div className="grid grid-cols-4 gap-3">
        <ScoreBadge label="Technique" score={verification.technical_score} />
        <ScoreBadge label="Crédibilité" score={verification.credibility_score} />
        <ScoreBadge label="Authenticité" score={verification.authenticity_score} />
        <ScoreBadge label="Global" score={verification.overall_score} />
      </div>

      {authenticity && <AuthenticityBanner authenticity={authenticity} />}

      {detection && (
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div className="rounded-xl border border-slate-100 bg-white px-4 py-3">
            <p className="text-xs uppercase tracking-wide text-slate-400">Collection Method</p>
            <p className="mt-1 font-semibold text-slate-700">
              {COLLECTION_METHOD_LABELS[detection.collection_method] || detection.collection_method}
            </p>
          </div>
          <div className="rounded-xl border border-slate-100 bg-white px-4 py-3">
            <p className="text-xs uppercase tracking-wide text-slate-400">Authentication</p>
            <p className={`mt-1 font-semibold ${detection.authentication_required ? "text-amber-600" : "text-slate-700"}`}>
              {detectionAuthText(detection)}
            </p>
          </div>
        </div>
      )}

      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
          Niveau 1 — Vérification technique
        </h3>
        <CheckList checks={technical} />
      </div>

      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
          Niveau 2 — Vérification de crédibilité
        </h3>
        <CheckList checks={credibility} />
      </div>

      {authenticity?.checks?.length > 0 && (
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
            Niveau 3 — Authenticité du lien
          </h3>
          <CheckList checks={authenticity.checks} />
        </div>
      )}
    </div>
  );
}
