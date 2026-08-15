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

// Rapport de vérification à deux niveaux (technique + crédibilité) + verdict enrichi.
export default function VerificationReport({ verification }) {
  const technical = verification.technical?.checks || [];
  const credibility = verification.credibility?.checks || [];
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

      <div className="grid grid-cols-3 gap-3">
        <ScoreBadge label="Technique" score={verification.technical_score} />
        <ScoreBadge label="Crédibilité" score={verification.credibility_score} />
        <ScoreBadge label="Global" score={verification.overall_score} />
      </div>

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
    </div>
  );
}
