import { CheckCircle2, XCircle } from "lucide-react";
import { DECISION_STYLES } from "../../pages/admin/sourceConstants";

// Vérification admin simplifiée : 3 indicateurs (URL fiable / contient des CVE / publie aujourd'hui).
function Indicator({ ok, label }) {
  return (
    <li className="flex items-center gap-3 rounded-xl border border-slate-100 px-4 py-3">
      {ok ? (
        <CheckCircle2 size={20} className="shrink-0 text-emerald-500" />
      ) : (
        <XCircle size={20} className="shrink-0 text-rose-500" />
      )}
      <span className={`text-sm font-medium ${ok ? "text-slate-700" : "text-slate-500"}`}>{label}</span>
    </li>
  );
}

export default function AdminVerdict({ verification }) {
  const ind = verification.admin_indicators || {};
  const cveLabel = ind.contains_cve
    ? `La source contient des CVE (${ind.cve_count})`
    : "La source contient des CVE";

  return (
    <div className="space-y-4">
      {verification.decision && (
        <div className="flex items-center justify-between">
          <span className="text-sm font-semibold uppercase tracking-wide text-slate-500">Verdict</span>
          <span className={`rounded-full px-3 py-1 text-sm font-semibold ${DECISION_STYLES[verification.decision]}`}>
            {verification.decision}
          </span>
        </div>
      )}

      <ul className="space-y-2">
        <Indicator ok={!!ind.url_reliable} label="URL valide et fiable" />
        <Indicator ok={!!ind.contains_cve} label={cveLabel} />
        <Indicator ok={!!ind.publishes_today} label="La source publie des CVE aujourd'hui (source active)" />
      </ul>
    </div>
  );
}
