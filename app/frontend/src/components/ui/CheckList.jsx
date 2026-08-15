import { CheckCircle2, XCircle, MinusCircle } from "lucide-react";

// Rend une liste de contrôles à 3 états : réussi (vert), échoué (rouge), indéterminé (ambre).
export default function CheckList({ checks }) {
  return (
    <ul className="space-y-2">
      {checks.map((item, i) => {
        let Icon = MinusCircle;
        let color = "text-amber-500";
        let textColor = "text-slate-500";
        if (item.passed === true) {
          Icon = CheckCircle2;
          color = "text-emerald-500";
          textColor = "text-slate-700";
        } else if (item.passed === false) {
          Icon = XCircle;
          color = "text-rose-500";
          textColor = "text-slate-600";
        }
        return (
          <li key={i} className="flex items-start gap-2 text-sm">
            <Icon size={16} className={`mt-0.5 shrink-0 ${color}`} />
            <span className={textColor}>
              {item.label}
              {item.detail && <span className="ml-1 text-xs text-slate-400">— {item.detail}</span>}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
