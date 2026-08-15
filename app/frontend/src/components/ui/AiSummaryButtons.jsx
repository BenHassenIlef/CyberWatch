import { useNavigate } from "react-router-dom";
import { Sparkles, FileText, ScrollText, GitCompare } from "lucide-react";

// Boutons de résumé IA réutilisables (fiche CVE, bulletin CVE, bulletin produit, page Assistant).
// `subject` = libellé injecté dans la question (ex. « la vulnérabilité CVE-2026-1234 » ou
// « les vulnérabilités Microsoft »). `group` masque « Expliquer les changements » (multi-CVE).
export default function AiSummaryButtons({ subject, group = false, size = "md", className = "" }) {
  const navigate = useNavigate();

  const go = (q, mode) =>
    navigate(`/consultant/assistant?q=${encodeURIComponent(q)}&mode=${mode}`);

  const btn =
    size === "sm"
      ? "inline-flex items-center gap-1.5 rounded-lg border border-brand-200 bg-white px-2.5 py-1.5 text-xs font-medium text-brand-700 transition hover:bg-brand-50"
      : "inline-flex items-center gap-1.5 rounded-xl border border-brand-200 bg-white px-3 py-2 text-sm font-semibold text-brand-700 transition hover:bg-brand-50 hover:-translate-y-0.5";
  const ic = size === "sm" ? 13 : 16;

  return (
    <div className={`flex flex-wrap items-center gap-2 ${className}`}>
      <button className={btn} onClick={() => go(`Résume ${subject}`, "technical")}>
        <Sparkles size={ic} /> Résumer avec l'IA
      </button>
      <button className={btn} onClick={() => go(`Résumé exécutif : ${subject}`, "executive")}>
        <ScrollText size={ic} /> Résumé exécutif
      </button>
      <button className={btn} onClick={() => go(`Résumé technique : ${subject}`, "technical")}>
        <FileText size={ic} /> Résumé technique
      </button>
      {!group && (
        <button className={btn} onClick={() => go(`Explique les changements de ${subject}`, "changes")}>
          <GitCompare size={ic} /> Expliquer les changements
        </button>
      )}
    </div>
  );
}
