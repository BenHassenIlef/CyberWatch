export const SEVERITY_LABELS = {
  low: "Faible",
  medium: "Moyenne",
  high: "Élevée",
  critical: "Critique",
};

export const SEVERITY_STYLES = {
  low: "bg-slate-100 text-slate-600",
  medium: "bg-amber-100 text-amber-700",
  high: "bg-orange-100 text-orange-700",
  critical: "bg-rose-100 text-rose-700",
};

export const SEVERITY_OPTIONS = [
  { value: "critical", label: "Critique" },
  { value: "high", label: "Élevée" },
  { value: "medium", label: "Moyenne" },
  { value: "low", label: "Faible" },
];

export const EXPLOIT_STYLES = {
  "Aucun exploit connu": "bg-slate-100 text-slate-600",
  "PoC disponible": "bg-amber-100 text-amber-700",
  "Exploité activement": "bg-rose-100 text-rose-700",
};

// Options de tri de la liste des CVE.
export const SORT_OPTIONS = [
  { value: "date", label: "Date de publication" },
  { value: "cvss", label: "Score CVSS" },
];

// Accents (dégradés) des cartes de synthèse, cohérents avec la page Admin.
export const SEVERITY_ACCENTS = {
  total: "from-slate-500 to-slate-700",
  new: "from-brand-500 to-brand-700",
  critical: "from-rose-500 to-brand-700",
  high: "from-orange-400 to-orange-600",
};
