// Méthodes de collecte détectées automatiquement (l'admin ne les choisit plus).
export const COLLECTION_METHOD_LABELS = {
  api_public: "API publique",
  api_protected: "API protégée",
  rss: "Flux RSS",
  scraping: "Web Scraping",
};

// Libellé « famille » de la méthode (API / RSS / Web Scraping) pour le rapport.
export const METHOD_FAMILY_LABELS = {
  api_public: "API",
  api_protected: "API",
  rss: "RSS",
  scraping: "Web Scraping",
};

export function methodLabel(method) {
  return METHOD_FAMILY_LABELS[method] || COLLECTION_METHOD_LABELS[method] || method || "—";
}

// Libellé d'une méthode de repli (valeur stockée : "rss" | "scraping" | null).
export function backupLabel(backup) {
  if (!backup) return "—";
  return { api: "API", rss: "RSS", scraping: "Web Scraping" }[backup] || backup;
}

export const AUTH_TYPE_LABELS = {
  api_key: "API Key",
  bearer: "Bearer Token",
  basic: "Basic Auth",
  oauth: "OAuth Token",
};

export const AUTH_TYPES = [
  { value: "api_key", label: "API Key" },
  { value: "bearer", label: "Bearer Token" },
  { value: "basic", label: "Basic Auth" },
  { value: "oauth", label: "OAuth Token" },
];

// Libellé d'authentification affiché à côté de la méthode de collecte.
export function authLabel(source) {
  if (!source?.authentication_required) return "Aucune";
  const type = source.authentication_type ? AUTH_TYPE_LABELS[source.authentication_type] : "Authentification";
  return source.authentication_status === "configured" ? `${type} (configurée)` : `${type} requise`;
}

export const DECISION_STYLES = {
  FIABLE: "bg-emerald-100 text-emerald-700",
  "À SURVEILLER": "bg-amber-100 text-amber-700",
  "NON FIABLE": "bg-rose-100 text-rose-700",
};

export const CONFIDENCE_STYLES = {
  ÉLEVÉ: "text-emerald-600",
  MOYEN: "text-amber-600",
  FAIBLE: "text-rose-600",
};

export const SYNC_FREQUENCIES = [
  { value: "15min", label: "Toutes les 15 min" },
  { value: "1h", label: "Toutes les heures" },
  { value: "6h", label: "Toutes les 6 heures" },
  { value: "24h", label: "Une fois par jour" },
];

export const SOURCE_STATUS_LABELS = {
  pending: "En attente",
  validated: "Validée",
  rejected: "Rejetée",
  disabled: "Désactivée",
};

export const SOURCE_STATUS_STYLES = {
  pending: "bg-amber-100 text-amber-700",
  validated: "bg-emerald-100 text-emerald-700",
  rejected: "bg-rose-100 text-rose-700",
  disabled: "bg-slate-100 text-slate-500",
};
