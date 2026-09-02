import { useEffect, useMemo, useState } from "react";
import { CalendarDays, Check, X } from "lucide-react";

// Sélecteur de PÉRIODE des bulletins par produit.
//
// Remplace l'ancienne « fenêtre : 45 jours », qui ne disait pas quels jours étaient couverts.
// Ici le consultant choisit une période et VOIT les dates qu'elle contient — toutes calculées
// à partir de la date du jour, jamais écrites en dur : le composant reste juste demain.
//
// Rien n'est appliqué avant « Appliquer » : « Annuler » laisse la période courante intacte.

const MS_JOUR = 86400000;

// Date locale au format AAAA-MM-JJ. `toISOString()` bascule en UTC et décalerait le jour
// pour tout fuseau à l'est de Greenwich — un bulletin « aujourd'hui » y perdrait sa journée.
export function versISO(d) {
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

const depuisISO = (s) => {
  const [a, m, j] = (s || "").split("-").map(Number);
  return a ? new Date(a, m - 1, j) : new Date();
};

const ajouter = (d, jours) => new Date(d.getTime() + jours * MS_JOUR);

// Lundi de la semaine courante (semaine ISO : la semaine commence le lundi).
function lundiDeLaSemaine(reference) {
  const d = new Date(reference);
  const decalage = (d.getDay() + 6) % 7;   // dimanche (0) -> 6
  return ajouter(d, -decalage);
}

// Bornes de chaque mode, calculées à l'instant de l'appel.
export function bornesDuMode(mode, aujourdhui = new Date()) {
  const jour = new Date(aujourdhui.getFullYear(), aujourdhui.getMonth(), aujourdhui.getDate());
  if (mode === "today") return { start: versISO(jour), end: versISO(jour) };
  if (mode === "last3") return { start: versISO(ajouter(jour, -2)), end: versISO(jour) };
  if (mode === "week") {
    const lundi = lundiDeLaSemaine(jour);
    return { start: versISO(lundi), end: versISO(ajouter(lundi, 6)) };
  }
  return null;   // « custom » : les bornes viennent de la saisie
}

function joursEntre(startISO, endISO) {
  const debut = depuisISO(startISO);
  const fin = depuisISO(endISO);
  const out = [];
  for (let d = debut; d <= fin && out.length < 40; d = ajouter(d, 1)) out.push(new Date(d));
  return out;
}

const LONG = { weekday: "long", day: "numeric", month: "long", year: "numeric" };
const COURT = { day: "2-digit", month: "2-digit", year: "numeric" };

export const formatCourt = (iso) => depuisISO(iso).toLocaleDateString("fr-FR", COURT);

// Libellé affiché sur le bouton d'ouverture.
export function libellePeriode(start, end, aujourdhui = new Date()) {
  for (const [mode, texte] of [["today", "Aujourd'hui"], ["last3", "3 derniers jours"],
                               ["week", "Cette semaine"]]) {
    const b = bornesDuMode(mode, aujourdhui);
    if (b && b.start === start && b.end === end) return texte;
  }
  return `${formatCourt(start)} → ${formatCourt(end)}`;
}

const OPTIONS = [
  { mode: "today", titre: "Aujourd'hui" },
  { mode: "last3", titre: "3 derniers jours" },
  { mode: "week", titre: "Cette semaine" },
];

export default function PeriodPicker({ start, end, onApply }) {
  const [ouvert, setOuvert] = useState(false);
  const [mode, setMode] = useState("last3");
  const [debut, setDebut] = useState(start);
  const [fin, setFin] = useState(end);

  // À chaque ouverture, le formulaire repart de la période RÉELLEMENT appliquée : une
  // sélection abandonnée la fois précédente ne doit pas resurgir.
  useEffect(() => {
    if (!ouvert) return;
    const trouve = OPTIONS.find((o) => {
      const b = bornesDuMode(o.mode);
      return b.start === start && b.end === end;
    });
    setMode(trouve ? trouve.mode : "custom");
    setDebut(start);
    setFin(end);
  }, [ouvert, start, end]);

  const bornesChoisies = useMemo(
    () => (mode === "custom" ? { start: debut, end: fin } : bornesDuMode(mode)),
    [mode, debut, fin]
  );

  const inverse = bornesChoisies.start > bornesChoisies.end;
  const jours = inverse ? [] : joursEntre(bornesChoisies.start, bornesChoisies.end);

  const appliquer = () => {
    if (inverse) return;
    onApply(bornesChoisies);
    setOuvert(false);
  };

  return (
    <>
      <button
        type="button"
        onClick={() => setOuvert(true)}
        className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm
                   font-medium text-slate-700 transition hover:border-brand-300 focus:outline-none
                   focus:ring-4 focus:ring-brand-100"
        title="Choisir la période du bulletin"
      >
        <CalendarDays size={16} className="text-brand-600" />
        Période : {libellePeriode(start, end)}
      </button>

      {ouvert && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4"
          onClick={() => setOuvert(false)}
        >
          <div
            className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-base font-semibold text-slate-800">
                <CalendarDays size={18} className="text-brand-600" /> Sélectionner la période
              </h2>
              <button type="button" onClick={() => setOuvert(false)}
                      className="text-slate-400 hover:text-slate-600" aria-label="Fermer">
                <X size={18} />
              </button>
            </div>

            <div className="space-y-2">
              {OPTIONS.map((o) => (
                <label key={o.mode}
                       className={`flex cursor-pointer items-center gap-3 rounded-xl border p-3 transition
                                   ${mode === o.mode ? "border-brand-400 bg-brand-50" : "border-slate-200 hover:border-slate-300"}`}>
                  <input type="radio" name="periode" checked={mode === o.mode}
                         onChange={() => setMode(o.mode)} className="accent-brand-600" />
                  <span className="text-sm font-medium text-slate-700">{o.titre}</span>
                </label>
              ))}

              <label className={`flex cursor-pointer items-center gap-3 rounded-xl border p-3 transition
                                 ${mode === "custom" ? "border-brand-400 bg-brand-50" : "border-slate-200 hover:border-slate-300"}`}>
                <input type="radio" name="periode" checked={mode === "custom"}
                       onChange={() => setMode("custom")} className="accent-brand-600" />
                <span className="text-sm font-medium text-slate-700">Période personnalisée</span>
              </label>

              {mode === "custom" && (
                <div className="grid grid-cols-2 gap-3 rounded-xl bg-slate-50 p-3">
                  <label className="text-xs font-medium text-slate-500">
                    Du
                    <input type="date" value={debut} onChange={(e) => setDebut(e.target.value)}
                           className="mt-1 w-full rounded-lg border border-slate-200 px-2 py-1.5 text-sm" />
                  </label>
                  <label className="text-xs font-medium text-slate-500">
                    Au
                    <input type="date" value={fin} onChange={(e) => setFin(e.target.value)}
                           className="mt-1 w-full rounded-lg border border-slate-200 px-2 py-1.5 text-sm" />
                  </label>
                </div>
              )}
            </div>

            {/* Jours RÉELLEMENT couverts — le consultant vérifie d'un coup d'œil. */}
            <div className="mt-4 max-h-44 overflow-y-auto rounded-xl border border-slate-100 bg-slate-50 p-3">
              {inverse ? (
                <p className="text-sm text-rose-600">
                  La date de début est postérieure à la date de fin.
                </p>
              ) : (
                <>
                  <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
                    {jours.length} jour(s) couvert(s)
                  </p>
                  <ul className="space-y-1">
                    {jours.map((d) => (
                      <li key={d.toISOString()} className="flex items-center gap-2 text-sm text-slate-600">
                        <Check size={14} className="text-emerald-500" />
                        {d.toLocaleDateString("fr-FR", LONG)}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>

            <div className="mt-5 flex justify-end gap-2">
              <button type="button" onClick={() => setOuvert(false)}
                      className="rounded-xl border border-slate-200 px-4 py-2 text-sm font-medium
                                 text-slate-600 transition hover:bg-slate-50">
                Annuler
              </button>
              <button type="button" onClick={appliquer} disabled={inverse}
                      className="rounded-xl bg-brand-600 px-4 py-2 text-sm font-semibold text-white
                                 transition hover:bg-brand-700 disabled:cursor-not-allowed disabled:opacity-50">
                Appliquer
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
