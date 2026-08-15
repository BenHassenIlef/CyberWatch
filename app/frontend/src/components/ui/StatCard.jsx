export default function StatCard({ label, value, icon: Icon, accent = "from-brand-500 to-brand-700" }) {
  return (
    <div className="group min-w-0 rounded-2xl border border-slate-200/70 bg-white p-5 shadow-lg shadow-slate-900/[0.04] transition-all duration-200 hover:-translate-y-1 hover:shadow-xl">
      <div className="flex items-center gap-4">
        <div
          className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br ${accent} text-white shadow-md transition-transform duration-200 group-hover:scale-110`}
        >
          {Icon && <Icon size={20} />}
        </div>
        <div className="min-w-0 flex-1">
          <p className="truncate text-2xl font-bold text-slate-800" title={typeof value === "string" ? value : undefined}>
            {value}
          </p>
          <p className="truncate text-sm text-slate-500">{label}</p>
        </div>
      </div>
    </div>
  );
}
