export default function Table({ columns, rows, emptyLabel = "Aucune donnée" }) {
  return (
    <div className="overflow-x-auto rounded-2xl border border-slate-200/70 bg-white shadow-lg shadow-slate-900/[0.04]">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-slate-100 bg-slate-50/80 text-xs uppercase tracking-wide text-slate-500">
            {columns.map((col) => (
              <th key={col.key} className="px-5 py-3 font-semibold">
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {rows.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-5 py-8 text-center text-slate-400">
                {emptyLabel}
              </td>
            </tr>
          )}
          {rows.map((row, i) => (
            <tr key={row.id || i} className="transition-colors hover:bg-brand-50/60">
              {columns.map((col) => (
                <td key={col.key} className="px-5 py-3.5 text-slate-700">
                  {col.render ? col.render(row) : row[col.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
