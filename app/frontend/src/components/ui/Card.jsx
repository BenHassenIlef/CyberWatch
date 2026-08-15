export default function Card({ className = "", children }) {
  return (
    <div className={`rounded-2xl border border-slate-200/70 bg-white shadow-lg shadow-slate-900/[0.04] ${className}`}>
      {children}
    </div>
  );
}
