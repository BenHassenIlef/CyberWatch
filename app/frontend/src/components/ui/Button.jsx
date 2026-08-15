const VARIANTS = {
  primary:
    "bg-gradient-to-r from-brand-600 to-brand-700 text-white shadow-glow hover:from-brand-500 hover:to-brand-600 hover:-translate-y-0.5 hover:shadow-glow-lg",
  secondary: "bg-white text-brand-700 border border-brand-200 hover:bg-brand-50 hover:-translate-y-0.5",
  danger: "bg-rose-600 text-white shadow-md shadow-rose-900/20 hover:bg-rose-500 hover:-translate-y-0.5",
  ghost: "text-slate-600 hover:bg-slate-100",
};

export default function Button({ variant = "primary", className = "", children, ...props }) {
  return (
    <button
      className={`inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold transition-all duration-200 active:scale-[0.97] disabled:opacity-50 disabled:pointer-events-none disabled:hover:translate-y-0 ${VARIANTS[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}
