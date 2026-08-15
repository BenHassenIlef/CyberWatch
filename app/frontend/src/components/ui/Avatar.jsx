// Photo de profil de l'utilisateur, avec repli sur ses initiales quand aucune image n'est définie.
function initials(name) {
  const parts = (name || "").split(/\s+/).filter(Boolean).slice(0, 2);
  return parts.map((part) => part[0].toUpperCase()).join("") || "?";
}

export default function Avatar({ src, name, size = 40, className = "" }) {
  const style = { width: size, height: size };

  if (src) {
    return (
      <img
        src={src}
        alt={name || "Photo de profil"}
        style={style}
        className={`shrink-0 rounded-full object-cover ring-2 ring-white shadow-sm ${className}`}
      />
    );
  }

  return (
    <span
      style={{ ...style, fontSize: Math.round(size * 0.38) }}
      className={`inline-flex shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-brand-600 to-brand-700 font-semibold text-white ring-2 ring-white shadow-sm ${className}`}
      aria-hidden="true"
    >
      {initials(name)}
    </span>
  );
}
