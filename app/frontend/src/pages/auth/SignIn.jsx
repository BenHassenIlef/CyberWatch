import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { LogIn } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import Button from "../../components/ui/Button";

const LABELS = {
  admin: "Administrateur",
  consultant: "Consultant",
};

const OTHER_ROLE = {
  admin: "consultant",
  consultant: "admin",
};

export default function SignIn({ role }) {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    // L'auto-remplissage du gestionnaire de mots de passe (Chrome, Edge…) peut renseigner les
    // champs sans déclencher onChange : l'état React resterait vide et on enverrait un mot de
    // passe vide (401). On lit donc les valeurs directement dans le formulaire à l'envoi.
    const email = (e.target.elements.email?.value || form.email).trim();
    const password = e.target.elements.password?.value || form.password;
    try {
      await login(email, password, role);
      navigate(`/${role}`);
    } catch (err) {
      if (!err.response) {
        // Pas de réponse HTTP du tout : serveur arrêté ou blocage réseau, pas un souci
        // d'identifiants — on le dit clairement au lieu du message trompeur « invalides ».
        setError("Serveur injoignable — vérifiez que le backend tourne sur le port 8000.");
      } else if (err.response.status === 401) {
        setError(`Identifiants invalides pour un compte ${LABELS[role]}.`);
      } else {
        setError(err.response.data?.detail || "Connexion impossible");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-md overflow-hidden rounded-3xl bg-white shadow-glow-lg">
        <div className="relative overflow-hidden bg-gradient-to-br from-brand-500 via-brand-600 to-brand-800 px-8 py-8 text-center">
          <div className="pointer-events-none absolute -right-10 -top-10 h-40 w-40 rounded-full bg-white/10" />
          <div className="pointer-events-none absolute -bottom-16 -left-10 h-48 w-48 rounded-full bg-white/5" />
          <div className="relative mx-auto mb-3 inline-flex items-center justify-center rounded-2xl bg-white px-4 py-2.5 shadow-lg">
            <img src="/logo-advancia.png" alt="Advancia" className="h-6 w-auto" />
          </div>
          <h1 className="relative text-xl font-bold text-white">Connexion {LABELS[role]}</h1>
          <p className="relative mt-1 text-sm text-white/80">CyberWatch AI</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 p-8">
          {error && <p className="rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-600">{error}</p>}
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-600">E-mail</label>
            <input
              required
              type="email"
              name="email"
              autoComplete="username"
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
              className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-600">Mot de passe</label>
            <input
              required
              type="password"
              name="password"
              autoComplete="current-password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100"
            />
          </div>

          <Button type="submit" className="w-full" disabled={loading}>
            <LogIn size={16} /> {loading ? "Connexion…" : "Se connecter"}
          </Button>

          <p className="pt-2 text-center text-sm text-slate-500">
            Pas encore de compte ?{" "}
            <Link to={`/${role}/signup`} className="font-semibold text-brand-600 hover:underline">
              Créer un compte
            </Link>
          </p>

          {/* Un compte n'existe que pour un seul rôle : se tromper de page renvoie « identifiants
              invalides » alors que le mot de passe est bon. D'où ce renvoi explicite. */}
          <p className="text-center text-sm text-slate-500">
            Vous êtes {LABELS[OTHER_ROLE[role]]} ?{" "}
            <Link
              to={`/${OTHER_ROLE[role]}/signin`}
              className="font-semibold text-brand-600 hover:underline"
            >
              Connexion {LABELS[OTHER_ROLE[role]]}
            </Link>
          </p>
        </form>
      </div>
    </div>
  );
}
