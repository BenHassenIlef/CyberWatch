import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { UserPlus } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import Button from "../../components/ui/Button";

const LABELS = {
  admin: "Administrateur",
  consultant: "Consultant",
};

const EMPTY_FORM = { full_name: "", email: "", password: "" };

export default function SignUp({ role }) {
  const { signup } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState(EMPTY_FORM);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await signup({ ...form, role });
      navigate(`/${role}`);
    } catch (err) {
      setError(err.response?.data?.detail || "Impossible de créer le compte");
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
          <h1 className="relative text-xl font-bold text-white">Créer un compte {LABELS[role]}</h1>
          <p className="relative mt-1 text-sm text-white/80">CyberWatch AI</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 p-8">
          {error && <p className="rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-600">{error}</p>}
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-600">Nom complet</label>
            <input
              required
              value={form.full_name}
              onChange={(e) => setForm({ ...form, full_name: e.target.value })}
              className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-600">E-mail</label>
            <input
              required
              type="email"
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
              minLength={6}
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm focus:border-brand-400 focus:outline-none focus:ring-4 focus:ring-brand-100"
            />
          </div>

          <Button type="submit" className="w-full" disabled={loading}>
            <UserPlus size={16} /> {loading ? "Création…" : "Créer le compte"}
          </Button>

          <p className="pt-2 text-center text-sm text-slate-500">
            Déjà un compte ?{" "}
            <Link to={`/${role}/signin`} className="font-semibold text-brand-600 hover:underline">
              Se connecter
            </Link>
          </p>
        </form>
      </div>
    </div>
  );
}
