import { useRef, useState } from "react";
import { Camera, Save, Trash2 } from "lucide-react";
import Layout from "../../components/Layout";
import PageHeader from "../../components/ui/PageHeader";
import Card from "../../components/ui/Card";
import Button from "../../components/ui/Button";
import Avatar from "../../components/ui/Avatar";
import api from "../../api/axios";
import { useAuth } from "../../context/AuthContext";
import { fileToAvatarDataUrl, MAX_UPLOAD_BYTES } from "./avatarImage";

const ROLE_LABELS = { admin: "Administrateur", consultant: "Consultant" };

// Extrait un message lisible d'une erreur FastAPI (detail = chaîne OU liste d'erreurs de validation).
function errorMessage(error) {
  const detail = error.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return detail[0].msg;
  return "Échec de l'enregistrement. Réessayez.";
}

// Page « Mon profil », partagée par l'admin et le consultant : modification du nom et de la photo.
export default function Profile({ role, homeLabel, navItems }) {
  const { user, updateUser } = useAuth();
  const fileInput = useRef(null);

  const [fullName, setFullName] = useState(user?.full_name ?? "");
  const [avatar, setAvatar] = useState(user?.avatar_url ?? null);
  const [status, setStatus] = useState(null);
  const [saving, setSaving] = useState(false);

  const trimmedName = fullName.trim();
  const dirty = trimmedName !== (user?.full_name ?? "") || avatar !== (user?.avatar_url ?? null);
  const canSave = dirty && trimmedName.length >= 2 && !saving;

  const handleFile = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = ""; // permet de resélectionner le même fichier après annulation
    if (!file) return;

    if (!file.type.startsWith("image/")) {
      setStatus({ type: "error", message: "Choisissez un fichier image (PNG, JPEG ou WebP)." });
      return;
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      setStatus({ type: "error", message: "Image trop lourde (5 Mo maximum)." });
      return;
    }

    try {
      setAvatar(await fileToAvatarDataUrl(file));
      setStatus(null);
    } catch (error) {
      setStatus({ type: "error", message: error.message });
    }
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSaving(true);
    setStatus(null);
    try {
      const { data } = await api.patch("/auth/me", { full_name: trimmedName, avatar_url: avatar });
      updateUser(data);
      setFullName(data.full_name);
      setAvatar(data.avatar_url ?? null);
      setStatus({ type: "ok", message: "Profil mis à jour." });
    } catch (error) {
      setStatus({ type: "error", message: errorMessage(error) });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Layout role={role} homeLabel={homeLabel} navItems={navItems}>
      <PageHeader title="Mon profil" subtitle="Modifier votre nom et votre photo" />

      <Card className="max-w-2xl p-8">
        <form onSubmit={handleSubmit} className="space-y-8">
          <div className="flex items-center gap-6">
            <Avatar src={avatar} name={trimmedName || user?.full_name} size={96} />

            <div className="space-y-3">
              <div className="flex flex-wrap gap-2">
                <Button type="button" variant="secondary" onClick={() => fileInput.current?.click()}>
                  <Camera size={16} /> {avatar ? "Changer la photo" : "Ajouter une photo"}
                </Button>
                {avatar && (
                  <Button type="button" variant="ghost" onClick={() => setAvatar(null)}>
                    <Trash2 size={16} /> Retirer
                  </Button>
                )}
              </div>
              <p className="text-xs text-slate-400">
                PNG, JPEG ou WebP — 5 Mo maximum. L'image est recadrée en carré et réduite à 256 px.
              </p>
              <input
                ref={fileInput}
                type="file"
                accept="image/png,image/jpeg,image/webp"
                onChange={handleFile}
                className="hidden"
              />
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label htmlFor="full_name" className="mb-1.5 block text-sm font-medium text-slate-700">
                Nom complet
              </label>
              <input
                id="full_name"
                type="text"
                value={fullName}
                onChange={(event) => setFullName(event.target.value)}
                maxLength={120}
                className="w-full rounded-xl border border-slate-200 px-4 py-2.5 text-sm text-slate-800 outline-none transition-colors focus:border-brand-500 focus:ring-2 focus:ring-brand-100"
              />
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-700">E-mail</label>
              <input
                type="text"
                value={user?.email ?? ""}
                readOnly
                disabled
                className="w-full cursor-not-allowed rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-sm text-slate-500"
              />
              <p className="mt-1.5 text-xs text-slate-400">
                L'e-mail sert d'identifiant de connexion et n'est pas modifiable ici.
              </p>
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-700">Rôle</label>
              <input
                type="text"
                value={ROLE_LABELS[user?.role] ?? user?.role ?? ""}
                readOnly
                disabled
                className="w-full cursor-not-allowed rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-sm text-slate-500"
              />
            </div>
          </div>

          {status && (
            <p
              className={`rounded-xl px-4 py-3 text-sm ${
                status.type === "ok" ? "bg-emerald-50 text-emerald-700" : "bg-rose-50 text-rose-700"
              }`}
            >
              {status.message}
            </p>
          )}

          <div className="flex items-center gap-3 border-t border-slate-100 pt-6">
            <Button type="submit" disabled={!canSave}>
              <Save size={16} /> {saving ? "Enregistrement…" : "Enregistrer"}
            </Button>
            {dirty && !saving && (
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  setFullName(user?.full_name ?? "");
                  setAvatar(user?.avatar_url ?? null);
                  setStatus(null);
                }}
              >
                Annuler
              </Button>
            )}
          </div>
        </form>
      </Card>
    </Layout>
  );
}
