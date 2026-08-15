import { NavLink, useNavigate } from "react-router-dom";
import { LogOut } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import Avatar from "./ui/Avatar";

export default function Layout({ role, homeLabel, navItems, children }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate(`/${role}/signin`);
  };

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-64 shrink-0 flex-col border-r border-slate-200/70 bg-white">
        <div className="px-6 py-5">
          <img src="/logo-advancia.png" alt="Advancia" className="h-12 w-auto" />
          <p className="mt-2 text-sm font-bold text-slate-800 leading-tight">CyberWatch AI</p>
          <p className="text-xs text-slate-400 leading-tight">{homeLabel}</p>
        </div>

        <nav className="flex-1 space-y-1 px-3 py-2">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-all duration-150 ${
                  isActive
                    ? "bg-gradient-to-r from-brand-600 to-brand-700 text-white shadow-glow"
                    : "text-slate-600 hover:translate-x-0.5 hover:bg-brand-50 hover:text-brand-700"
                }`
              }
            >
              <item.icon size={18} />
              <span className="flex-1">{item.label}</span>
              {item.badge > 0 && (
                <span className="ml-auto inline-flex h-5 min-w-[1.25rem] items-center justify-center rounded-full bg-brand-600 px-1.5 text-xs font-semibold text-white">
                  {item.badge > 99 ? "99+" : item.badge}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-slate-100 px-4 py-4">
          {/* Bloc utilisateur cliquable : raccourci vers « Mon profil » (nom + photo). */}
          <NavLink
            to={`/${role}/profile`}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-xl px-2 py-2 transition-colors ${
                isActive ? "bg-brand-50" : "hover:bg-slate-50"
              }`
            }
          >
            <Avatar src={user?.avatar_url} name={user?.full_name} size={36} />
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold text-slate-700">{user?.full_name}</p>
              <p className="truncate text-xs text-slate-400">{user?.email}</p>
            </div>
          </NavLink>
          <button
            onClick={handleLogout}
            className="mt-3 flex w-full items-center gap-2 rounded-xl px-3 py-2 text-sm font-medium text-rose-600 transition-colors hover:bg-rose-50"
          >
            <LogOut size={16} />
            Déconnexion
          </button>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto p-8">{children}</main>
    </div>
  );
}
