import { createContext, useContext, useState, useCallback } from "react";
import api from "../api/axios";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const raw = localStorage.getItem("cyberwatch_user");
    return raw ? JSON.parse(raw) : null;
  });

  const persist = (token, user) => {
    localStorage.setItem("cyberwatch_token", token);
    localStorage.setItem("cyberwatch_user", JSON.stringify(user));
    localStorage.setItem("cyberwatch_role", user.role);
    setUser(user);
  };

  const login = useCallback(async (email, password, role) => {
    const { data } = await api.post("/auth/login", { email, password, role });
    persist(data.access_token, data.user);
    return data.user;
  }, []);

  const signup = useCallback(async (payload) => {
    const { data } = await api.post("/auth/signup", payload);
    persist(data.access_token, data.user);
    return data.user;
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem("cyberwatch_token");
    localStorage.removeItem("cyberwatch_user");
    localStorage.removeItem("cyberwatch_role");
    setUser(null);
  }, []);

  // Rafraîchit l'utilisateur en session après modification du profil (nom / photo), sans
  // toucher au token : la sidebar et le widget de chat se mettent à jour immédiatement.
  const updateUser = useCallback((updated) => {
    localStorage.setItem("cyberwatch_user", JSON.stringify(updated));
    setUser(updated);
  }, []);

  return (
    <AuthContext.Provider value={{ user, login, signup, logout, updateUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
