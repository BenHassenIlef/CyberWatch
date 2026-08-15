import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import api from "../api/axios";

// Contexte des notifications Consultant : nombre de nouvelles CVE non consultées (badge).
// Isolé à l'espace Consultant — n'affecte en rien l'interface Admin.
const NotificationsContext = createContext({ unreadCount: 0, refresh: () => {}, markAllRead: async () => {} });

const POLL_MS = 30000;

export function NotificationsProvider({ children }) {
  const [unreadCount, setUnreadCount] = useState(0);
  const timer = useRef(null);

  const refresh = useCallback(async () => {
    try {
      const { data } = await api.get("/consultant/notifications/count");
      setUnreadCount(data.count || 0);
    } catch {
      /* silencieux : le badge n'est pas critique */
    }
  }, []);

  const markAllRead = useCallback(async () => {
    await api.post("/consultant/notifications/read");
    setUnreadCount(0);
  }, []);

  useEffect(() => {
    refresh();
    timer.current = setInterval(refresh, POLL_MS);
    return () => clearInterval(timer.current);
  }, [refresh]);

  return (
    <NotificationsContext.Provider value={{ unreadCount, refresh, markAllRead }}>
      {children}
    </NotificationsContext.Provider>
  );
}

export function useNotifications() {
  return useContext(NotificationsContext);
}
