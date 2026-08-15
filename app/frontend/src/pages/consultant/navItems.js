import { Bug, Clock, Bell, FileText, Sparkles, Radar } from "lucide-react";
import { useNotifications } from "../../context/NotificationsContext";

export const CONSULTANT_NAV_ITEMS = [
  { to: "/consultant/cves", label: "CVE", icon: Bug },
  { to: "/consultant/product-bulletins", label: "Bulletins produit", icon: FileText },
  { to: "/consultant/monitoring", label: "Produits surveillés", icon: Radar },
  { to: "/consultant/assistant", label: "Assistant IA", icon: Sparkles },
  { to: "/consultant/notifications", label: "Notifications", icon: Bell },
  { to: "/consultant/schedule", label: "Planification", icon: Clock },
];

// Items de nav du consultant avec le badge « notifications » (la messagerie est un widget flottant).
export function useConsultantNavItems() {
  const { unreadCount } = useNotifications();
  return CONSULTANT_NAV_ITEMS.map((item) =>
    item.to === "/consultant/notifications" ? { ...item, badge: unreadCount } : item
  );
}
