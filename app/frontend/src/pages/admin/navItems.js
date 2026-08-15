import { KeyRound } from "lucide-react";

export const ADMIN_NAV_ITEMS = [{ to: "/admin/sources", label: "Sources", icon: KeyRound }];

// (La messagerie est désormais un widget flottant global, plus un item de navigation.)
export function useAdminNavItems() {
  return ADMIN_NAV_ITEMS;
}
