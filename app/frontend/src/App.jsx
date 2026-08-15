import { Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./context/AuthContext";
import { NotificationsProvider } from "./context/NotificationsContext";
import ProtectedRoute from "./routes/ProtectedRoute";

import SignIn from "./pages/auth/SignIn";
import SignUp from "./pages/auth/SignUp";

import Sources from "./pages/admin/Sources";
import SourceNew from "./pages/admin/SourceNew";
import SourceDetail from "./pages/admin/SourceDetail";

import ConsultantCves from "./pages/consultant/Cves";
import ConsultantCveDetail from "./pages/consultant/CveDetail";
import ConsultantCveBulletin from "./pages/consultant/CveBulletin";
import ConsultantSchedule from "./pages/consultant/Schedule";
import ConsultantNotifications from "./pages/consultant/Notifications";
import ProductBulletins from "./pages/consultant/ProductBulletins";
import ProductBulletinDetail from "./pages/consultant/ProductBulletinDetail";
import Monitoring from "./pages/consultant/Monitoring";
import Assistant from "./pages/consultant/Assistant";
import ChatWidget from "./components/ChatWidget";

import Profile from "./pages/profile/Profile";
import { useAdminNavItems } from "./pages/admin/navItems";
import { useConsultantNavItems } from "./pages/consultant/navItems";

// Enveloppe une page Consultant protégée + le contexte des notifications (badge).
function ConsultantRoute({ children }) {
  return (
    <ProtectedRoute role="consultant">
      <NotificationsProvider>{children}</NotificationsProvider>
    </ProtectedRoute>
  );
}

// « Mon profil » est la même page pour les deux rôles ; seuls la nav et le libellé changent.
// Les items de nav venant de hooks, chaque rôle a son petit composant d'enveloppe.
function AdminProfile() {
  return <Profile role="admin" homeLabel="Espace Admin" navItems={useAdminNavItems()} />;
}

function ConsultantProfile() {
  return <Profile role="consultant" homeLabel="Espace Consultant" navItems={useConsultantNavItems()} />;
}

function RootRedirect() {
  const { user } = useAuth();
  if (!user) return <Navigate to="/admin/signin" replace />;
  return <Navigate to={`/${user.role}`} replace />;
}

export default function App() {
  const { user } = useAuth();
  return (
    <>
    <Routes>
      <Route path="/" element={<RootRedirect />} />

      <Route path="/admin/signin" element={<SignIn role="admin" />} />
      <Route path="/admin/signup" element={<SignUp role="admin" />} />
      <Route path="/consultant/signin" element={<SignIn role="consultant" />} />
      <Route path="/consultant/signup" element={<SignUp role="consultant" />} />

      {/* Admin — gestion des sources uniquement */}
      <Route path="/admin" element={<Navigate to="/admin/sources" replace />} />
      <Route path="/admin/dashboard" element={<Navigate to="/admin/sources" replace />} />
      <Route
        path="/admin/sources"
        element={
          <ProtectedRoute role="admin">
            <Sources />
          </ProtectedRoute>
        }
      />
      <Route
        path="/admin/sources/new"
        element={
          <ProtectedRoute role="admin">
            <SourceNew />
          </ProtectedRoute>
        }
      />
      <Route
        path="/admin/sources/:id"
        element={
          <ProtectedRoute role="admin">
            <SourceDetail />
          </ProtectedRoute>
        }
      />
      <Route
        path="/admin/profile"
        element={
          <ProtectedRoute role="admin">
            <AdminProfile />
          </ProtectedRoute>
        }
      />

      {/* Consultant — consultation des CVE uniquement */}
      <Route path="/consultant" element={<Navigate to="/consultant/cves" replace />} />
      <Route path="/consultant/cves" element={<ConsultantRoute><ConsultantCves /></ConsultantRoute>} />
      <Route path="/consultant/cves/:id" element={<ConsultantRoute><ConsultantCveDetail /></ConsultantRoute>} />
      <Route path="/consultant/cves/:id/bulletin" element={<ConsultantRoute><ConsultantCveBulletin /></ConsultantRoute>} />
      <Route path="/consultant/product-bulletins" element={<ConsultantRoute><ProductBulletins /></ConsultantRoute>} />
      <Route path="/consultant/product-bulletins/:vendor" element={<ConsultantRoute><ProductBulletinDetail /></ConsultantRoute>} />
      <Route path="/consultant/monitoring" element={<ConsultantRoute><Monitoring /></ConsultantRoute>} />
      <Route path="/consultant/notifications" element={<ConsultantRoute><ConsultantNotifications /></ConsultantRoute>} />
      <Route path="/consultant/schedule" element={<ConsultantRoute><ConsultantSchedule /></ConsultantRoute>} />
      <Route path="/consultant/assistant" element={<ConsultantRoute><Assistant /></ConsultantRoute>} />
      <Route path="/consultant/profile" element={<ConsultantRoute><ConsultantProfile /></ConsultantRoute>} />

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
    {user && <ChatWidget />}
    </>
  );
}
