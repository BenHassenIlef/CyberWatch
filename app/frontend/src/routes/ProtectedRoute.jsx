import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function ProtectedRoute({ role, children }) {
  const { user } = useAuth();

  if (!user) {
    return <Navigate to={`/${role}/signin`} replace />;
  }
  if (user.role !== role) {
    return <Navigate to={`/${user.role}`} replace />;
  }
  return children;
}
