import { Navigate, Outlet, useLocation } from "react-router";
import { useAuth } from "./AuthContext";

/**
 * Garde de navigation : simple confort d'affichage. Les droits réels sont vérifiés par l'API à chaque requête.
 */
export function RequireAuth() {
  const { auth } = useAuth();
  const location = useLocation();
  if (auth.status === "loading") {
    return <p role="status" className="p-10 text-center text-ink-soft">Vérification de votre session…</p>;
  }
  if (auth.status === "anonymous") {
    return <Navigate to="/connexion" replace state={{ from: location.pathname }} />;
  }
  return <Outlet />;
}
