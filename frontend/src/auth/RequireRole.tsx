import { Navigate, Outlet } from "react-router";
import { useAuth } from "./AuthContext";

export type Space = "client" | "soc" | "admin" | "audit" | "agent";

const HOME: Record<Space, string> = { client: "/espace", soc: "/soc", admin: "/admin", audit: "/audit", agent: "/agent" };
const ROLE_SPACE: [string, Space][] = [
  ["SUPER_ADMIN", "admin"], ["SECURITY_ANALYST", "soc"], ["AUDITOR", "audit"], ["SUPPORT_AGENT", "agent"], ["CLIENT", "client"],
];

export function spaceFor(roles: string[]): Space {
  return ROLE_SPACE.find(([role]) => roles.includes(role))?.[1] ?? "client";
}

/** Garde de confort : renvoie chacun vers son espace. L'API reste seule juge des droits. */
export function RequireRole({ space }: { space: Space }) {
  const { auth } = useAuth();
  if (auth.status !== "authenticated") return null;
  const mine = spaceFor(auth.me.user.roles);
  return mine === space ? <Outlet /> : <Navigate to={HOME[mine]} replace />;
}
