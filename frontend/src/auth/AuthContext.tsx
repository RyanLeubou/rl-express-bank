import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from "react";
import { UNAUTHENTICATED_EVENT } from "../services/api";
import { fetchMe, logout as logoutRequest, type Me } from "../services/auth";

type AuthState =
  | { status: "loading"; me: null }
  | { status: "anonymous"; me: null }
  | { status: "authenticated"; me: Me };

interface AuthContextValue {
  auth: AuthState;
  /** À appeler après une connexion réussie : recharge l'identité depuis le serveur (source de vérité). */
  refreshIdentity: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);
const ME_KEY = ["auth", "me"] as const;

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const { data, isPending } = useQuery({
    queryKey: ME_KEY,
    queryFn: () => fetchMe().catch(() => null),   // 401 = visiteur anonyme, pas une erreur
    retry: false,
    staleTime: 60_000,
  });

  const clear = useCallback(() => {
    queryClient.setQueryData(ME_KEY, null);
    queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== "auth" && q.queryKey[0] !== "readiness" });
  }, [queryClient]);

  // Le client HTTP signale qu'aucun renouvellement n'est possible : on repasse en anonyme
  useEffect(() => {
    window.addEventListener(UNAUTHENTICATED_EVENT, clear);
    return () => window.removeEventListener(UNAUTHENTICATED_EVENT, clear);
  }, [clear]);

  const value = useMemo<AuthContextValue>(() => ({
    auth: isPending ? { status: "loading", me: null }
      : data ? { status: "authenticated", me: data } : { status: "anonymous", me: null },
    refreshIdentity: () => queryClient.invalidateQueries({ queryKey: ME_KEY }),
    signOut: async () => {
      try { await logoutRequest(); } finally { clear(); }
    },
  }), [data, isPending, queryClient, clear]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth doit être utilisé dans <AuthProvider>");
  return ctx;
}
