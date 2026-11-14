import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { useAuth } from "../auth/AuthContext";
import { BrandMark } from "../components/ui/BrandMark";
import { StepUpProvider } from "../components/ui/StepUp";
import { bank } from "../services/bank";

export interface NavItem { to: string; label: string; end?: boolean }

const LINK = "whitespace-nowrap rounded-lg px-3 py-1.5 text-sm font-semibold";

/** Cadre commun des espaces authentifiés : marque, navigation par profil, déconnexion. */
export function AppShell({ space, nav, notifications = false }: { space: string; nav: NavItem[]; notifications?: boolean }) {
  const { auth, signOut } = useAuth();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const navRef = useRef<HTMLElement>(null);
  // Écran étroit : les onglets défilent horizontalement ; on garde l'onglet actif visible
  useEffect(() => {
    navRef.current?.querySelector('[aria-current="page"]')?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [pathname, auth.status]);
  const unread = useQuery({
    queryKey: ["notifications", "unread"], enabled: notifications, refetchInterval: 20_000,
    queryFn: async () => (await bank.notifications()).filter((n) => !n.read).length,
  });
  if (auth.status !== "authenticated") return null;
  const me = auth.me;

  return (
    <StepUpProvider>
      <div className="min-h-screen">
        <header className="border-b border-rule bg-paper">
          {/* Rangée 1 : marque et compte ; rangée 2 : onglets sur une seule ligne, défilants sur écran étroit */}
          <div className="mx-auto max-w-6xl px-5">
            <div className="flex items-center justify-between gap-4 py-3">
              <div className="flex min-w-0 items-center gap-3">
                <BrandMark className="h-9 w-9 shrink-0" />
                <div className="min-w-0 leading-tight">
                  <p className="truncate font-bold tracking-tight">RL EXPRESS BANK</p>
                  <p className="truncate text-xs text-ink-soft">{space}</p>
                </div>
              </div>
              <div className="flex shrink-0 items-center gap-3 text-sm">
                {notifications && (
                  <NavLink to="/espace/notifications" className={`${LINK} flex items-center hover:bg-mist`}>
                    {/* Petit écran : cloche seule, le libellé reste lu par les lecteurs d'écran */}
                    <svg aria-hidden="true" viewBox="0 0 24 24" className="h-5 w-5 sm:hidden" fill="none" stroke="currentColor"
                      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" /><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" />
                    </svg>
                    <span className="sr-only sm:not-sr-only">Notifications</span>
                    {unread.data ? <span className="ml-1 rounded-full bg-laterite px-2 py-0.5 text-xs text-white">{unread.data}</span> : null}
                  </NavLink>
                )}
                <span className="hidden text-ink-soft sm:inline">{me.user.first_name} {me.user.last_name}</span>
                <button type="button" className="rounded-lg border border-ink px-3 py-1.5 font-semibold hover:bg-mist"
                  onClick={() => void signOut().then(() => navigate("/connexion", { replace: true }))}>
                  Quitter
                </button>
              </div>
            </div>
            <nav ref={navRef} aria-label="Navigation principale"
              className="-mx-5 flex gap-1 overflow-x-auto px-5 pb-3 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
              {nav.map((item) => (
                <NavLink key={item.to} to={item.to} end={item.end}
                  className={({ isActive }) => `${LINK} shrink-0 ${isActive ? "bg-ink text-white" : "hover:bg-mist"}`}>
                  {item.label}
                </NavLink>
              ))}
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-5 py-6"><Outlet /></main>
      </div>
    </StepUpProvider>
  );
}

export const CLIENT_NAV: NavItem[] = [
  { to: "/espace", label: "Comptes", end: true },
  { to: "/espace/virements", label: "Virements" },
  { to: "/espace/cartes", label: "Cartes et paiements" },
  { to: "/espace/retraits", label: "Retraits" },
  { to: "/espace/securite", label: "Sécurité" },
  { to: "/espace/aide", label: "RL SOLUTION" },
];
