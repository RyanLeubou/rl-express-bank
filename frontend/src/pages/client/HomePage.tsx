import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router";
import { useAuth } from "../../auth/AuthContext";
import { BrandMark } from "../../components/ui/BrandMark";
import { fetchSessions, revokeSession } from "../../services/auth";

const LEVELS: Record<number, string> = {
  1: "Mot de passe seul",
  2: "Mot de passe + second facteur",
};

const when = (iso: string) =>
  new Date(iso).toLocaleString("fr-FR", { timeZone: "Africa/Douala", dateStyle: "short", timeStyle: "short" });

/** Espace sécurisé provisoire : identité, niveau d'assurance et sessions. Les comptes arrivent en phase 6. */
export function HomePage() {
  const { auth, signOut } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const sessions = useQuery({ queryKey: ["sessions"], queryFn: fetchSessions });
  const revoke = useMutation({
    mutationFn: revokeSession,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["sessions"] }),
  });
  if (auth.status !== "authenticated") return null;
  const { me } = auth;

  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col px-5 py-10 sm:py-16">
      <header className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <BrandMark className="h-11 w-11" />
          <div>
            <p className="text-xl font-bold tracking-tight">RL EXPRESS BANK</p>
            <p className="text-sm text-ink-soft">Espace sécurisé</p>
          </div>
        </div>
        <button type="button" className="rounded-lg border border-ink px-4 py-2 text-sm font-semibold hover:bg-mist"
          onClick={() => void signOut().then(() => navigate("/connexion", { replace: true }))}>
          Se déconnecter
        </button>
      </header>

      <section aria-labelledby="who" className="mt-10 rounded-2xl bg-paper px-6 py-7 shadow-[0_1px_0_#d5dfe2]">
        <h1 id="who" className="border-b-2 border-ink pb-4 text-3xl font-bold tracking-tight">
          Bonjour {me.user.first_name}
        </h1>
        <dl className="mt-4 grid grid-cols-2 gap-4 text-sm">
          <div><dt className="text-ink-soft">Profil</dt><dd className="font-semibold">{me.user.roles.join(", ")}</dd></div>
          <div><dt className="text-ink-soft">Niveau d'authentification</dt>
            <dd className="font-semibold">{LEVELS[me.aal] ?? `Niveau ${me.aal}`}</dd></div>
          <div><dt className="text-ink-soft">Appareil</dt>
            <dd className="font-semibold">{me.device_trusted ? "De confiance" : "Non vérifié"}</dd></div>
          <div><dt className="text-ink-soft">Double authentification</dt>
            <dd className="font-semibold">{me.user.mfa_enabled ? "Activée" : "Non activée"}</dd></div>
        </dl>
      </section>

      <section aria-labelledby="sessions-title" className="mt-6 rounded-2xl bg-paper px-6 py-7 shadow-[0_1px_0_#d5dfe2]">
        <h2 id="sessions-title" className="border-b-2 border-ink pb-3 text-xl font-bold">Mes sessions actives</h2>
        {sessions.isPending && <p className="mt-4 text-ink-soft">Chargement…</p>}
        <ul className="mt-2 divide-y divide-rule">
          {sessions.data?.map((s) => (
            <li key={s.id} className="flex items-center justify-between gap-4 py-3">
              <div>
                <p className="font-semibold">{s.device ?? "Appareil inconnu"}{s.current && " (cette session)"}</p>
                <p className="tabular text-sm text-ink-soft">{s.ip ?? "IP inconnue"} · dernière activité {when(s.last_activity)}</p>
              </div>
              {!s.current && (
                <button type="button" disabled={revoke.isPending} onClick={() => revoke.mutate(s.id)}
                  className="rounded-lg border border-laterite px-3 py-1.5 text-sm font-semibold text-laterite hover:bg-mist">
                  Révoquer
                </button>
              )}
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}
