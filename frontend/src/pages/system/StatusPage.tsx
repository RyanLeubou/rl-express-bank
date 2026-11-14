import { useQuery } from "@tanstack/react-query";
import { BrandMark } from "../../components/ui/BrandMark";
import { StatementLine } from "../../components/ui/StatementLine";
import { fetchReadiness } from "../../services/health";

const SERVICES = [
  { key: "database", label: "Base de données", hint: "Comptes, opérations et journaux d'audit" },
  { key: "cache", label: "Cache de sécurité", hint: "Limitation des tentatives et challenges d'authentification" },
  { key: "worker", label: "Traitements en arrière-plan", hint: "Envoi des événements de sécurité et tâches planifiées" },
] as const;

const SUMMARY = {
  ok: { title: "Tous les services répondent.", tone: "border-ok" },
  degraded: { title: "La banque fonctionne, un service secondaire est arrêté.", tone: "border-saffron" },
  down: { title: "Un service indispensable ne répond pas.", tone: "border-laterite" },
} as const;

const ENVIRONMENTS = { development: "Développement", demo: "Démonstration", test: "Test" } as const;

export function StatusPage() {
  const { data, error, isFetching, refetch, dataUpdatedAt } = useQuery({
    queryKey: ["readiness"],
    queryFn: fetchReadiness,
    refetchInterval: 10_000,
  });

  const summary = data ? SUMMARY[data.status] : null;
  const checkedAt = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString("fr-FR", { timeZone: "Africa/Douala" })
    : null;

  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col px-5 py-10 sm:py-16">
      <header className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <BrandMark className="h-11 w-11" />
          <div>
            <p className="text-xl font-bold tracking-tight">RL EXPRESS BANK</p>
            <p className="text-sm text-ink-soft">Banque virtuelle</p>
          </div>
        </div>
        <div className="flex gap-2">
          <a href="/inscription" className="rounded-lg border border-lagoon px-4 py-2 text-sm font-semibold text-lagoon hover:bg-mist">
            Ouvrir un compte
          </a>
          <a href="/connexion" className="rounded-lg bg-lagoon px-4 py-2 text-sm font-semibold text-white hover:bg-lagoon-deep">
            Se connecter
          </a>
        </div>
      </header>

      <section aria-labelledby="statement-title" className="mt-12 rounded-2xl bg-paper px-6 py-7 shadow-[0_1px_0_#d5dfe2] sm:px-9">
        <div className="flex flex-wrap items-end justify-between gap-3 border-b-2 border-ink pb-4">
          <h1 id="statement-title" className="text-3xl font-bold leading-tight tracking-tight sm:text-4xl">
            Relevé d'état de la plateforme
          </h1>
          {checkedAt && <p className="tabular text-sm text-ink-soft">Relevé à {checkedAt}</p>}
        </div>

        {error && !data && (
          <p role="alert" className="mt-6 border-l-4 border-laterite pl-4">
            L'API ne répond pas. Vérifiez que les conteneurs tournent avec <code>docker compose ps</code>,
            puis relancez la vérification.
          </p>
        )}

        {summary && (
          <p role="status" className={`mt-6 border-l-4 pl-4 text-lg font-semibold ${summary.tone}`}>
            {summary.title}
          </p>
        )}

        {data && (
          <ul className="mt-2 divide-y divide-rule">
            {SERVICES.map((s) => (
              <StatementLine key={s.key} label={s.label} hint={s.hint}
                check={data.checks[s.key] ?? { status: "unknown" }} />
            ))}
          </ul>
        )}

        {data && (
          <dl className="mt-4 grid grid-cols-2 gap-4 border-t-2 border-ink pt-4 text-sm">
            <div>
              <dt className="text-ink-soft">Environnement</dt>
              <dd className="font-semibold">{ENVIRONMENTS[data.environment]}</dd>
            </div>
            <div>
              <dt className="text-ink-soft">Mode laboratoire</dt>
              <dd className="font-semibold">{data.lab_mode ? "Activé, simulations autorisées" : "Désactivé"}</dd>
            </div>
          </dl>
        )}

        <button type="button" onClick={() => refetch()} disabled={isFetching}
          className="mt-7 rounded-lg bg-lagoon px-5 py-2.5 font-semibold text-paper transition-colors hover:bg-lagoon-deep disabled:cursor-wait disabled:opacity-60">
          {isFetching ? "Vérification en cours" : "Vérifier maintenant"}
        </button>
      </section>

      <footer className="mt-auto pt-10 text-sm text-ink-soft">
        Projet universitaire de cybersécurité. Comptes, cartes, IBAN et opérations sont entièrement fictifs.
      </footer>
    </main>
  );
}
