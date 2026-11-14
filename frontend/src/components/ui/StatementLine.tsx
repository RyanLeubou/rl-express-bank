import type { HealthCheck } from "../../types/health";

const STATE = {
  ok: { label: "Opérationnel", tone: "text-ok" },
  down: { label: "Indisponible", tone: "text-laterite" },
  unknown: { label: "Inconnu", tone: "text-saffron" },
} as const;

function measure(check: HealthCheck): string {
  if (check.latency_ms !== undefined) return `${check.latency_ms.toLocaleString("fr-FR")} ms`;
  if (check.seconds_since_heartbeat !== undefined)
    return `signal il y a ${Math.round(check.seconds_since_heartbeat)} s`;
  return "";
}

/** Une ligne de relevé : libellé, points de conduite, état et mesure alignés à droite. */
export function StatementLine({ label, hint, check }: { label: string; hint: string; check: HealthCheck }) {
  const state = STATE[check.status] ?? STATE.unknown;
  return (
    <li className="py-4">
      <div className="flex items-baseline gap-3">
        <span className="font-medium">{label}</span>
        <span aria-hidden="true" className="min-w-8 flex-1 translate-y-[-3px] border-b border-dotted border-rule" />
        <span className={`font-semibold ${state.tone}`}>{state.label}</span>
      </div>
      <div className="mt-1 flex justify-between gap-4 text-sm text-ink-soft">
        <span>{hint}</span>
        <span className="tabular shrink-0">{measure(check)}</span>
      </div>
    </li>
  );
}
