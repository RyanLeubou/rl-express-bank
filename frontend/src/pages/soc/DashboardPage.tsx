import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { Badge, Empty, PageTitle, Panel, Select, Stat, Table, Td } from "../../components/ui/kit";
import { SEVERITY_LABEL, dateTime } from "../../lib/format";
import { staff } from "../../services/staff";

function Bars({ items }: { items: { label: string; value: number }[] }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className="space-y-2">
      {items.map((i) => (
        <li key={i.label} className="grid grid-cols-[9rem_1fr_3rem] items-center gap-3 text-sm">
          <span className="truncate">{i.label}</span>
          <span className="h-3 rounded bg-mist"><span className="block h-3 rounded bg-lagoon" style={{ width: `${(i.value / max) * 100}%` }} /></span>
          <span className="tabular text-right font-semibold">{i.value}</span>
        </li>
      ))}
    </ul>
  );
}

export function DashboardPage() {
  const [hours, setHours] = useState(24);
  const stats = useQuery({ queryKey: ["soc-stats", hours], queryFn: () => staff.stats(hours), refetchInterval: 15_000 });
  const latest = useQuery({ queryKey: ["soc-latest"], queryFn: () => staff.alerts({ limit: 8 }), refetchInterval: 15_000 });
  const s = stats.data;
  return (
    <>
      <PageTitle sub="Vue d'ensemble de la détection et de la réponse automatisée.">Tableau de bord SOC</PageTitle>
      <div className="mb-4 w-48"><Select aria-label="Période" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
        <option value={1}>Dernière heure</option><option value={24}>24 heures</option><option value={168}>7 jours</option><option value={720}>30 jours</option>
      </Select></div>
      {s && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Stat label="Alertes ouvertes" value={s.open_alerts} tone={s.open_alerts ? "warn" : undefined} />
          <Stat label="Opérations bloquées" value={s.blocked_operations} tone={s.blocked_operations ? "bad" : undefined} />
          <Stat label="Alertes critiques" value={s.alerts_by_severity.CRITICAL ?? 0} tone={(s.alerts_by_severity.CRITICAL ?? 0) ? "bad" : undefined} />
          <Stat label="Événements" value={Object.values(s.events_by_category).reduce((a, b) => a + b, 0)} />
        </div>
      )}
      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <Panel title="Règles les plus déclenchées">
          {s?.top_rules.length ? <Bars items={s.top_rules.map((r) => ({ label: r.code, value: r.count }))} /> : <Empty>Aucune règle déclenchée.</Empty>}
        </Panel>
        <Panel title="Décisions de la politique">
          {s && Object.keys(s.decisions).length ? <Bars items={Object.entries(s.decisions).map(([k, v]) => ({ label: k, value: v }))} /> : <Empty>Aucune évaluation.</Empty>}
        </Panel>
        <Panel title="Alertes par sévérité">
          {s && Object.keys(s.alerts_by_severity).length
            ? <Bars items={Object.entries(s.alerts_by_severity).map(([k, v]) => ({ label: SEVERITY_LABEL[k] ?? k, value: v }))} />
            : <Empty>Aucune alerte.</Empty>}
        </Panel>
        <Panel title="Événements par catégorie">
          {s && Object.keys(s.events_by_category).length
            ? <Bars items={Object.entries(s.events_by_category).map(([k, v]) => ({ label: k, value: v }))} /> : <Empty>Aucun événement.</Empty>}
        </Panel>
      </div>
      <Panel title="Dernières alertes" className="mt-5" action={<Link to="/soc/alertes" className="text-sm font-semibold text-lagoon underline">Toutes les alertes</Link>}>
        {!latest.data?.length ? <Empty>Aucune alerte.</Empty> : (
          <Table head={["Date", "Alerte", "Cible", "Score", "Sévérité", "Statut"]}>
            {latest.data.map((a) => (
              <tr key={a.id}>
                <Td className="whitespace-nowrap text-ink-soft">{dateTime(a.created_at)}</Td>
                <Td><Link className="font-semibold underline" to={`/soc/alertes/${a.id}`}>{a.title}</Link></Td>
                <Td>{a.user_label ?? "—"}</Td><Td className="tabular">{a.risk_score ?? "—"}</Td>
                <Td><Badge value={a.severity} kind="severity" /></Td><Td><Badge value={a.status} /></Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
