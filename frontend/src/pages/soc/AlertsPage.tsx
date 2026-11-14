import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { Badge, Empty, PageTitle, Panel, Select, Table, Td } from "../../components/ui/kit";
import { dateTime } from "../../lib/format";
import { staff } from "../../services/staff";

export function AlertsPage() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const alerts = useQuery({
    queryKey: ["alerts", status, severity], refetchInterval: 15_000,
    queryFn: () => staff.alerts({ limit: 100, ...(status && { status }), ...(severity && { severity }) }),
  });
  return (
    <>
      <PageTitle sub="Alertes corrélées par client et par heure.">Alertes de sécurité</PageTitle>
      <div className="mb-4 flex flex-wrap gap-3">
        <div className="w-52"><Select aria-label="Statut" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">Tous les statuts</option>
          {["NEW", "TRIAGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].map((s) => <option key={s}>{s}</option>)}
        </Select></div>
        <div className="w-52"><Select aria-label="Sévérité" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">Toutes les sévérités</option>
          {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s}>{s}</option>)}
        </Select></div>
      </div>
      <Panel>
        {!alerts.data?.length ? <Empty>Aucune alerte pour ces filtres.</Empty> : (
          <Table head={["Date", "Alerte", "Cible", "Règles", "Score", "Sévérité", "Statut"]}>
            {alerts.data.map((a) => (
              <tr key={a.id}>
                <Td className="whitespace-nowrap text-ink-soft">{dateTime(a.created_at)}</Td>
                <Td><Link className="font-semibold underline" to={`/soc/alertes/${a.id}`}>{a.title}</Link></Td>
                <Td>{a.user_label ?? "—"}</Td>
                <Td className="text-xs text-ink-soft">{a.reasons.map((r) => r.code).join(", ")}</Td>
                <Td className="tabular">{a.risk_score ?? "—"}</Td>
                <Td><Badge value={a.severity} kind="severity" /></Td><Td><Badge value={a.status} /></Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
