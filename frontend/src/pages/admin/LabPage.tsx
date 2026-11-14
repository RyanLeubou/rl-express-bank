import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Btn, Empty, ErrorLine, PageTitle, Panel, Table, Td } from "../../components/ui/kit";
import { dateTime } from "../../lib/format";
import { toApiError } from "../../services/api";
import { staff } from "../../services/staff";

export function LabPage() {
  const qc = useQueryClient();
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: staff.scenarios });
  const runs = useQuery({ queryKey: ["runs"], queryFn: staff.runs });
  const launch = useMutation({ mutationFn: staff.launch, onSuccess: () => void qc.invalidateQueries({ queryKey: ["runs"] }) });
  return (
    <>
      <PageTitle sub="Attaques simulées sur données de démonstration. Les événements sont marqués « simulation » et n'affectent pas les profils de comportement.">Laboratoire d'attaques</PageTitle>
      <ErrorLine message={launch.error ? toApiError(launch.error).message : null} />
      <Panel title="Scénarios" className="mt-3">
        {!scenarios.data?.length ? <Empty>Aucun scénario (mode laboratoire désactivé ?).</Empty> : (
          <ul className="divide-y divide-rule">
            {scenarios.data.map((s) => (
              <li key={s.id} className="flex items-center justify-between gap-4 py-3">
                <div><p className="font-mono text-sm font-semibold">{s.id}</p><p className="text-sm text-ink-soft">{s.description}</p></div>
                <Btn disabled={launch.isPending} onClick={() => launch.mutate(s.id)}>Lancer</Btn>
              </li>
            ))}
          </ul>
        )}
      </Panel>
      <Panel title="Dernières exécutions" className="mt-5">
        {!runs.data?.length ? <Empty>Aucune exécution.</Empty> : (
          <Table head={["Date", "Scénario", "Statut", "Alertes", "Bloquées"]}>
            {runs.data.map((r) => (
              <tr key={r.id}><Td>{dateTime(r.started_at)}</Td><Td className="font-mono text-xs">{r.scenario}</Td><Td><Badge value={r.status} /></Td>
                <Td className="tabular">{r.summary?.alerts ?? "—"}</Td><Td className="tabular">{r.summary?.blocked ?? "—"}</Td></tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
