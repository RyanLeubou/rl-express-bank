import { useQuery } from "@tanstack/react-query";
import { Badge, Empty, PageTitle, Panel, Table, Td } from "../../components/ui/kit";
import { dateTime } from "../../lib/format";
import { staff } from "../../services/staff";

export function AssessmentsPage() {
  const rows = useQuery({ queryKey: ["assessments"], queryFn: () => staff.assessments({ limit: 100 }), refetchInterval: 15_000 });
  return (
    <>
      <PageTitle sub="Chaque opération sensible est évaluée par des règles explicables. Le score IA reste vide tant qu'aucun modèle n'est branché.">Évaluations de risque</PageTitle>
      <Panel>
        {!rows.data?.length ? <Empty>Aucune évaluation.</Empty> : (
          <Table head={["Date", "Opération", "Score", "Niveau", "Décision", "Raisons", "IA"]}>
            {rows.data.map((r) => (
              <tr key={r.id}><Td className="whitespace-nowrap text-ink-soft">{dateTime(r.created_at)}</Td><Td className="font-mono text-xs">{r.operation}</Td>
                <Td className="tabular font-bold">{r.score}</Td><Td><Badge value={r.level} kind="severity" /></Td><Td>{r.decision}</Td>
                <Td className="text-xs text-ink-soft">{r.reasons.map((x) => `${x.code} ${x.points > 0 ? "+" : ""}${x.points}`).join(", ")}</Td>
                <Td className="text-xs text-ink-soft">{r.ai_score ?? "—"}</Td></tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
