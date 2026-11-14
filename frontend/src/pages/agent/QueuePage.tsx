import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router";
import { Badge, Btn, Empty, ErrorLine, PageTitle, Panel, Table, Td } from "../../components/ui/kit";
import { dateTime } from "../../lib/format";
import { toApiError } from "../../services/api";
import { staff } from "../../services/staff";

export function QueuePage() {
  const qc = useQueryClient();
  const queue = useQuery({ queryKey: ["queue"], queryFn: staff.queue, refetchInterval: 10_000 });
  const accept = useMutation({ mutationFn: staff.accept, onSuccess: () => void qc.invalidateQueries({ queryKey: ["queue"] }) });
  return (
    <>
      <PageTitle sub="Vous n'accédez qu'aux dossiers des tickets que vous avez pris en charge, pendant 2 heures.">File d'attente</PageTitle>
      <ErrorLine message={accept.error ? toApiError(accept.error).message : null} />
      <Panel className="mt-3">
        {!queue.data?.length ? <Empty>Aucun ticket en attente.</Empty> : (
          <Table head={["Date", "Catégorie", "Priorité", "Arnaque ?", "Statut", ""]}>
            {queue.data.map((t) => (
              <tr key={t.id}><Td className="whitespace-nowrap text-ink-soft">{dateTime(t.created_at)}</Td><Td>{t.category}</Td><Td><Badge value={t.priority} /></Td>
                <Td>{t.scam_signal ? <Badge value="CRITICAL" kind="severity" /> : "—"}</Td><Td><Badge value={t.status} /></Td>
                <Td className="text-right">{t.assigned_to_me
                  ? <Link className="font-semibold text-lagoon underline" to={`/agent/tickets/${t.id}`}>Ouvrir</Link>
                  : <Btn tone="ghost" disabled={accept.isPending} onClick={() => accept.mutate(t.id)}>Prendre</Btn>}</Td></tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
