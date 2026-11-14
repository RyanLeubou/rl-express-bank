import { useQuery } from "@tanstack/react-query";
import { Badge, Empty, PageTitle, Panel, Table, Td } from "../../components/ui/kit";
import { dateTime } from "../../lib/format";
import { staff } from "../../services/staff";

export function InvestigationsPage() {
  const rows = useQuery({ queryKey: ["investigations"], queryFn: staff.investigations });
  return (
    <>
      <PageTitle sub="Dossiers ouverts à partir des alertes.">Investigations</PageTitle>
      <Panel>
        {!rows.data?.length ? <Empty>Aucune investigation. Ouvrez-en une depuis le détail d'une alerte.</Empty> : (
          <Table head={["Ouverte le", "Titre", "Statut", "Synthèse"]}>
            {rows.data.map((i) => (
              <tr key={i.id}><Td className="whitespace-nowrap text-ink-soft">{dateTime(i.created_at)}</Td><Td className="font-semibold">{i.title}</Td>
                <Td><Badge value={i.status} /></Td><Td>{i.summary ?? "—"}</Td></tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
