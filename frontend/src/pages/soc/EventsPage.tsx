import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Empty, Field, PageTitle, Panel, Select, Table, TextInput, Td } from "../../components/ui/kit";
import { dateTime, xaf } from "../../lib/format";
import { staff } from "../../services/staff";

export function EventsPage() {
  const [category, setCategory] = useState("");
  const [type, setType] = useState("");
  const events = useQuery({
    queryKey: ["events", category, type], refetchInterval: 15_000,
    queryFn: () => staff.events({ limit: 150, ...(category && { category }), ...(type && { event_type: type }) }),
  });
  return (
    <>
      <PageTitle sub="Journal des événements de sécurité (append-only).">Événements</PageTitle>
      <div className="mb-4 flex flex-wrap gap-3">
        <div className="w-52"><Field id="cat" label="Catégorie"><Select id="cat" value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">Toutes</option>
          {["AUTH", "BANKING", "ATM", "RISK", "SECURITY", "SUPPORT", "ADMIN", "STAFF"].map((c) => <option key={c}>{c}</option>)}
        </Select></Field></div>
        <div className="w-64"><Field id="evt" label="Type d'événement"><TextInput id="evt" value={type} onChange={(e) => setType(e.target.value.toUpperCase())} /></Field></div>
      </div>
      <Panel>
        {!events.data?.length ? <Empty>Aucun événement.</Empty> : (
          <Table head={["#", "Date", "Type", "Sévérité", "Lieu", "Montant", "Score"]}>
            {events.data.map((e) => (
              <tr key={e.id}><Td className="tabular text-ink-soft">{e.seq}</Td><Td className="whitespace-nowrap text-ink-soft">{dateTime(e.timestamp)}</Td>
                <Td className="font-mono text-xs">{e.type}</Td><Td><Badge value={e.severity} kind="severity" /></Td>
                <Td>{e.location ?? "—"}</Td><Td className="tabular">{e.amount ? xaf(e.amount) : "—"}</Td><Td className="tabular">{e.risk_score ?? "—"}</Td></tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
