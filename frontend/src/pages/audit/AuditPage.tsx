import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Btn, Empty, Field, PageTitle, Panel, Table, TextInput, Td } from "../../components/ui/kit";
import { dateTime } from "../../lib/format";
import { staff } from "../../services/staff";

export function AuditPage() {
  const [action, setAction] = useState("");
  const rows = useQuery({ queryKey: ["audit", action], queryFn: () => staff.audit({ limit: 200, ...(action && { action }) }) });
  const verify = useMutation({ mutationFn: staff.verifyAudit });
  const v = verify.data;
  return (
    <>
      <PageTitle sub="Journal chaîné par SHA-256 : toute modification a posteriori est détectée.">Journal d'audit</PageTitle>
      <Panel className="mb-5">
        <div className="flex flex-wrap items-end gap-3">
          <div className="w-64"><Field id="aa" label="Filtrer par action"><TextInput id="aa" value={action} onChange={(e) => setAction(e.target.value.toUpperCase())} /></Field></div>
          <Btn tone="ghost" disabled={verify.isPending} onClick={() => verify.mutate()}>Vérifier l'intégrité</Btn>
          <a className="rounded-lg border border-ink px-4 py-2.5 text-sm font-semibold hover:bg-mist" href="/api/v1/audit/export" download>Exporter en CSV</a>
        </div>
        {v && <p role="status" className={`mt-3 text-sm font-semibold ${v.valid ? "text-ok" : "text-laterite"}`}>
          {v.valid ? `Chaîne intègre : ${v.entries} entrées vérifiées.` : `Rupture détectée à l'entrée n° ${v.broken_at_seq}.`}</p>}
      </Panel>
      <Panel>
        {!rows.data?.length ? <Empty>Aucune entrée.</Empty> : (
          <Table head={["#", "Date", "Acteur", "Action", "Cible", "Justification", "Empreinte"]}>
            {rows.data.map((a) => (
              <tr key={a.seq}><Td className="tabular text-ink-soft">{a.seq}</Td><Td className="whitespace-nowrap text-ink-soft">{dateTime(a.timestamp)}</Td>
                <Td>{a.actor_role ? <Badge value={a.actor_role} /> : "système"}</Td><Td className="font-mono text-xs">{a.action}</Td>
                <Td className="text-xs">{a.target_type}</Td><Td>{a.justification ?? "—"}</Td><Td className="font-mono text-xs text-ink-soft">{a.hash.slice(0, 10)}…</Td></tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
