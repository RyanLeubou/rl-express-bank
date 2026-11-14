import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Btn, Empty, ErrorLine, Field, PageTitle, Panel, Select, Table, TextInput, Td } from "../../components/ui/kit";
import { toApiError } from "../../services/api";
import { staff, type Policy } from "../../services/staff";

const DECISIONS = ["ALLOW", "ALLOW_AND_MONITOR", "STEP_UP_TOTP", "STEP_UP_PASSKEY", "BLOCK"];

export function PoliciesPage() {
  const qc = useQueryClient();
  const rows = useQuery({ queryKey: ["policies"], queryFn: staff.policies });
  const [edit, setEdit] = useState<{ p: Policy; decision: string; why: string } | null>(null);
  const save = useMutation({
    mutationFn: () => staff.patchPolicy(edit!.p.id, { decision: edit!.decision, justification: edit!.why }),
    onSuccess: () => { setEdit(null); void qc.invalidateQueries({ queryKey: ["policies"] }); },
  });
  return (
    <>
      <PageTitle sub="Décision appliquée par opération et par niveau de risque. Sans politique, l'opération est refusée.">Politiques de sécurité</PageTitle>
      {edit && (
        <Panel title={`${edit.p.operation} · ${edit.p.level}`} className="mb-5">
          <form className="grid gap-3 md:grid-cols-3" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
            <Field id="dec" label="Décision"><Select id="dec" value={edit.decision} onChange={(e) => setEdit({ ...edit, decision: e.target.value })}>
              {DECISIONS.map((d) => <option key={d}>{d}</option>)}</Select></Field>
            <Field id="pwhy" label="Justification"><TextInput id="pwhy" value={edit.why} onChange={(e) => setEdit({ ...edit, why: e.target.value })} /></Field>
            <div className="flex items-end gap-2"><Btn type="submit" disabled={save.isPending || edit.why.trim().length < 3}>Enregistrer</Btn><Btn tone="ghost" type="button" onClick={() => setEdit(null)}>Annuler</Btn></div>
          </form>
          <ErrorLine message={save.error ? toApiError(save.error).message : null} />
        </Panel>
      )}
      <Panel>
        {!rows.data?.length ? <Empty>Aucune politique.</Empty> : (
          <Table head={["Opération", "Niveau", "Décision", "Plancher", "Actions automatiques", "v", ""]}>
            {rows.data.map((p) => (
              <tr key={p.id}><Td className="font-mono text-xs">{p.operation}</Td><Td><Badge value={p.level} kind="severity" /></Td><Td>{p.decision}</Td>
                <Td>{p.floor ?? "—"}</Td><Td className="text-xs text-ink-soft">{p.actions.join(", ") || "—"}</Td><Td className="tabular">{p.version}</Td>
                <Td className="text-right"><Btn tone="ghost" onClick={() => setEdit({ p, decision: p.decision, why: "" })}>Modifier</Btn></Td></tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
