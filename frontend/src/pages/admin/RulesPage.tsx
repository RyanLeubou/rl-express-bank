import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Btn, Empty, ErrorLine, Field, PageTitle, Panel, Table, TextInput, Td } from "../../components/ui/kit";
import { toApiError } from "../../services/api";
import { staff, type Rule } from "../../services/staff";

export function RulesPage() {
  const qc = useQueryClient();
  const rules = useQuery({ queryKey: ["rules"], queryFn: staff.rules });
  const cfg = useQuery({ queryKey: ["cfg"], queryFn: staff.config });
  const [edit, setEdit] = useState<{ rule: Rule; weight: number; enabled: boolean; why: string } | null>(null);
  const save = useMutation({
    mutationFn: () => staff.patchRule(edit!.rule.id, { weight: edit!.weight, enabled: edit!.enabled, justification: edit!.why }),
    onSuccess: () => { setEdit(null); void qc.invalidateQueries({ queryKey: ["rules"] }); },
  });
  return (
    <>
      <PageTitle sub="Chaque modification exige une justification et est versionnée dans le journal d'audit.">Règles de risque</PageTitle>
      {cfg.data && <p className="mb-4 text-sm text-ink-soft">Seuils : moyen ≥ {cfg.data.risk_thresholds.medium} · élevé ≥ {cfg.data.risk_thresholds.high} · critique ≥ {cfg.data.risk_thresholds.critical}{cfg.data.lab_mode ? " · mode laboratoire actif" : ""}</p>}
      {edit && (
        <Panel title={`Modifier ${edit.rule.code}`} className="mb-5">
          <form className="grid gap-3 md:grid-cols-4" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
            <Field id="w" label="Poids (−50 à 50)"><TextInput id="w" type="number" min={-50} max={50} value={edit.weight} onChange={(e) => setEdit({ ...edit, weight: Number(e.target.value) })} /></Field>
            <label className="mt-7 flex items-center gap-2 text-sm"><input type="checkbox" checked={edit.enabled} onChange={(e) => setEdit({ ...edit, enabled: e.target.checked })} />Active</label>
            <Field id="why" label="Justification"><TextInput id="why" value={edit.why} onChange={(e) => setEdit({ ...edit, why: e.target.value })} /></Field>
            <div className="flex items-end gap-2"><Btn type="submit" disabled={save.isPending || edit.why.trim().length < 3}>Enregistrer</Btn><Btn tone="ghost" type="button" onClick={() => setEdit(null)}>Annuler</Btn></div>
          </form>
          <ErrorLine message={save.error ? toApiError(save.error).message : null} />
        </Panel>
      )}
      <Panel>
        {!rules.data?.length ? <Empty>Aucune règle.</Empty> : (
          <Table head={["Règle", "Description", "Opérations", "Poids", "État", "v", ""]}>
            {rules.data.map((r) => (
              <tr key={r.id}><Td className="font-mono text-xs">{r.code}</Td><Td>{r.description}</Td><Td className="text-xs text-ink-soft">{r.operations.join(", ")}</Td>
                <Td className="tabular font-bold">{r.weight}</Td><Td><Badge value={r.enabled ? "ACTIVE" : "DISABLED"} /></Td><Td className="tabular">{r.version}</Td>
                <Td className="text-right"><Btn tone="ghost" onClick={() => setEdit({ rule: r, weight: r.weight, enabled: r.enabled, why: "" })}>Modifier</Btn></Td></tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
