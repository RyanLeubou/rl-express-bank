import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Btn, Empty, ErrorLine, Field, PageTitle, Panel, Table, TextInput, Td } from "../../components/ui/kit";
import { dateTime } from "../../lib/format";
import { toApiError } from "../../services/api";
import { staff } from "../../services/staff";

export function UsersPage() {
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ["admin-users"], queryFn: staff.users });
  const [why, setWhy] = useState("");
  const done = () => { setWhy(""); void qc.invalidateQueries({ queryKey: ["admin-users"] }); };
  const status = useMutation({ mutationFn: (v: { id: string; status: string }) => staff.userStatus(v.id, v.status, why), onSuccess: done });
  const reset = useMutation({ mutationFn: (id: string) => staff.mfaReset(id, why), onSuccess: done });
  const err = status.error ?? reset.error;
  const ok = why.trim().length >= 3;
  return (
    <>
      <PageTitle sub="Renseignez une justification avant toute action : elle est enregistrée dans le journal d'audit.">Utilisateurs</PageTitle>
      <Panel className="mb-5"><Field id="uwhy" label="Justification"><TextInput id="uwhy" value={why} onChange={(e) => setWhy(e.target.value)} /></Field>
        <ErrorLine message={err ? toApiError(err).message : null} /></Panel>
      <Panel>
        {!users.data?.length ? <Empty>Aucun utilisateur.</Empty> : (
          <Table head={["Nom", "E-mail", "Rôles", "Statut", "Dernière connexion", ""]}>
            {users.data.map((u) => (
              <tr key={u.id}><Td className="font-semibold">{u.name}</Td><Td className="text-xs">{u.email}</Td><Td className="text-xs">{u.roles.join(", ")}</Td>
                <Td><Badge value={u.status} /></Td><Td className="whitespace-nowrap text-ink-soft">{u.last_login_at ? dateTime(u.last_login_at) : "—"}</Td>
                <Td className="space-x-2 whitespace-nowrap text-right">
                  <Btn tone="ghost" disabled={!ok} onClick={() => status.mutate({ id: u.id, status: u.status === "ACTIVE" ? "DISABLED" : "ACTIVE" })}>{u.status === "ACTIVE" ? "Désactiver" : "Réactiver"}</Btn>
                  <Btn tone="ghost" disabled={!ok} onClick={() => reset.mutate(u.id)}>Réinitialiser MFA</Btn></Td></tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
