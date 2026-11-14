import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { CustomerFile } from "../../components/CustomerFile";
import { Empty, Field, PageTitle, Panel, TextInput } from "../../components/ui/kit";
import { staff } from "../../services/staff";

export function CustomersPage() {
  const [params, setParams] = useSearchParams();
  const id = params.get("id");
  const [q, setQ] = useState("");
  const found = useQuery({ queryKey: ["user-search", q], enabled: q.trim().length >= 2, queryFn: () => staff.searchUsers(q.trim()) });
  const file = useQuery({ queryKey: ["customer", id], enabled: !!id, queryFn: () => staff.customer(id ?? "") });
  return (
    <>
      <PageTitle sub="La consultation d'un dossier est enregistrée et analysée (UEBA du personnel).">Dossiers clients</PageTitle>
      <Panel>
        <Field id="q" label="Rechercher (nom ou e-mail)"><TextInput id="q" value={q} onChange={(e) => setQ(e.target.value)} /></Field>
        {found.data && (found.data.length ? (
          <ul className="mt-3 divide-y divide-rule text-sm">
            {found.data.map((u) => (
              <li key={u.id} className="flex justify-between py-2">
                <span>{u.name} <span className="text-ink-soft">· {u.email}</span></span>
                <button type="button" className="font-semibold text-lagoon underline" onClick={() => setParams({ id: u.id })}>Ouvrir</button>
              </li>
            ))}
          </ul>
        ) : <Empty>Aucun résultat.</Empty>)}
      </Panel>
      {file.isError && <p role="alert" className="mt-4 text-sm font-semibold text-laterite">Accès refusé ou dossier introuvable.</p>}
      {file.data && <div className="mt-5"><CustomerFile c={file.data} /></div>}
    </>
  );
}
