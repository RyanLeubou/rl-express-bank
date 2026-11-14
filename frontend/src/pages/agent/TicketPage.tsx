import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { CustomerFile } from "../../components/CustomerFile";
import { Btn, ErrorLine, PageTitle, Panel, TextInput } from "../../components/ui/kit";
import { dateTime } from "../../lib/format";
import { toApiError } from "../../services/api";
import { staff } from "../../services/staff";

export function TicketPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [text, setText] = useState("");
  const [showFile, setShowFile] = useState(false);
  const ticket = useQuery({ queryKey: ["ticket", id], queryFn: () => staff.ticket(id), refetchInterval: 8_000 });
  const file = useQuery({ queryKey: ["ticket-customer", id], enabled: showFile, queryFn: () => staff.ticketCustomer(id) });
  const reply = useMutation({ mutationFn: () => staff.reply(id, text), onSuccess: () => { setText(""); void qc.invalidateQueries({ queryKey: ["ticket", id] }); } });
  const lock = useMutation({ mutationFn: (cardId: string) => staff.lockCard(id, cardId, "Verrouillage à la demande du client"), onSuccess: () => void qc.invalidateQueries({ queryKey: ["ticket-customer", id] }) });
  const close = useMutation({ mutationFn: () => staff.closeTicket(id), onSuccess: () => navigate("/agent") });
  const t = ticket.data;
  const error = reply.error ?? lock.error ?? close.error ?? (file.isError ? file.error : null) ?? (ticket.isError ? ticket.error : null);
  if (!t) return <p className="text-ink-soft">{ticket.isError ? "Ticket indisponible ou accès expiré." : "Chargement…"}</p>;
  return (
    <>
      <p className="mb-2 text-sm"><Link to="/agent" className="font-semibold text-lagoon underline">← File d'attente</Link></p>
      <PageTitle sub={t.access_expires_at ? `Accès au dossier jusqu'à ${dateTime(t.access_expires_at)}` : undefined}>{t.category}</PageTitle>
      <ErrorLine message={error ? toApiError(error).message : null} />
      <div className="mt-3 grid gap-5 lg:grid-cols-2">
        <Panel title="Conversation">
          {t.conversation.scam_signal && <p role="alert" className="mb-3 rounded-lg bg-laterite/10 px-3 py-2 text-sm font-semibold text-laterite">Arnaque possible : ne demandez jamais de code au client.</p>}
          <ul className="max-h-96 space-y-2 overflow-y-auto">
            {t.messages.map((m) => (
              <li key={m.id} className={`rounded-lg px-3 py-2 text-sm ${m.author === "CUSTOMER" ? "bg-mist" : "bg-lagoon/10"}`}>
                <p className="text-xs font-semibold text-ink-soft">{m.author} · {dateTime(m.at)}</p><p>{m.content}</p></li>
            ))}
          </ul>
          <form className="mt-3 flex gap-2" onSubmit={(e) => { e.preventDefault(); reply.mutate(); }}>
            <TextInput aria-label="Réponse" className="!mt-0" value={text} maxLength={1000} onChange={(e) => setText(e.target.value)} />
            <Btn type="submit" disabled={reply.isPending || !text.trim()}>Envoyer</Btn>
          </form>
          <div className="mt-3 flex gap-2"><Btn tone="ghost" onClick={() => setShowFile(true)}>Consulter le dossier client</Btn><Btn tone="ghost" disabled={close.isPending} onClick={() => close.mutate()}>Clôturer</Btn></div>
        </Panel>
        <div>{file.data ? <CustomerFile c={file.data} onLockCard={(cid) => lock.mutate(cid)} /> : <Panel title="Dossier client"><p className="text-sm text-ink-soft">La consultation est tracée. Ouvrez-le uniquement si le client le demande.</p></Panel>}</div>
      </div>
    </>
  );
}
