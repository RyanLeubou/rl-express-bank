import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Btn, Empty, ErrorLine, PageTitle, Panel, TextInput } from "../../components/ui/kit";
import { dateTime } from "../../lib/format";
import { toApiError } from "../../services/api";
import { bank, type Conversation } from "../../services/bank";

const WHO = { CUSTOMER: "Vous", BOT: "RL SOLUTION", AGENT: "Conseiller", SYSTEM: "Système" } as const;

export function HelpPage() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["conversations"], queryFn: bank.conversations });
  const [current, setCurrent] = useState<string | null>(null);
  const [text, setText] = useState("");
  const id = current ?? list.data?.[0]?.id ?? null;
  const conv = useQuery({ queryKey: ["conversation", id], queryFn: () => bank.conversation(id ?? ""), enabled: !!id, refetchInterval: 8_000 });
  const send = useMutation({
    mutationFn: async (): Promise<Conversation> => (id ? bank.sendMessage(id, text) : bank.startConversation("Question générale", text)),
    onSuccess: (c) => { setText(""); setCurrent(c.id); qc.setQueryData(["conversation", c.id], c); void qc.invalidateQueries({ queryKey: ["conversations"] }); },
  });
  return (
    <>
      <PageTitle sub="RL EXPRESS BANK ne vous demandera jamais votre mot de passe, un code reçu ou votre PIN.">RL SOLUTION</PageTitle>
      <Panel title={conv.data ? conv.data.topic : "Nouvelle conversation"}>
        <ErrorLine message={send.error ? toApiError(send.error).message : null} />
        {conv.data?.scam_signal && (
          <p className="mb-3 border-l-4 border-saffron pl-3 text-sm font-semibold">
            Une arnaque possible a été signalée. Si vous avez communiqué un code, bloquez votre carte dans « Cartes et paiements ».
          </p>
        )}
        <div className="max-h-[26rem] min-h-40 space-y-3 overflow-y-auto" aria-live="polite">
          {!conv.data?.messages?.length && <Empty>Posez votre question : retrait sans carte, carte bloquée, opération refusée…</Empty>}
          {conv.data?.messages?.map((m) => (
            <div key={m.id} className={`max-w-[85%] rounded-xl px-4 py-2 text-sm ${m.author === "CUSTOMER" ? "ml-auto bg-ink text-white" : "bg-mist"}`}>
              <p className="text-xs opacity-70">{WHO[m.author]} · {dateTime(m.at)}</p>
              <p>{m.content}</p>
            </div>
          ))}
        </div>
        <form className="mt-4 flex gap-3" onSubmit={(e) => { e.preventDefault(); if (text.trim()) send.mutate(); }}>
          <TextInput aria-label="Votre message" maxLength={1500} value={text} onChange={(e) => setText(e.target.value)} placeholder="Votre message" />
          <Btn type="submit" disabled={send.isPending || !text.trim()} className="mt-1 shrink-0">Envoyer</Btn>
        </form>
        <p className="mt-2 text-xs text-ink-soft">Les codes et PIN que vous écrivez sont masqués avant enregistrement.</p>
      </Panel>
    </>
  );
}
