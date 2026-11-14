import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Btn, Empty, ErrorLine, Field, PageTitle, Panel, Select, Table, TextInput, Td } from "../../components/ui/kit";
import { useGuarded } from "../../components/ui/StepUp";
import { dateTime, xaf } from "../../lib/format";
import { toApiError } from "../../services/api";
import { bank } from "../../services/bank";

interface Issued { reference: string; code: string; expires_at: string; withdrawal_id: string }

export function WithdrawalsPage() {
  const qc = useQueryClient();
  const run = useGuarded();
  const accounts = useQuery({ queryKey: ["accounts"], queryFn: bank.accounts });
  const cards = useQuery({ queryKey: ["cards"], queryFn: bank.cards });
  const atms = useQuery({ queryKey: ["atms"], queryFn: bank.atms });
  const history = useQuery({ queryKey: ["withdrawals"], queryFn: bank.withdrawals });
  const [mode, setMode] = useState<"CARDLESS" | "CARD">("CARDLESS");
  const [form, setForm] = useState({ account: "", atm: "", amount: "", pin: "" });
  const [issued, setIssued] = useState<Issued | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const account = form.account || accounts.data?.find((a) => a.type === "CURRENT")?.id || "";
  const atm = form.atm || atms.data?.find((a) => a.status === "ONLINE")?.id || "";
  const card = cards.data?.find((c) => c.account_id === account);
  const refresh = () => void qc.invalidateQueries();

  const withdraw = useMutation({
    mutationFn: () => run(bank.withdraw({
      type: mode, account_id: account, amount: Number(form.amount), atm_id: atm,
      ...(mode === "CARD" ? { card_id: card?.id, pin: form.pin } : {}) })),
    onSuccess: (result) => {
      setForm((f) => ({ ...f, amount: "", pin: "" }));
      if (mode === "CARDLESS") { setIssued(result as unknown as Issued); setNotice(null); }
      else { setIssued(null); setNotice("Retrait effectué : récupérez vos billets."); }
      refresh();
    },
    onError: () => { setForm((f) => ({ ...f, pin: "" })); setNotice(null); },
  });
  const cancel = useMutation({ mutationFn: bank.cancelCardless, onSuccess: () => { setIssued(null); refresh(); } });
  const error = withdraw.error ?? cancel.error;

  return (
    <>
      <PageTitle sub="Le retrait sans carte réserve les fonds 15 minutes. Le code ne s'affiche qu'une seule fois.">Retraits</PageTitle>
      <ErrorLine message={error ? toApiError(error).message : null} />
      {notice && <p role="status" className="mb-4 rounded-lg bg-green-100 px-4 py-2 font-semibold text-ok">{notice}</p>}
      <div className="mt-4 grid gap-5 lg:grid-cols-2">
        <Panel title="Nouveau retrait">
          <div role="tablist" className="mb-4 flex gap-2">
            {(["CARDLESS", "CARD"] as const).map((m) => (
              <button key={m} role="tab" aria-selected={mode === m} type="button" onClick={() => setMode(m)}
                className={`rounded-lg px-3 py-1.5 text-sm font-semibold ${mode === m ? "bg-ink text-white" : "border border-rule"}`}>
                {m === "CARDLESS" ? "Sans carte" : "Avec carte"}
              </button>
            ))}
          </div>
          <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); withdraw.mutate(); }}>
            <Field id="wacc" label="Compte">
              <Select id="wacc" value={account} onChange={(e) => setForm({ ...form, account: e.target.value })}>
                {accounts.data?.filter((a) => a.type !== "INTERNAL").map((a) => (
                  <option key={a.id} value={a.id}>{a.label} — {xaf(a.available_balance)}</option>))}
              </Select>
            </Field>
            <Field id="watm" label="Distributeur">
              <Select id="watm" value={atm} onChange={(e) => setForm({ ...form, atm: e.target.value })}>
                {atms.data?.filter((a) => a.status === "ONLINE" || a.status === "SUSPICIOUS").map((a) => (
                  <option key={a.id} value={a.id}>{a.code} — {a.name}, {a.city}</option>))}
              </Select>
            </Field>
            <Field id="wamt" label="Montant (XAF)">
              <TextInput id="wamt" inputMode="numeric" className="tabular" value={form.amount}
                onChange={(e) => setForm({ ...form, amount: e.target.value.replace(/\D/g, "") })} />
            </Field>
            {mode === "CARD" && (
              <Field id="wpin" label="PIN de la carte" hint="Quatre chiffres. Trois erreurs bloquent la carte.">
                <TextInput id="wpin" type="password" inputMode="numeric" maxLength={4} autoComplete="off" value={form.pin}
                  onChange={(e) => setForm({ ...form, pin: e.target.value.replace(/\D/g, "") })} />
              </Field>
            )}
            <Btn type="submit" disabled={withdraw.isPending || !form.amount || !atm || (mode === "CARD" && form.pin.length !== 4)}>
              {mode === "CARDLESS" ? "Générer un code de retrait" : "Retirer"}
            </Btn>
          </form>
        </Panel>

        <Panel title="Code de retrait sans carte">
          {issued ? (
            <div className="space-y-3" data-testid="issued-code">
              <p className="text-sm text-ink-soft">Présentez ces deux valeurs au distributeur. Notez-les : elles ne seront plus affichées.</p>
              <div className="rounded-xl bg-ink p-5 text-center text-white">
                <p className="text-xs uppercase tracking-widest text-white/60">Référence</p>
                <p className="tabular text-2xl font-bold tracking-[0.3em]">{issued.reference}</p>
                <p className="mt-3 text-xs uppercase tracking-widest text-white/60">Code</p>
                <p className="tabular text-3xl font-bold tracking-[0.4em]">{issued.code}</p>
              </div>
              <p className="text-sm text-ink-soft">Valable jusqu'à {dateTime(issued.expires_at)}. Usage unique, 3 essais.</p>
              <Btn tone="danger" onClick={() => cancel.mutate(issued.withdrawal_id)}>Annuler ce code</Btn>
            </div>
          ) : <Empty>Aucun code actif affiché.</Empty>}
        </Panel>
      </div>

      <Panel title="Mes retraits" className="mt-5">
        {!history.data?.length ? <Empty>Aucun retrait.</Empty> : (
          <Table head={["Date", "Type", "Ville", "Montant", "Statut"]}>
            {history.data.map((w) => (
              <tr key={w.id}>
                <Td className="whitespace-nowrap text-ink-soft">{dateTime(w.created_at)}</Td>
                <Td>{w.type === "CARD" ? "Carte" : "Sans carte"}</Td><Td>{w.city ?? "—"}</Td>
                <Td className="tabular text-right font-semibold">{xaf(w.amount)}</Td><Td><Badge value={w.status} /></Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
