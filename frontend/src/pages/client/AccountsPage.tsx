import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Btn, Empty, ErrorLine, PageTitle, Panel, Table, Td } from "../../components/ui/kit";
import { EyeToggle, PaymentCard } from "../../components/ui/PaymentCard";
import { dateTime, xaf } from "../../lib/format";
import { toApiError } from "../../services/api";
import { bank, type Account } from "../../services/bank";

function History({ account }: { account: Account }) {
  const entries = useQuery({ queryKey: ["transactions", account.id], queryFn: () => bank.transactions(account.id) });
  if (entries.isPending) return <p className="text-sm text-ink-soft">Chargement…</p>;
  if (!entries.data?.length) return <Empty>Aucune opération.</Empty>;
  return (
    <Table head={["Date", "Libellé", "Montant", "Solde"]}>
      {entries.data.map((e) => (
        <tr key={e.seq}>
          <Td className="whitespace-nowrap text-ink-soft">{dateTime(e.date)}</Td>
          <Td>{e.description}</Td>
          <Td className={`tabular text-right font-semibold ${e.amount < 0 ? "text-laterite" : "text-ok"}`}>
            {e.amount > 0 ? "+" : ""}{xaf(e.amount)}
          </Td>
          <Td className="tabular text-right text-ink-soft">{xaf(e.balance_after)}</Td>
        </tr>
      ))}
    </Table>
  );
}

function RibCard({ account }: { account: Account }) {
  const [show, setShow] = useState(false);
  const rib = useQuery({ queryKey: ["rib", account.id], queryFn: () => bank.rib(account.id), enabled: show });
  const copy = useMutation({
    mutationFn: async () => {
      if (rib.data) await navigator.clipboard.writeText(rib.data.iban.replace(/ /g, ""));
      await bank.ribEvent(account.id, "copied");
    },
  });
  return (
    <div className="mt-3">
      {!show ? <Btn tone="ghost" onClick={() => setShow(true)}>Afficher mon RIB</Btn> : rib.data && (
        <dl className="grid gap-x-6 gap-y-2 rounded-lg border border-rule bg-mist p-4 text-sm sm:grid-cols-2">
          <div><dt className="text-ink-soft">Titulaire</dt><dd className="font-semibold">{rib.data.holder}</dd></div>
          <div><dt className="text-ink-soft">Banque</dt><dd className="font-semibold">{rib.data.bank}</dd></div>
          <div className="sm:col-span-2"><dt className="text-ink-soft">IBAN</dt>
            <dd className="tabular font-bold tracking-wide">{rib.data.iban}</dd></div>
          <div><dt className="text-ink-soft">Code banque / guichet</dt>
            <dd className="tabular font-semibold">{rib.data.bank_code} / {rib.data.branch_code}</dd></div>
          <div><dt className="text-ink-soft">N° de compte · clé</dt>
            <dd className="tabular font-semibold">{rib.data.account_number} · {rib.data.rib_key}</dd></div>
          <div><dt className="text-ink-soft">BIC</dt><dd className="font-semibold">{rib.data.bic}</dd></div>
          <div className="flex items-end gap-2">
            <Btn tone="ghost" onClick={() => copy.mutate()}>{copy.isSuccess ? "Copié" : "Copier l'IBAN"}</Btn>
          </div>
        </dl>
      )}
    </div>
  );
}

const HIDE_KEY = "rlbank:hide-balances";

function readHidden(): boolean {
  try { return localStorage.getItem(HIDE_KEY) === "1"; } catch { return false; }
}

export function AccountsPage() {
  const accounts = useQuery({ queryKey: ["accounts"], queryFn: bank.accounts });
  const cards = useQuery({ queryKey: ["cards"], queryFn: bank.cards });
  const qc = useQueryClient();
  const openSavings = useMutation({
    mutationFn: bank.openSavings, onSuccess: () => void qc.invalidateQueries({ queryKey: ["accounts"] }),
  });
  const hasSavings = accounts.data?.some((a) => a.type === "SAVINGS");
  const [open, setOpen] = useState<string | null>(null);
  const [hidden, setHidden] = useState(readHidden);   // préférence de l'appareil (discrétion en public)
  const toggleHidden = () => {
    setHidden(!hidden);
    try { localStorage.setItem(HIDE_KEY, hidden ? "0" : "1"); } catch { /* stockage indisponible */ }
  };
  const amount = (value: number) => (hidden ? "•••••• XAF" : xaf(value));
  return (
    <>
      <PageTitle sub="Soldes et opérations. Les numéros sont masqués tant que vous n'affichez pas votre RIB.">Mes comptes</PageTitle>
      {accounts.isPending && <p className="text-ink-soft">Chargement…</p>}
      <div className="space-y-4">
        {accounts.data?.map((a) => (
          <Panel key={a.id} title={a.label} action={<Badge value={a.status} />}>
            <div className="flex flex-wrap items-start justify-between gap-5">
              <div>
                <div className="flex items-center gap-1">
                  <p data-testid="balance" className="tabular text-3xl font-bold">{amount(a.balance)}</p>
                  <EyeToggle shown={!hidden} onToggle={toggleHidden} label="les soldes" className="text-ink-soft" />
                </div>
                <p className="tabular text-sm text-ink-soft">Disponible {amount(a.available_balance)} · {a.iban_masked}</p>
                <Btn tone="ghost" className="mt-3" onClick={() => setOpen(open === a.id ? null : a.id)}>
                  {open === a.id ? "Masquer l'historique" : "Voir l'historique"}
                </Btn>
              </div>
              {cards.data?.filter((c) => c.account_id === a.id).map((c) => (
                <div key={c.id} className="w-full max-w-sm"><PaymentCard card={c} /></div>
              ))}
            </div>
            <RibCard account={a} />
            {open === a.id && <div className="mt-4"><History account={a} /></div>}
          </Panel>
        ))}
        {accounts.data && !hasSavings && (
          <Panel title="Livret épargne">
            <p className="text-sm text-ink-soft">
              Mettez de l'argent de côté sur un compte distinct, avec son propre RIB, rattaché à votre agence.
            </p>
            <ErrorLine message={openSavings.error ? toApiError(openSavings.error).message : null} />
            <Btn className="mt-3" disabled={openSavings.isPending} onClick={() => openSavings.mutate()}>
              {openSavings.isPending ? "Ouverture…" : "Ouvrir mon livret épargne"}
            </Btn>
          </Panel>
        )}
      </div>
    </>
  );
}
