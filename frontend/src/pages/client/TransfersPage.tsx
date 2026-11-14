import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Badge, Btn, Empty, ErrorLine, Field, PageTitle, Panel, Select, Table, TextInput, Td } from "../../components/ui/kit";
import { useGuarded } from "../../components/ui/StepUp";
import { dateTime, xaf } from "../../lib/format";
import { toApiError } from "../../services/api";
import { bank, type Beneficiary, type Transfer } from "../../services/bank";

type Direction = "ALL" | "IN" | "OUT";

function saveFile(file: File) {
  const url = URL.createObjectURL(file);
  const a = document.createElement("a");
  a.href = url;
  a.download = file.name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function TransferDetailDialog({ transfer, onClose }: { transfer: Transfer; onClose: () => void }) {
  const detail = useQuery({ queryKey: ["transfer", transfer.direction, transfer.id], queryFn: () => bank.transferDetail(transfer) });
  // PDF préparé dès l'ouverture : le partage doit partir immédiatement après le clic (exigence des navigateurs)
  const receipt = useQuery({
    queryKey: ["receipt", transfer.direction, transfer.id], queryFn: () => bank.transferReceipt(transfer), gcTime: 0,
  });
  const [shareNote, setShareNote] = useState<string | null>(null);
  const share = async () => {
    if (!receipt.data) return;
    const file = receipt.data;
    if (navigator.canShare?.({ files: [file] })) {
      try {
        await navigator.share({ files: [file], title: "Avis de virement RL EXPRESS BANK",
          text: `Avis de virement de ${xaf(transfer.amount)} — ${transfer.reference}` });
        setShareNote(null);
      } catch (e) {
        if ((e as DOMException).name !== "AbortError") setShareNote("Le partage a échoué. Le PDF peut être téléchargé.");
      }
      return;
    }
    saveFile(file);
    setShareNote("Ce navigateur ne permet pas le partage direct : le PDF a été téléchargé, joignez-le à votre message.");
  };
  const d = detail.data;
  const incoming = transfer.direction === "IN";
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-ink/60 px-4" role="presentation" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-labelledby="tr-title" onClick={(e) => e.stopPropagation()}
        className="max-h-[90vh] w-full max-w-lg space-y-4 overflow-y-auto rounded-2xl bg-paper p-6 shadow-xl">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 id="tr-title" className="text-xl font-bold">{incoming ? "Virement reçu" : "Virement émis"}</h2>
            <p className={`tabular mt-1 text-2xl font-bold ${incoming ? "text-ok" : ""}`}>
              {incoming ? "+" : "−"}{xaf(transfer.amount)}
            </p>
          </div>
          <Badge value={transfer.status} />
        </div>
        {detail.isPending && <p className="text-sm text-ink-soft">Chargement…</p>}
        <ErrorLine message={detail.error ? toApiError(detail.error).message : null} />
        {d && (
          <dl className="grid gap-x-6 gap-y-3 rounded-lg border border-rule bg-mist p-4 text-sm sm:grid-cols-2">
            <div className="sm:col-span-2"><dt className="text-ink-soft">Motif</dt><dd className="font-semibold">{d.reference}</dd></div>
            <div><dt className="text-ink-soft">{incoming ? "Émetteur" : "Bénéficiaire"}</dt>
              <dd className="font-semibold">{d.counterparty.name}</dd></div>
            <div><dt className="text-ink-soft">Banque</dt><dd>{d.counterparty.bank ?? "—"}</dd></div>
            {d.counterparty.iban && <div className="sm:col-span-2"><dt className="text-ink-soft">IBAN {incoming ? "de l'émetteur" : "du bénéficiaire"}</dt>
              <dd className="tabular font-semibold tracking-wide">{d.counterparty.iban}</dd></div>}
            <div><dt className="text-ink-soft">{incoming ? "Compte crédité" : "Compte débité"}</dt>
              <dd>{d.account.label}<span className="tabular block text-ink-soft">{d.account.iban_masked}</span></dd></div>
            <div><dt className="text-ink-soft">Date</dt><dd>{dateTime(d.created_at)}</dd></div>
            {!incoming && <div><dt className="text-ink-soft">Exécuté le</dt><dd>{d.executed_at ? dateTime(d.executed_at) : "Non exécuté"}</dd></div>}
            {incoming && d.balance_after !== undefined && <div><dt className="text-ink-soft">Solde après</dt>
              <dd className="tabular">{xaf(d.balance_after)}</dd></div>}
            {d.risk_level && <div><dt className="text-ink-soft">Analyse de sécurité</dt>
              <dd><Badge value={d.risk_level} />{d.risk_score != null && <span className="tabular ml-2 text-ink-soft">{d.risk_score}/100</span>}</dd></div>}
            {d.failure_reason && <div className="sm:col-span-2"><dt className="text-ink-soft">Motif du refus</dt><dd>{d.failure_reason}</dd></div>}
          </dl>
        )}
        {shareNote && <p role="status" className="text-sm text-ink-soft">{shareNote}</p>}
        <ErrorLine message={receipt.error ? "Impossible de préparer l'avis de virement." : null} />
        <div className="flex flex-wrap justify-end gap-3">
          <Btn tone="ghost" onClick={onClose}>Fermer</Btn>
          <Btn tone="ghost" disabled={!receipt.data} onClick={() => void share()}>Partager</Btn>
          <Btn disabled={!receipt.data} onClick={() => receipt.data && saveFile(receipt.data)}>
            {receipt.isPending ? "Préparation du PDF…" : "Télécharger le PDF"}
          </Btn>
        </div>
      </div>
    </div>
  );
}

function BeneficiaryDetailDialog({ ben, onClose, onVerify, verifying }: {
  ben: Beneficiary; onClose: () => void; onVerify: () => void; verifying: boolean;
}) {
  const detail = useQuery({ queryKey: ["beneficiary", ben.id], queryFn: () => bank.beneficiary(ben.id) });
  const d = detail.data;
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-ink/60 px-4" role="presentation" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-labelledby="ben-title" onClick={(e) => e.stopPropagation()}
        className="max-h-[90vh] w-full max-w-lg space-y-4 overflow-y-auto rounded-2xl bg-paper p-6 shadow-xl">
        <div className="flex items-start justify-between gap-3">
          <h2 id="ben-title" className="text-xl font-bold">{ben.name}</h2>
          <Badge value={ben.status} />
        </div>
        {detail.isPending && <p className="text-sm text-ink-soft">Chargement…</p>}
        <ErrorLine message={detail.error ? toApiError(detail.error).message : null} />
        {d && (
          <dl className="grid gap-x-6 gap-y-3 rounded-lg border border-rule bg-mist p-4 text-sm sm:grid-cols-2">
            <div><dt className="text-ink-soft">Prénom</dt><dd className="font-semibold">{d.first_name}</dd></div>
            <div><dt className="text-ink-soft">Nom</dt><dd className="font-semibold">{d.last_name}</dd></div>
            <div><dt className="text-ink-soft">Banque</dt><dd className="font-semibold">{d.bank_name}</dd></div>
            <div><dt className="text-ink-soft">Type</dt>
              <dd className="font-semibold">{d.internal ? "Client RL EXPRESS BANK" : "Autre banque"}</dd></div>
            <div className="sm:col-span-2"><dt className="text-ink-soft">IBAN</dt>
              <dd className="tabular font-bold tracking-wide">{d.iban}</dd></div>
            <div><dt className="text-ink-soft">Ajouté le</dt><dd>{dateTime(d.created_at)}</dd></div>
            <div><dt className="text-ink-soft">Vérifié le</dt><dd>{d.activated_at ? dateTime(d.activated_at) : "Pas encore vérifié"}</dd></div>
          </dl>
        )}
        {d && (
          <div>
            <h3 className="text-sm font-semibold">Derniers virements vers ce bénéficiaire</h3>
            {!d.transfers.length ? <p className="mt-1 text-sm text-ink-soft">Aucun virement.</p> : (
              <ul className="mt-2 divide-y divide-rule text-sm">
                {d.transfers.map((t) => (
                  <li key={t.id} className="flex items-center justify-between gap-3 py-2">
                    <span><span className="block">{t.reference}</span>
                      <span className="text-ink-soft">{dateTime(t.created_at)}</span></span>
                    <span className="tabular font-semibold">{xaf(t.amount)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
        <div className="flex justify-end gap-3">
          <Btn tone="ghost" onClick={onClose}>Fermer</Btn>
          {ben.status === "PENDING_VERIFICATION" &&
            <Btn disabled={verifying} onClick={onVerify}>{verifying ? "Vérification…" : "Vérifier"}</Btn>}
        </div>
      </div>
    </div>
  );
}

export function TransfersPage() {
  const qc = useQueryClient();
  const run = useGuarded();
  const accounts = useQuery({ queryKey: ["accounts"], queryFn: bank.accounts });
  const beneficiaries = useQuery({ queryKey: ["beneficiaries"], queryFn: bank.beneficiaries });
  const transfers = useQuery({ queryKey: ["transfers"], queryFn: bank.transfers });
  const [form, setForm] = useState({ source: "", beneficiary: "", amount: "", reference: "" });
  const [newBen, setNewBen] = useState({ first_name: "", last_name: "", bank_name: "", iban: "" });
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = () => void qc.invalidateQueries();
  const transfer = useMutation({
    mutationFn: () => run(bank.transfer({
      source_account_id: form.source || accounts.data?.[0]?.id || "", beneficiary_id: form.beneficiary,
      amount: Number(form.amount), reference: form.reference })),
    onSuccess: () => { setNotice("Virement effectué."); setForm({ ...form, amount: "", reference: "" }); refresh(); },
    onError: () => setNotice(null),
  });
  const addBen = useMutation({
    mutationFn: () => run(bank.addBeneficiary(newBen)),
    onSuccess: () => { setNotice("Bénéficiaire ajouté et activé."); setNewBen({ first_name: "", last_name: "", bank_name: "", iban: "" }); refresh(); },
  });
  const del = useMutation({ mutationFn: bank.deleteBeneficiary, onSuccess: refresh });
  const [opened, setOpened] = useState<Beneficiary | null>(null);
  const [openedTransfer, setOpenedTransfer] = useState<Transfer | null>(null);
  const [direction, setDirection] = useState<Direction>("ALL");
  const shown = transfers.data?.filter((t) => direction === "ALL" || t.direction === direction);
  const verify = useMutation({
    mutationFn: (id: string) => run(bank.verifyBeneficiary(id)),
    onSuccess: () => { setNotice("Bénéficiaire vérifié et activé."); setOpened(null); refresh(); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); setNotice(null); transfer.mutate(); };
  const error = transfer.error ?? addBen.error ?? del.error ?? verify.error;

  return (
    <>
      <PageTitle sub="Un virement inhabituel peut demander une confirmation par code, ou être bloqué par mesure de sécurité.">Virements</PageTitle>
      {notice && <p role="status" className="mb-4 rounded-lg bg-green-100 px-4 py-2 font-semibold text-ok">{notice}</p>}
      <ErrorLine message={error ? toApiError(error).message : null} />
      <div className="mt-4 grid gap-5 lg:grid-cols-2">
        <Panel title="Nouveau virement">
          <form onSubmit={submit} className="space-y-4">
            <Field id="src" label="Compte à débiter">
              <Select id="src" value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })}>
                {accounts.data?.filter((a) => a.type !== "INTERNAL").map((a) => (
                  <option key={a.id} value={a.id}>{a.label} — {xaf(a.available_balance)}</option>))}
              </Select>
            </Field>
            <Field id="ben" label="Bénéficiaire">
              <Select id="ben" value={form.beneficiary} onChange={(e) => setForm({ ...form, beneficiary: e.target.value })}>
                <option value="">Choisir…</option>
                {beneficiaries.data?.filter((b) => b.status === "ACTIVE").map((b) => (
                  <option key={b.id} value={b.id}>{b.name} — {b.bank_name}</option>))}
              </Select>
            </Field>
            <Field id="amount" label="Montant (XAF)">
              <TextInput id="amount" inputMode="numeric" value={form.amount} className="tabular"
                onChange={(e) => setForm({ ...form, amount: e.target.value.replace(/\D/g, "") })} />
            </Field>
            <Field id="ref" label="Motif">
              <TextInput id="ref" maxLength={140} value={form.reference} onChange={(e) => setForm({ ...form, reference: e.target.value })} />
            </Field>
            <Btn type="submit" disabled={transfer.isPending || !form.beneficiary || !form.amount || !form.reference}>
              {transfer.isPending ? "Envoi…" : "Envoyer le virement"}
            </Btn>
          </form>
        </Panel>

        <Panel title="Ajouter un bénéficiaire">
          <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); setNotice(null); addBen.mutate(); }}>
            <div className="grid grid-cols-2 gap-3">
              <Field id="bf" label="Prénom"><TextInput id="bf" value={newBen.first_name} onChange={(e) => setNewBen({ ...newBen, first_name: e.target.value })} /></Field>
              <Field id="bl" label="Nom"><TextInput id="bl" value={newBen.last_name} onChange={(e) => setNewBen({ ...newBen, last_name: e.target.value })} /></Field>
            </div>
            <Field id="bb" label="Banque"><TextInput id="bb" value={newBen.bank_name} onChange={(e) => setNewBen({ ...newBen, bank_name: e.target.value })} /></Field>
            <Field id="bi" label="IBAN" hint="Une confirmation par code est toujours demandée.">
              <TextInput id="bi" value={newBen.iban} className="tabular" onChange={(e) => setNewBen({ ...newBen, iban: e.target.value })} />
            </Field>
            <Btn type="submit" disabled={addBen.isPending || !newBen.iban || !newBen.last_name}>Ajouter</Btn>
          </form>
        </Panel>
      </div>

      <Panel title="Mes bénéficiaires" className="mt-5">
        {!beneficiaries.data?.length ? <Empty>Aucun bénéficiaire.</Empty> : (
          <Table head={["Nom", "Banque", "IBAN", "Statut", ""]}>
            {beneficiaries.data.map((b) => (
              <tr key={b.id} onClick={() => setOpened(b)} className="cursor-pointer hover:bg-mist">
                <Td className="font-semibold">
                  <button type="button" className="text-left underline-offset-2 hover:underline"
                    onClick={(e) => { e.stopPropagation(); setOpened(b); }}>{b.name}</button>
                </Td>
                <Td>{b.bank_name}</Td>
                <Td className="tabular text-ink-soft">{b.iban_masked}</Td><Td><Badge value={b.status} /></Td>
                <Td className="text-right">
                  <span className="inline-flex gap-2" onClick={(e) => e.stopPropagation()}>
                    {b.status === "PENDING_VERIFICATION" &&
                      <Btn disabled={verify.isPending} onClick={() => { setNotice(null); verify.mutate(b.id); }}>Vérifier</Btn>}
                    <Btn tone="danger" onClick={() => del.mutate(b.id)}>Supprimer</Btn>
                  </span>
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>

      {opened && <BeneficiaryDetailDialog ben={opened} onClose={() => setOpened(null)} verifying={verify.isPending}
        onVerify={() => { setNotice(null); verify.mutate(opened.id); }} />}

      {openedTransfer && <TransferDetailDialog transfer={openedTransfer} onClose={() => setOpenedTransfer(null)} />}

      <Panel title="Derniers virements" className="mt-5" action={
        <div role="group" aria-label="Filtrer les virements" className="flex gap-1 rounded-lg border border-rule p-1 text-sm">
          {([["ALL", "Tous"], ["IN", "Reçus"], ["OUT", "Émis"]] as const).map(([value, label]) => (
            <button key={value} type="button" aria-pressed={direction === value} onClick={() => setDirection(value)}
              className={`rounded-md px-3 py-1 font-semibold ${direction === value ? "bg-lagoon text-white" : "text-ink-soft hover:bg-mist"}`}>
              {label}
            </button>
          ))}
        </div>
      }>
        {!shown?.length ? <Empty>Aucun virement.</Empty> : (
          <Table head={["Date", "Sens", "Émetteur / bénéficiaire", "Motif", "Montant", "Statut"]}>
            {shown.map((t) => (
              <tr key={`${t.direction}-${t.id}`} onClick={() => setOpenedTransfer(t)} className="cursor-pointer hover:bg-mist">
                <Td className="whitespace-nowrap text-ink-soft">{dateTime(t.created_at)}</Td>
                <Td>
                  <button type="button" onClick={(e) => { e.stopPropagation(); setOpenedTransfer(t); }}
                    className={`whitespace-nowrap font-semibold ${t.direction === "IN" ? "text-ok" : "text-laterite"}`}>
                    {t.direction === "IN" ? "↓ Reçu" : "↑ Émis"}
                  </button>
                </Td>
                <Td>{t.counterparty ?? "—"}</Td><Td>{t.reference}</Td>
                <Td className={`tabular whitespace-nowrap text-right font-semibold ${t.direction === "IN" ? "text-ok" : ""}`}>
                  {t.direction === "IN" ? "+" : "−"}{xaf(t.amount)}
                </Td>
                <Td><Badge value={t.status} /></Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
