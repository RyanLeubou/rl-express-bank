import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Badge, Btn, Empty, ErrorLine, Field, PageTitle, Panel, Select, Table, TextInput, Td } from "../../components/ui/kit";
import { PaymentCard } from "../../components/ui/PaymentCard";
import { useGuarded } from "../../components/ui/StepUp";
import { dateTime, xaf } from "../../lib/format";
import { toApiError } from "../../services/api";
import { bank } from "../../services/bank";

const CATEGORIES = ["FOOD", "TRANSPORT", "TECHNOLOGY", "HOTEL", "RESTAURANT", "SHOPPING", "TRAVEL", "OTHER"];
const CITIES = ["Douala", "Yaoundé", "Kribi", "Bafoussam", "Paris", "Lagos", "Dubaï"];

export function CardsPage() {
  const qc = useQueryClient();
  const run = useGuarded();
  const cards = useQuery({ queryKey: ["cards"], queryFn: bank.cards });
  const payments = useQuery({ queryKey: ["payments"], queryFn: bank.payments });
  const [pay, setPay] = useState({ merchant: "", amount: "", category: "SHOPPING", city: "Douala" });
  const [notice, setNotice] = useState<string | null>(null);
  const refresh = () => void qc.invalidateQueries();
  const block = useMutation({ mutationFn: bank.blockCard, onSuccess: refresh });
  const unblock = useMutation({ mutationFn: (id: string) => run(bank.unblockCard(id)), onSuccess: refresh });
  const card = cards.data?.[0];
  const payment = useMutation({
    mutationFn: () => run(bank.pay({ card_id: card?.id ?? "", amount: Number(pay.amount), merchant: pay.merchant,
      category: pay.category, city: pay.city })),
    onSuccess: () => { setNotice("Paiement accepté."); setPay({ ...pay, amount: "", merchant: "" }); refresh(); },
    onError: () => setNotice(null),
  });
  const error = block.error ?? unblock.error ?? payment.error;

  return (
    <>
      <PageTitle sub="Carte fictive : le numéro complet et le CVV ne sont jamais stockés, ils sont recalculés à l'affichage.">Cartes et paiements</PageTitle>
      <ErrorLine message={error ? toApiError(error).message : null} />
      {notice && <p role="status" className="mb-4 rounded-lg bg-green-100 px-4 py-2 font-semibold text-ok">{notice}</p>}
      <div className="mt-4 grid gap-5 lg:grid-cols-2">
        {card ? (
          <Panel title="Ma carte" action={<Badge value={card.status} />}>
            <PaymentCard card={card} />
            <p className="tabular mt-3 text-sm text-ink-soft">
              Plafonds par jour : paiement {xaf(card.daily_payment_limit)} · retrait {xaf(card.daily_withdrawal_limit)}
            </p>
            {card.blocked_reason === "SECURITY_LOCK" && (
              <p className="mt-3 border-l-4 border-saffron pl-3 text-sm font-semibold">
                Carte verrouillée par la sécurité. Contactez RL SOLUTION pour la débloquer.
              </p>
            )}
            <div className="mt-4 flex gap-3">
              {card.status === "ACTIVE"
                ? <Btn tone="danger" disabled={block.isPending} onClick={() => block.mutate(card.id)}>Bloquer ma carte</Btn>
                : card.blocked_reason !== "SECURITY_LOCK" &&
                  <Btn disabled={unblock.isPending} onClick={() => unblock.mutate(card.id)}>Débloquer (avec code)</Btn>}
            </div>
          </Panel>
        ) : <Panel title="Ma carte"><Empty>Aucune carte.</Empty></Panel>}

        <Panel title="Payer chez un commerçant (simulation)">
          <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); setNotice(null); payment.mutate(); }}>
            <Field id="merchant" label="Commerçant"><TextInput id="merchant" value={pay.merchant} onChange={(e) => setPay({ ...pay, merchant: e.target.value })} /></Field>
            <Field id="pamount" label="Montant (XAF)"><TextInput id="pamount" inputMode="numeric" className="tabular" value={pay.amount}
              onChange={(e) => setPay({ ...pay, amount: e.target.value.replace(/\D/g, "") })} /></Field>
            <div className="grid grid-cols-2 gap-3">
              <Field id="cat" label="Catégorie"><Select id="cat" value={pay.category} onChange={(e) => setPay({ ...pay, category: e.target.value })}>
                {CATEGORIES.map((c) => <option key={c}>{c}</option>)}</Select></Field>
              <Field id="city" label="Ville"><Select id="city" value={pay.city} onChange={(e) => setPay({ ...pay, city: e.target.value })}>
                {CITIES.map((c) => <option key={c}>{c}</option>)}</Select></Field>
            </div>
            <Btn type="submit" disabled={!card || payment.isPending || !pay.amount || !pay.merchant}>Payer</Btn>
          </form>
        </Panel>
      </div>

      <Panel title="Derniers paiements" className="mt-5">
        {!payments.data?.length ? <Empty>Aucun paiement.</Empty> : (
          <Table head={["Date", "Commerçant", "Ville", "Montant", "Statut"]}>
            {payments.data.map((p) => (
              <tr key={p.id}>
                <Td className="whitespace-nowrap text-ink-soft">{dateTime(p.date)}</Td><Td>{p.merchant}</Td><Td>{p.city}</Td>
                <Td className="tabular text-right font-semibold">{xaf(p.amount)}</Td><Td><Badge value={p.status} /></Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
