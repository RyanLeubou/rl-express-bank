import { Badge, Empty, Panel, Table, Td } from "./ui/kit";
import { dateTime, xaf } from "../lib/format";
import type { Customer } from "../services/staff";

/** Dossier client en lecture seule. Chaque consultation est tracée côté API. */
export function CustomerFile({ c, onLockCard }: { c: Customer; onLockCard?: (cardId: string) => void }) {
  return (
    <div className="space-y-5">
      <Panel title={c.user.name}>
        <p className="text-sm text-ink-soft">{c.user.email} · {c.user.city ?? "ville inconnue"} · <Badge value={c.user.status} /></p>
      </Panel>
      {c.accounts && (
        <Panel title="Comptes">
          <Table head={["Compte", "IBAN", "Solde", "Disponible", "Statut"]}>
            {c.accounts.map((a) => (
              <tr key={a.id}><Td>{a.label}</Td><Td className="font-mono text-xs">{a.iban_masked}</Td><Td className="tabular">{xaf(a.balance)}</Td>
                <Td className="tabular">{xaf(a.available)}</Td><Td><Badge value={a.status} /></Td></tr>
            ))}
          </Table>
        </Panel>
      )}
      <Panel title="Cartes">
        {!c.cards.length ? <Empty>Aucune carte.</Empty> : (
          <Table head={["Carte", "Statut", "Motif", ""]}>
            {c.cards.map((k) => (
              <tr key={k.id}><Td className="font-mono">{k.masked_pan}</Td><Td><Badge value={k.status} /></Td><Td>{k.blocked_reason ?? "—"}</Td>
                <Td className="text-right">{onLockCard && k.status === "ACTIVE" &&
                  <button type="button" className="font-semibold text-lagoon underline" onClick={() => onLockCard(k.id)}>Verrouiller</button>}</Td></tr>
            ))}
          </Table>
        )}
      </Panel>
      <Panel title="Appareils">
        {!c.devices.length ? <Empty>Aucun appareil.</Empty> : (
          <Table head={["Appareil", "Statut", "Ville", "Dernière activité"]}>
            {c.devices.map((d) => (<tr key={d.id}><Td>{d.name}</Td><Td><Badge value={d.status} /></Td><Td>{d.city ?? "—"}</Td><Td>{dateTime(d.last_seen)}</Td></tr>))}
          </Table>
        )}
      </Panel>
      <Panel title="Dernières opérations">
        {!c.transfers.length && !c.payments.length && !c.withdrawals.length ? <Empty>Aucune opération.</Empty> : (
          <Table head={["Date", "Type", "Détail", "Montant", "Statut"]}>
            {c.transfers.map((t) => (<tr key={t.id}><Td>{dateTime(t.date)}</Td><Td>Virement</Td><Td>score {t.risk_score ?? "—"}</Td><Td className="tabular">{xaf(t.amount)}</Td><Td><Badge value={t.status} /></Td></tr>))}
            {c.payments.map((p) => (<tr key={p.id}><Td>{dateTime(p.date)}</Td><Td>Paiement</Td><Td>{p.merchant}</Td><Td className="tabular">{xaf(p.amount)}</Td><Td><Badge value={p.status} /></Td></tr>))}
            {c.withdrawals.map((w) => (<tr key={w.id}><Td>{dateTime(w.date)}</Td><Td>Retrait</Td><Td>{w.city ?? "—"}</Td><Td className="tabular">{xaf(w.amount)}</Td><Td><Badge value={w.status} /></Td></tr>))}
          </Table>
        )}
      </Panel>
    </div>
  );
}
