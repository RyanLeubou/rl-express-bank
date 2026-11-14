import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { useAuth } from "../../auth/AuthContext";
import { Badge, Btn, Empty, ErrorLine, Field, PageTitle, Panel, Select, Table, TextInput, Td } from "../../components/ui/kit";
import { dateTime, xaf } from "../../lib/format";
import { toApiError } from "../../services/api";
import { staff } from "../../services/staff";

const ACTIONS = [
  ["LOCK_CARD", "Verrouiller une carte (identifiant carte)"], ["REVOKE_SESSION", "Révoquer une session (identifiant session)"],
  ["BLOCK_DEVICE", "Bloquer un appareil (identifiant appareil)"], ["CANCEL_CARDLESS_CODES", "Annuler les codes sans carte (identifiant client)"],
  ["NOTIFY_CUSTOMER", "Notifier le client (identifiant client)"],
] as const;
const ADMIN_ACTIONS = [["FREEZE_ACCOUNT", "Geler un compte (identifiant compte)"], ["FORCE_PASSWORD_RESET", "Forcer le changement de mot de passe (identifiant client)"]] as const;

export function AlertDetailPage() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const { auth } = useAuth();
  const perms = auth.status === "authenticated" ? auth.me.user.permissions : [];
  const canAct = perms.includes("security_action:execute:any");
  const canAdmin = perms.includes("security_action:execute_admin:any");
  const canUpdate = perms.includes("alert:update:any");
  const alert = useQuery({ queryKey: ["alert", id], queryFn: () => staff.alert(id) });
  const [note, setNote] = useState("");
  const [act, setAct] = useState({ type: "LOCK_CARD", target: "", why: "" });
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["alert", id] }); void qc.invalidateQueries({ queryKey: ["alerts"] }); };
  const patch = useMutation({ mutationFn: (body: Record<string, unknown>) => staff.patchAlert(id, body), onSuccess: refresh });
  const run = useMutation({
    mutationFn: () => staff.action({ action_type: act.type, target_id: act.target.trim(), justification: act.why },
      id, ADMIN_ACTIONS.some(([k]) => k === act.type)),
    onSuccess: () => { setAct({ ...act, target: "", why: "" }); refresh(); },
  });
  const revert = useMutation({ mutationFn: (actionId: string) => staff.revert(actionId, "Annulation par l'analyste"), onSuccess: refresh });
  const open = useMutation({ mutationFn: () => staff.openInvestigation(`Investigation — ${alert.data?.title ?? ""}`, [id]), onSuccess: refresh });
  const error = patch.error ?? run.error ?? revert.error ?? open.error;
  const a = alert.data;
  if (!a) return <p className="text-ink-soft">Chargement…</p>;
  const closed = a.status === "RESOLVED" || a.status === "FALSE_POSITIVE";

  return (
    <>
      <p className="mb-2 text-sm"><Link to="/soc/alertes" className="font-semibold text-lagoon underline">← Alertes</Link></p>
      <PageTitle sub={`Créée le ${dateTime(a.created_at)} · source ${a.source}`}>{a.title}</PageTitle>
      <ErrorLine message={error ? toApiError(error).message : null} />
      <div className="mt-3 grid gap-5 lg:grid-cols-3">
        <Panel title="Synthèse" className="lg:col-span-1">
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between"><dt>Sévérité</dt><dd><Badge value={a.severity} kind="severity" /></dd></div>
            <div className="flex justify-between"><dt>Statut</dt><dd><Badge value={a.status} /></dd></div>
            <div className="flex justify-between"><dt>Score de risque</dt><dd className="tabular font-bold">{a.risk_score ?? "—"} / 100</dd></div>
            <div className="flex justify-between"><dt>Cible</dt><dd>{a.user ? `${a.user.name} (${a.user.type.toLowerCase()})` : "—"}</dd></div>
            <div><dt>MITRE ATT&amp;CK</dt><dd className="mt-1 flex flex-wrap gap-1">
              {a.mitre.length ? a.mitre.map((t) => <span key={t} className="rounded bg-mist px-2 py-0.5 font-mono text-xs">{t}</span>) : "—"}</dd></div>
            {a.user && <div><Link className="font-semibold text-lagoon underline" to={`/soc/clients?id=${a.user.id}`}>Ouvrir le dossier</Link></div>}
          </dl>
          {canUpdate && (
            <div className="mt-4 space-y-2 border-t border-rule pt-4">
              <div className="flex flex-wrap gap-2">
                {a.status === "NEW" && <Btn tone="ghost" onClick={() => patch.mutate({ status: "TRIAGED" })}>Marquer triée</Btn>}
                {!a.investigation_id && !closed && <Btn tone="ghost" onClick={() => open.mutate()}>Ouvrir une investigation</Btn>}
              </div>
              {!closed && (
                <>
                  <Field id="note" label="Note de résolution (obligatoire pour clore)">
                    <TextInput id="note" value={note} onChange={(e) => setNote(e.target.value)} />
                  </Field>
                  <div className="flex gap-2">
                    <Btn disabled={note.trim().length < 3} onClick={() => patch.mutate({ status: "RESOLVED", resolution_note: note })}>Résoudre</Btn>
                    <Btn tone="ghost" disabled={note.trim().length < 3} onClick={() => patch.mutate({ status: "FALSE_POSITIVE", resolution_note: note })}>Faux positif</Btn>
                  </div>
                </>
              )}
              {a.resolution_note && <p className="text-sm"><strong>Résolution :</strong> {a.resolution_note}</p>}
            </div>
          )}
        </Panel>

        <Panel title="Pourquoi cette alerte ?" className="lg:col-span-2">
          {!a.reasons.length ? <Empty>Aucun détail.</Empty> : (
            <Table head={["Règle", "Points", "Explication"]}>
              {a.reasons.map((r) => (
                <tr key={r.code}><Td className="font-mono text-xs">{r.code}</Td>
                  <Td className={`tabular font-bold ${r.points < 0 ? "text-ok" : ""}`}>{r.points > 0 ? "+" : ""}{r.points}</Td><Td>{r.detail}</Td></tr>
              ))}
            </Table>
          )}
        </Panel>
      </div>

      <Panel title="Événements liés" className="mt-5">
        {!a.events.length ? <Empty>Aucun événement lié.</Empty> : (
          <Table head={["Date", "Type", "Lieu", "Montant", "Appareil", "Score"]}>
            {a.events.map((e) => (
              <tr key={e.id}><Td className="whitespace-nowrap text-ink-soft">{dateTime(e.timestamp)}</Td>
                <Td className="font-mono text-xs">{e.type}</Td><Td>{e.location ?? "—"}</Td>
                <Td className="tabular">{e.amount ? xaf(e.amount) : "—"}</Td><Td>{e.device ?? "—"}</Td><Td className="tabular">{e.risk_score ?? "—"}</Td></tr>
            ))}
          </Table>
        )}
      </Panel>

      <Panel title="Actions de sécurité" className="mt-5">
        {!a.actions.length ? <Empty>Aucune action exécutée.</Empty> : (
          <Table head={["Date", "Action", "Cible", "Statut", "Justification", ""]}>
            {a.actions.map((x) => (
              <tr key={x.id}><Td className="whitespace-nowrap text-ink-soft">{dateTime(x.created_at)}</Td><Td className="font-mono text-xs">{x.type}</Td>
                <Td className="font-mono text-xs">{x.target_id.slice(0, 8)}…</Td><Td><Badge value={x.status} /></Td>
                <Td>{x.justification ?? "Automatique (politique)"}</Td>
                <Td className="text-right">{canAct && x.status === "EXECUTED" && x.type !== "REVOKE_SESSION" && x.type !== "NOTIFY_CUSTOMER" &&
                  <Btn tone="ghost" onClick={() => revert.mutate(x.id)}>Annuler</Btn>}</Td></tr>
            ))}
          </Table>
        )}
        {canAct && !closed && (
          <form className="mt-4 grid gap-3 border-t border-rule pt-4 md:grid-cols-4" onSubmit={(e) => { e.preventDefault(); run.mutate(); }}>
            <Field id="atype" label="Action"><Select id="atype" value={act.type} onChange={(e) => setAct({ ...act, type: e.target.value })}>
              {[...ACTIONS, ...(canAdmin ? ADMIN_ACTIONS : [])].map(([k, l]) => <option key={k} value={k}>{l}</option>)}</Select></Field>
            <Field id="atarget" label="Identifiant de la cible"><TextInput id="atarget" className="font-mono text-sm" value={act.target} onChange={(e) => setAct({ ...act, target: e.target.value })} /></Field>
            <Field id="awhy" label="Justification"><TextInput id="awhy" value={act.why} onChange={(e) => setAct({ ...act, why: e.target.value })} /></Field>
            <div className="flex items-end"><Btn type="submit" disabled={run.isPending || act.target.length < 30 || act.why.trim().length < 3}>Exécuter</Btn></div>
          </form>
        )}
      </Panel>
    </>
  );
}
