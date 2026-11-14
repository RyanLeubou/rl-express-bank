import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useAuth } from "../../auth/AuthContext";
import { Badge, Btn, Empty, ErrorLine, Field, PageTitle, Panel, Table, TextInput, Td } from "../../components/ui/kit";
import { useGuarded } from "../../components/ui/StepUp";
import { dateTime, xaf } from "../../lib/format";
import { toApiError } from "../../services/api";
import { bank } from "../../services/bank";
import { TotpKey } from "../../components/ui/TotpKey";
import { confirmEnrollment, fetchSessions, revokeSession, startEnrollment, type EnrollStart } from "../../services/auth";

function TotpSetup() {
  const { refreshIdentity } = useAuth();
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [secret, setSecret] = useState<EnrollStart | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const start = useMutation({ mutationFn: () => startEnrollment(password), onSuccess: (r) => { setSecret(r); setPassword(""); } });
  const confirm = useMutation({
    mutationFn: () => confirmEnrollment(code),
    onSuccess: async (r) => { setCodes(r.recovery_codes); setSecret(null); setCode(""); await refreshIdentity(); },
    onError: () => setCode(""),
  });
  const error = start.error ?? confirm.error;
  return (
    <div className="space-y-3">
      <ErrorLine message={error ? toApiError(error).message : null} />
      {codes.length > 0 && (
        <div>
          <p className="text-sm">Codes de secours (affichés une seule fois) :</p>
          <ul className="tabular mt-2 grid grid-cols-2 gap-2 rounded-lg border border-rule bg-mist p-3 text-center font-mono font-bold">
            {codes.map((c) => <li key={c}>{c}</li>)}
          </ul>
        </div>
      )}
      {!secret && codes.length === 0 && (
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); start.mutate(); }}>
          <p className="text-sm text-ink-soft">Active un code à 6 chiffres requis pour les opérations sensibles.</p>
          <Field id="pw" label="Mot de passe actuel">
            <TextInput id="pw" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          <Btn type="submit" disabled={!password || start.isPending}>Activer la double authentification</Btn>
        </form>
      )}
      {secret && (
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); confirm.mutate(); }}>
          <TotpKey enroll={secret} />
          <Field id="tc" label="Puis saisissez le code à 6 chiffres affiché par l'application">
            <TextInput id="tc" inputMode="numeric" maxLength={6} className="tabular" value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
          </Field>
          <Btn type="submit" disabled={code.length !== 6 || confirm.isPending}>Confirmer</Btn>
        </form>
      )}
    </div>
  );
}

export function SecurityPage() {
  const { auth } = useAuth();
  const qc = useQueryClient();
  const run = useGuarded();
  const devices = useQuery({ queryKey: ["devices"], queryFn: bank.devices });
  const sessions = useQuery({ queryKey: ["sessions"], queryFn: fetchSessions });
  const events = useQuery({ queryKey: ["own-events"], queryFn: bank.ownEvents });
  const refresh = () => void qc.invalidateQueries();
  const trust = useMutation({ mutationFn: (id: string) => run(bank.trustDevice(id)), onSuccess: refresh });
  const revokeDev = useMutation({ mutationFn: bank.revokeDevice, onSuccess: refresh });
  const revokeSess = useMutation({ mutationFn: revokeSession, onSuccess: refresh });
  const mfa = auth.status === "authenticated" && auth.me.user.mfa_enabled;
  const error = trust.error ?? revokeDev.error ?? revokeSess.error;

  return (
    <>
      <PageTitle sub="Appareils, sessions et historique de sécurité. Révoquez tout ce que vous ne reconnaissez pas.">Sécurité</PageTitle>
      <ErrorLine message={error ? toApiError(error).message : null} />
      <div className="mt-4 grid gap-5 lg:grid-cols-2">
        <Panel title="Double authentification" action={<Badge value={mfa ? "ACTIVE" : "PENDING"} />}>
          {mfa ? <p className="text-sm text-ink-soft">Activée. Elle est demandée pour les opérations sensibles.</p> : <TotpSetup />}
        </Panel>
        <Panel title="Sessions actives">
          <ul className="divide-y divide-rule">
            {sessions.data?.map((s) => (
              <li key={s.id} className="flex items-center justify-between gap-3 py-2.5">
                <div>
                  <p className="font-semibold">{s.device ?? "Appareil inconnu"}{s.current && " (cette session)"}</p>
                  <p className="tabular text-xs text-ink-soft">{s.ip ?? "IP inconnue"} · {dateTime(s.last_activity)}</p>
                </div>
                {!s.current && <Btn tone="danger" onClick={() => revokeSess.mutate(s.id)}>Révoquer</Btn>}
              </li>
            ))}
          </ul>
        </Panel>
      </div>
      <Panel title="Mes appareils" className="mt-5">
        {!devices.data?.length ? <Empty>Aucun appareil.</Empty> : (
          <Table head={["Appareil", "Lieu", "Dernière activité", "Statut", ""]}>
            {devices.data.map((d) => (
              <tr key={d.id}>
                <Td className="font-semibold">{d.name}{d.current && " (actuel)"}</Td><Td>{d.city ?? "—"}</Td>
                <Td className="text-ink-soft">{dateTime(d.last_seen)}</Td><Td><Badge value={d.status} /></Td>
                <Td className="space-x-2 text-right">
                  {d.status !== "TRUSTED" && d.status !== "BLOCKED" && mfa &&
                    <Btn tone="ghost" onClick={() => trust.mutate(d.id)}>Faire confiance</Btn>}
                  {!d.current && d.status !== "BLOCKED" && <Btn tone="danger" onClick={() => revokeDev.mutate(d.id)}>Révoquer</Btn>}
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
      <Panel title="Mon historique de sécurité" className="mt-5">
        {!events.data?.length ? <Empty>Aucun événement.</Empty> : (
          <Table head={["Date", "Événement", "Lieu", "Montant", "Niveau"]}>
            {events.data.map((e) => (
              <tr key={e.id}>
                <Td className="whitespace-nowrap text-ink-soft">{dateTime(e.date)}</Td><Td className="font-mono text-xs">{e.type}</Td>
                <Td>{e.location ?? "—"}</Td><Td className="tabular">{e.amount ? xaf(e.amount) : "—"}</Td>
                <Td><Badge value={e.severity} kind="severity" /></Td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </>
  );
}
