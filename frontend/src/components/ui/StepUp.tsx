import { createContext, useCallback, useContext, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router";
import { useAuth } from "../../auth/AuthContext";
import { ApiError, api, toApiError } from "../../services/api";
import { Btn, ErrorLine, Field, TextInput } from "./kit";

export interface OpResult {
  status: "completed" | "step_up_required" | "blocked";
  challenge_id?: string;
  [key: string]: unknown;
}
type Run = (call: () => Promise<{ data: OpResult }>) => Promise<OpResult>;

const StepUpContext = createContext<Run | null>(null);

/**
 * Fournit `useGuarded()` : exécute une opération et, si le serveur répond « authentification renforcée requise »
 * (HTTP 202), ouvre la fenêtre de saisie du code TOTP puis retourne le résultat final de l'opération.
 */
export function StepUpProvider({ children }: { children: ReactNode }) {
  const { auth } = useAuth();
  // Sans TOTP activé, aucun code ne peut être valide : on oriente vers l'activation au lieu d'un champ inutile
  const noMfa = auth.status === "authenticated" && !auth.me.user.mfa_enabled;
  const [challenge, setChallenge] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const pending = useRef<{ resolve: (r: OpResult) => void; reject: (e: unknown) => void } | null>(null);

  const run = useCallback<Run>(async (call) => {
    const first = (await call()).data;
    if (first.status !== "step_up_required" || !first.challenge_id) return first;
    return new Promise<OpResult>((resolve, reject) => {
      pending.current = { resolve, reject };
      setCode("");
      setError(null);
      setChallenge(first.challenge_id ?? null);
    });
  }, []);

  const close = () => { setChallenge(null); pending.current = null; };

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!challenge) return;
    setBusy(true);
    setError(null);
    try {
      const done = (await api.post<OpResult>(`/step-up/${challenge}/verify`, { code })).data;
      pending.current?.resolve(done);
      close();
    } catch (raised) {
      const err = toApiError(raised);
      setCode("");
      if (err.status === 404 || err.status === 410) { pending.current?.reject(err); close(); }
      else setError(err.retryAfter ? `${err.message} (environ ${err.retryAfter} s)` : err.message);
    } finally {
      setBusy(false);
    }
  }

  function cancel() {
    pending.current?.reject(new ApiError(0, "cancelled", "Opération annulée."));
    close();
  }

  return (
    <StepUpContext.Provider value={run}>
      {children}
      {challenge && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/60 px-4" role="presentation">
          <form onSubmit={submit} role="dialog" aria-modal="true" aria-labelledby="stepup-title"
            className="w-full max-w-sm space-y-4 rounded-2xl bg-paper p-6 shadow-xl">
            <h2 id="stepup-title" className="text-xl font-bold">
              {noMfa ? "Activez la double authentification" : "Confirmez avec votre code"}
            </h2>
            {noMfa ? (<>
            <p className="text-sm text-ink-soft">
              Cette opération demande une vérification par code, mais la double authentification n'est pas encore
              activée sur votre compte. Activez-la dans la page Sécurité avec une application d'authentification
              (Google Authenticator, Aegis, 2FAS…), puis recommencez l'opération.
            </p>
            <div className="flex justify-end gap-3">
              <Btn tone="ghost" onClick={cancel}>Annuler</Btn>
              <Link to="/espace/securite" onClick={cancel}
                className="rounded-lg bg-lagoon px-4 py-2 text-sm font-semibold text-white hover:bg-lagoon-deep">
                Activer maintenant
              </Link>
            </div>
            </>) : (<>
            <p className="text-sm text-ink-soft">
              Par précaution, cette opération demande une vérification. Saisissez le code à 6 chiffres de votre
              application d'authentification. Un nouveau code est nécessaire à chaque vérification.
            </p>
            <ErrorLine message={error} />
            <Field id="stepup-code" label="Code à 6 chiffres">
              <TextInput id="stepup-code" autoFocus inputMode="numeric" autoComplete="one-time-code" maxLength={6}
                value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} className="tabular tracking-widest" />
            </Field>
            <div className="flex justify-end gap-3">
              <Btn tone="ghost" onClick={cancel}>Annuler</Btn>
              <Btn type="submit" disabled={busy || code.length !== 6}>{busy ? "Vérification…" : "Confirmer"}</Btn>
            </div>
            </>)}
          </form>
        </div>
      )}
    </StepUpContext.Provider>
  );
}

export function useGuarded(): Run {
  const run = useContext(StepUpContext);
  if (!run) throw new Error("useGuarded doit être utilisé dans <StepUpProvider>");
  return run;
}
