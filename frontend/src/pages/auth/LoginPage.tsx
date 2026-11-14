import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router";
import { useAuth } from "../../auth/AuthContext";
import { BrandMark } from "../../components/ui/BrandMark";
import { TotpKey } from "../../components/ui/TotpKey";
import { toApiError } from "../../services/api";
import { confirmEnrollment, login, startEnrollment, verifyMfa, type EnrollStart } from "../../services/auth";

type Step = "password" | "mfa" | "enroll" | "recovery";

export const INPUT = "mt-1 block w-full rounded-lg border border-rule bg-white px-3 py-2.5 text-base";
export const PRIMARY = "w-full rounded-lg bg-lagoon px-4 py-3 font-semibold text-white hover:bg-lagoon-deep " +
  "disabled:cursor-not-allowed disabled:opacity-60";

export function Field({ id, label, children }: { id: string; label: string; children: ReactNode }) {
  return (
    <div>
      <label htmlFor={id} className="text-sm font-semibold">{label}</label>
      {children}
    </div>
  );
}

export function LoginPage() {
  const { refreshIdentity } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const destination = (location.state as { from?: string } | null)?.from ?? "/espace";

  const [step, setStep] = useState<Step>("password");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [trust, setTrust] = useState(false);
  const [enroll, setEnroll] = useState<EnrollStart | null>(null);
  const [recovery, setRecovery] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => { heading.current?.focus(); }, [step]);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (raised) {
      const err = toApiError(raised);
      setCode("");                                        // un code refusé n'est jamais conservé
      if (err.code === "mfa_session_invalid") setStep("password");   // défi expiré : retour au mot de passe
      setError(err.retryAfter ? `${err.message} (environ ${err.retryAfter} s)` : err.message);
    } finally {
      setBusy(false);
    }
  }

  async function finish() {
    await refreshIdentity();
    navigate(destination, { replace: true });
  }

  const onPassword = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const result = await login(email, password);
      setPassword("");                                        // le mot de passe ne reste pas en mémoire de l'interface
      if (result.status === "authenticated") return finish();
      if (result.status === "mfa_required") { setStep("mfa"); return; }
      setEnroll(await startEnrollment());                     // personnel : activation obligatoire du TOTP
      setStep("enroll");
    });
  };

  const onVerify = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => { await verifyMfa(code, trust); setCode(""); await finish(); });
  };

  const onConfirm = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const done = await confirmEnrollment(code);
      setCode("");
      setRecovery(done.recovery_codes);
      setStep("recovery");
    });
  };

  const titles: Record<Step, string> = {
    password: "Connexion à votre espace",
    mfa: "Vérification en deux étapes",
    enroll: "Activez la vérification en deux étapes",
    recovery: "Conservez vos codes de secours",
  };

  return (
    <main className="mx-auto flex min-h-screen max-w-md flex-col px-5 py-10 sm:py-16">
      <header className="flex items-center gap-4">
        <BrandMark className="h-11 w-11" />
        <div>
          <p className="text-xl font-bold tracking-tight">RL EXPRESS BANK</p>
          <p className="text-sm text-ink-soft">Banque virtuelle</p>
        </div>
      </header>

      <section aria-labelledby="login-title" className="mt-10 rounded-2xl bg-paper px-6 py-7 shadow-[0_1px_0_#d5dfe2]">
        <h1 id="login-title" ref={heading} tabIndex={-1}
          className="border-b-2 border-ink pb-4 text-2xl font-bold leading-tight tracking-tight outline-none">
          {titles[step]}
        </h1>

        {error && <p role="alert" className="mt-5 border-l-4 border-laterite pl-4 font-semibold">{error}</p>}

        {step === "password" && (
          <form onSubmit={onPassword} className="mt-6 space-y-5" noValidate>
            <Field id="email" label="Adresse e-mail">
              <input id="email" type="text" inputMode="email" autoComplete="username" required value={email}
                onChange={(e) => setEmail(e.target.value)} className={INPUT} />
            </Field>
            <Field id="password" label="Mot de passe">
              <input id="password" type="password" autoComplete="current-password" required value={password}
                onChange={(e) => setPassword(e.target.value)} className={INPUT} />
            </Field>
            <button type="submit" disabled={busy || !email || !password} className={PRIMARY}>
              {busy ? "Vérification…" : "Se connecter"}
            </button>
            <p className="text-center text-sm text-ink-soft">
              Pas encore client ?{" "}
              <Link to="/inscription" className="font-semibold text-lagoon underline">Ouvrir un compte</Link>
            </p>
          </form>
        )}

        {step === "mfa" && (
          <form onSubmit={onVerify} className="mt-6 space-y-5" noValidate>
            <p className="text-ink-soft">
              Saisissez le code à 6 chiffres de votre application d'authentification, ou un code de secours.
            </p>
            <Field id="code" label="Code de vérification">
              <input id="code" type="text" inputMode="text" autoComplete="one-time-code" required value={code}
                onChange={(e) => setCode(e.target.value)} className={`${INPUT} tabular tracking-widest`} />
            </Field>
            <label className="flex items-start gap-3 text-sm">
              <input type="checkbox" checked={trust} onChange={(e) => setTrust(e.target.checked)}
                className="mt-1 h-4 w-4" />
              <span>Faire confiance à cet appareil : le code ne sera plus demandé ici pour la connexion.</span>
            </label>
            <button type="submit" disabled={busy || code.trim().length < 6} className={PRIMARY}>
              {busy ? "Vérification…" : "Valider"}
            </button>
          </form>
        )}

        {step === "enroll" && enroll && (
          <form onSubmit={onConfirm} className="mt-6 space-y-5" noValidate>
            <p className="text-ink-soft">
              Votre profil exige un second facteur. Ajoutez ce compte dans une application d'authentification
              (Google Authenticator, Aegis, 2FAS…) en scannant le QR code ci-dessous, puis saisissez le code affiché.
            </p>
            <TotpKey enroll={enroll} />
            <Field id="enroll-code" label="Code à 6 chiffres">
              <input id="enroll-code" type="text" inputMode="numeric" autoComplete="one-time-code" maxLength={6}
                required value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                className={`${INPUT} tabular tracking-widest`} />
            </Field>
            <button type="submit" disabled={busy || code.length !== 6} className={PRIMARY}>
              {busy ? "Vérification…" : "Activer et continuer"}
            </button>
          </form>
        )}

        {step === "recovery" && (
          <div className="mt-6 space-y-5">
            <p className="text-ink-soft">
              Ces codes à usage unique permettent de vous connecter si vous perdez votre téléphone.
              Ils ne seront <strong>plus jamais affichés</strong> : enregistrez-les maintenant dans un endroit sûr.
            </p>
            <ul data-testid="recovery-codes" className="tabular grid grid-cols-2 gap-2 rounded-lg border border-rule
              bg-mist p-4 text-center font-mono text-base font-bold">
              {recovery.map((c) => <li key={c}>{c}</li>)}
            </ul>
            <button type="button" className={PRIMARY} disabled={busy} onClick={() => void run(finish)}>
              J'ai conservé mes codes, continuer
            </button>
          </div>
        )}
      </section>
    </main>
  );
}
