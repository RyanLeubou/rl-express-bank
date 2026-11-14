import { useQuery } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { useAuth } from "../../auth/AuthContext";
import { BrandMark } from "../../components/ui/BrandMark";
import { toApiError } from "../../services/api";
import { fetchCities, register, type RegisterInput, type RegisterResult } from "../../services/auth";
import { Field, INPUT, PRIMARY } from "./LoginPage";

type Form = Omit<RegisterInput, "password">;

// Même règle que l'API : elle reste seule juge, ce contrôle n'évite qu'un aller-retour
function passwordProblem(password: string): string | null {
  if (password.length < 12) return "Au moins 12 caractères.";
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password))
    return "Au moins une majuscule, une minuscule et un chiffre.";
  return null;
}

export function RegisterPage() {
  const { refreshIdentity } = useAuth();
  const navigate = useNavigate();
  const cities = useQuery({ queryKey: ["register-cities"], queryFn: fetchCities, staleTime: Infinity });
  const [form, setForm] = useState<Form>({
    first_name: "", last_name: "", address: "", city: "", phone: "", email: "", profession: "",
  });
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState<RegisterResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const set = (key: keyof Form) => (e: { target: { value: string } }) => setForm((f) => ({ ...f, [key]: e.target.value }));
  const agency = cities.data?.find((c) => c.city === form.city);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const problem = passwordProblem(password) ?? (password !== confirm ? "Les mots de passe ne correspondent pas." : null);
    if (problem) { setError(problem); return; }
    setBusy(true);
    setError(null);
    void (async () => {
      try {
        const result = await register({ ...form, password });
        setPassword("");
        setConfirm("");
        setDone(result);
      } catch (raised) {
        const err = toApiError(raised);
        setError(err.retryAfter ? `${err.message} (environ ${err.retryAfter} s)` : err.message);
      } finally {
        setBusy(false);
      }
    })();
  };

  const enter = () => {
    setBusy(true);
    void refreshIdentity().then(() => navigate("/espace", { replace: true }));
  };

  const complete = Object.values(form).every((v) => v.trim()) && password && confirm;

  return (
    <main className="mx-auto flex min-h-screen max-w-lg flex-col px-5 py-10 sm:py-16">
      <header className="flex items-center gap-4">
        <BrandMark className="h-11 w-11" />
        <div>
          <p className="text-xl font-bold tracking-tight">RL EXPRESS BANK</p>
          <p className="text-sm text-ink-soft">Banque virtuelle</p>
        </div>
      </header>

      <section aria-labelledby="register-title" className="mt-10 rounded-2xl bg-paper px-6 py-7 shadow-[0_1px_0_#d5dfe2]">
        <h1 id="register-title" className="border-b-2 border-ink pb-4 text-2xl font-bold leading-tight tracking-tight">
          {done ? "Votre compte est ouvert" : "Ouvrir un compte"}
        </h1>

        {error && <p role="alert" className="mt-5 border-l-4 border-laterite pl-4 font-semibold">{error}</p>}

        {done ? (
          <div className="mt-6 space-y-5">
            <dl className="grid gap-3 rounded-lg border border-rule bg-mist p-4 text-sm">
              <div><dt className="text-ink-soft">IBAN</dt><dd className="tabular font-bold tracking-wide">{done.iban}</dd></div>
              <div><dt className="text-ink-soft">Agence</dt>
                <dd className="font-semibold">{done.agency} · code guichet <span className="tabular">{done.branch_code}</span></dd></div>
            </dl>
            <div className="rounded-lg border-2 border-ink p-4">
              <p className="text-sm text-ink-soft">Code PIN de votre carte</p>
              <p data-testid="card-pin" className="tabular mt-1 text-3xl font-bold tracking-[0.4em]">{done.card_pin}</p>
              <p className="mt-2 text-sm">
                Il ne sera <strong>plus jamais affiché</strong> : mémorisez-le maintenant. Il vous servira aux
                distributeurs et pour les paiements.
              </p>
            </div>
            <button type="button" className={PRIMARY} disabled={busy} onClick={enter}>
              J'ai mémorisé mon code, accéder à mon espace
            </button>
          </div>
        ) : (
          <form onSubmit={onSubmit} className="mt-6 space-y-5" noValidate>
            <div className="grid grid-cols-2 gap-4">
              <Field id="last_name" label="Nom">
                <input id="last_name" autoComplete="family-name" required maxLength={80} value={form.last_name}
                  onChange={set("last_name")} className={INPUT} />
              </Field>
              <Field id="first_name" label="Prénom">
                <input id="first_name" autoComplete="given-name" required maxLength={80} value={form.first_name}
                  onChange={set("first_name")} className={INPUT} />
              </Field>
            </div>
            <Field id="address" label="Adresse">
              <input id="address" autoComplete="street-address" required maxLength={200} value={form.address}
                placeholder="Rue, quartier" onChange={set("address")} className={INPUT} />
            </Field>
            <Field id="city" label="Ville">
              <select id="city" required value={form.city} onChange={set("city")} className={INPUT}
                aria-describedby="agency-help">
                <option value="" disabled>Choisissez votre ville</option>
                {cities.data?.map((c) => <option key={c.city}>{c.city}</option>)}
              </select>
              <p id="agency-help" className="mt-1 text-sm text-ink-soft">
                {agency ? `Agence attribuée : ${agency.agency} (code guichet ${agency.branch_code})`
                  : "Votre agence et votre RIB sont attribués selon votre ville."}
              </p>
            </Field>
            <div className="grid grid-cols-2 gap-4">
              <Field id="phone" label="Téléphone">
                <input id="phone" type="tel" autoComplete="tel" required placeholder="+237 6…" value={form.phone}
                  onChange={set("phone")} className={INPUT} />
              </Field>
              <Field id="profession" label="Profession">
                <input id="profession" autoComplete="organization-title" required maxLength={80} value={form.profession}
                  onChange={set("profession")} className={INPUT} />
              </Field>
            </div>
            <Field id="email" label="Adresse e-mail">
              <input id="email" type="email" autoComplete="email" required value={form.email}
                onChange={set("email")} className={INPUT} />
            </Field>
            <Field id="password" label="Mot de passe">
              <input id="password" type="password" autoComplete="new-password" required value={password}
                onChange={(e) => setPassword(e.target.value)} className={INPUT} aria-describedby="password-help" />
              <p id="password-help" className="mt-1 text-sm text-ink-soft">
                12 caractères minimum, avec une majuscule, une minuscule et un chiffre.
              </p>
            </Field>
            <Field id="confirm" label="Confirmer le mot de passe">
              <input id="confirm" type="password" autoComplete="new-password" required value={confirm}
                onChange={(e) => setConfirm(e.target.value)} className={INPUT} />
            </Field>
            <p className="text-sm text-ink-soft">
              Un compte courant, son RIB et votre carte de débit sont créés automatiquement. Vous pourrez ensuite ouvrir un livret épargne depuis votre espace.
            </p>
            <button type="submit" disabled={busy || !complete} className={PRIMARY}>
              {busy ? "Création du compte…" : "Créer mon compte"}
            </button>
            <p className="text-center text-sm text-ink-soft">
              Déjà client ?{" "}
              <Link to="/connexion" className="font-semibold text-lagoon underline">Se connecter</Link>
            </p>
          </form>
        )}
      </section>
    </main>
  );
}
