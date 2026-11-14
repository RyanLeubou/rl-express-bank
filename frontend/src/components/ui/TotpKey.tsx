import type { EnrollStart } from "../../services/auth";

/** Ajout du compte dans l'application d'authentification : QR code, lien direct (mobile) et clé manuelle. */
export function TotpKey({ enroll }: { enroll: EnrollStart }) {
  return (
    <div className="rounded-lg border border-rule bg-mist p-4">
      <ol className="list-decimal space-y-1 pl-5 text-sm">
        <li>Ouvrez votre application d'authentification (Google Authenticator, Microsoft Authenticator, Aegis, 2FAS…).</li>
        <li>Choisissez « Ajouter un compte » puis « Scanner un QR code ».</li>
      </ol>
      <img src={enroll.qr_code} alt="QR code à scanner avec votre application d'authentification"
        className="mx-auto my-4 h-48 w-48 rounded bg-white" />
      <a href={enroll.otpauth_uri}
        className="block rounded-lg bg-lagoon px-4 py-2.5 text-center text-sm font-semibold text-white hover:bg-lagoon-deep">
        Sur ce téléphone : ouvrir dans mon application
      </a>
      <p className="mt-4 text-sm text-ink-soft">Ou saisissez cette clé à la main (type « basé sur l'heure ») :</p>
      <p data-testid="totp-secret" className="tabular mt-1 break-all font-bold tracking-wider">
        {enroll.secret.match(/.{1,4}/g)?.join(" ")}
      </p>
    </div>
  );
}
