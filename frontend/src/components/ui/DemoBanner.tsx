/**
 * Bandeau permanent, sur toutes les pages : RL EXPRESS BANK est une banque fictive.
 * Sur une instance publique, il évite qu'un visiteur saisisse de vraies données et que le site soit pris
 * pour une page d'hameçonnage.
 */
export function DemoBanner() {
  return (
    <div role="note" aria-label="Avertissement"
      className="bg-saffron px-4 py-1.5 text-center text-xs font-semibold leading-snug text-white sm:text-sm">
      Démonstration pédagogique : RL EXPRESS BANK est une <strong>banque fictive</strong>.
      N'entrez aucune donnée réelle (identité, carte bancaire, mot de passe utilisé ailleurs).
    </div>
  );
}
