/**
 * Logo RL EXPRESS BANK : trident doré en perspective cavalière (fuyante à 45°).
 * Source unique : public/favicon.svg (icône sur fond Encre Wouri) et public/trident.svg (trident seul).
 * Servi en <img> : pas de collision d'identifiants de dégradé, compatible avec la CSP stricte (img-src 'self').
 */
export function BrandMark({ className = "h-10 w-10", bare = false }: { className?: string; bare?: boolean }) {
  return <img src={bare ? "/trident.svg" : "/favicon.svg"} alt="" aria-hidden="true" className={className} />;
}
