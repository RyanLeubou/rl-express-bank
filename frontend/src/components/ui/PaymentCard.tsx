import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { bank, type Card } from "../../services/bank";

const REVEAL_SECONDS = 30;   // les données sensibles se masquent d'elles-mêmes

/** Bouton « œil » : affiche ou masque une information. */
export function EyeToggle({ shown, onToggle, label, className = "" }: {
  shown: boolean; onToggle: () => void; label: string; className?: string;
}) {
  return (
    <button type="button" onClick={onToggle} aria-pressed={shown}
      aria-label={`${shown ? "Masquer" : "Afficher"} ${label}`} title={`${shown ? "Masquer" : "Afficher"} ${label}`}
      className={`inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full hover:bg-black/10 ${className}`}>
      <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2"
        strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" />
        <circle cx="12" cy="12" r="3" />
        {shown && <path d="M3 3l18 18" />}
      </svg>
    </button>
  );
}

/** Carte bancaire avec révélation du numéro complet et du CVV (chaque affichage est tracé côté API). */
export function PaymentCard({ card }: { card: Card }) {
  const [shown, setShown] = useState(false);
  const details = useQuery({
    queryKey: ["card-details", card.id], queryFn: () => bank.cardDetails(card.id),
    enabled: shown, gcTime: 0, staleTime: 0,          // jamais gardé en cache une fois masqué
  });

  useEffect(() => {
    if (!shown) return;
    const timer = setTimeout(() => setShown(false), REVEAL_SECONDS * 1000);
    return () => clearTimeout(timer);
  }, [shown]);

  const visible = shown && details.data;
  return (
    <div className="rounded-xl bg-ink p-5 text-white">
      <div className="flex items-start justify-between">
        <p className="text-xs uppercase tracking-widest text-white/60">{card.type === "PREMIUM" ? "Premium" : "Débit"}</p>
        <EyeToggle shown={shown} onToggle={() => setShown(!shown)} label="les informations de la carte"
          className="-mr-2 -mt-2 text-white" />
      </div>
      <p data-testid="card-pan" className="tabular mt-4 text-xl tracking-widest">
        {visible ? details.data.pan : card.masked_pan}
      </p>
      <div className="mt-4 flex items-end justify-between gap-4 text-sm">
        <span>{card.holder}</span>
        <span className="flex gap-4">
          <span><span className="block text-xs text-white/60">Expire</span><span className="tabular">{card.expiry}</span></span>
          <span><span className="block text-xs text-white/60">CVV</span>
            <span data-testid="card-cvv" className="tabular">{visible ? details.data.cvv : "•••"}</span></span>
        </span>
      </div>
      {shown && details.isPending && <p className="mt-3 text-xs text-white/60">Chargement…</p>}
      {shown && details.isError && <p role="alert" className="mt-3 text-xs">Impossible d'afficher les informations.</p>}
      {visible && <p className="mt-3 text-xs text-white/60">Masquage automatique dans {REVEAL_SECONDS} s.</p>}
    </div>
  );
}
