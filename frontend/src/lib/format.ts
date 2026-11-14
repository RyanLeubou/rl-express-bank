const TZ = "Africa/Douala";

export const xaf = (n: number): string => `${n.toLocaleString("fr-FR")} XAF`;
export const dateTime = (iso: string | null | undefined): string =>
  iso ? new Date(iso).toLocaleString("fr-FR", { timeZone: TZ, dateStyle: "short", timeStyle: "short" }) : "—";
export const day = (iso: string): string =>
  new Date(iso).toLocaleDateString("fr-FR", { timeZone: TZ, dateStyle: "medium" });

export const SEVERITY_LABEL: Record<string, string> = {
  INFO: "Info", LOW: "Faible", MEDIUM: "Moyenne", HIGH: "Élevée", CRITICAL: "Critique",
};
export const STATUS_LABEL: Record<string, string> = {
  NEW: "Nouvelle", TRIAGED: "Triée", INVESTIGATING: "En investigation", RESOLVED: "Résolue",
  FALSE_POSITIVE: "Faux positif", COMPLETED: "Effectué", PENDING: "En attente", BLOCKED: "Bloqué",
  FAILED: "Échoué", CANCELLED: "Annulé", APPROVED: "Approuvé", DECLINED: "Refusé", ACTIVE: "Actif",
  PENDING_VERIFICATION: "À vérifier", EXECUTED: "Exécutée", REVERTED: "Annulée", OPEN: "Ouvert",
  IN_PROGRESS: "En cours", CLOSED: "Clos", ONLINE: "En ligne", OFFLINE: "Hors ligne",
  MAINTENANCE: "Maintenance", SUSPICIOUS: "Suspect", TRUSTED: "De confiance", NEW_DEVICE: "Nouveau",
  DISABLED: "Désactivé", LOCKED: "Verrouillé", SUSPENDED: "Suspendu",
};
export const label = (v: string): string => STATUS_LABEL[v] ?? v;
