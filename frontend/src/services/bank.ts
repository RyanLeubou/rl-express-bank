import { api } from "./api";
import type { OpResult } from "../components/ui/StepUp";

// RL SOLUTION : la réponse du LLM peut dépasser le délai global d'axios (10 s). Aligné sur LLM_TIMEOUT_SECONDS
// (30 s) plus une marge pour la lecture des fiches et l'enregistrement.
const ASSISTANT_TIMEOUT_MS = 45_000;

export interface Account {
  id: string; label: string; type: string; balance: number; available_balance: number; currency: string;
  status: string; iban_masked: string; account_number_last4: string;
}
export interface Entry { seq: number; date: string; amount: number; balance_after: number; type: string; description: string }
export interface BeneficiaryDetail {
  id: string; first_name: string; last_name: string; bank_name: string; iban: string; status: string; internal: boolean;
  created_at: string; activated_at: string | null;
  transfers: { id: string; amount: number; reference: string; status: string; created_at: string }[];
}
export interface Beneficiary {
  id: string; name: string; bank_name: string; iban_masked: string; status: string; internal: boolean; activated_at: string | null;
}
export interface Transfer {
  id: string; direction: "IN" | "OUT"; amount: number; reference: string; status: string; counterparty: string | null;
  created_at: string; executed_at: string | null; risk_level: string | null;
}
export interface TransferDetail {
  id: string; direction: "IN" | "OUT"; amount: number; currency: string; reference: string; status: string;
  created_at: string; executed_at: string | null; account: { label: string; iban_masked: string };
  counterparty: { name: string; bank: string | null; iban: string | null; internal: boolean };
  risk_level?: string | null; risk_score?: number | null; failure_reason?: string | null; balance_after?: number;
}
export interface CardDetails { pan: string; cvv: string; expiry: string; holder: string }
export interface Card {
  id: string; masked_pan: string; holder: string; type: string; expiry: string; status: string;
  blocked_reason: string | null; account_id: string; daily_withdrawal_limit: number; daily_payment_limit: number;
}
export interface Payment { id: string; merchant: string; category: string; city: string; amount: number; status: string; date: string }
export interface Withdrawal { id: string; type: string; amount: number; status: string; city: string | null; created_at: string }
export interface Atm { id: string; code: string; name: string; city: string; status: string }
export interface Rib {
  holder: string; bank: string; bank_code: string; branch_code: string; account_number: string; rib_key: string; iban: string; bic: string;
}
export interface Notice { id: string; type: string; title: string; body: string; severity: string; created_at: string; read: boolean }
export interface DeviceInfo { id: string; name: string; os: string | null; browser: string | null; status: string; city: string | null; last_seen: string; current: boolean }
export interface OwnEvent { id: string; type: string; severity: string; date: string; location: string | null; amount: number | null }
export interface ChatMessage { id: string; author: "CUSTOMER" | "BOT" | "AGENT" | "SYSTEM"; content: string; at: string }
export interface Conversation { id: string; topic: string; status: string; scam_signal: boolean; messages?: ChatMessage[] }

const get = <T>(url: string) => api.get<T>(url).then((r) => r.data);
const idem = () => ({ headers: { "Idempotency-Key": crypto.randomUUID() } });

export const bank = {
  accounts: () => get<Account[]>("/accounts"),
  transactions: (id: string) => get<Entry[]>(`/accounts/${id}/transactions?limit=40`),
  rib: (id: string) => get<Rib>(`/accounts/${id}/rib`),
  ribEvent: (id: string, action: "copied" | "downloaded") => api.post(`/accounts/${id}/rib/event`, { action }),
  beneficiaries: () => get<Beneficiary[]>("/beneficiaries"),
  addBeneficiary: (body: { first_name: string; last_name: string; bank_name: string; iban: string }) =>
    () => api.post<OpResult>("/beneficiaries", body),
  beneficiary: (id: string) => get<BeneficiaryDetail>(`/beneficiaries/${id}`),
  verifyBeneficiary: (id: string) => () => api.post<OpResult>(`/beneficiaries/${id}/verify`),
  deleteBeneficiary: (id: string) => api.delete(`/beneficiaries/${id}`),
  transfers: () => get<Transfer[]>("/transfers?limit=50"),
  /** Avis de virement (PDF) : fichier prêt à télécharger ou à partager. */
  transferReceipt: async (t: Transfer): Promise<File> => {
    const path = t.direction === "OUT" ? `/transfers/sent/${t.id}` : `/transfers/received/${t.id}`;
    const r = await api.get<Blob>(`${path}/receipt.pdf`, { responseType: "blob" });
    const name = /filename="([^"]+)"/.exec(String(r.headers["content-disposition"] ?? ""))?.[1] ?? "avis-virement.pdf";
    return new File([r.data], name, { type: "application/pdf" });
  },
  transferDetail: (t: Transfer) =>
    get<TransferDetail>(t.direction === "OUT" ? `/transfers/sent/${t.id}` : `/transfers/received/${t.id}`),
  transfer: (body: { source_account_id: string; beneficiary_id: string; amount: number; reference: string }) =>
    () => api.post<OpResult>("/transfers", body, idem()),
  openSavings: () => api.post<Account>("/accounts/savings").then((r) => r.data),
  cards: () => get<Card[]>("/cards"),
  cardDetails: (id: string) => get<CardDetails>(`/cards/${id}/details`),
  blockCard: (id: string) => api.post(`/cards/${id}/block`),
  unblockCard: (id: string) => () => api.post<OpResult>(`/cards/${id}/unblock`),
  payments: () => get<Payment[]>("/payments"),
  pay: (body: { card_id: string; amount: number; merchant: string; category: string; city: string }) =>
    () => api.post<OpResult>("/payments", body, idem()),
  atms: () => get<Atm[]>("/atms"),
  withdrawals: () => get<Withdrawal[]>("/withdrawals"),
  withdraw: (body: Record<string, unknown>) => () => api.post<OpResult>("/withdrawals", body, idem()),
  cancelCardless: (id: string) => api.post(`/withdrawals/${id}/cancel`),
  devices: () => get<DeviceInfo[]>("/devices"),
  trustDevice: (id: string) => () => api.post<OpResult>(`/devices/${id}/trust`),
  revokeDevice: (id: string) => api.delete(`/devices/${id}`),
  notifications: () => get<Notice[]>("/notifications"),
  readNotification: (id: string) => api.post(`/notifications/${id}/read`),
  ownEvents: () => get<OwnEvent[]>("/me/security-events"),
  conversations: () => get<Conversation[]>("/support/conversations"),
  conversation: (id: string) => get<Conversation>(`/support/conversations/${id}`),
  startConversation: (topic: string, message: string) =>
    api.post<Conversation>("/support/conversations", { topic, message }, { timeout: ASSISTANT_TIMEOUT_MS })
      .then((r) => r.data),
  sendMessage: (id: string, message: string) =>
    api.post<Conversation>(`/support/conversations/${id}/messages`, { message }, { timeout: ASSISTANT_TIMEOUT_MS })
      .then((r) => r.data),
};
