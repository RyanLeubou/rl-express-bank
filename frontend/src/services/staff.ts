import { api } from "./api";

export interface Alert {
  id: string; title: string; severity: string; risk_score: number | null; risk_level: string | null; status: string;
  source: string; user_id: string | null; user_label?: string | null; reasons: Reason[]; mitre: string[];
  assigned_to: string | null; investigation_id: string | null; resolution_note: string | null; created_at: string;
}
export interface Reason { code: string; points: number; detail: string }
export interface SecEvent {
  id: string; seq: number; timestamp: string; type: string; category: string; severity: string; user_id: string | null;
  ip: string | null; device: string | null; location: string | null; amount: number | null; status: string | null;
  risk_score: number | null; metadata: Record<string, unknown>;
}
export interface ActionRow {
  id: string; alert_id: string | null; type: string; target_type: string; target_id: string; status: string;
  justification: string | null; created_at: string;
}
export interface AlertDetail extends Alert {
  events: SecEvent[]; actions: ActionRow[];
  user: { id: string; name: string; email: string; type: string; status: string } | null;
}
export interface Stats {
  hours: number; alerts_by_severity: Record<string, number>; alerts_by_status: Record<string, number>;
  events_by_category: Record<string, number>; decisions: Record<string, number>;
  top_rules: { code: string; count: number }[]; blocked_operations: number; open_alerts: number;
  events_per_hour: { hour: string; count: number }[];
}
export interface Assessment {
  id: string; user_id: string; operation: string; score: number; level: string; decision: string;
  reasons: Reason[]; ai_score: number | null; model_version: string | null; degraded: boolean; created_at: string;
}
export interface Investigation { id: string; title: string; status: string; summary: string | null; created_at: string }
export interface Customer {
  user: { id: string; name: string; email?: string; city: string | null; status: string; type: string };
  accounts?: { id: string; label: string; balance: number; available: number; status: string; iban_masked: string }[];
  cards: { id: string; masked_pan: string; status: string; blocked_reason: string | null }[];
  devices: { id: string; name: string; status: string; city: string | null; last_seen: string }[];
  transfers: { id: string; amount: number; status: string; date: string; risk_score: number | null }[];
  payments: { id: string; merchant: string; amount: number; status: string; date: string }[];
  withdrawals: { id: string; type: string; amount: number; status: string; city: string | null; date: string }[];
}
export interface Rule { id: string; code: string; description: string; operations: string[]; weight: number; params: Record<string, unknown>; enabled: boolean; version: number }
export interface Policy { id: string; operation: string; level: string; decision: string; floor: string | null; actions: string[]; enabled: boolean; version: number }
export interface AdminUser { id: string; name: string; email: string; type: string; status: string; roles: string[]; last_login_at: string | null }
export interface AuditRow {
  seq: number; timestamp: string; actor_role: string | null; action: string; target_type: string; target_id: string | null;
  before: unknown; after: unknown; justification: string | null; hash: string;
}
export interface Ticket {
  id: string; category: string; priority: string; status: string; assigned_to_me: boolean; scam_signal: boolean;
  conversation_id: string; created_at: string;
}
export interface TicketDetail {
  id: string; category: string; priority: string; status: string; access_expires_at: string | null;
  conversation: { id: string; status: string; scam_signal: boolean };
  messages: { id: string; author: string; content: string; at: string }[];
}
export interface Scenario { id: string; description: string }
export interface Run { id: string; scenario: string; status: string; started_at: string; summary: { steps?: { step: string; score: number; level: string; decision: string; reasons: string[]; blocked: boolean }[]; alerts?: number; blocked?: number } }

const get = <T>(url: string, params?: Record<string, unknown>) => api.get<T>(url, { params }).then((r) => r.data);

export const staff = {
  stats: (hours = 24) => get<Stats>("/soc/stats", { hours }),
  alerts: (params: Record<string, unknown> = {}) => get<Alert[]>("/soc/alerts", params),
  alert: (id: string) => get<AlertDetail>(`/soc/alerts/${id}`),
  patchAlert: (id: string, body: Record<string, unknown>) => api.patch<Alert>(`/soc/alerts/${id}`, body).then((r) => r.data),
  action: (body: { action_type: string; target_id: string; justification: string }, alertId?: string, admin = false) =>
    api.post<ActionRow>(`${admin ? "/soc/admin-actions" : "/soc/actions"}${alertId ? `?alert_id=${alertId}` : ""}`, body).then((r) => r.data),
  revert: (id: string, justification: string) => api.post<ActionRow>(`/soc/actions/${id}/revert`, { justification }).then((r) => r.data),
  events: (params: Record<string, unknown> = {}) => get<SecEvent[]>("/soc/events", params),
  assessments: (params: Record<string, unknown> = {}) => get<Assessment[]>("/soc/risk-assessments", params),
  investigations: () => get<Investigation[]>("/soc/investigations"),
  openInvestigation: (title: string, alert_ids: string[]) => api.post("/soc/investigations", { title, alert_ids }).then((r) => r.data),
  searchUsers: (q: string) => get<{ id: string; name: string; email: string; type: string; status: string }[]>("/soc/users", { q }),
  customer: (id: string) => get<Customer>(`/soc/customers/${id}`),
  rules: () => get<Rule[]>("/admin/risk-rules"),
  patchRule: (id: string, body: { weight?: number; enabled?: boolean; justification: string }) => api.patch(`/admin/risk-rules/${id}`, body).then((r) => r.data),
  policies: () => get<Policy[]>("/admin/policies"),
  patchPolicy: (id: string, body: { decision?: string; floor_decision?: string; enabled?: boolean; justification: string }) => api.patch(`/admin/policies/${id}`, body).then((r) => r.data),
  users: () => get<AdminUser[]>("/admin/users"),
  userStatus: (id: string, status: string, justification: string) => api.post(`/admin/users/${id}/status`, { status, justification }),
  mfaReset: (id: string, justification: string) => api.post(`/admin/users/${id}/mfa-reset`, { status: "reset", justification }),
  config: () => get<{ risk_thresholds: Record<string, number>; lab_mode: boolean }>("/admin/config"),
  scenarios: () => get<Scenario[]>("/lab/scenarios"),
  runs: () => get<Run[]>("/lab/runs"),
  launch: (scenario: string) => api.post<Run>("/lab/runs", { scenario }).then((r) => r.data),
  audit: (params: Record<string, unknown> = {}) => get<AuditRow[]>("/audit/logs", params),
  verifyAudit: () => get<{ valid: boolean; entries: number; broken_at_seq: number | null }>("/audit/verify"),
  queue: () => get<Ticket[]>("/support/queue"),
  ticket: (id: string) => get<TicketDetail>(`/support/tickets/${id}`),
  accept: (id: string) => api.post(`/support/tickets/${id}/accept`),
  reply: (id: string, message: string) => api.post(`/support/tickets/${id}/reply`, { message }),
  ticketCustomer: (id: string) => get<Customer>(`/support/tickets/${id}/customer`),
  lockCard: (id: string, card_id: string, justification: string) => api.post(`/support/tickets/${id}/lock-card`, { card_id, justification }),
  closeTicket: (id: string) => api.post(`/support/tickets/${id}/close`),
};
