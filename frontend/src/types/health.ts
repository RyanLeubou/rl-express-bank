export type CheckStatus = "ok" | "down" | "unknown";

export interface HealthCheck {
  status: CheckStatus;
  latency_ms?: number;
  seconds_since_heartbeat?: number;
}

export interface ReadyResponse {
  status: "ok" | "degraded" | "down";
  environment: "development" | "demo" | "test";
  lab_mode: boolean;
  checks: Record<string, HealthCheck>;
}
