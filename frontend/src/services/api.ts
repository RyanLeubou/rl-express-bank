import axios, { AxiosError, type AxiosRequestConfig } from "axios";

/**
 * Client HTTP unique. Même origine que la SPA (Caddy) : aucune configuration CORS.
 *
 * Aucun jeton n'est manipulé par le JavaScript : la session vit dans des cookies HttpOnly.
 * Seul le jeton CSRF (cookie lisible, lié à la session côté serveur) est recopié dans un en-tête
 * pour les requêtes modifiantes. Sur 401, une seule tentative de renouvellement de session est
 * partagée entre toutes les requêtes en vol, puis la requête d'origine est rejouée une fois.
 */
export const api = axios.create({
  baseURL: "/api/v1",
  timeout: 10_000,
  withCredentials: true,
  headers: { Accept: "application/json" },
});

const CSRF_COOKIE = "__Host-rlb_csrf";
const SAFE_METHODS = new Set(["get", "head", "options"]);
const NO_REFRESH_PATHS = ["/auth/login", "/auth/mfa/", "/auth/refresh", "/auth/logout"];
export const UNAUTHENTICATED_EVENT = "rlb:unauthenticated";

export function readCookie(name: string): string | null {
  const prefix = `${encodeURIComponent(name)}=`;
  const hit = document.cookie.split("; ").find((c) => c.startsWith(prefix));
  return hit ? decodeURIComponent(hit.slice(prefix.length)) : null;
}

api.interceptors.request.use((config) => {
  if (!SAFE_METHODS.has((config.method ?? "get").toLowerCase())) {
    const csrf = readCookie(CSRF_COOKIE);
    if (csrf) config.headers.set("X-CSRF-Token", csrf);
  }
  return config;
});

/** Erreur RFC 9457 normalisée : le message est celui du serveur, jamais un détail technique. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly retryAfter?: number,
  ) {
    super(message);
  }
}

export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  if (axios.isAxiosError(error) && error.response) {
    const data = (error.response.data ?? {}) as { code?: string; detail?: string };
    const retry = Number(error.response.headers?.["retry-after"]);
    return new ApiError(
      error.response.status,
      data.code ?? String(error.response.status),
      data.detail ?? "Une erreur est survenue. Réessayez.",
      Number.isFinite(retry) && retry > 0 ? retry : undefined,
    );
  }
  return new ApiError(0, "network_error", "Le serveur ne répond pas. Vérifiez votre connexion.");
}

let refreshing: Promise<void> | null = null;

async function refreshSession(): Promise<void> {
  try {
    await api.post("/auth/refresh");
  } catch (error) {
    // Deux onglets qui renouvellent en même temps : le second réessaie une fois avec le cookie à jour
    if (toApiError(error).code === "refresh_race") {
      await new Promise((resolve) => setTimeout(resolve, 300));
      await api.post("/auth/refresh");
      return;
    }
    throw error;
  }
}

api.interceptors.response.use(undefined, async (error: AxiosError) => {
  const config = error.config as (AxiosRequestConfig & { _retried?: boolean }) | undefined;
  const url = config?.url ?? "";
  if (error.response?.status !== 401 || !config || config._retried || NO_REFRESH_PATHS.some((p) => url.includes(p))) {
    throw error;
  }
  config._retried = true;
  try {
    refreshing ??= refreshSession().finally(() => { refreshing = null; });
    await refreshing;
  } catch {
    window.dispatchEvent(new Event(UNAUTHENTICATED_EVENT));
    throw error;
  }
  return api.request(config);
});
