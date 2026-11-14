import { AxiosError, type AxiosAdapter, type InternalAxiosRequestConfig } from "axios";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, toApiError, UNAUTHENTICATED_EVENT } from "./api";

type Reply = { status: number; data?: unknown; headers?: Record<string, string> };

/** Adaptateur HTTP factice : enregistre les requêtes et répond selon un script. */
function script(respond: (config: InternalAxiosRequestConfig, n: number) => Reply) {
  const calls: InternalAxiosRequestConfig[] = [];
  const adapter: AxiosAdapter = async (config) => {
    calls.push(config);
    const reply = respond(config, calls.length);
    const response = { data: reply.data ?? {}, status: reply.status, statusText: "", headers: reply.headers ?? {}, config };
    if (reply.status >= 400) throw new AxiosError("échec", "ERR_BAD_REQUEST", config, null, response);
    return response;
  };
  api.defaults.adapter = adapter;
  return calls;
}

beforeEach(() => {
  Object.defineProperty(document, "cookie", { configurable: true, get: () => "x=1; __Host-rlb_csrf=abc.def" });
});
afterEach(() => vi.restoreAllMocks());

describe("client API", () => {
  it("recopie le jeton CSRF sur les requêtes modifiantes uniquement", async () => {
    const calls = script(() => ({ status: 200 }));
    await api.get("/auth/me");
    await api.post("/auth/logout");
    expect(calls[0]!.headers.get("X-CSRF-Token")).toBeFalsy();
    expect(calls[1]!.headers.get("X-CSRF-Token")).toBe("abc.def");
  });

  it("renouvelle la session une seule fois pour plusieurs requêtes 401 simultanées, puis les rejoue", async () => {
    const seen = new Map<string, number>();
    const calls = script((config) => {
      const url = config.url ?? "";
      if (url.includes("/auth/refresh")) return { status: 200 };
      const n = (seen.get(url) ?? 0) + 1;
      seen.set(url, n);
      return n === 1 ? { status: 401 } : { status: 200, data: { ok: url } };
    });
    const [a, b] = await Promise.all([api.get("/accounts"), api.get("/cards")]);
    expect(a.data).toEqual({ ok: "/accounts" });
    expect(b.data).toEqual({ ok: "/cards" });
    expect(calls.filter((c) => c.url?.includes("/auth/refresh"))).toHaveLength(1);
  });

  it("signale la perte de session quand le renouvellement échoue", async () => {
    script(() => ({ status: 401 }));
    const listener = vi.fn();
    window.addEventListener(UNAUTHENTICATED_EVENT, listener);
    await expect(api.get("/accounts")).rejects.toBeTruthy();
    window.removeEventListener(UNAUTHENTICATED_EVENT, listener);
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("ne tente pas de renouvellement pour une erreur de connexion (mauvais mot de passe)", async () => {
    const calls = script(() => ({ status: 401, data: { code: "invalid_credentials", detail: "Identifiant ou mot de passe incorrect." } }));
    await expect(api.post("/auth/login", {})).rejects.toBeTruthy();
    expect(calls).toHaveLength(1);
  });

  it("tolère une course de renouvellement entre onglets", async () => {
    let refreshes = 0;
    let accounts = 0;
    script((config) => {
      if (config.url?.includes("/auth/refresh")) {
        refreshes += 1;
        return refreshes === 1 ? { status: 401, data: { code: "refresh_race" } } : { status: 200 };
      }
      accounts += 1;
      return accounts === 1 ? { status: 401 } : { status: 200 };
    });
    // 401 -> renouvellement perdu face à un autre onglet -> second essai -> requête rejouée
    await expect(api.get("/accounts")).resolves.toBeTruthy();
    expect(refreshes).toBe(2);
    expect(accounts).toBe(2);
  });
});

describe("toApiError", () => {
  it("extrait le code, le message serveur et Retry-After", () => {
    const config = {} as InternalAxiosRequestConfig;
    const err = new AxiosError("x", "ERR_BAD_REQUEST", config, null, {
      status: 429, statusText: "", config, headers: { "retry-after": "12" },
      data: { code: "too_many_attempts", detail: "Trop de tentatives." },
    });
    const parsed = toApiError(err);
    expect(parsed).toBeInstanceOf(ApiError);
    expect([parsed.status, parsed.code, parsed.message, parsed.retryAfter]).toEqual([429, "too_many_attempts", "Trop de tentatives.", 12]);
  });

  it("n'expose jamais le détail technique d'une panne réseau", () => {
    const parsed = toApiError(new Error("ECONNREFUSED 10.0.0.5:8000"));
    expect(parsed.code).toBe("network_error");
    expect(parsed.message).not.toContain("10.0.0.5");
  });
});
