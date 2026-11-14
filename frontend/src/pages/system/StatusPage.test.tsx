import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { StatusPage } from "./StatusPage";
import * as health from "../../services/health";

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><StatusPage /></QueryClientProvider>);
}

afterEach(() => vi.restoreAllMocks());

describe("StatusPage", () => {
  it("affiche chaque service comme une ligne de relevé", async () => {
    vi.spyOn(health, "fetchReadiness").mockResolvedValue({
      status: "degraded", environment: "development", lab_mode: true,
      checks: { database: { status: "ok", latency_ms: 1.2 }, cache: { status: "ok", latency_ms: 0.4 },
        worker: { status: "down" } },
    });
    renderPage();
    expect(await screen.findByText("La banque fonctionne, un service secondaire est arrêté.")).toBeInTheDocument();
    expect(screen.getByText("Base de données")).toBeInTheDocument();
    expect(screen.getByText("Indisponible")).toBeInTheDocument();
    expect(screen.getByText("Activé, simulations autorisées")).toBeInTheDocument();
  });

  it("explique quoi faire quand l'API ne répond pas", async () => {
    vi.spyOn(health, "fetchReadiness").mockRejectedValue(new Error("network"));
    renderPage();
    expect(await screen.findByRole("alert")).toHaveTextContent("docker compose ps");
  });
});
