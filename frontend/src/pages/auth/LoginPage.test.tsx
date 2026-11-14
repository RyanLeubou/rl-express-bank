import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../../auth/AuthContext";
import { ApiError } from "../../services/api";
import * as auth from "../../services/auth";
import { LoginPage } from "./LoginPage";

const USER: auth.User = {
  id: "u1", email: "jean@demo.test", first_name: "Jean", last_name: "Dupont", user_type: "CUSTOMER",
  roles: ["CLIENT"], permissions: [], mfa_enabled: false,
};
const ME: auth.Me = { user: USER, aal: 1, amr: ["pwd"], device_trusted: false, session_expires_at: "2026-10-20T10:00:00Z" };

function renderLogin() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <AuthProvider>
        <MemoryRouter initialEntries={["/connexion"]}>
          <Routes>
            <Route path="/connexion" element={<LoginPage />} />
            <Route path="/espace" element={<p>Espace sécurisé atteint</p>} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

async function submitCredentials(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Adresse e-mail"), "jean@demo.test");
  await user.type(screen.getByLabelText("Mot de passe"), "Client!Demo2026");
  await user.click(screen.getByRole("button", { name: "Se connecter" }));
}

afterEach(() => vi.restoreAllMocks());

describe("LoginPage", () => {
  it("connecte un client sans second facteur et ouvre son espace", async () => {
    vi.spyOn(auth, "fetchMe").mockRejectedValueOnce(new Error("401")).mockResolvedValue(ME);
    vi.spyOn(auth, "login").mockResolvedValue({ status: "authenticated", user: USER, new_device: false });
    const user = userEvent.setup();
    renderLogin();
    await submitCredentials(user);
    expect(await screen.findByText("Espace sécurisé atteint")).toBeInTheDocument();
    expect(auth.login).toHaveBeenCalledWith("jean@demo.test", "Client!Demo2026");
  });

  it("affiche le message générique du serveur, sans révéler quel champ est faux", async () => {
    vi.spyOn(auth, "fetchMe").mockRejectedValue(new Error("401"));
    vi.spyOn(auth, "login").mockRejectedValue(
      new ApiError(401, "invalid_credentials", "Identifiant ou mot de passe incorrect."));
    const user = userEvent.setup();
    renderLogin();
    await submitCredentials(user);
    expect(await screen.findByRole("alert")).toHaveTextContent("Identifiant ou mot de passe incorrect.");
    expect(screen.getByLabelText("Mot de passe")).toBeInTheDocument();   // reste sur l'étape mot de passe
  });

  it("indique le délai d'attente quand le serveur ralentit les essais", async () => {
    vi.spyOn(auth, "fetchMe").mockRejectedValue(new Error("401"));
    vi.spyOn(auth, "login").mockRejectedValue(new ApiError(429, "too_many_attempts", "Trop de tentatives.", 8));
    const user = userEvent.setup();
    renderLogin();
    await submitCredentials(user);
    expect(await screen.findByRole("alert")).toHaveTextContent("Trop de tentatives. (environ 8 s)");
  });

  it("demande le second facteur, puis ouvre la session", async () => {
    vi.spyOn(auth, "fetchMe").mockRejectedValueOnce(new Error("401")).mockResolvedValue({ ...ME, aal: 2 });
    vi.spyOn(auth, "login").mockResolvedValue({ status: "mfa_required", user: null, new_device: true });
    const verify = vi.spyOn(auth, "verifyMfa")
      .mockRejectedValueOnce(new ApiError(401, "invalid_code", "Code incorrect ou expiré."))
      .mockResolvedValueOnce({ status: "authenticated", user: USER, recovery_codes_left: null });
    const user = userEvent.setup();
    renderLogin();
    await submitCredentials(user);
    expect(await screen.findByRole("heading", { name: "Vérification en deux étapes" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Mot de passe")).not.toBeInTheDocument();

    await user.type(screen.getByLabelText("Code de vérification"), "000000");
    await user.click(screen.getByRole("button", { name: "Valider" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Code incorrect ou expiré.");

    await user.type(screen.getByLabelText("Code de vérification"), "123456");
    await user.click(screen.getByLabelText(/Faire confiance à cet appareil/));
    await user.click(screen.getByRole("button", { name: "Valider" }));
    expect(await screen.findByText("Espace sécurisé atteint")).toBeInTheDocument();
    expect(verify).toHaveBeenLastCalledWith("123456", true);
  });

  it("revient au mot de passe quand le défi MFA a expiré", async () => {
    vi.spyOn(auth, "fetchMe").mockRejectedValue(new Error("401"));
    vi.spyOn(auth, "login").mockResolvedValue({ status: "mfa_required", user: null, new_device: false });
    vi.spyOn(auth, "verifyMfa").mockRejectedValue(
      new ApiError(401, "mfa_session_invalid", "Session de vérification expirée. Reconnectez-vous."));
    const user = userEvent.setup();
    renderLogin();
    await submitCredentials(user);
    await user.type(await screen.findByLabelText("Code de vérification"), "123456");
    await user.click(screen.getByRole("button", { name: "Valider" }));
    expect(await screen.findByLabelText("Mot de passe")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Session de vérification expirée");
  });

  it("guide le personnel dans l'activation obligatoire du TOTP et affiche les codes de secours une fois", async () => {
    vi.spyOn(auth, "fetchMe").mockRejectedValueOnce(new Error("401")).mockResolvedValue({ ...ME, aal: 2 });
    vi.spyOn(auth, "login").mockResolvedValue({ status: "mfa_enrollment_required", user: null, new_device: true });
    vi.spyOn(auth, "startEnrollment").mockResolvedValue({
      secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/RL:admin?secret=JBSWY3DP", qr_code: "data:image/svg+xml,qr",
    });
    vi.spyOn(auth, "confirmEnrollment").mockResolvedValue({
      status: "authenticated", user: USER, recovery_codes: ["ABCDE-FGHJK", "LMNPQ-RSTUV"],
    });
    const user = userEvent.setup();
    renderLogin();
    await submitCredentials(user);
    expect(await screen.findByTestId("totp-secret")).toHaveTextContent("JBSW Y3DP EHPK 3PXP");

    const confirm = screen.getByRole("button", { name: "Activer et continuer" });
    expect(confirm).toBeDisabled();                                       // 6 chiffres exigés
    await user.type(screen.getByLabelText("Code à 6 chiffres"), "12a3456");
    expect(screen.getByLabelText("Code à 6 chiffres")).toHaveValue("123456");   // les non-chiffres sont ignorés
    await user.click(confirm);

    expect(await screen.findByTestId("recovery-codes")).toHaveTextContent("ABCDE-FGHJK");
    await user.click(screen.getByRole("button", { name: /J'ai conservé mes codes/ }));
    await waitFor(() => expect(screen.getByText("Espace sécurisé atteint")).toBeInTheDocument());
  });
});
