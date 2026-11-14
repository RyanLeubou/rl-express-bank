import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../../auth/AuthContext";
import { ApiError } from "../../services/api";
import * as auth from "../../services/auth";
import { RegisterPage } from "./RegisterPage";

const USER: auth.User = {
  id: "u9", email: "aicha@demo.test", first_name: "Aïcha", last_name: "Ngono", user_type: "CUSTOMER",
  roles: ["CLIENT"], permissions: [], mfa_enabled: false,
};
const ME: auth.Me = { user: USER, aal: 1, amr: ["pwd"], device_trusted: false, session_expires_at: "2026-12-01T10:00:00Z" };

function renderRegister() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <AuthProvider>
        <MemoryRouter initialEntries={["/inscription"]}>
          <Routes>
            <Route path="/inscription" element={<RegisterPage />} />
            <Route path="/espace" element={<p>Espace sécurisé atteint</p>} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

const CITIES: auth.City[] = [
  { city: "Douala", agency: "Douala", branch_code: "00101" }, { city: "Mbalmayo", agency: "Yaoundé", branch_code: "00201" },
];
const RESULT: auth.RegisterResult = {
  status: "authenticated", user: USER, new_device: true, card_pin: "4071", iban: "CM21 9999 0002 0112 3456 7890 123",
  agency: "Yaoundé", branch_code: "00201",
};

async function fill(user: ReturnType<typeof userEvent.setup>, password: string, confirm = password) {
  await user.type(screen.getByLabelText("Nom"), "Ngono");
  await user.type(screen.getByLabelText("Prénom"), "Aïcha");
  await user.type(screen.getByLabelText("Adresse"), "12 rue des Manguiers");
  await screen.findByRole("option", { name: "Mbalmayo" });
  await user.selectOptions(screen.getByLabelText("Ville"), "Mbalmayo");
  await user.type(screen.getByLabelText("Téléphone"), "+237 690000000");
  await user.type(screen.getByLabelText("Profession"), "Infirmière");
  await user.type(screen.getByLabelText("Adresse e-mail"), "aicha@demo.test");
  await user.type(screen.getByLabelText("Mot de passe"), password);
  await user.type(screen.getByLabelText("Confirmer le mot de passe"), confirm);
  await user.click(screen.getByRole("button", { name: "Créer mon compte" }));
}

beforeEach(() => { vi.spyOn(auth, "fetchCities").mockResolvedValue(CITIES); });
afterEach(() => vi.restoreAllMocks());

describe("RegisterPage", () => {
  it("crée le compte, montre le RIB et le PIN une fois, puis ouvre l'espace client", async () => {
    vi.spyOn(auth, "fetchMe").mockRejectedValueOnce(new Error("401")).mockResolvedValue(ME);
    vi.spyOn(auth, "register").mockResolvedValue(RESULT);
    const user = userEvent.setup();
    renderRegister();
    await fill(user, "Nouveau!Client2026");
    expect(screen.queryByText(/Agence attribuée/)).toBeNull();
    expect(await screen.findByTestId("card-pin")).toHaveTextContent("4071");
    expect(screen.getByText(RESULT.iban)).toBeInTheDocument();
    expect(auth.register).toHaveBeenCalledWith({
      first_name: "Aïcha", last_name: "Ngono", address: "12 rue des Manguiers", city: "Mbalmayo",
      phone: "+237 690000000", email: "aicha@demo.test", profession: "Infirmière",
      password: "Nouveau!Client2026",
    });
    await user.click(screen.getByRole("button", { name: /accéder à mon espace/ }));
    expect(await screen.findByText("Espace sécurisé atteint")).toBeInTheDocument();
  });

  it("indique l'agence attribuée selon la ville", async () => {
    vi.spyOn(auth, "fetchMe").mockRejectedValue(new Error("401"));
    const user = userEvent.setup();
    renderRegister();
    await screen.findByRole("option", { name: "Mbalmayo" });
  await user.selectOptions(screen.getByLabelText("Ville"), "Mbalmayo");
    expect(screen.getByText("Agence attribuée : Yaoundé (code guichet 00201)")).toBeInTheDocument();
  });

  it("refuse un mot de passe faible sans appeler l'API", async () => {
    vi.spyOn(auth, "fetchMe").mockRejectedValue(new Error("401"));
    const spy = vi.spyOn(auth, "register");
    const user = userEvent.setup();
    renderRegister();
    await fill(user, "toutenminuscule1");
    expect(await screen.findByRole("alert")).toHaveTextContent("majuscule");
    expect(spy).not.toHaveBeenCalled();
  });

  it("affiche l'erreur de l'API si l'adresse est déjà utilisée", async () => {
    vi.spyOn(auth, "fetchMe").mockRejectedValue(new Error("401"));
    vi.spyOn(auth, "register").mockRejectedValue(
      new ApiError(409, "email_taken", "Un compte existe déjà avec cette adresse e-mail. Connectez-vous."));
    const user = userEvent.setup();
    renderRegister();
    await fill(user, "Nouveau!Client2026");
    expect(await screen.findByRole("alert")).toHaveTextContent("existe déjà");
  });
});
