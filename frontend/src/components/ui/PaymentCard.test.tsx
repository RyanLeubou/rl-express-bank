import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { bank, type Card } from "../../services/bank";
import { PaymentCard } from "./PaymentCard";

const CARD: Card = {
  id: "c1", masked_pan: "**** **** **** 4821", holder: "JEAN DUPONT", type: "DEBIT", expiry: "07/29", status: "ACTIVE",
  blocked_reason: null, account_id: "a1", daily_withdrawal_limit: 500000, daily_payment_limit: 1000000,
};

function renderCard() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><PaymentCard card={CARD} /></QueryClientProvider>);
}

afterEach(() => vi.restoreAllMocks());

describe("PaymentCard", () => {
  it("masque le numéro et le CVV par défaut, sans appel à l'API", () => {
    const spy = vi.spyOn(bank, "cardDetails");
    renderCard();
    expect(screen.getByTestId("card-pan")).toHaveTextContent("**** **** **** 4821");
    expect(screen.getByTestId("card-cvv")).toHaveTextContent("•••");
    expect(spy).not.toHaveBeenCalled();
  });

  it("l'œil affiche puis masque le numéro complet et le CVV", async () => {
    vi.spyOn(bank, "cardDetails").mockResolvedValue({ pan: "9999 9012 3454 4821", cvv: "357", expiry: "07/29", holder: "JEAN DUPONT" });
    const user = userEvent.setup();
    renderCard();
    await user.click(screen.getByRole("button", { name: "Afficher les informations de la carte" }));
    expect(await screen.findByText("9999 9012 3454 4821")).toBeInTheDocument();
    expect(screen.getByTestId("card-cvv")).toHaveTextContent("357");
    await user.click(screen.getByRole("button", { name: "Masquer les informations de la carte" }));
    expect(screen.getByTestId("card-pan")).toHaveTextContent("**** **** **** 4821");
    expect(screen.getByTestId("card-cvv")).toHaveTextContent("•••");
  });
});
