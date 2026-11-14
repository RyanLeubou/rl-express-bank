import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DemoBanner } from "./DemoBanner";

describe("DemoBanner", () => {
  it("prévient que la banque est fictive et qu'aucune donnée réelle ne doit être saisie", () => {
    render(<DemoBanner />);
    const note = screen.getByRole("note", { name: "Avertissement" });
    expect(note.textContent).toContain("banque fictive");
    expect(note.textContent).toContain("N'entrez aucune donnée réelle");
  });
});
