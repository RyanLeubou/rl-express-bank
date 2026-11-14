import { describe, expect, it } from "vitest";
import { spaceFor } from "./RequireRole";

describe("spaceFor", () => {
  it("oriente chaque rôle vers son espace", () => {
    expect(spaceFor(["CLIENT"])).toBe("client");
    expect(spaceFor(["SECURITY_ANALYST"])).toBe("soc");
    expect(spaceFor(["SUPER_ADMIN"])).toBe("admin");
    expect(spaceFor(["AUDITOR"])).toBe("audit");
    expect(spaceFor(["SUPPORT_AGENT"])).toBe("agent");
  });
  it("retombe sur l'espace client sans rôle connu", () => {
    expect(spaceFor([])).toBe("client");
  });
});
