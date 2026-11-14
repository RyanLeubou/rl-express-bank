import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Vitest n'expose pas les globales : le nettoyage du DOM entre deux tests doit être explicite
afterEach(() => cleanup());
