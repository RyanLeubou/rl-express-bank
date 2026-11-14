import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router";
import "@fontsource-variable/hanken-grotesk";
import "./styles/index.css";
import { Providers } from "./app/providers";
import { router } from "./app/router";
import { DemoBanner } from "./components/ui/DemoBanner";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Providers>
      <DemoBanner />
      <RouterProvider router={router} />
    </Providers>
  </StrictMode>,
);
