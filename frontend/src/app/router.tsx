import { createBrowserRouter } from "react-router";
import { RequireAuth } from "../auth/RequireAuth";
import { RequireRole } from "../auth/RequireRole";
import { AppShell, CLIENT_NAV, type NavItem } from "../layouts/AppShell";
import { AtmKioskPage } from "../pages/atm/AtmKioskPage";
import { LoginPage } from "../pages/auth/LoginPage";
import { RegisterPage } from "../pages/auth/RegisterPage";
import { AccountsPage } from "../pages/client/AccountsPage";
import { CardsPage } from "../pages/client/CardsPage";
import { HelpPage } from "../pages/client/HelpPage";
import { NotificationsPage } from "../pages/client/NotificationsPage";
import { SecurityPage } from "../pages/client/SecurityPage";
import { TransfersPage } from "../pages/client/TransfersPage";
import { WithdrawalsPage } from "../pages/client/WithdrawalsPage";
import { NotFoundPage } from "../pages/system/NotFoundPage";
import { StatusPage } from "../pages/system/StatusPage";
import { QueuePage } from "../pages/agent/QueuePage";
import { TicketPage } from "../pages/agent/TicketPage";
import { AuditPage } from "../pages/audit/AuditPage";
import { LabPage } from "../pages/admin/LabPage";
import { PoliciesPage } from "../pages/admin/PoliciesPage";
import { RulesPage } from "../pages/admin/RulesPage";
import { UsersPage } from "../pages/admin/UsersPage";
import { AlertDetailPage } from "../pages/soc/AlertDetailPage";
import { AlertsPage } from "../pages/soc/AlertsPage";
import { AssessmentsPage } from "../pages/soc/AssessmentsPage";
import { CustomersPage } from "../pages/soc/CustomersPage";
import { DashboardPage } from "../pages/soc/DashboardPage";
import { EventsPage } from "../pages/soc/EventsPage";
import { InvestigationsPage } from "../pages/soc/InvestigationsPage";

const SOC_NAV: NavItem[] = [
  { to: "/soc", label: "Tableau de bord", end: true }, { to: "/soc/alertes", label: "Alertes" }, { to: "/soc/evenements", label: "Événements" },
  { to: "/soc/evaluations", label: "Évaluations" }, { to: "/soc/investigations", label: "Investigations" }, { to: "/soc/clients", label: "Clients" },
];
const ADMIN_NAV: NavItem[] = [
  { to: "/admin", label: "Règles", end: true }, { to: "/admin/politiques", label: "Politiques" }, { to: "/admin/utilisateurs", label: "Utilisateurs" },
  { to: "/admin/laboratoire", label: "Laboratoire" }, { to: "/admin/audit", label: "Audit" },
  { to: "/admin/soc", label: "SOC" }, { to: "/admin/soc/alertes", label: "Alertes" },
];
const AUDIT_NAV: NavItem[] = [
  { to: "/audit", label: "Journal d'audit", end: true }, { to: "/audit/alertes", label: "Alertes" }, { to: "/audit/evenements", label: "Événements" },
];
const AGENT_NAV: NavItem[] = [{ to: "/agent", label: "File d'attente", end: true }];

// Les gardes côté client ne sont qu'une aide à la navigation : la sécurité est dans l'API.
export const router = createBrowserRouter([
  { path: "/", element: <StatusPage /> },
  { path: "/connexion", element: <LoginPage /> },
  { path: "/inscription", element: <RegisterPage /> },
  { path: "/atm", element: <AtmKioskPage /> },
  {
    element: <RequireAuth />,
    children: [
      {
        element: <RequireRole space="client" />,
        children: [{
          path: "/espace", element: <AppShell space="Espace client" nav={CLIENT_NAV} notifications />,
          children: [
            { index: true, element: <AccountsPage /> }, { path: "virements", element: <TransfersPage /> },
            { path: "cartes", element: <CardsPage /> }, { path: "retraits", element: <WithdrawalsPage /> },
            { path: "securite", element: <SecurityPage /> }, { path: "aide", element: <HelpPage /> },
            { path: "notifications", element: <NotificationsPage /> },
          ],
        }],
      },
      {
        element: <RequireRole space="soc" />,
        children: [{
          path: "/soc", element: <AppShell space="Centre de sécurité (SOC)" nav={SOC_NAV} />,
          children: [
            { index: true, element: <DashboardPage /> }, { path: "alertes", element: <AlertsPage /> },
            { path: "alertes/:id", element: <AlertDetailPage /> }, { path: "evenements", element: <EventsPage /> },
            { path: "evaluations", element: <AssessmentsPage /> }, { path: "investigations", element: <InvestigationsPage /> },
            { path: "clients", element: <CustomersPage /> },
          ],
        }],
      },
      {
        element: <RequireRole space="admin" />,
        children: [{
          path: "/admin", element: <AppShell space="Administration" nav={ADMIN_NAV} />,
          children: [
            { index: true, element: <RulesPage /> }, { path: "politiques", element: <PoliciesPage /> },
            { path: "utilisateurs", element: <UsersPage /> }, { path: "laboratoire", element: <LabPage /> },
            { path: "audit", element: <AuditPage /> }, { path: "soc", element: <DashboardPage /> },
            { path: "soc/alertes", element: <AlertsPage /> }, { path: "soc/alertes/:id", element: <AlertDetailPage /> },
          ],
        }],
      },
      {
        element: <RequireRole space="audit" />,
        children: [{
          path: "/audit", element: <AppShell space="Audit et conformité" nav={AUDIT_NAV} />,
          children: [
            { index: true, element: <AuditPage /> }, { path: "alertes", element: <AlertsPage /> },
            { path: "evenements", element: <EventsPage /> },
          ],
        }],
      },
      {
        element: <RequireRole space="agent" />,
        children: [{
          path: "/agent", element: <AppShell space="Support RL SOLUTION" nav={AGENT_NAV} />,
          children: [{ index: true, element: <QueuePage /> }, { path: "tickets/:id", element: <TicketPage /> }],
        }],
      },
    ],
  },
  { path: "*", element: <NotFoundPage /> },
]);
