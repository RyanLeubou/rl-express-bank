import { Link } from "react-router";

export function NotFoundPage() {
  return (
    <main className="mx-auto max-w-xl px-5 py-24">
      <h1 className="text-3xl font-bold tracking-tight">Cette page n'existe pas.</h1>
      <p className="mt-3 text-ink-soft">L'adresse est peut-être incomplète, ou l'espace n'est pas encore disponible.</p>
      <Link to="/" className="mt-6 inline-block font-semibold text-lagoon underline underline-offset-4">
        Revenir au relevé d'état
      </Link>
    </main>
  );
}
