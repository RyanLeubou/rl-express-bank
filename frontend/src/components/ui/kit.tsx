import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";
import { SEVERITY_LABEL, label } from "../../lib/format";

export const INPUT = "mt-1 block w-full rounded-lg border border-rule bg-white px-3 py-2.5 text-base";

export function Panel({ title, action, children, className = "" }: {
  title?: string; action?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`rounded-2xl bg-paper px-5 py-5 shadow-[0_1px_0_#d5dfe2] ${className}`}>
      {title && (
        <div className="mb-3 flex items-center justify-between gap-3 border-b-2 border-ink pb-2">
          <h2 className="text-lg font-bold tracking-tight">{title}</h2>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export const PageTitle = ({ children, sub }: { children: ReactNode; sub?: string }) => (
  <div className="mb-5">
    <h1 className="text-2xl font-bold tracking-tight">{children}</h1>
    {sub && <p className="mt-1 text-sm text-ink-soft">{sub}</p>}
  </div>
);

type Tone = "primary" | "ghost" | "danger";
const TONES: Record<Tone, string> = {
  primary: "bg-lagoon text-white hover:bg-lagoon-deep",
  ghost: "border border-ink text-ink hover:bg-mist",
  danger: "border border-laterite text-laterite hover:bg-mist",
};
export function Btn({ tone = "primary", className = "", ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { tone?: Tone }) {
  return (
    <button type="button" {...rest}
      className={`rounded-lg px-4 py-2 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50 ${TONES[tone]} ${className}`} />
  );
}

export function Field({ id, label: text, children, hint }: { id: string; label: string; children: ReactNode; hint?: string }) {
  return (
    <div>
      <label htmlFor={id} className="text-sm font-semibold">{text}</label>
      {children}
      {hint && <p className="mt-1 text-xs text-ink-soft">{hint}</p>}
    </div>
  );
}
export const TextInput = (p: InputHTMLAttributes<HTMLInputElement>) => <input {...p} className={`${INPUT} ${p.className ?? ""}`} />;
export const Select = (p: SelectHTMLAttributes<HTMLSelectElement>) => <select {...p} className={`${INPUT} ${p.className ?? ""}`} />;

const BADGE: Record<string, string> = {
  INFO: "bg-mist text-ink-soft", LOW: "bg-mist text-ink", MEDIUM: "bg-amber-100 text-saffron",
  HIGH: "bg-red-100 text-laterite", CRITICAL: "bg-laterite text-white",
  OK: "bg-green-100 text-ok", BAD: "bg-red-100 text-laterite", WARN: "bg-amber-100 text-saffron",
};
const GOOD = new Set(["COMPLETED", "APPROVED", "ACTIVE", "ONLINE", "TRUSTED", "RESOLVED", "EXECUTED", "CLOSED"]);
const BAD_SET = new Set(["BLOCKED", "FAILED", "DECLINED", "SUSPICIOUS", "LOCKED", "DISABLED", "FALSE_POSITIVE"]);

export function Badge({ value, kind }: { value: string; kind?: "severity" | "status" }) {
  const tone = kind === "severity" || value in SEVERITY_LABEL
    ? BADGE[value] ?? BADGE.INFO
    : GOOD.has(value) ? BADGE.OK : BAD_SET.has(value) ? BADGE.BAD : BADGE.WARN;
  const text = kind === "severity" ? SEVERITY_LABEL[value] ?? value : label(value);
  return <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-bold ${tone}`}>{text}</span>;
}

export const ErrorLine = ({ message }: { message: string | null | undefined }) =>
  message ? <p role="alert" className="border-l-4 border-laterite pl-3 text-sm font-semibold">{message}</p> : null;

export const Empty = ({ children }: { children: ReactNode }) => <p className="py-6 text-center text-sm text-ink-soft">{children}</p>;

export function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead><tr className="border-b border-rule text-ink-soft">
          {head.map((h) => <th key={h} scope="col" className="px-2 py-2 font-semibold">{h}</th>)}
        </tr></thead>
        <tbody className="divide-y divide-rule">{children}</tbody>
      </table>
    </div>
  );
}
export const Td = ({ children, className = "" }: { children: ReactNode; className?: string }) =>
  <td className={`px-2 py-2.5 align-top ${className}`}>{children}</td>;

export function Stat({ label: text, value, tone }: { label: string; value: ReactNode; tone?: "bad" | "warn" }) {
  const color = tone === "bad" ? "text-laterite" : tone === "warn" ? "text-saffron" : "text-ink";
  return (
    <div className="rounded-xl border border-rule px-4 py-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-ink-soft">{text}</p>
      <p className={`tabular mt-1 text-2xl font-bold ${color}`}>{value}</p>
    </div>
  );
}
