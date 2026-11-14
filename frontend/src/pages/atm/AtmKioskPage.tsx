import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { BrandMark } from "../../components/ui/BrandMark";
import { Btn, ErrorLine, Field, TextInput } from "../../components/ui/kit";
import { xaf } from "../../lib/format";
import { api, toApiError } from "../../services/api";

/** Borne ATM simulée : s'authentifie comme terminal (code + secret), puis valide un retrait sans carte. */
export function AtmKioskPage() {
  const [term, setTerm] = useState({ code: "", secret: "" });
  const [form, setForm] = useState({ reference: "", code: "" });
  const redeem = useMutation({
    mutationFn: async () => (await api.post<{ status: string; amount: number }>("/atm-terminal/cardless/redeem", form,
      { headers: { "X-ATM-Code": term.code, "X-ATM-Secret": term.secret } })).data,
    onSuccess: () => setForm({ reference: "", code: "" }),
  });
  return (
    <main className="mx-auto max-w-md px-5 py-10">
      <div className="mb-6 flex items-center gap-3"><BrandMark className="h-10 w-10" /><h1 className="text-2xl font-bold">Borne ATM (simulation)</h1></div>
      <section className="rounded-2xl border border-rule bg-paper p-5">
        <h2 className="font-semibold">Identification du terminal</h2>
        <Field id="tc" label="Code du terminal"><TextInput id="tc" value={term.code} autoComplete="off" onChange={(e) => setTerm({ ...term, code: e.target.value })} /></Field>
        <Field id="ts" label="Secret du terminal"><TextInput id="ts" type="password" value={term.secret} autoComplete="off" onChange={(e) => setTerm({ ...term, secret: e.target.value })} /></Field>
      </section>
      <form className="mt-5 rounded-2xl border border-rule bg-paper p-5" onSubmit={(e) => { e.preventDefault(); redeem.mutate(); }}>
        <h2 className="font-semibold">Retrait sans carte</h2>
        <Field id="ref" label="Référence"><TextInput id="ref" value={form.reference} onChange={(e) => setForm({ ...form, reference: e.target.value })} /></Field>
        <Field id="rc" label="Code à usage unique"><TextInput id="rc" inputMode="numeric" autoComplete="off" value={form.code} onChange={(e) => setForm({ ...form, code: e.target.value })} /></Field>
        <ErrorLine message={redeem.error ? toApiError(redeem.error).message : null} />
        {redeem.data && <p role="status" className="mt-3 font-semibold text-ok">Retrait autorisé : {xaf(redeem.data.amount)}. Récupérez vos billets.</p>}
        <div className="mt-4"><Btn type="submit" disabled={redeem.isPending || !term.code || !term.secret || !form.reference || !form.code}>Valider</Btn></div>
      </form>
    </main>
  );
}
