import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Btn, Empty, PageTitle, Panel } from "../../components/ui/kit";
import { dateTime } from "../../lib/format";
import { bank } from "../../services/bank";

export function NotificationsPage() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["notifications"], queryFn: bank.notifications });
  const read = useMutation({ mutationFn: bank.readNotification, onSuccess: () => void qc.invalidateQueries({ queryKey: ["notifications"] }) });
  return (
    <>
      <PageTitle>Notifications</PageTitle>
      <Panel>
        {!list.data?.length ? <Empty>Aucune notification.</Empty> : (
          <ul className="divide-y divide-rule">
            {list.data.map((n) => (
              <li key={n.id} className={`flex items-start justify-between gap-4 py-3 ${n.read ? "opacity-60" : ""}`}>
                <div>
                  <p className="font-semibold">{n.title} <Badge value={n.severity} kind="severity" /></p>
                  <p className="text-sm">{n.body}</p>
                  <p className="text-xs text-ink-soft">{dateTime(n.created_at)}</p>
                </div>
                {!n.read && <Btn tone="ghost" onClick={() => read.mutate(n.id)}>Marquer comme lue</Btn>}
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </>
  );
}
