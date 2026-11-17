import { useState } from "react";
import type { Snippets } from "../../bindings";
import { Button, Panel, Tabs, useToast } from "../../ui";
import { QueryGate } from "./QueryGate";
import { useAgentsT } from "./format";
import { useSnippets } from "./queries";

type SnippetTab = "mcp" | "curl" | "env";

/** Integration snippets from `agent_snippets`. They name `$CERBERUS_TOKEN` and never hold a token. */
export function SnippetsPanel({ agentId }: { agentId: string }) {
  const s = useAgentsT();
  const toast = useToast();
  const query = useSnippets(agentId);
  const [tab, setTab] = useState<SnippetTab>("mcp");

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.push({ tone: "success", title: s("snip.copied") });
    } catch {
      toast.push({ tone: "error", title: s("snip.failed") });
    }
  };

  const pick = (data: Snippets): Record<SnippetTab, string> => ({ mcp: data.mcp_json, curl: data.curl, env: data.env });

  return (
    <Panel
      flush
      icon="terminal"
      title={s("snip.title")}
      actions={
        query.data && (
          <Button size="sm" icon="copy" onClick={() => void copy(pick(query.data)[tab])}>
            {s("snip.copy")}
          </Button>
        )
      }
    >
      <QueryGate query={query} action={s("snip.action")} loadingLabel={s("snip.loading")} rows={2}>
        {(data) => {
          const texts = pick(data);
          return (
            <div className="snippets">
              <Tabs
                label={s("snip.label")}
                value={tab}
                onChange={setTab}
                tabs={[
                  { id: "mcp", label: s("snip.mcp"), panel: <pre className="snip" tabIndex={0}>{texts.mcp}</pre> },
                  { id: "curl", label: s("snip.curl"), panel: <pre className="snip" tabIndex={0}>{texts.curl}</pre> },
                  { id: "env", label: s("snip.env"), panel: <pre className="snip" tabIndex={0}>{texts.env}</pre> },
                ]}
              />
              <p className="small muted snip-note">{s("snip.note")}</p>
            </div>
          );
        }}
      </QueryGate>
    </Panel>
  );
}
