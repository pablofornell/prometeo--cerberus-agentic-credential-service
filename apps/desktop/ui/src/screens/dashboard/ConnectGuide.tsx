import { useState } from "react";
import { useLocation } from "wouter";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure } from "../../ipc/client";
import { pickSavePath } from "../../ipc/dialogs";
import { useCan } from "../../state/session";
import { Button, Dialog, ErrorState, errorText, Skeleton, Tabs, useToast } from "../../ui";
import { messages } from "./messages";
import { dashKeys } from "./queries";
import { useQuery } from "@tanstack/react-query";
import { cliSnippets, mcpSnippets, restSnippets, serverUrl, type Snippet } from "./snippets";

type Method = "mcp" | "rest" | "cli";

function CodeSnippet({ snippet }: { snippet: Snippet }) {
  const m = useScreenT(messages);
  const toast = useToast();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(snippet.code);
      toast.push({ tone: "success", title: m("connect.snippetCopied") });
    } catch {
      toast.push({ tone: "error", title: m("connect.copyFailed") });
    }
  };
  return (
    <div className="snippet">
      <div className="snippet-head">
        <span className="label">{snippet.label}</span>
        <Button size="sm" variant="ghost" icon="copy" onClick={() => void copy()} aria-label={`${m("connect.copySnippet")}: ${snippet.label}`}>
          {m("connect.copySnippet")}
        </Button>
      </div>
      <pre className="code-block" tabIndex={0} aria-label={snippet.label}>
        <code>{snippet.code}</code>
      </pre>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  const m = useScreenT(messages);
  const toast = useToast();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      toast.push({ tone: "success", title: m("connect.copied", { what: label }) });
    } catch {
      toast.push({ tone: "error", title: m("connect.copyFailed") });
    }
  };
  return (
    <div className="fact">
      <span className="k">{label}</span>
      <code>{value}</code>
      <Button size="sm" variant="ghost" icon="copy" onClick={() => void copy()} aria-label={m("connect.copy", { what: label })}>
        <span className="sr-only">{m("connect.copy", { what: label })}</span>
      </Button>
    </div>
  );
}

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * The integration guide: how an agent connects over MCP, REST or the CLI. It reads the server address and the CA
 * fingerprint over IPC. No token is ever shown: the snippets use a file or the variable `$CERBERUS_TOKEN`.
 */
export function ConnectGuide({ open, onOpenChange }: Props) {
  const m = useScreenT(messages);
  const [, navigate] = useLocation();
  const toast = useToast();
  const canCreateToken = useCan("operator");
  const [method, setMethod] = useState<Method>("mcp");
  const network = useQuery({ queryKey: dashKeys.network(), queryFn: () => ipc.networkStatus(), enabled: open });

  const exportCa = async () => {
    try {
      const dest = await pickSavePath("cerberus-ca.pem");
      if (dest === null) return;
      await ipc.tlsExportCa(dest);
      toast.push({ tone: "success", title: m("connect.step2.done") });
    } catch (error) {
      toast.push({ tone: "error", title: m("connect.copyFailed"), detail: isIpcFailure(error) ? errorText(error.error) : undefined });
    }
  };

  const body = () => {
    if (network.isPending) return <Skeleton label={m("connect.loading")} rows={3} />;
    if (network.isError) return <ErrorState action={m("connect.error.action")} error={network.error} onRetry={() => void network.refetch()} />;
    const net = network.data;
    const url = serverUrl(net);
    const panels: Record<Method, { intro: string; after: string; snippets: Snippet[] }> = {
      mcp: { intro: m("connect.mcp.intro"), after: m("connect.mcp.after"), snippets: mcpSnippets(url, net.pin) },
      rest: { intro: m("connect.rest.intro"), after: m("connect.rest.after"), snippets: restSnippets(url) },
      cli: { intro: m("connect.cli.intro"), after: m("connect.cli.after"), snippets: cliSnippets(url, net.pin) },
    };
    const panel = (id: Method) => (
      <div className="tab-body">
        <p className="secondary">{panels[id].intro}</p>
        {panels[id].snippets.map((s) => (
          <CodeSnippet key={s.label} snippet={s} />
        ))}
        <p className="small muted">{panels[id].after}</p>
      </div>
    );
    return (
      <div className="connect">
        {!net.listening && <p className="status warn">{m("connect.server.down", { reason: net.error ?? "" })}</p>}
        {net.custom_cert && <p className="status warn">{m("connect.custom")}</p>}
        <div className="facts-grid">
          <Fact label={m("connect.server")} value={url} />
          <Fact label={m("connect.fingerprint")} value={net.ca_fingerprint} />
          <Fact label={m("connect.pin")} value={net.pin} />
        </div>
        <p className="small muted">{m("connect.pinHint")}</p>
        <ol className="guide">
          <li>
            <span className="step-title">{m("connect.step1")}</span>
            <span className="small muted">{canCreateToken ? m("connect.step1.hint") : m("connect.viewer")}</span>
            <span>
              <Button
                size="sm"
                variant="primary"
                icon="key"
                disabled={!canCreateToken}
                onClick={() => {
                  onOpenChange(false);
                  navigate("~/agents?new=1");
                }}
              >
                {m("connect.step1.action")}
              </Button>
            </span>
          </li>
          <li>
            <span className="step-title">{m("connect.step2")}</span>
            <span className="small muted">{m("connect.step2.hint")}</span>
            <span>
              <Button size="sm" icon="download" onClick={() => void exportCa()}>
                {m("connect.step2.action")}
              </Button>
            </span>
          </li>
          <li>
            <span className="step-title">{m("connect.step3")}</span>
            <Tabs
              label={m("connect.tabs")}
              value={method}
              onChange={setMethod}
              tabs={[
                { id: "mcp", label: m("connect.tab.mcp"), panel: panel("mcp") },
                { id: "rest", label: m("connect.tab.rest"), panel: panel("rest") },
                { id: "cli", label: m("connect.tab.cli"), panel: panel("cli") },
              ]}
            />
          </li>
        </ol>
      </div>
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      wide
      title={m("connect.title")}
      description={m("connect.desc")}
      footer={<Button onClick={() => onOpenChange(false)}>{m("connect.close")}</Button>}
    >
      {body()}
    </Dialog>
  );
}
