// Builds the connection snippets of the integration guide. Pure text: no token ever goes in. The token stays in
// the variable `$CERBERUS_TOKEN` or in a token file (docs/guides/mcp-client-config.md).
import type { NetworkView_Serialize } from "../../bindings";

export const TOKEN_FILE = "~/.config/cerberus/token";
export const CA_FILE = "~/.config/cerberus/ca.pem";

/** `https://127.0.0.1:7373`. A wildcard bind is shown as the loopback address, and IPv6 gets brackets. */
export function serverUrl(network: Pick<NetworkView_Serialize, "bind" | "port">): string {
  const first = network.bind.find((a) => a !== "0.0.0.0" && a !== "::") ?? "127.0.0.1";
  const host = first.includes(":") ? `[${first}]` : first;
  return `https://${host}:${network.port}`;
}

export interface Snippet {
  /** Short name of the file or the shell. */
  label: string;
  code: string;
}

export function mcpSnippets(url: string, pin: string): Snippet[] {
  const json = JSON.stringify(
    {
      mcpServers: {
        cerberus: {
          command: "cerberus-mcp",
          env: {
            CERBERUS_URL: url,
            CERBERUS_CA_FILE: CA_FILE,
            CERBERUS_CA_PIN: pin,
            CERBERUS_TOKEN_FILE: TOKEN_FILE,
          },
        },
      },
    },
    null,
    2,
  );
  return [
    { label: ".mcp.json", code: json },
    { label: "token file", code: `install -m 0600 /dev/null ${TOKEN_FILE}\n# paste the token into that file once, then close the editor` },
  ];
}

export function restSnippets(url: string): Snippet[] {
  return [
    {
      label: "curl",
      code: [
        `curl --cacert ${CA_FILE} \\`,
        `  -H "Authorization: Bearer $CERBERUS_TOKEN" \\`,
        `  ${url}/v1/status`,
      ].join("\n"),
    },
    {
      label: "curl, find a credential",
      code: [
        `curl --cacert ${CA_FILE} \\`,
        `  -H "Authorization: Bearer $CERBERUS_TOKEN" \\`,
        `  -H "Content-Type: application/json" \\`,
        `  -d '{"app":"shop","environment":"staging","purpose":"run the checkout tests","mode":"candidates"}' \\`,
        `  ${url}/v1/credentials/resolve`,
      ].join("\n"),
    },
  ];
}

export function cliSnippets(url: string, pin: string): Snippet[] {
  return [
    {
      label: "shell",
      code: [
        `export CERBERUS_URL=${url}`,
        `export CERBERUS_CA_FILE=${CA_FILE}`,
        `export CERBERUS_CA_PIN=${pin}`,
        `export CERBERUS_TOKEN_FILE=${TOKEN_FILE}`,
      ].join("\n"),
    },
    {
      label: "run a command",
      code: "cerberus run --app shop --env staging --role admin -- ./run-tests.sh",
    },
  ];
}
