import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { describe, expect, it } from "vitest";
import { mockError } from "../../ipc/mock/core";
import { renderApp } from "../../test/renderApp";
import { recordedHandlers } from "../agents/testkit";

describe("Policies screen", () => {
  it("shows the builder, the grants in plain words and the simulator, with no axe violations", async () => {
    const { handlers } = recordedHandlers();
    const { container } = renderApp({ path: "/policies", handlers });
    expect(await screen.findByRole("heading", { name: "New grant" })).toBeInTheDocument();
    const grants = await screen.findByRole("list", { name: "Grants" });
    expect(within(grants).getAllByRole("listitem")).toHaveLength(4);
    expect(within(grants).getByText("asks always")).toBeInTheDocument();
    expect(within(grants).getByText("blocked", { selector: ".mode" })).toBeInTheDocument();

    const sim = await screen.findByRole("table", { name: "What the agent can do with each item" });
    const row = (title: string) => within(sim).getAllByText(title)[0]?.closest("tr") as HTMLElement;
    expect(within(row("Shop staging admin")).getByText("Reads, never asks")).toBeInTheDocument();
    expect(within(row("Shop admin login")).getByText("Reads, asks every time")).toBeInTheDocument();
    expect(within(row("Billing API key")).getByText("Blocked")).toBeInTheDocument();
    expect(within(row("build-01 deploy key")).getByText("Invisible, no grant")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "What can QA runner see?" })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("writes each grant as a plain sentence", async () => {
    const { handlers } = recordedHandlers();
    renderApp({ path: "/policies", handlers });
    const grants = await screen.findByRole("list", { name: "Grants" });
    const texts = within(grants).getAllByRole("listitem").map((li) => li.querySelector("p")?.textContent ?? "");
    expect(texts).toContain("Can read items in workspace shop-frontend, env staging, any category. ");
    expect(texts).toContain("Can create sessions in workspace shop-frontend, any env, any category. ");
    expect(texts.some((text) => /items items|env any env|sessions items/.test(text))).toBe(false);
  });

  it("saves a grant built in words and refreshes the simulator", async () => {
    const user = userEvent.setup();
    const { handlers, calls } = recordedHandlers();
    renderApp({ path: "/policies", handlers });
    await screen.findByRole("heading", { name: "New grant" });
    await user.selectOptions(screen.getByLabelText("Workspace"), "ws-infra");
    await user.selectOptions(screen.getByLabelText("Environment"), "staging");
    await user.selectOptions(screen.getByLabelText("Category"), "SSH");
    await user.click(screen.getByRole("radio", { name: "once" }));
    expect(screen.getByText(/Once: the first read asks you/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save grant" }));
    await waitFor(() => expect(calls.grant_put).toHaveLength(1));
    expect(calls.grant_put?.[0]).toMatchObject({
      input: {
        id: null,
        agent_id: "agent-qa",
        permissions: ["read"],
        mode: "ask_once",
        selector: { workspace_ids: ["ws-infra"], environments: ["staging"], categories: ["SSH"] },
        allow_prod_auto: false,
      },
    });
    expect(await screen.findByText("Grant saved. The simulator is up to date.")).toBeInTheDocument();
    await waitFor(() => expect(calls.policy_simulate?.length).toBeGreaterThan(1));
    expect(await screen.findByRole("list", { name: "Grants" })).toHaveTextContent("build-infra");
  });

  it("moves the mode with arrow keys and warns that prod stays at always", async () => {
    const user = userEvent.setup();
    const { handlers } = recordedHandlers();
    renderApp({ path: "/policies", handlers });
    await screen.findByRole("heading", { name: "New grant" });
    await user.selectOptions(screen.getByLabelText("Environment"), "prod");
    expect(screen.getByText('Prod stays at "always".')).toBeInTheDocument();
    const never = screen.getByRole("radio", { name: "never" });
    never.focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("radio", { name: "once" })).toBeChecked();
    expect(screen.queryByText('Prod stays at "always".')).toBeNull();
  });

  it("lets only the owner skip prod approval, and shows the error code when the backend refuses", async () => {
    const user = userEvent.setup();
    const { handlers } = recordedHandlers({
      grant_put: () => {
        throw mockError("forbidden", "only the owner can allow prod reads without asking");
      },
    });
    renderApp({ path: "/policies", role: "operator", handlers });
    await screen.findByRole("heading", { name: "New grant" });
    await user.selectOptions(screen.getByLabelText("Environment"), "prod");
    expect(screen.getByRole("switch", { name: /Allow prod without asking/ })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Save grant" }));
    expect(await screen.findByText("The grant was not saved")).toBeInTheDocument();
    expect(screen.getByText("grant_put: forbidden")).toBeInTheDocument();
  });

  it("edits and deletes an existing grant", async () => {
    const user = userEvent.setup();
    const { handlers, calls } = recordedHandlers();
    renderApp({ path: "/policies", handlers });
    const grants = await screen.findByRole("list", { name: "Grants" });
    await user.click(within(grants).getAllByRole("button", { name: "Edit grant" })[0] as HTMLElement);
    expect(await screen.findByRole("heading", { name: "Edit grant" })).toBeInTheDocument();
    expect(screen.getByLabelText("Environment")).toHaveValue("staging");
    await user.click(screen.getByRole("button", { name: "Cancel edit" }));
    await user.click(within(grants).getAllByRole("button", { name: "Delete grant" })[0] as HTMLElement);
    const dialog = await screen.findByRole("dialog", { name: "Delete this grant?" });
    await user.click(within(dialog).getByRole("button", { name: "Delete grant" }));
    await waitFor(() => expect(calls.grant_delete).toEqual([{ grant: "grt_1" }]));
  });

  it("is read only for a viewer but still runs the simulator", async () => {
    const { handlers } = recordedHandlers();
    renderApp({ path: "/policies", role: "viewer", handlers });
    expect(await screen.findByText(/You are a viewer/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save grant" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit grant" })).toBeNull();
    expect(screen.getByLabelText("Environment")).toBeDisabled();
    expect(await screen.findByRole("table", { name: "What the agent can do with each item" })).toBeInTheDocument();
  });

  it("shows empty, loading and error states", async () => {
    const none = recordedHandlers({ agent_list: () => [] });
    const a = renderApp({ path: "/policies", handlers: none.handlers });
    expect(await screen.findByRole("heading", { name: "Create an agent first" })).toBeInTheDocument();
    a.unmount();

    const bare = recordedHandlers({ grant_list: () => [] });
    const b = renderApp({ path: "/policies", handlers: bare.handlers });
    expect(await screen.findByRole("heading", { name: "QA runner can see nothing" })).toBeInTheDocument();
    expect(await axe(b.container)).toHaveNoViolations();
    b.unmount();

    const slow = recordedHandlers({ agent_list: () => new Promise(() => undefined) });
    const c = renderApp({ path: "/policies", handlers: slow.handlers });
    expect(await screen.findByRole("status", { name: "Loading policies" })).toBeInTheDocument();
    c.unmount();

    const broken = recordedHandlers({
      policy_simulate: () => {
        throw mockError("internal", "boom");
      },
    });
    renderApp({ path: "/policies", handlers: broken.handlers });
    expect(await screen.findByRole("heading", { name: "Cannot run the simulator" })).toBeInTheDocument();
  });
});
