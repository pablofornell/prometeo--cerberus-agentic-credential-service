import { act, render, screen } from "@testing-library/react";
import { Router, useLocation } from "wouter";
import { describe, expect, it } from "vitest";
import { useHashLocation, useHashQuery } from "./location";

function Probe() {
  const [path] = useLocation();
  const query = useHashQuery();
  return (
    <p>
      {path} | agent={query.get("agent") ?? "-"} new={query.get("new") ?? "-"}
    </p>
  );
}

const renderProbe = () =>
  render(
    <Router hook={useHashLocation}>
      <Probe />
    </Router>,
  );

const setHash = (hash: string) =>
  act(async () => {
    window.location.hash = hash;
    window.dispatchEvent(new HashChangeEvent("hashchange"));
  });

describe("hash location", () => {
  it("keeps the query out of the path and reads it with useHashQuery", () => {
    window.location.hash = "#/agents?agent=a_1&new=1";
    renderProbe();
    expect(screen.getByText("/agents | agent=a_1 new=1")).toBeInTheDocument();
  });

  it("has an empty query when the hash has none", () => {
    window.location.hash = "#/vault";
    renderProbe();
    expect(screen.getByText("/vault | agent=- new=-")).toBeInTheDocument();
  });

  it("updates path and query when the hash changes", async () => {
    window.location.hash = "#/agents";
    renderProbe();
    expect(screen.getByText("/agents | agent=- new=-")).toBeInTheDocument();
    await setHash("#/policies?new=1");
    expect(screen.getByText("/policies | agent=- new=1")).toBeInTheDocument();
  });

  it("decodes encoded values", () => {
    window.location.hash = "#/agents?agent=a%20b";
    renderProbe();
    expect(screen.getByText("/agents | agent=a b new=-")).toBeInTheDocument();
  });
});
