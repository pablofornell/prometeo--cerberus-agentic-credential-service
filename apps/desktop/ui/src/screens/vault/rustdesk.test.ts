import { describe, expect, it } from "vitest";
import { carriesServer, cleanRustdeskId, isRustdeskId, rustdeskConnection, rustdeskLink, rustdeskShareText } from "./rustdesk";

const labels = { id: "ID", idServer: "ID server", relayServer: "Relay", serverKey: "Key", link: "Link" };

describe("RustDesk helpers", () => {
  it("accepts 9 to 20 digits and removes the spaces RustDesk shows", () => {
    expect(isRustdeskId(cleanRustdeskId(" 123 456 789 "))).toBe(true);
    expect(isRustdeskId("12345678")).toBe(false);
    expect(isRustdeskId("123456789012345678901")).toBe(false);
    expect(isRustdeskId("12345678a")).toBe(false);
  });

  it("builds the link RustDesk reads: the ID, or the ID on a self-hosted server with its encoded key", () => {
    const link = (custom: Record<string, string>) => rustdeskLink(rustdeskConnection({ rustdesk_id: "123456789", ...custom }));
    expect(link({})).toBe("rustdesk://123456789");
    expect(link({ server_key: "a+b/c=" })).toBe("rustdesk://123456789");
    expect(link({ id_server: "rd.example.test:21116" })).toBe("rustdesk://connect/123456789@rd.example.test:21116");
    expect(link({ id_server: "rd.example.test", server_key: "a+b/c=" })).toBe("rustdesk://connect/123456789@rd.example.test?key=a%2Bb%2Fc%3D");
    expect(link({ id_server: "[2001:db8::1]:21116", server_key: "k" })).toBe("rustdesk://123456789");
    expect(carriesServer(rustdeskConnection({ rustdesk_id: "1", id_server: "[2001:db8::1]" }))).toBe(false);
    expect(carriesServer(rustdeskConnection({ rustdesk_id: "1", id_server: "10.0.0.7" }))).toBe(true);
  });

  it("shares only the facts that are set, and never a password", () => {
    const c = rustdeskConnection({ rustdesk_id: "123456789", id_server: "rd.example.test", relay_server: " ", password: "fake-rd-password" });
    const text = rustdeskShareText(c, labels);
    expect(text).toBe("ID: 123456789\nID server: rd.example.test\nLink: rustdesk://connect/123456789@rd.example.test");
    expect(text).not.toContain("fake-rd-password");
  });
});
