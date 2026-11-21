import { describe, expect, it } from "vitest";
import { cleanRustdeskId, isRustdeskId, rustdeskConnection, rustdeskLink, rustdeskShareText } from "./rustdesk";

const labels = { id: "ID", idServer: "ID server", relayServer: "Relay", serverKey: "Key", link: "Link" };

describe("RustDesk helpers", () => {
  it("accepts 9 to 20 digits and removes the spaces RustDesk shows", () => {
    expect(isRustdeskId(cleanRustdeskId(" 123 456 789 "))).toBe(true);
    expect(isRustdeskId("12345678")).toBe(false);
    expect(isRustdeskId("123456789012345678901")).toBe(false);
    expect(isRustdeskId("12345678a")).toBe(false);
  });

  it("builds the link with an encoded key only when there is one", () => {
    expect(rustdeskLink(rustdeskConnection({ rustdesk_id: "123456789" }))).toBe("rustdesk://123456789");
    expect(rustdeskLink(rustdeskConnection({ rustdesk_id: "123456789", server_key: "a+b/c=" }))).toBe("rustdesk://123456789?key=a%2Bb%2Fc%3D");
  });

  it("shares only the facts that are set, and never a password", () => {
    const c = rustdeskConnection({ rustdesk_id: "123456789", id_server: "rd.example.test", relay_server: " ", password: "fake-rd-password" });
    const text = rustdeskShareText(c, labels);
    expect(text).toBe("ID: 123456789\nID server: rd.example.test\nLink: rustdesk://123456789");
    expect(text).not.toContain("fake-rd-password");
  });
});
