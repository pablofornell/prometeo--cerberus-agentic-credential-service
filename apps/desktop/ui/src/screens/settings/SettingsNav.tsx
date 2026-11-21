import { memo, useCallback, useEffect, useRef, useState, type RefObject } from "react";
import { useScreenT } from "../../i18n";
import { Icon, type IconName } from "../../ui";
import { messages } from "./messages";

export type SectionId = "security" | "network" | "server" | "remote" | "appearance" | "backup" | "about";

export const SECTION_ICONS: Record<SectionId, IconName> = {
  security: "shield",
  network: "globe",
  server: "server",
  remote: "monitor",
  appearance: "palette",
  backup: "hardDrive",
  about: "info",
};

interface Props {
  sections: readonly SectionId[];
  /** The element that holds the sections (`[data-section]`). */
  root: RefObject<HTMLElement | null>;
  /** What the body shows. The sections are watched only while it is `sections`. */
  body: "sections" | "loading" | "error";
  /** A dot on the remote server entry while this desktop uses a server. */
  link: "ok" | "bad" | null;
}

/**
 * The section index. It owns the "section in view" state, so a change of the current section re-renders these few
 * buttons and not the settings route under them. The scroll-spy sets state only when the section changed.
 */
export const SettingsNav = memo(function SettingsNav({ sections, root, body, link }: Props) {
  const t = useScreenT(messages);
  const [current, setCurrent] = useState<SectionId>(sections[0] ?? "security");
  const shown = useRef(current);

  const show = useCallback((id: SectionId) => {
    if (shown.current === id) return;
    shown.current = id;
    setCurrent(id);
  }, []);

  // The nav marks the section in view. jsdom and old webviews have no IntersectionObserver: the nav then stays on the last click.
  useEffect(() => {
    const el = root.current;
    if (!el || body !== "sections" || typeof IntersectionObserver === "undefined") return;
    const io = new IntersectionObserver(
      (entries) => {
        let id: SectionId | undefined;
        for (const entry of entries) {
          if (entry.isIntersecting) id = (entry.target as HTMLElement).dataset.section as SectionId | undefined;
        }
        if (id) show(id);
      },
      { rootMargin: "-120px 0px -60% 0px" },
    );
    el.querySelectorAll("[data-section]").forEach((s) => io.observe(s));
    return () => io.disconnect();
  }, [root, body, show]);

  const go = useCallback(
    (id: SectionId) => {
      show(id);
      const target = root.current?.querySelector<HTMLElement>(`[data-section="${id}"]`);
      if (!target) return;
      const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
      target.scrollIntoView?.({ behavior: reduce ? "auto" : "smooth", block: "start" });
      target.querySelector<HTMLElement>("h2")?.focus({ preventScroll: true });
    },
    [root, show],
  );

  return (
    <nav className="subnav" aria-label={t("nav.label")}>
      {sections.map((id) => (
        <button key={id} type="button" aria-current={current === id ? "true" : undefined} onClick={() => go(id)}>
          <Icon name={SECTION_ICONS[id]} size={16} />
          <span>{t(`nav.${id}`)}</span>
          {id === "server" && link && <i className={`nav-dot ${link}`} aria-hidden="true" />}
        </button>
      ))}
    </nav>
  );
});
