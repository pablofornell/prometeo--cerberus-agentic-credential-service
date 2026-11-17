import { t } from "../i18n";
import { Icon, Kbd } from "../ui";
import { screenById, type ScreenDef } from "./screens";
import { openOverlay } from "./uiStore";

/**
 * Page title (the h1), crumb, page actions slot and palette trigger. The lock state and the auto-lock countdown
 * live in the rail collar only (DEC-T21-1). The trigger's name is its visible text (WCAG 2.5.3).
 */
export function TopBar({ screen, setSlot }: { screen: ScreenDef; setSlot: (el: HTMLElement | null) => void }) {
  const parent = screen.parent ? screenById(screen.parent) : null;
  const mod = typeof navigator !== "undefined" && /mac/i.test(navigator.platform) ? "⌘" : "Ctrl";
  return (
    <header className="topbar">
      {parent && (
        <>
          <span className="crumb">{t(`screen.${parent.id}`)}</span>
          <Icon name="chevR" />
        </>
      )}
      <h1 id="page-title">{t(`screen.${screen.id}`)}</h1>
      <div className="actions">
        <span className="slot" ref={setSlot} />
        <button type="button" className="palette-trigger" aria-keyshortcuts="Control+K Meta+K" onClick={() => openOverlay("palette")}>
          <Icon name="search" />
          <span className="ph">{t("topbar.search")}</span>
          <span aria-hidden="true">
            <Kbd>{mod} K</Kbd>
          </span>
        </button>
      </div>
    </header>
  );
}
