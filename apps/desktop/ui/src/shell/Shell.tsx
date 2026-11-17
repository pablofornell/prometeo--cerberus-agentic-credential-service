import { useEffect, useRef, type ReactNode } from "react";
import { Router } from "wouter";
import { t } from "../i18n";
import { ipc } from "../ipc/client";
import { useVaultStatus } from "../ipc/queries";
import { CommandPalette } from "./CommandPalette";
import { PageActionsSlot } from "./PageActions";
import { PanicDialog } from "./PanicDialog";
import { Rail } from "./Rail";
import { ShortcutsDialog, useGlobalShortcuts } from "./shortcuts";
import { TopBar } from "./TopBar";
import type { ScreenDef } from "./screens";

const ACTIVITY_THROTTLE_MS = 10_000;

/** Tells the backend a person is at work, so the idle lock waits. At most once every 10 s. */
function useActivityReport(): void {
  useEffect(() => {
    let last = 0;
    const report = () => {
      const now = Date.now();
      if (now - last < ACTIVITY_THROTTLE_MS) return;
      last = now;
      ipc.uiActivity().catch(() => undefined);
    };
    window.addEventListener("pointerdown", report);
    window.addEventListener("keydown", report);
    return () => {
      window.removeEventListener("pointerdown", report);
      window.removeEventListener("keydown", report);
    };
  }, []);
}

interface ShellProps {
  screen: ScreenDef;
  children: ReactNode;
}

/** The app layout: rail, top bar, content. Focus moves to the content on each route change. */
export function Shell({ screen, children }: ShellProps) {
  const status = useVaultStatus();
  const main = useRef<HTMLElement>(null);
  const first = useRef(true);
  useGlobalShortcuts();
  useActivityReport();

  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    main.current?.focus();
  }, [screen.id]);

  return (
    <PageActionsSlot>
      {({ setSlot }) => (
        <div className="shell">
          <a className="skip-link" href="#main" onClick={(e) => { e.preventDefault(); main.current?.focus(); }}>
            {t("app.skip")}
          </a>
          <Rail current={screen} inert={status.data?.state === "locking"} />
          <div className="workarea">
            <TopBar screen={screen} setSlot={setSlot} />
            <main id="main" className="content" tabIndex={-1} ref={main} aria-labelledby="page-title">
              {/* Screens with their own sub-routes get a base path, so they route relative to their folder. */}
              <Router base={screen.path}>{children}</Router>
            </main>
          </div>
          <CommandPalette />
          <ShortcutsDialog />
          <PanicDialog />
        </div>
      )}
    </PageActionsSlot>
  );
}
