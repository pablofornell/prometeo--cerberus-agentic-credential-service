import { Link } from "wouter";
import { t } from "../i18n";
import { usePendingRequests, useVaultStatus } from "../ipc/queries";
import { useAutolockSeconds, useSessionLabel } from "../state/session";
import { formatLeft } from "../state/time";
import { Button, GateMark, IconButton, Icon, Kbd, TtlRing, useRandomTurn } from "../ui";
import { useShellActions } from "./actions";
import { navOwner, SCREENS, type ScreenDef } from "./screens";
import { openOverlay } from "./uiStore";

/** The rail (272 px, 240 px in compact density): brand, navigation with `G` hints, and the collar (who unlocked, auto-lock ring, Lock, panic). */
export function Rail({ current, inert }: { current: ScreenDef; inert?: boolean }) {
  const owner = navOwner(current);
  const pending = usePendingRequests();
  const count = pending.data?.length ?? 0;
  const nav = SCREENS.filter((s) => s.nav);
  const main = nav.filter((s) => s.id !== "settings");
  const settings = nav.filter((s) => s.id === "settings");
  const turning = useRandomTurn();

  const link = (s: ScreenDef) => (
    <Link key={s.id} href={s.path} aria-current={owner === s.id ? "page" : undefined}>
      <Icon name={s.icon} />
      <span>{t(`screen.${s.id}`)}</span>
      {s.id === "approval" && count > 0 ? (
        <span className="count" aria-label={`${count}`}>
          {count}
        </span>
      ) : (
        s.goKey && (
          <span className="keys" aria-hidden="true">
            <Kbd>G</Kbd> <Kbd>{s.goKey.toUpperCase()}</Kbd>
          </span>
        )
      )}
    </Link>
  );

  return (
    <aside className="sidebar" inert={inert}>
      <Link className="brand" href="/dashboard">
        <GateMark size={32} className={turning ? "gate-mark--turn" : undefined} />
        <span className="brand-txt">
          <span className="word">{t("app.name")}</span>
          <span className="tagline" aria-hidden="true">
            {t("app.tagline")}
          </span>
        </span>
      </Link>
      <nav className="nav" aria-label={t("nav.label")}>
        {main.map(link)}
        <div className="sep" role="separator" />
        {settings.map(link)}
      </nav>
      <Collar />
    </aside>
  );
}

function Collar() {
  const label = useSessionLabel();
  const left = useAutolockSeconds();
  const actions = useShellActions();
  const state = useVaultStatus().data?.state ?? "sealed";
  const open = state === "unlocked";
  return (
    <div className="collar" role="group" aria-label={t("collar.label")}>
      <div className="who">
        {open ? <TtlRing gate total={1800} left={left ?? 1800} size={32} /> : <GateMark size={32} mode="locked" />}
        <span className="t">
          <span className="small">
            {!open ? t(state === "locking" ? "collar.locking" : "collar.locked") : label ? t("collar.unlockedBy", { name: label }) : t("collar.unlocked")}
          </span>
          {open && <span className="small muted num">{left === null ? t("collar.autolock.off") : t("collar.autolock", { time: formatLeft(left) })}</span>}
        </span>
      </div>
      {open && (
        <div className="row">
          <Button size="sm" icon="lock" title={t("collar.lock.title")} onClick={actions.lock}>
            {t("collar.lock")}
          </Button>
          <IconButton icon="siren" size="sm" variant="danger-ghost" label={t("collar.panic")} onClick={() => openOverlay("panic")} />
        </div>
      )}
    </div>
  );
}
