import { createContext, useContext, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

const SlotContext = createContext<HTMLElement | null>(null);

/** The top bar renders `SlotProvider` around the shell and puts the slot element into it. */
export function PageActionsSlot({ children }: { children: (props: { setSlot: (el: HTMLElement | null) => void }) => ReactNode }) {
  const [slot, setSlot] = useState<HTMLElement | null>(null);
  return <SlotContext value={slot}>{children({ setSlot })}</SlotContext>;
}

/**
 * Put page actions (New item, Export) in the top bar from any screen:
 * `<PageActions><Button variant="primary">New item</Button></PageActions>`.
 * Render nothing when the screen is not inside the shell (solo or approval window).
 */
export function PageActions({ children }: { children: ReactNode }) {
  const slot = useContext(SlotContext);
  return slot ? createPortal(children, slot) : null;
}
