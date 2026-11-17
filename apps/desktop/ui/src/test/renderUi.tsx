import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { ToastProvider } from "../ui";

/** Renders a component inside the providers the library needs (toasts). */
export const renderUi = (ui: ReactElement) => render(<ToastProvider>{ui}</ToastProvider>);
