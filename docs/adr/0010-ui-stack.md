# ADR-0010: UI uses React, TypeScript, Vite, Tailwind and shadcn/ui; languages English and Spanish

- Status: Accepted
- Date: 2026-11-16
- Plan reference: D10
- Related: ADR-0003, ADR-0011, ADR-0023

## Context

The desktop UI runs in the Tauri webview. It must look modern, be accessible (WCAG 2.2 AA) and have typed calls
to the backend.

## Decision

1. Stack (latest stable on 2026-11-16, checked on npm; T02 and T16 check again):

   | Package | Version |
   |---|---|
   | react | 19.3.1 |
   | typescript | 7.0.2 |
   | vite | 8.3.8 |
   | tailwindcss | 4.3.5 |
   | shadcn (CLI, copies components into the repo) | 4.23.0 |
   | @tauri-apps/api, @tauri-apps/cli | 2.12.4 |
   | @tanstack/react-query | 5.107.1 |
   | zustand | 5.1.0 |
   | motion (Framer Motion) | 14.14.0 |
   | lucide-react | 1.73.0 |
   | i18next / react-i18next | 27.1.2 / 18.0.1 |
   | vitest | 5.1.0 |
   | @playwright/test | 1.65.1 |

2. IPC types come from `tauri-specta` (generated `bindings.ts`). Hand-written IPC types are not allowed.
3. Languages: English (`en`, default) and Spanish (`es`). Strings are in `ui/src/locales/{en,es}.json`.
   A test fails if a key exists in one file and not in the other.
4. Fonts Inter and JetBrains Mono are bundled as files. No font CDN (CSP has no remote origins).
5. Secret values never go into a React Query cache, Zustand store or `localStorage`. They stay in a component
   state that clears on hide (15 s auto-hide).

## Consequences

- One type source for IPC. A changed command signature breaks the UI build, not the runtime.
- shadcn components are owned code. Updates are manual.

## Alternatives considered

- **Svelte or Solid.** Rejected. Smaller component ecosystem for accessible primitives.
- **Leptos or Yew (Rust UI).** Rejected. Less mature for the design system that T14 needs.
