# ClaudIA 5GC Management Portal — Style Guide

**Scope:** the professional view of `tools/mgmt-portal/web` (React 18 + TypeScript + Vite +
Tailwind). This document is the **source of truth** for visual language, component usage and
accessibility. If code and this guide disagree, one of them is a bug.

- Tokens live in [`src/index.css`](src/index.css) — the only place colour literals exist.
- Token → utility mapping lives in [`tailwind.config.js`](tailwind.config.js).
- The component layer lives in [`src/components/ui/`](src/components/ui/) (barrel: `./ui`).
- Shared display formatting lives in [`src/lib/format.ts`](src/lib/format.ts);
  React-free page logic in `src/lib/` (`navigation.ts`, `metricsRange.ts`, `theme.ts`).
- The contrast audit lives in [`scripts/contrast-audit.mjs`](scripts/contrast-audit.mjs).
- Backlog context: `dev/BACKLOG.md` → `PORTAL-UI-02` (tokens/primitives) … `PORTAL-UI-19`
  (final sweeps + this guide), plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md`
  Phases B and G.

> **Rule 0 — no raw palette utilities.** Never ship `bg-slate-900`, `text-red-400`,
> `border-blue-700`, `fill-amber-300`, … anywhere in `src/`. Consume semantic tokens
> (`bg-card`, `text-muted-fg`, `border-border`, `text-success-fg`) or a primitive.
> Raw palette classes do not flip with the theme and are the reason the pre-redesign
> portal was dark-only. Enforcement: [§ Enforcement](#enforcement).

---

## 1. Principles

| Principle | Consequence |
|---|---|
| **Minimalism / Swiss style** | Flat surfaces (`bg-card` + `border-border`), no gradients, no decorative shadows beyond `shadow-card` / `shadow-overlay`. |
| **Semantic over literal** | Components name intent (`variant="destructive"`), never a colour. |
| **Density with air** | Data-dense tables (`px-4 py-2.5`) but generous page rhythm (`p-6`, `mb-6`/`mb-8`). |
| **One way to do it** | One Button, one Table, one Dialog, one Toast. Extend via props, not a new component. |
| **Accessible by default** | The primitive carries the ARIA/focus wiring; a caller cannot "forget" it. |
| **Subtle motion** | 150–300 ms transitions, meaning-carrying only; `prefers-reduced-motion` collapses everything globally. |
| **Desktop-first, tablet-safe** | Designed at 1280–1920 px; must stay usable at 768–1024 px (projector/second screen). |

---

## 2. Theming contract

Two themes only — **Light** and **Dark** — implemented as a `.dark` class on `<html>`.

- `localStorage["theme"]` (`"light"` | `"dark"`) is an *explicit user choice* and overrides
  the OS. With no stored value the portal follows `prefers-color-scheme`.
- There is **no "System" option** in the UI (two-state toggle by design). Returning to
  OS-following requires clearing the key — `clearThemePreference()` in
  [`src/lib/theme.ts`](src/lib/theme.ts) — deliberately not exposed as a control.
- The inline bootstrap in [`index.html`](index.html) sets the class **before** the
  stylesheet paints (anti-FOUC). `theme.ts` and that inline script must stay in sync —
  they are the two halves of this contract.
- Any component that needs different *content* per theme uses `useTheme()` from
  `src/lib/theme.ts`; any component that needs different *colours* just uses tokens
  (they resolve automatically).

```tsx
const { theme, isDark, toggle, setTheme } = useTheme()
```

---

## 3. Tokens

41 CSS variables, declared identically for both themes in `src/index.css`:
`:root` = light, `.dark` = dark (the audit script asserts the two sets are equal in size).
A value is a **space-separated sRGB triplet** so Tailwind can emit opacity variants
(`bg-card/50`).

### Surfaces & text

| Token | Tailwind utility | Light | Dark | Use for |
|---|---|---|---|---|
| `--c-bg` | `bg-bg` | `#F8FAFC` | `#0F172A` | page background |
| `--c-fg` | `text-fg` | `#1E293B` | `#F8FAFC` | default text on the page |
| `--c-card` | `bg-card` | `#FFFFFF` | `#1B2336` | panels, tables, dialogs |
| `--c-card-fg` | `text-card-fg` | `#1E293B` | `#F8FAFC` | text on a card |
| `--c-muted` | `bg-muted` | `#E9EFF8` | `#272F42` | subtle fills, hover rows, skeletons |
| `--c-muted-fg` | `text-muted-fg` | `#475569` | `#94A3B8` | secondary/label text |
| `--c-border` | `border-border` | `#E2E8F0` | `#334155` | default border |
| `--c-border-strong` | `border-border-strong` | `#CBD5E1` | `#475569` | hover/emphasis border, chart axis |
| `--c-input` | `bg-input` | `#FFFFFF` | `#1B2336` | form control fill |
| `--c-input-border` | `border-input-border` | `#64748B` | `#64748B` | form control outline |
| `--c-ring` | `ring-ring` | `#2563EB` | `#60A5FA` | focus ring (global `:focus-visible`) |
| `--c-overlay` | `bg-overlay/60` | `#0F172A` | `#020617` | dialog / drawer scrim (always with an alpha) |

### Brand, actions, status

| Token | Tailwind utility | Light | Dark | Use for |
|---|---|---|---|---|
| `--c-primary` | `bg-primary` / `border-primary` | `#2563EB` | `#2563EB` | primary action **fill**, active nav background |
| `--c-primary-fg` | `text-primary-fg` | `#FFFFFF` | `#FFFFFF` | label on primary |
| `--c-primary-text` | `text-primary-text` | `#1D4ED8` | `#60A5FA` | primary as **text** (brand wordmark, coloured words, links) |
| `--c-secondary` | `bg-secondary` | `#3B82F6` | `#3B82F6` | secondary brand fill |
| `--c-secondary-fg` | `text-secondary-fg` | `#0F172A` | `#0F172A` | label on secondary |
| `--c-accent` | `bg-accent` / `border-accent` | `#EA580C` | `#EA580C` | reserved CTA fill / PWS emphasis (fill or ≥24 px figure only; see the 3:1 row below) |
| `--c-accent-fg` | `text-accent-fg` | `#0F172A` | `#0F172A` | label on accent |
| `--c-accent-text` | `text-accent-text` | `#9A3412` | `#FB923C` | accent as **text** (an accent-coloured word or figure) |
| `--c-destructive` | `bg-destructive` | `#DC2626` | `#DC2626` | destructive action |
| `--c-destructive-fg` | `text-destructive-fg` | `#FFFFFF` | `#FFFFFF` | label on destructive |
| `--c-success-{fg,surface,border}` | `text-success-fg`, `bg-success-surface`, `border-success-border` | `#15803D` / `#DCFCE7` / `#86EFAC` | `#4ADE80` / `#10251A` / `#225E3C` | success badge/status |
| `--c-warning-{fg,surface,border}` | `text-warning-fg`, `bg-warning-surface`, `border-warning-border` | `#92400E` / `#FEF3C7` / `#FCD34D` | `#FBBF24` / `#2A1F07` / `#856414` | warning / degraded |
| `--c-danger-{fg,surface,border}` | `text-danger-fg`, `bg-danger-surface`, `border-danger-border` | `#B91C1C` / `#FEE2E2` / `#FCA5A5` | `#F87171` / `#2A0F0F` / `#991B1B` | error / down |
| `--c-info-{fg,surface,border}` | `text-info-fg`, `bg-info-surface`, `border-info-border` | `#1D4ED8` / `#DBEAFE` / `#93C5FD` | `#60A5FA` / `#0E1E33` / `#1E40AF` | info / neutral-badged values |
| `--c-log-bg` / `--c-log-fg` | `bg-log-bg` / `text-log-fg` | `#EEF2F7` / `#1E293B` | `#0B1120` / `#E2E8F0` | log & terminal surfaces |
| `--c-chart-1..5` | `border-l-chart-N`, read at runtime for Recharts | see below | see below | series identity / NF accents |

Chart ramp (light → dark): `#2563EB→#60A5FA`, `#EA580C→#FB923C`, `#15803D→#4ADE80`,
`#7C3AED→#C084FC`, `#0891B2→#22D3EE`.

**Opacity:** every colour token supports `/N` (`bg-overlay/60`, `bg-muted/50`,
`text-danger-fg/90`). Prefer it over inventing a new token.

### Contrast (measured)

Computed from the emitted CSS in **both** themes (`relative luminance` per WCAG 2.x).
Requirement: **≥4.5:1** body text, **≥3:1** large text / UI boundaries / graphical objects.

**This table is machine-checked**: [`scripts/contrast-audit.mjs`](scripts/contrast-audit.mjs)
parses `src/index.css` and re-runs every sanctioned pair. Run it after any token change
(a token is not done until both themes pass):

```bash
node scripts/contrast-audit.mjs          # human-readable table
node scripts/contrast-audit.mjs --json   # machine-readable (exit 1 on a failure)
```

| Pair | Light | Dark | Req |
|---|---|---|---|
| body text on page/card/muted (`fg`) | 13.98 / 14.63 / 12.66 | 17.06 / 14.98 / 12.77 | 4.5 |
| card text on card (`card-fg`) | 14.63 | 14.98 | 4.5 |
| muted text on page/card/muted | 7.24 / 7.58 / 6.56 | 6.96 / 6.11 / 5.21 | 4.5 |
| label on primary | 5.17 | 5.17 | 4.5 |
| label on secondary | 4.85 | 4.85 | 4.5 |
| label on accent | 5.02 | 5.02 | 4.5 |
| label on destructive | 4.83 | 4.83 | 4.5 |
| **primary text** on page / card / muted (`primary-text`) | 6.41 / 6.70 / 5.80 | 7.02 / 6.16 / 5.26 | 4.5 |
| status text on page (success/warning/danger/info) | 4.79 / 6.78 / 6.18 / 6.41 | 10.25 / 10.69 / 6.45 / 7.02 | 4.5 |
| success / warning / danger / info badge text | 4.57 / 6.37 / 5.30 / 5.49 | 9.26 / 9.70 / 6.47 / 6.60 | 4.5 |
| log text on log surface | 13.01 | 15.27 | 4.5 |
| status text on log surface (`warning`/`danger`/`info-fg`) | 6.31 / 5.76 / 5.96 | 11.28 / 6.81 / 7.41 | 4.5 |
| focus ring on page | 4.94 | 7.02 | 3.0 |
| input border on card | 4.76 | 3.29 | 3.0 |
| **accent** on page / card (fill / ≥24 px figure only) | 3.40 / 3.56 | 5.02 / 4.40 | 3.0 |
| **accent text** on page / card / muted (`accent-text`) | 6.98 / 7.31 / 6.32 | 7.89 / 6.92 / 5.90 | 4.5 |
| chart series 1–5 on page | 4.94 / 3.40 / 4.79 / 5.45 / 3.52 | 7.02 / 7.89 / 10.25 / 6.76 / 9.88 | 3.0 |

**38 sanctioned pairs × 2 themes = 76 checks, 0 failures** (PORTAL-UI-19).

> **Found by the audit, not by eye (PORTAL-UI-19).** The manual table that preceded the
> script tracked ring/border/chart pairs but never checked the *brand* tokens as text, so it
> missed that `text-primary` (`#2563EB`) is **3.45:1** on the dark page and **3.03:1** on a
> dark card — a WCAG 1.4.3 failure in the header wordmark and the primary `StatCard`. It is
> invisible to the raw-colour grep because the class *is* a semantic token.

#### Two rules the audit encodes

1. **`primary` and `accent` are fills; `*-text` are the text roles.** `#2563EB` as text on the
   dark page is only 3.45:1 (3.03:1 on a dark card) and 4.5:1 on light `bg-muted`; `#EA580C`
   as text is 3.40:1 on the light page. So use `text-primary-text` / `text-accent-text` for
   coloured words, links and figures, and `bg-primary` / `bg-accent` for fills. Both `-text`
   tokens pass 4.5:1 on `bg`, `card` **and** `muted` in both themes. Enforcement: § 10 check 2.
2. **`accent` at body size is still legal only as a fill** — the surface behind it supplies the
   contrast (`accent-fg` on `accent` = 5.02:1). Never put `bg-accent` behind non-`accent-fg`
   text.

> **Log-surface caveat (resolved 2026-09-16).** `success-fg` on the *light* log surface
> measures **4.46:1** — 0.04 below the body-text bar — because `--c-log-bg` (#EEF2F7) is
> darker than the page background. It is therefore **not** a log-surface token: on a log
> surface use `text-log-fg`/`text-fg` for successful lines and reserve
> `warning-fg` / `danger-fg` / `info-fg` (all ≥4.5:1 in both themes) for the lines that
> genuinely need a colour cue. The one call site (the ping `time=` colouring in
> `src/pages/UERANSim.tsx`) was moved to `text-fg`; the pair is deliberately absent from the
> sanctioned pair list above so the audit cannot silently bless a new misuse.

---

## 4. Typography

Fonts: **Fira Sans** (UI) + **Fira Code** (mono) with system fallbacks, loaded from Google
Fonts in `index.html`. The **300 weight is intentionally excluded** (projector legibility);
do not use `font-light`.

Tailwind families: `font-sans` (default) and `font-mono` (`font-mono-terminal` component
class sets 0.8 rem / 1.5 for log surfaces).

| Role | Classes |
|---|---|
| Page title | `text-xl font-semibold` (via `PageHeader`; renders `<h1>`) |
| Section title | `text-sm font-semibold` (via `Section`; renders `<h3>` by default) |
| Body | `text-sm` (14 px) |
| Secondary / labels | `text-xs text-muted-fg` |
| Table header | `text-xs uppercase tracking-wider text-muted-fg` |
| KPI value | `text-3xl font-bold tabular-nums` |
| Identifiers / IPs | `font-mono text-xs` (`TableCell mono`) |

Never go below `text-xs` for content the operator must read. `tabular-nums` is required on
figures that sit in a column (counters, TEIDs, byte sizes).

---

## 5. Spacing, layout, radii, shadows

**Spacing scale (Tailwind 4 px base).** Use it; do not invent arbitrary values.

| Context | Value |
|---|---|
| Page padding | `p-6` |
| Section gap | `mb-6` (header→content), `mb-8` (between page blocks) |
| Card padding | `p-5` |
| Grid gaps | `gap-4` (cards) / `gap-2` (inline controls) |
| Table cell | `px-4 py-2.5` (body), `px-4 py-3` (header) |
| Control height | `h-8` sm / `h-10` md / `h-11` lg (44 px touch target) |

**Layout:** app shell = fixed sidebar (`w-64`) + scrollable `main`; below `lg` the sidebar
becomes an overlay drawer. Pages compose top-down: `PageHeader` → grid of `Card`/`StatCard`
→ `Section`s. Tables scroll horizontally inside their own container (`Table`), never the page.

**Radii:** `rounded-control` (6 px) for controls, `rounded-card` (8 px) for surfaces,
`rounded` (2 px) for badges/chips.

**Elevation:** `shadow-card` for resting surfaces, `shadow-overlay` for dialogs/toasts.
No other shadows.

---

## 6. Focus & motion

- A global `:focus-visible` ring (`2px solid rgb(var(--c-ring))`, `outline-offset: 2px`)
  is defined in `index.css`. **Never** add `outline-none` / `focus:outline-none` without
  an equivalent replacement.
- Transitions: `transition-colors` for state changes, `200ms` default. No animation on
  layout properties.
- `@media (prefers-reduced-motion: reduce)` collapses all durations globally — do not
  re-enable motion inside a component.

---

## 7. Component catalogue

Import from the barrel:

```tsx
import { Button, Card, Section, Table, TableHead, TableBody, TableRow,
         TableHeaderCell, TableCell, TableEmptyRow, Badge, Field, Input,
         Checkbox, Select, SegmentedControl, Tabs, Disclosure, EmptyState,
         Loading, ErrorState, DegradedState, Dialog, ConfirmDialog,
         IconButton, useToast } from '../components/ui'
```

### Button / IconButton

Variants `primary | secondary | destructive | ghost | icon`; sizes `sm | md | lg | icon`.
`loading` swaps in a spinner and blocks interaction.

```tsx
<Button variant="primary" onClick={save} loading={isSaving} icon={<Save size={16} />}>Save</Button>
<IconButton label="Refresh containers" onClick={refetch}><RefreshCw size={18} /></IconButton>
```

- **Do** use `primary` for the single main action of a view.
- **Do** use `IconButton` (never a bare `<button>`) for icon-only controls — `label` is a
  required prop and becomes both `aria-label` and `title`, and the ref is forwarded so a
  caller can move focus back to it (the nav drawer does).
- **Don't** encode state in colour alone (`variant` + text/icon must agree).
- **The three allowed bare `<button>`s** are inline *text-labelled* expanders/sorters that a
  `Button`/`IconButton` would mis-shape: the nav group toggle (`App.tsx`), the PCAP file-sort
  header, and the Policies "Show/Hide JSON rules" expander — each carries visible text plus
  `aria-expanded`/`aria-controls` (or `aria-sort` on the enclosing cell). Any new one needs
  the same justification.

### Input / Textarea / Select / Field

Always wrap a control in `Field`; use the render prop so ids and `aria-describedby` are wired.

```tsx
<Field label="DNN" hint="Only DNNs from operator.yaml are accepted" error={errors.dnn} required>
  {({ id, describedBy, invalid }) => (
    <Input id={id} aria-describedby={describedBy} invalid={invalid} value={dnn}
           onChange={e => setDnn(e.target.value)} />
  )}
</Field>

<Field label="PDU session type">
  {({ id }) => (
    <Select id={id} options={[{ value: 'IPv4', label: 'IPv4' }, { value: 'IPv4v6', label: 'IPv4v6' }]} />
  )}
</Field>
```

- Error text is announced (`role="alert"`); **never** put validation only in a page-level banner.
- `invalid` paints the danger border and sets `aria-invalid`; it does not replace the message.
- `Textarea` is mono and is the log/filter surface.

### Checkbox

One token-styled checkbox; the whole label row is the hit target. Omit `label` only in a
table cell / toolbar, where an `aria-label` **must** be passed instead.

```tsx
<Checkbox checked={restart} onChange={setRestart} label="Restart AMF, SMF and NSSF after saving" />

<Checkbox aria-label="Select all files" checked={allSelected} indeterminate={someSelected}
          disabled={rows.length === 0} onChange={setAll} />
```

- **Do** pass `indeterminate` for a select-all whose rows are partially selected — the native
  "mixed" state is announced, so partial selection is not a colour-only cue.
- **Don't** hand-roll `<input type="checkbox" className="…accent-primary">`.
- `labelClassName` overrides the label's default `text-sm text-fg` (e.g. the muted secondary
  option in Policies).

### SegmentedControl

One-of-a-few exclusive choice, rendered as a joined button row. Built on native radios in a
`<fieldset>`/`<legend>`, so arrow keys move the selection and the visible label is the
accessible name.

```tsx
<SegmentedControl label="PDU session type" value={pduType} onChange={setPduType}
                  options={[{ value: 'IPv4', label: 'IPv4' }, { value: 'IPv6', label: 'IPv6' },
                            { value: 'IPv4v6', label: 'IPv4v6' }]}
                  hint="IPv6/IPv4v6 need patch 0060 + a DNN ue_ipv6_prefix" />
```

- **Do** use it when there are ≤4 short options and reading them all at once helps.
- **Do** let it render its own label/hint/error (`role="alert"`); it does **not** go inside
  `Field` (a radio group is a `fieldset`, not a single `htmlFor` control).
- **Don't** use it for a long or dynamic list — that is a `Select`.

### Card / Section / PageHeader

- `Card` = surface only. `Section` = `Card` + title/description/actions; `bare` for nesting.
- `PageHeader` = one per page, `<h1>`, optional `eyebrow` (domain group) + `action`.
- **Don't** hand-roll a `div.rounded-card.border…` — use `Card`.

### Badge

Variants: `neutral | primary | success | warning | danger | info` — the canonical enum and
the only one left. The rollout's legacy aliases (`green|red|yellow|blue|gray`) were deleted at
PORTAL-UI-19; a page that still uses one no longer compiles.

```tsx
<Badge label="REGISTERED" variant="success" icon={<Check size={12} />} />
```

- **Rule:** a status badge must pair colour with an icon **and** meaningful text. If the
  label doesn't say the state, add an `sr-only` word (see `NFStatusCard`).

### Table family

```tsx
<Table caption="Active PDU sessions">
  <TableHead>
    <TableRow><TableHeaderCell>SUPI</TableHeaderCell><TableHeaderCell>UE IP</TableHeaderCell></TableRow>
  </TableHead>
  <TableBody>
    {rows.map(r => (
      <TableRow key={r.ref}>
        <TableCell mono>{r.supi}</TableCell>
        <TableCell mono>{r.ue_ip}</TableCell>
      </TableRow>
    ))}
    {rows.length === 0 && <TableEmptyRow colSpan={2}>No active sessions</TableEmptyRow>}
  </TableBody>
</Table>
```

Use `mono` for identifiers/IPs/TEIDs, `caption` for the accessible name,
`TableEmptyRow` for the in-place empty case (or `<DegradedState>` above the table when the
data source is unavailable).

`Table` brings its own card chrome — place it directly in the page (with an `h2`/`h3`
above it), or inside `<Section bare>`/`<Card padded={false}>`; do not nest it inside a
chrome'd `Section` or `Card`, which would draw a second border.

### Tabs

Controlled, ARIA tabs pattern (roving tabindex, Arrow/Home/End). Use for the PCAP /
PacketRusher / Logs-style multi-viewer surfaces.

```tsx
<Tabs label="Log source" value={tab} onChange={setTab}
      tabs={[{ id: 'pr', label: 'PacketRusher', content: <LogPanel /> },
             { id: 'amf', label: 'AMF', content: <LogPanel /> }]} />
```

### Disclosure

A collapsed-by-default `Card` whose header toggles a panel — the standard shape for a
section-scale long-running panel or an appendix (the QoS E2E / NW-triggered panels, the
Policies 3GPP reference). Uncontrolled (`defaultOpen`) or controlled (`open`/`onOpenChange`).

```tsx
<Disclosure title="NW-Triggered PDU Session" icon={<Radio size={16} />}
            hint="app detected → URSP delivery — TS 23.503 §6.6.2">
  …panel…
</Disclosure>
```

- The trigger is a real `<button>` with `aria-expanded` + `aria-controls`; the panel is
  mounted but `hidden` when closed, so an in-panel form keeps its state.
- `variant="sm"` is the muted, smaller appendix header (reference material).
- **Don't** use it for an inline expander *inside* a card or table row (e.g. "Show JSON
  rules", the per-policy rule row) — that keeps its local control, because the primitive
  would nest a second card chrome.

### States — empty vs degraded vs error vs loading

| Primitive | Meaning | When |
|---|---|---|
| `Loading` (spinner / `rows` skeleton) | request in flight | initial fetch, mutation pending |
| `EmptyState` | backend answered, **there is no data** | filtered list is empty, no sessions |
| `DegradedState` | **backend not available/configured** (`Store/Docker/NRF/Prometheus == nil`, CLAUDE.md §10) | never render `EmptyState` here |
| `ErrorState` | an action/fetch **failed** | mutation error, 5xx with retry |

Getting empty vs degraded wrong misinforms the operator — this is a review-blocking defect.

### Modal / Dialog / ConfirmDialog

`Modal` owns the overlay contract: portal to `body`, backdrop, scroll lock, ESC, focus trap,
focus restore. `Dialog` adds the labelled header/body/footer. `ConfirmDialog` is the
destructive-action variant (`role="alertdialog"`).

```tsx
<Dialog open={open} onClose={close} title="Modify QoS" description="NW-initiated PDU session modification"
        footer={<><Button variant="secondary" onClick={close}>Cancel</Button>
                   <Button onClick={apply} loading={busy}>Apply</Button></>}>
  …form…
</Dialog>

<ConfirmDialog open={confirming} destructive title="Delete DNN?"
  description="Removes the DNN from operator.yaml, SMF and UPF and drops the Docker network."
  confirmLabel="Delete" loading={deleting} onConfirm={remove} onCancel={() => setConfirming(false)} />
```

- **Do** put a `Dialog` in the component tree unconditionally and drive it with `open`;
  the internally-mounted `Modal` handles cleanup.
- **Don't** re-implement `fixed inset-0` overlays, `Escape` handlers or focus moves.
- Max width: `sm | md | lg | xl`.

### Toast

`<ToastProvider>` is mounted once in `src/main.tsx`. Call `useToast()` anywhere below it.

```tsx
const { toast } = useToast()
toast({ variant: 'success', title: 'QoS updated', description: '5QI 7 applied to PSI 1' })
toast({ variant: 'error', title: 'Push failed', description: err.message, duration: 0 })
```

- Errors use `role="alert"`; success/info/warning use `role="status"`.
- Auto-dismiss default 6000 ms; pass `duration: 0` for failures that must be acknowledged.
- Max 4 concurrent toasts; the dismiss button is labelled.

### ChartWrapper / useChartTheme

`ChartWrapper` = theme-aware chart card with four states and a tabular fallback.
`useChartTheme()` resolves token colours for axis/grid/tooltip/series.

```tsx
const chart = useChartTheme()
const state = isLoading ? 'loading' : error ? 'unavailable' : points.length ? 'ready' : 'empty'

<ChartWrapper title="UEs registered" state={state} ariaLabel="UEs registered over time"
  table={{ caption: 'UEs registered', columns: ['Time', 'UEs'], rows: tableRows }}>
  <LineChart data={points}>
    <CartesianGrid stroke={chart.grid} strokeDasharray="3 3" />
    <XAxis dataKey="t" tick={{ fill: chart.tick }} stroke={chart.axis} />
    <YAxis tick={{ fill: chart.tick }} stroke={chart.axis} />
    <Tooltip contentStyle={{ ...chart.tooltip }} />
    <Line type="monotone" dataKey="v" stroke={chart.series[0]} dot={false} />
  </LineChart>
</ChartWrapper>
```

- Pass a **bare** chart element — the wrapper provides `ResponsiveContainer`.
- `state="unavailable"` when Prometheus is unreachable → never plot zeros for missing data.
- Provide `table` for the accessible fallback; the toggle is keyboard-operable
  (`aria-pressed`).
- Distinguish series without hue: vary line style/markers and add direct labels, in
  addition to the ramp.
- **Reserved slots.** Where the layout must hold space before the data source exists,
  use a `Card` with `border-dashed` carrying the chart's title + description and its
  icon (see `Dashboard.tsx`'s "Metrics" grid, reserved for Phase F). Do not fake a
  `ChartWrapper` state — `state="empty"`/"unavailable" must mean what it says.
- `ChartWrapper` links the chart region to its `description` with `aria-describedby`
  (the region carries `role="img"` + `ariaLabel`).

### RangeControl (metrics time range)

`RangeControl` is the PRD S17 range selector used by the Dashboard charts: the
`15 m / 1 h / 6 h / 24 h` presets (default **1 h**) plus a custom `from`/`to` picker.
It is controlled — the page owns the selection and resolves the window through
`lib/metricsRange.ts`:

```tsx
const [rangeId, setRangeId] = useState<RangeId>(DEFAULT_RANGE_ID)
const [customRange, setCustomRange] = useState<CustomRange | null>(null)

<RangeControl
  value={rangeId}
  custom={customRange}
  onChange={(id, next) => {
    setRangeId(id)
    if (next) setCustomRange(next)
  }}
/>
```

- **Presets are relative.** The query key holds the preset id only; the window is
  recomputed as `to = now` inside `queryFn`, so polling slides the window forward
  without changing the key (no selection reset, no chart flicker — PRD §5.2).
- **A custom range is absolute.** Polling is disabled while one is selected.
- **Custom validation** lives in `lib/metricsRange.validateCustomRange`: both ends
  present, end > start, ≥10 s (the scrape interval) and ≤15 d (Prometheus retention).
  An invalid draft is never applied; the message is announced with `role="alert"`.

### Dashboard charts (PORTAL-UI-18, reworked PORTAL-UI-20)

The Dashboard's six 3GPP-grounded charts answer "is the core healthy right now?" — control
plane (registration, sessions), security (5G-AKA) and user plane (N3 throughput) — and are the
reference composition of the page-local `MetricChart` over the curated range endpoint
(`lib/api.getMetricsRange`):

| Chart | Metric key | Axis |
|---|---|---|
| UEs registered | `ue_registered` | count |
| Registration success rate | `registration_success_rate` | percent |
| Procedure results | `procedure_rates_by_result` | rate |
| PDU sessions active | `pdu_sessions_active` | count |
| 5G-AKA authentications | `authentication_rate` | rate |
| User-plane throughput (N3) | `upf_gtp_throughput` | throughput |

- **Axis modes.** `count` forces integer ticks; `rate` shows three decimals; `percent` pins a
  fixed `[0, 100]` domain with `%` ticks and an `n.nn %` tooltip; `throughput` formats SI
  bits/s via `lib/format.formatBitsPerSec`. The `rate`/`count` rendering is unchanged from
  PORTAL-UI-18 — only the two new modes are additive.
- **No-attempt windows stay gaps.** `registration_success_rate` is
  `100 × OK-rate / total-rate`; with no attempts it is `0/0 = NaN`, which the backend drops
  (`rangePoints`), so the chart shows a gap rather than a misleading 0% or 100% line.
- Series are merged onto their shared timestamp grid by `mergeSeries`; a missing
  sample stays absent, so a gap never becomes a zero line.
- Multi-series charts add a **dash-pattern** discriminator (solid / `6 3` / `2 4`) and
  a legend labelled in `text-fg` — never hue alone. The legend text avoids the series
  colour because small text needs 4.5:1, while the ramp is contrast-verified at 3:1 as
  a line/marker.
- Every chart passes `table` (the tabular fallback) and an `ariaLabel`.
- State mapping: `isLoading → loading`, request error → `unavailable` (never a zero
  line), no samples → `empty`, else `ready`. The `unavailable` description carries the
  backend error so a 400/502/503 is not mistaken for "no data".

### Map panel (Leaflet)

`Location` is the only Leaflet surface. The map is a `Card padded={false}` with a fixed
height (`h-[460px] overflow-hidden`), so the tiles get the same surface/radius/border as
every other panel.

- **Dark tiles (decision, PORTAL-UI-14).** The light OpenStreetMap layer stays the single
  tile source; the dark theme inverts it with a CSS filter on the **tile pane only** —
  `.dark .leaflet-tile-pane { filter: invert(1) hue-rotate(180deg) brightness(.92)
  contrast(.9) saturate(.75) }` in [`src/index.css`](src/index.css). Rejected: a dark
  tile-provider URL (extra runtime network dependency, extra attribution, different
  offline behaviour for no gain). Scoping the filter to the pane leaves the overlay,
  tooltip and control panes untouched, so markers keep their colours.
- **Marker / circle colours** come from `useChartTheme()` (Leaflet needs concrete colour
  values, not classes): the accuracy circle uses `series[0]`, the located marker
  `series[2]`. Re-resolving per theme means a live theme toggle re-styles the paths.
- **Vendor chrome** (zoom bar, attribution, tooltip + arrow) is re-tinted with tokens in
  `index.css`. Those rules live **outside** `@layer components` on purpose: Tailwind
  hoists that layer ahead of the imported `leaflet.css`, so an equal-specificity rule
  there is resolved in Leaflet's favour.
- **Accessibility:** the map is a visual aid; the `Table` below it (with `caption`) is
  the accessible data equivalent. The map container carries no `role`, so the focusable
  Leaflet canvas is not hidden from assistive tech.

---

## 8. Iconography

- **lucide-react only.** Never emoji, never a hand-written `<svg>` for a standard glyph.
- Default sizes: `14` inline in dense text, `16–18` in controls/headers, `28–32` in states.
- Decorative icons are `aria-hidden="true"` (the primitives already do this).
- Icon-only controls need a text alternative — use `IconButton label=…`.

---

## 9. Accessibility checklist (WCAG 2.1 AA)

Run this against any new/changed view:

- [ ] Every interactive element is reachable and operable by keyboard alone.
- [ ] Every control shows the focus ring (no `outline-none` without replacement).
- [ ] Icon-only buttons have an accessible name (`IconButton label`, or `aria-label`).
- [ ] Overlays trap focus, close on `ESC`, and restore focus to the trigger — including the
      below-`lg` navigation drawer (`useFocusTrap` with `enabled: drawerOpen`).
- [ ] Status is never conveyed by colour alone — pair with an icon and/or text.
- [ ] A select-all checkbox exposes the native `indeterminate` mixed state.
- [ ] Form fields have a visible `<label>`; errors sit next to the field and are announced.
- [ ] Text contrast ≥4.5:1; UI boundaries / chart lines ≥3:1, **in both themes** (§ 3).
- [ ] Charts have an accessible alternative (fallback table) and a text `ariaLabel`.
- [ ] Tables have a `caption`; header cells use `scope="col"`.
- [ ] Live regions are used for async outcomes (toasts/states), not for decoration.
- [ ] Nothing relies on hover to reveal essential content.
- [ ] Motion is subtle and honours `prefers-reduced-motion`.
- [ ] No page-level horizontal scroll at 1280 px: wide content scrolls **inside** its own
      container (`Table`, `overflow-x-auto` `<pre>`, `.log-surface`), never the page.
- [ ] No text below `text-xs`; no `font-light`/`font-thin` (projector legibility, § 4).

---

## 10. Enforcement

Three checks, all runnable from `tools/mgmt-portal/web`. No lint plugin or test runner is
added — the plan was accepted with these commands plus the per-page `CLAUDE.md` §5 behaviour
checklists as the regression control.

**1 — no raw palette utilities (S12).**

```bash
grep -rnE '(bg|text|border|ring|from|to|via|fill|stroke|divide|placeholder|outline|decoration|caret|shadow)-(gray|slate|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-[0-9]{2,3}' src --include='*.tsx'
```

**Expected:** no output. The **only** files allowed to contain colour literals are
`src/index.css` (the token definitions) and, if unavoidable, a documented exception in a
primitive — there are none today.

**2 — fill tokens are never used as text.**

```bash
grep -rnE 'text-(primary|accent)([^-a-z]|$)' src --include='*.tsx'
```

**Expected:** no output. Use `text-primary-text` / `text-accent-text` for coloured words and
figures; `bg-primary` / `bg-accent` remain the fills (§ 3, contrast rule 1).

**3 — contrast over the token table.**

```bash
node scripts/contrast-audit.mjs
```

**Expected:** `76 checks passed, 0 failures` (38 sanctioned pairs × 2 themes). But **this is
not sufficient** — a page can still misuse a token on the wrong surface. Two misuse rules the
pair list deliberately does not cover are review-blocking:

- `success-fg` on a log surface (use `text-fg`/`text-log-fg` there — § 3 caveat).
- `primary-fg` (white) on anything other than `primary`; `accent-fg` on anything other than
  `accent`.

**Recorded result (PORTAL-UI-02, primitives layer):**

| Scope | Hits |
|---|---|
| `src/components/ui/**` | 0 |
| `src/components/*.tsx` (reworked) | 0 |
| `src/main.tsx`, `src/lib/cn.ts` | 0 |
| `src/pages/Services.tsx` (PORTAL-UI-03) | 0 |
| `src/pages/Sessions.tsx` (PORTAL-UI-04) | 0 |
| `src/pages/Logs.tsx` (PORTAL-UI-05) | 0 |
| `src/pages/PCAP.tsx` (PORTAL-UI-06) | 0 |
| `src/pages/Subscribers.tsx` (PORTAL-UI-07) | 0 |
| `src/pages/Slices.tsx` (PORTAL-UI-08) | 0 |
| `src/pages/Policies.tsx` (PORTAL-UI-09) | 0 |
| `src/pages/UERANSim.tsx` (PORTAL-UI-10) | 0 |
| `src/pages/PacketRusher.tsx` (PORTAL-UI-11) | 0 |
| `src/pages/QoS.tsx` (PORTAL-UI-12) | 0 |
| `src/pages/PublicWarning.tsx` (PORTAL-UI-13) | 0 |
| `src/pages/Location.tsx` (PORTAL-UI-14) | 0 |
| `src/pages/Dashboard.tsx` (PORTAL-UI-15) | 0 |
| `src/components/ui/RangeControl.tsx` + `src/components/ui/ChartWrapper.tsx` (PORTAL-UI-18) | 0 |
| `src/pages/Dashboard.tsx` metrics charts (PORTAL-UI-18) | 0 |
| `src/components/ui/{Checkbox,Disclosure,SegmentedControl}.tsx`, `src/lib/format.ts` (PORTAL-UI-19) | 0 |
| Dashboard 6-chart rework — `src/pages/Dashboard.tsx`, `src/lib/format.ts`, `src/lib/api.ts` (PORTAL-UI-20) | 0 |
| Dashboard instant KPI cards — `src/pages/Dashboard.tsx`, `src/lib/api.ts` (PORTAL-UI-21) | 0 |
| **All of `src/**/*.tsx` + `src/**/*.ts`** (Phase C rollout + Phase F charts + Phase G sweeps + PORTAL-UI-20 + PORTAL-UI-21) | **0** |

The three commands were **executed clean at PORTAL-UI-19**: 0 raw-colour hits across
`src/**/*.tsx` and `src/**/*.ts`, 0 `text-primary`/`text-accent` text usages, and
`76 checks passed, 0 failures` on the contrast audit. The audit earned its keep in that pass:
with zero raw-colour hits, `text-primary` was still **3.03:1** on a dark card — a WCAG 1.4.3
failure the grep audit structurally cannot see — which is why `--c-primary-text` /
`--c-accent-text` now exist.

Re-run clean at the **PORTAL-UI-20** Dashboard 6-chart rework: 0 raw-colour hits, 0
fill-as-text uses, `76 checks passed, 0 failures` (the new charts reuse existing
tokens/primitives — percent and throughput axes add formatting, not colour).

Re-run clean at the **PORTAL-UI-21** Dashboard instant KPI cards: 0 raw-colour hits, 0
fill-as-text uses, `76 checks passed, 0 failures` (the two cards are existing `StatCard`s on
the `info` variant — no new colour).

---

## 11. Building a new component (recipe)

1. **Create** `src/components/ui/MyThing.tsx`; import `cn` from `../../lib/cn`.
2. **Structure**: one default export for the component, named exports only for compound
   parts; export a `MyThingProps` interface.
3. **Style**: semantic tokens only (`bg-card`, `text-muted-fg`, `border-border`,
   `rounded-control`/`rounded-card`, `shadow-card`). Use `cn()` for conditional classes and
   keep the base classes first so callers can append overrides.
4. **Accessibility**: add ARIA roles/labels; if it overlays, use `Modal`/`useFocusTrap`
   rather than re-implementing; if it shows status, pair colour with text/icon.
5. **States**: accept `loading`/`disabled`/empty affordances instead of leaving them to the caller.
6. **Export** it from `src/components/ui/index.ts` (values via `export { … }`, types via
   `export type { … }` — `isolatedModules` is on).
7. **Document** it in this guide (§ Components) with a usage snippet and a do/don't.
8. **Verify**: `npm run build` (tsc + vite) and all three § Enforcement checks pass
   (raw-colour grep, fill-as-text grep, `node scripts/contrast-audit.mjs`).
9. **Check both themes**: tokens must be used for *every* colour — if you cannot name the
   token for a colour you want, the design system is missing one; add it to `index.css`
   for *both* themes and to `tailwind.config.js` first.

> There is **no frontend test runner** (deliberate — PRD C2/C12, avoids a new dependency).
> Verification = type-check + build + grep audit + the per-page behaviour checklist in
> `tools/mgmt-portal/CLAUDE.md` §5 executed manually.

---

## 12. Decisions (closed at PORTAL-UI-19)

| Topic | Decision |
|---|---|
| Accent `#EA580C` | **Kept** as a fill / ≥24 px figure (3.40:1 light). Text uses the new `#9A3412` / `#FB923C` `accent-text` (≥6.3:1). Label on accent: `#0F172A` → 5.02:1. |
| Webfonts | **Kept on Google Fonts** — the runtime dependency is accepted for a dev tool, the stack carries system fallbacks so a projector without internet still renders, and the 300 weight is excluded. Self-hosting stays a possible follow-up, not a defect. |
| Leaflet dark tiles | **Decided (PORTAL-UI-14):** CSS filter on `.leaflet-tile-pane` in `index.css` (see § Map panel) — no dark tile provider, no new dependency. |
| Large-volume tables | **Closed:** no page needed truncation beyond the existing `max-w-[…] truncate` cells; `Table` scrolls internally. Revisit only if a page exceeds ~500 rows. |
| Formatting helpers | **Resolved:** [`src/lib/format.ts`](src/lib/format.ts) — `formatBytes` (PCAP) and `formatHex32` (TEID/TMSI). Add a helper only when a second page needs the same formatting. |
| Old URLs / redirects | **Closed (PORTAL-UI-16):** IA regrouping kept every path, so no `<Navigate>` redirects are needed. |
| Metrics endpoint shape | **Closed (PORTAL-UI-17):** curated whitelist, no arbitrary PromQL from the browser. |

---

## 13. Anticipated surfaces

Patterns the current 13 pages do not yet exercise in full, recorded so the next feature starts
from the guide instead of inventing a fourth look.

### Map panels (Leaflet)

Only `Location` today. Treat the map as a `Card padded={false}` with a fixed height and
`overflow-hidden`; keep the OSM tile layer and toggle dark with the `.leaflet-tile-pane`
filter; resolve marker/circle colours from `useChartTheme()`; always pair the map with a
`Table` carrying the same data as the accessible equivalent. Rejected: a dark tile-provider
URL (extra runtime dependency for no gain).

### Query forms (run a lookup, inspect the answer)

The `QoS` subscription inspector is the reference: `Field` + `Input` for the key, an explicit
submit, `EmptyState` for "no match" distinct from `DegradedState` for "backend unavailable",
and results in `Card`s/`KeyValue` rows rather than raw JSON. Never fire a query on every
keystroke against the core; submit on demand.

### Config forms (create/edit + optional restart)

The `Slices` / `Subscribers` forms are the reference: `Field` + `Input`/`Select`/
`SegmentedControl` for every control, inline `error` (never a page-level banner), the
restart/confirm side effect as a `Checkbox` next to the submit `Button`, and destructive paths
through `ConfirmDialog`. Large forms stay in-page; only short "apply this thing to that UE"
flows become a `Dialog` (`Policies`).

### Long-running orchestration status panels

The `QoS` NW-triggered / E2E panels are the reference: a `Disclosure` holding a step list where
each step pairs an icon with an `sr-only` succeeded/failed word, a pass-count `Badge`, a
partial-failure `Retry` action next to the failed-step summary, and the whole thing driven by
one mutation (not a page-local toast). A long-running action must never look like a normal
button press: `Button loading`, then a persistent status region.

### Data-dense tables

`Table` + `mono` cells + `TableEmptyRow`; sort with a text-labelled `<button>` inside the
header cell (`PCAP`); bulk selection with the `Checkbox` `indeterminate` state; export via a
plain link (`pcapDownloadURL`). If a table ever needs a detail row, `Policies`' expander row
(an `IconButton` with `aria-expanded`/`aria-controls` in the first cell) is the pattern.

---

## 14. Phase 2 — "basic view" considerations

The reduced **presentational** view discussed for showcases/workshops is out of scope for this
redesign, but the professional view already leaves room for it — do not hard-code against it:

- **One theme contract, two presets.** A basic view is a *layout* preset, not a second design
  system: it should reuse the same 41 tokens. If it wants a single fixed theme, set
  `localStorage.theme` / the `html` class rather than adding a palette.
- **Tokens, not per-view palettes.** Because no page hard-codes colour, a "basic" shell can
  restyle every page without touching them.
- **Reduced surfaces are subtractions, not forks.** The natural cuts are: hide the charts
  (`ChartWrapper` is self-contained), collapse the `Disclosure` panels, and drop the
  operations/safety pages from the nav (`lib/navigation.ts` is data, `NAV_GROUPS`). No page
  needs a `mode` prop for that.
- **Keep `lib/navigation.ts` React-free.** It is the single IA source; a second nav preset
  belongs there as a derived list, not as JSX in `App.tsx`.
- **No auth/restrictions.** The basic view is presentational only (no server-side restriction,
  no login gate); it must not be relied on to hide capability, and the API is unchanged.

---

*Living document. Phase B draft (PORTAL-UI-02); **finalised at PORTAL-UI-19 (Phase G)** — token
table machine-checked by `scripts/contrast-audit.mjs`, component catalogue complete (including
`Checkbox`, `Disclosure`, `SegmentedControl`), enforcement commands executed clean, anticipated
surfaces (§ 13) and phase-2 basic-view considerations (§ 14) recorded. If code and this guide
disagree, one of them is a bug.*
