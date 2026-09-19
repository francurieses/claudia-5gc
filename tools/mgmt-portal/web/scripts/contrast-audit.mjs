#!/usr/bin/env node
/**
 * Contrast audit for the Management Portal design tokens (PORTAL-UI-19).
 *
 * Reads the `--c-*` triplet variables straight out of `src/index.css` for the
 * light (`:root`) and dark (`.dark`) palettes and checks the sanctioned
 * foreground/background pairs against WCAG 2.1 AA:
 *
 *   - body text  ≥ 4.5:1
 *   - large text / UI boundaries / chart lines ≥ 3:1
 *
 * Only the pairs the design system actually sanctions are listed. `success-fg`
 * is deliberately absent as a *log-surface* foreground: measured 4.46:1 on the
 * light log surface, so it is not a log token (see STYLE_GUIDE §3 caveat).
 *
 * Dependency-free (Node builtins only) — no test runner is added to the app.
 * Run from `tools/mgmt-portal/web`:
 *
 *   node scripts/contrast-audit.mjs            # human-readable
 *   node scripts/contrast-audit.mjs --json     # machine-readable
 *
 * Exit code 1 if any sanctioned pair fails, so it can gate a change.
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const CSS_PATH = join(HERE, '..', 'src', 'index.css')

/** `[foreground, background, minimum ratio]` — every sanctioned token pair. */
const PAIRS = [
  // Surfaces & text
  ['fg', 'bg', 4.5],
  ['fg', 'card', 4.5],
  ['fg', 'muted', 4.5],
  ['card-fg', 'card', 4.5],
  ['muted-fg', 'bg', 4.5],
  ['muted-fg', 'card', 4.5],
  ['muted-fg', 'muted', 4.5],
  // Brand / actions
  ['primary-fg', 'primary', 4.5],
  ['secondary-fg', 'secondary', 4.5],
  ['accent-fg', 'accent', 4.5],
  ['destructive-fg', 'destructive', 4.5],
  // `primary` is a fill; `primary-text` is the body-safe blue as text — the fill
  // is only 3.5:1 on the dark page (and 4.5:1 on light `muted`).
  ['primary-text', 'bg', 4.5],
  ['primary-text', 'card', 4.5],
  ['primary-text', 'muted', 4.5],
  // Accent mirrors primary: `accent` is a fill / large-figure colour (3.4:1 on
  // the light page, hence 3:1) and `accent-text` is the body-safe variant.
  ['accent', 'bg', 3],
  ['accent', 'card', 3],
  ['accent-text', 'bg', 4.5],
  ['accent-text', 'card', 4.5],
  ['accent-text', 'muted', 4.5],
  // Status text on the page
  ['success-fg', 'bg', 4.5],
  ['warning-fg', 'bg', 4.5],
  ['danger-fg', 'bg', 4.5],
  ['info-fg', 'bg', 4.5],
  // Status text on its badge/chip surface
  ['success-fg', 'success-surface', 4.5],
  ['warning-fg', 'warning-surface', 4.5],
  ['danger-fg', 'danger-surface', 4.5],
  ['info-fg', 'info-surface', 4.5],
  // Log / terminal surface
  ['log-fg', 'log-bg', 4.5],
  ['warning-fg', 'log-bg', 4.5],
  ['danger-fg', 'log-bg', 4.5],
  ['info-fg', 'log-bg', 4.5],
  // UI boundaries / focus indicator
  ['ring', 'bg', 3],
  ['input-border', 'card', 3],
  // Chart series (graphical objects)
  ['chart-1', 'bg', 3],
  ['chart-2', 'bg', 3],
  ['chart-3', 'bg', 3],
  ['chart-4', 'bg', 3],
  ['chart-5', 'bg', 3],
]

// ---- parse -----------------------------------------------------------------

/** Extract `--c-name: R G B` triplets from one CSS rule block. */
function parseBlock(css, selector) {
  // Comments first — the header comment mentions `:root`, which would
  // otherwise be found before the real rule.
  const source = css.replace(/\/\*[\s\S]*?\*\//g, '')
  const rule = new RegExp(`${selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\{([^}]*)\\}`).exec(source)
  if (!rule) throw new Error(`selector ${selector} not found in ${CSS_PATH}`)

  const tokens = {}
  for (const match of rule[1].matchAll(/--c-([a-z0-9-]+):\s*(\d{1,3})\s+(\d{1,3})\s+(\d{1,3})\s*;/g)) {
    const [, name, r, g, b] = match
    tokens[name] = [Number(r), Number(g), Number(b)]
  }
  return tokens
}

// ---- contrast --------------------------------------------------------------

/** WCAG 2.1 relative luminance. */
function luminance([r, g, b]) {
  const channel = v => {
    const s = v / 255
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
  }
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}

function ratio(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

// ---- run -------------------------------------------------------------------

const css = readFileSync(CSS_PATH, 'utf8')
const themes = {
  light: parseBlock(css, ':root'),
  dark: parseBlock(css, '.dark'),
}

// Invariant: both palettes must be complete and identical in shape — a token
// defined for one theme only is a bug (index.css § Convention).
const lightNames = Object.keys(themes.light).sort()
const darkNames = Object.keys(themes.dark).sort()
const onlyLight = lightNames.filter(name => !(name in themes.dark))
const onlyDark = darkNames.filter(name => !(name in themes.light))
if (onlyLight.length || onlyDark.length) {
  throw new Error(
    `token sets differ between themes — light-only: [${onlyLight}] dark-only: [${onlyDark}]`,
  )
}

const json = process.argv.includes('--json')
const results = []
let failures = 0

for (const [themeName, tokens] of Object.entries(themes)) {
  for (const [fgName, bgName, min] of PAIRS) {
    const fg = tokens[fgName]
    const bg = tokens[bgName]
    if (!fg) throw new Error(`token --c-${fgName} missing from ${themeName}`)
    if (!bg) throw new Error(`token --c-${bgName} missing from ${themeName}`)

    const value = ratio(fg, bg)
    const pass = value >= min
    if (!pass) failures += 1
    results.push({ theme: themeName, fg: fgName, bg: bgName, min, ratio: Number(value.toFixed(2)), pass })
  }
}

if (json) {
  console.log(JSON.stringify({ pairs: PAIRS.length, checks: results.length, failures, results }, null, 2))
} else {
  console.log(`Contrast audit — ${CSS_PATH}`)
  console.log(`${PAIRS.length} sanctioned pairs × ${Object.keys(themes).length} themes = ${results.length} checks\n`)

  let current = null
  for (const r of results) {
    if (r.theme !== current) {
      current = r.theme
      console.log(`  ${r.theme.toUpperCase()}`)
    }
    const mark = r.pass ? 'ok  ' : 'FAIL'
    console.log(
      `    ${mark} ${r.fg.padEnd(15)} on ${r.bg.padEnd(16)} ` +
        `${r.ratio.toFixed(2).padStart(6)}:1  (min ${r.min})`,
    )
  }

  console.log(
    failures === 0
      ? `\n✓ ${results.length} checks passed, ${failures} failures`
      : `\n✗ ${failures} of ${results.length} checks FAILED`,
  )
}

process.exit(failures === 0 ? 0 : 1)
