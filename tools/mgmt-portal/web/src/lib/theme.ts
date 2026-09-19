/**
 * Theme (Light/Dark) — single source of truth for the client-side theme contract.
 *
 * Contract (mirrors the inline anti-FOUC bootstrap in `index.html`):
 *   - `localStorage["theme"]` ∈ {"light","dark"} is an *explicit user choice*
 *     and overrides the operating system.
 *   - With no stored value, the first visit follows `prefers-color-scheme` and
 *     keeps following it until the user makes an explicit choice.
 *   - There is no "System" state in the UI (two-state toggle, per the design
 *     decision). Returning to OS-following is only possible by clearing the
 *     stored preference — see {@link clearThemePreference} — and is deliberately
 *     not exposed as a control.
 *
 * There is no auth model in the portal (PRD §2), so the preference is
 * necessarily client-side.
 */

import { useCallback, useEffect, useState } from 'react'

export type Theme = 'light' | 'dark'

/** Must match the key read by the inline bootstrap in `index.html`. */
export const THEME_STORAGE_KEY = 'theme'

const DARK_QUERY = '(prefers-color-scheme: dark)'

function isTheme(value: unknown): value is Theme {
  return value === 'light' || value === 'dark'
}

/** The explicitly chosen theme, or `null` when the user has never toggled. */
export function getStoredTheme(): Theme | null {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY)
    return isTheme(stored) ? stored : null
  } catch {
    // Storage can throw in private mode / with cookies blocked.
    return null
  }
}

/** The operating system preference. Defaults to `light` when unavailable. */
export function getSystemTheme(): Theme {
  try {
    return window.matchMedia(DARK_QUERY).matches ? 'dark' : 'light'
  } catch {
    return 'light'
  }
}

/** The theme that should be active right now: explicit choice, else OS. */
export function resolveInitialTheme(): Theme {
  return getStoredTheme() ?? getSystemTheme()
}

/** Apply a theme to the document without persisting it. */
export function applyTheme(theme: Theme): void {
  const root = document.documentElement
  root.classList.toggle('dark', theme === 'dark')
  root.style.colorScheme = theme
}

/** Apply and persist an explicit user choice. */
export function setTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme)
  } catch {
    // Preference is best-effort; the theme still applies for this session.
  }
  applyTheme(theme)
}

/**
 * Drop the stored preference so the portal follows the OS again.
 * Not wired to any control (two-state toggle by design) — available for
 * support/debug use and documented in STYLE_GUIDE.md.
 */
export function clearThemePreference(): void {
  try {
    window.localStorage.removeItem(THEME_STORAGE_KEY)
  } catch {
    // ignore
  }
  applyTheme(getSystemTheme())
}

/** Ensure the DOM matches the resolved theme. Call once before first render. */
export function initTheme(): Theme {
  const theme = resolveInitialTheme()
  applyTheme(theme)
  return theme
}

export interface ThemeController {
  theme: Theme
  isDark: boolean
  /** Flip to the opposite theme and persist it (overrides the OS). */
  toggle: () => void
  /** Set an explicit theme and persist it. */
  setTheme: (theme: Theme) => void
}

/**
 * React binding for the theme contract.
 *
 * - Keeps `document.documentElement` in sync with the state.
 * - Follows live OS changes while no explicit preference is stored.
 * - Stays in sync across browser tabs via the `storage` event.
 */
export function useTheme(): ThemeController {
  const [theme, setThemeState] = useState<Theme>(() => resolveInitialTheme())

  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  // Follow the OS only while the user has not expressed a preference.
  useEffect(() => {
    if (getStoredTheme()) return
    let media: MediaQueryList
    try {
      media = window.matchMedia(DARK_QUERY)
    } catch {
      return
    }
    const onChange = (event: MediaQueryListEvent) => {
      setThemeState(event.matches ? 'dark' : 'light')
    }
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [theme])

  // Cross-tab consistency.
  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key !== THEME_STORAGE_KEY) return
      setThemeState(isTheme(event.newValue) ? event.newValue : getSystemTheme())
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const commit = useCallback((next: Theme) => {
    setTheme(next) // module-level: persists then applies to the document
    setThemeState(next)
  }, [])

  const toggle = useCallback(() => {
    commit(theme === 'dark' ? 'light' : 'dark')
  }, [theme, commit])

  return { theme, isDark: theme === 'dark', toggle, setTheme: commit }
}
