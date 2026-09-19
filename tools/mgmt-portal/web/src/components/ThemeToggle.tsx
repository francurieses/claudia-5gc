import { Moon, Sun } from 'lucide-react'
import { useTheme } from '../lib/theme'
import { IconButton } from './ui/Button'

/**
 * Two-state Light/Dark switch for the portal header.
 *
 * - Icon-only ⇒ `IconButton` requires an `aria-label` describing the *action*.
 * - Persists the choice in `localStorage` via `useTheme`, overriding the OS.
 * - 44×44 px hit area (touch target) from the `IconButton` primitive.
 */
export default function ThemeToggle() {
  const { isDark, toggle } = useTheme()
  const label = isDark ? 'Switch to light theme' : 'Switch to dark theme'

  return (
    <IconButton label={label} variant="secondary" onClick={toggle}>
      {isDark ? <Sun size={18} /> : <Moon size={18} />}
    </IconButton>
  )
}
