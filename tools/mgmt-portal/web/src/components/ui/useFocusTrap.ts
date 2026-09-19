import { useEffect, useRef } from 'react'
import type { RefObject } from 'react'

/**
 * Focus-trap hook for overlays (dialogs, drawers).
 *
 * Contract:
 *  - On mount, focus moves into the container (the `initialFocus` element, else
 *    the first tabbable child, else the container itself — give it `tabIndex={-1}`).
 *  - `Tab`/`Shift+Tab` cycle within the container.
 *  - `Escape` invokes `onEscape`.
 *  - On unmount, focus returns to the element that was focused before.
 *
 * The container ref returned by the hook must be attached to the element that
 * owns the focusable content.
 */

const FOCUSABLE = [
  'a[href]',
  'area[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'iframe',
  'object',
  'embed',
  '[contenteditable="true"]',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

export interface FocusTrapOptions {
  /** Called when Escape is pressed inside the overlay. */
  onEscape?: () => void
  /** Element focused when the overlay opens (defaults to first tabbable child). */
  initialFocus?: RefObject<HTMLElement | null>
  /** Disable without unmounting the hook (default `true`). */
  enabled?: boolean
}

export function useFocusTrap<T extends HTMLElement>(options: FocusTrapOptions = {}): RefObject<T> {
  const containerRef = useRef<T>(null)
  const onEscapeRef = useRef(options.onEscape)
  const initialFocusRef = useRef(options.initialFocus)
  const enabled = options.enabled ?? true

  // Keep the latest callbacks without re-arming the trap on every render.
  onEscapeRef.current = options.onEscape
  initialFocusRef.current = options.initialFocus

  useEffect(() => {
    if (!enabled) return
    const container = containerRef.current
    if (!container) return

    const previouslyFocused =
      document.activeElement instanceof HTMLElement ? document.activeElement : null

    const getTabbable = () =>
      Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        el => el.tabIndex !== -1 && el.getAttribute('aria-hidden') !== 'true',
      )

    const firstTarget: HTMLElement =
      initialFocusRef.current?.current ?? getTabbable()[0] ?? container
    firstTarget.focus()

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation()
        onEscapeRef.current?.()
        return
      }
      if (event.key !== 'Tab') return

      const tabbable = getTabbable()
      if (tabbable.length === 0) {
        event.preventDefault()
        container.focus()
        return
      }

      const first = tabbable[0]
      const last = tabbable[tabbable.length - 1]
      const active = document.activeElement

      if (event.shiftKey) {
        if (active === first || !container.contains(active)) {
          event.preventDefault()
          last.focus()
        }
      } else if (active === last || !container.contains(active)) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown, true)
    return () => {
      document.removeEventListener('keydown', onKeyDown, true)
      previouslyFocused?.focus()
    }
  }, [enabled])

  return containerRef
}
