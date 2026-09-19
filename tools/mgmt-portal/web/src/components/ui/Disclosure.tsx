import { useId, useState } from 'react'
import type { ReactNode } from 'react'
import { ChevronDown } from 'lucide-react'
import Card from './Card'
import { cn } from '../../lib/cn'

/**
 * Disclosure primitive — a collapsed-by-default `Card` whose header toggles a
 * panel. Replaces the three page-local re-implementations the page rollout left
 * behind (QoS's two long-running panels, Policies' 3GPP spec reference)
 * — PORTAL-UI-19 consolidation.
 *
 * Contract:
 *  - The trigger is a real `<button>` with `aria-expanded` and `aria-controls`,
 *    so the panel relationship is exposed and keyboard-operable.
 *  - Controlled (`open` + `onOpenChange`) or uncontrolled (`defaultOpen`).
 *  - The panel is mounted but `hidden` when closed, so `aria-controls` always
 *    points at a real element and an in-panel form keeps its state.
 *
 * Use it for a **section-scale** disclosure. An inline expander *inside* a card
 * or table row (e.g. "Show JSON rules" in Policies) is a different pattern and
 * stays a local control — the primitive would nest a second card chrome.
 */

export interface DisclosureProps {
  title: ReactNode
  /** Right-aligned, secondary header text. */
  hint?: ReactNode
  /** Leading glyph (lucide icon). Marked decorative; the title is the label. */
  icon?: ReactNode
  children: ReactNode
  /** Uncontrolled: start expanded. */
  defaultOpen?: boolean
  /** Controlled open state — pair with `onOpenChange`. */
  open?: boolean
  onOpenChange?: (open: boolean) => void
  /**
   * Header emphasis: `md` (default) = section headline; `sm` = secondary
   * reference row (smaller, muted → foreground on hover, à la an appendix).
   */
  variant?: 'md' | 'sm'
  /** Extra classes for the panel body. */
  bodyClassName?: string
  className?: string
}

const HEADER = {
  md: 'gap-2 px-4 py-3 text-left text-sm font-semibold text-fg',
  sm: 'gap-2 px-4 py-2.5 text-left text-xs font-medium text-muted-fg hover:text-fg',
} as const

const BODY = {
  md: 'p-4',
  sm: 'px-4 py-4 text-xs leading-relaxed',
} as const

export default function Disclosure({
  title,
  hint,
  icon,
  children,
  defaultOpen = false,
  open,
  onOpenChange,
  variant = 'md',
  bodyClassName,
  className,
}: DisclosureProps) {
  const bodyId = useId()
  const [internalOpen, setInternalOpen] = useState(defaultOpen)
  const isOpen = open ?? internalOpen

  const toggle = () => {
    const next = !isOpen
    if (open === undefined) setInternalOpen(next)
    onOpenChange?.(next)
  }

  return (
    <Card padded={false} className={cn('overflow-hidden', className)}>
      <button
        type="button"
        onClick={toggle}
        aria-expanded={isOpen}
        aria-controls={bodyId}
        className={cn(
          'flex w-full flex-wrap items-center justify-between transition-colors hover:bg-muted/50',
          HEADER[variant],
        )}
      >
        <span className="flex items-center gap-2">
          <ChevronDown
            size={variant === 'md' ? 16 : 14}
            aria-hidden="true"
            className={cn('flex-shrink-0 transition-transform duration-200', !isOpen && '-rotate-90')}
          />
          {icon && <span aria-hidden="true" className="flex-shrink-0">{icon}</span>}
          {title}
        </span>
        {hint && <span className="text-xs font-normal text-muted-fg">{hint}</span>}
      </button>

      <div id={bodyId} hidden={!isOpen} className={cn('border-t border-border', BODY[variant], bodyClassName)}>
        {children}
      </div>
    </Card>
  )
}
