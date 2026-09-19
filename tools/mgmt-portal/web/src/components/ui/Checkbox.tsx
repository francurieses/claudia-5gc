import { useEffect, useRef } from 'react'
import type { ReactNode } from 'react'
import { cn } from '../../lib/cn'

/**
 * Checkbox primitive — one token-styled control for the whole portal.
 *
 * Replaces the native `<input type="checkbox" className="…accent-primary">`
 * that Slices, PCAP and Policies were each repeating (PORTAL-UI-19
 * consolidation). The whole label row is the hit target.
 *
 * Accessibility:
 *  - A visible `label` is standard. In a table cell / toolbar where there is no
 *    room for text, omit `label` and pass `aria-label` — a checkbox is never
 *    left without an accessible name.
 *  - `indeterminate` (select-all) is a native flag set via ref; assistive tech
 *    announces it as "mixed", so partial selection is never a colour-only cue.
 */

const INPUT =
  'h-4 w-4 flex-shrink-0 cursor-pointer rounded border-border accent-primary disabled:cursor-not-allowed disabled:opacity-50'
const LABEL_TEXT = 'text-sm text-fg'

export interface CheckboxProps {
  checked: boolean
  onChange: (checked: boolean) => void
  /** Visible label text. Omit only when an `aria-label` is supplied. */
  label?: ReactNode
  /** Secondary line rendered under the label (smaller, muted). */
  description?: ReactNode
  disabled?: boolean
  /** Partial-selection state (e.g. a table's "select all"). */
  indeterminate?: boolean
  className?: string
  /** Override the label text styling (default `text-sm text-fg`). */
  labelClassName?: string
  'aria-label'?: string
}

export default function Checkbox({
  checked,
  onChange,
  label,
  description,
  disabled = false,
  indeterminate = false,
  className,
  labelClassName,
  'aria-label': ariaLabel,
}: CheckboxProps) {
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (inputRef.current) inputRef.current.indeterminate = indeterminate
  }, [indeterminate])

  const input = (
    <input
      ref={inputRef}
      type="checkbox"
      checked={checked}
      disabled={disabled}
      aria-label={ariaLabel}
      onChange={event => onChange(event.target.checked)}
      className={INPUT}
    />
  )

  if (label === undefined && description === undefined) {
    // Bare control (table cell / toolbar) — the accessible name is `aria-label`.
    return <span className={cn('inline-flex', className)}>{input}</span>
  }

  return (
    <label
      className={cn(
        'flex cursor-pointer items-center gap-2',
        disabled && 'cursor-not-allowed opacity-50',
        className,
      )}
    >
      {input}
      {description !== undefined ? (
        <span className="min-w-0">
          <span className={cn('block', LABEL_TEXT, labelClassName)}>{label}</span>
          <span className="block text-xs text-muted-fg">{description}</span>
        </span>
      ) : (
        <span className={cn(LABEL_TEXT, labelClassName)}>{label}</span>
      )}
    </label>
  )
}
