import { useId } from 'react'
import { cn } from '../../lib/cn'

/**
 * SegmentedControl primitive — one-of-a-few exclusive choice rendered as a
 * joined button row (PDU session type `IPv4 | IPv6 | IPv4v6`, TS 23.501
 * §5.8.2.2). Added at PORTAL-UI-19 to replace the page-local radiogroup in
 * UERANSim and the dropdown it duplicated in QoS.
 *
 * Built on native `<input type="radio">` inside a `<fieldset>`/`<legend>`:
 *  - real radio semantics — arrow keys move between options, one Tab stop;
 *  - the visible legend *is* the label, plus an optional hint/error wired by
 *    `aria-describedby` (an error is announced with `role="alert"`);
 *  - the inputs are visually hidden but focusable; the visible segment paints
 *    the focus ring, so the focus indicator is never lost.
 *
 * Use when the options are short and few (≲4) and reading them all at once
 * helps the operator. For a longer or dynamic list use `Select`.
 */

export interface SegmentedOption<T extends string> {
  value: T
  label: string
  disabled?: boolean
}

export interface SegmentedControlProps<T extends string> {
  /** Visible + accessible group label (rendered as the `<legend>`). */
  label: string
  value: T
  onChange: (value: T) => void
  options: ReadonlyArray<SegmentedOption<T>>
  hint?: string
  error?: string
  disabled?: boolean
  size?: 'sm' | 'md'
  className?: string
}

export default function SegmentedControl<T extends string>({
  label,
  value,
  onChange,
  options,
  hint,
  error,
  disabled = false,
  size = 'md',
  className,
}: SegmentedControlProps<T>) {
  const name = useId()
  const hintId = hint ? `${name}-hint` : undefined
  const errorId = error ? `${name}-error` : undefined
  const describedBy = [errorId, hintId].filter(Boolean).join(' ') || undefined

  // `m-0`/`min-w-0` on the fieldset: a `<fieldset>` keeps its UA margin and a
  // `min-content` floor, which would stop it shrinking inside a flex/grid cell.
  return (
    <fieldset className={cn('m-0 min-w-0 border-0 p-0', className)} aria-describedby={describedBy}>
      <legend className="mb-1 text-xs font-medium text-muted-fg">{label}</legend>

      <div
        className={cn(
          'inline-flex overflow-hidden rounded-control border',
          size === 'md' ? 'h-10' : 'h-8',
          error ? 'border-danger' : 'border-border',
        )}
      >
        {options.map((option, index) => {
          const optionId = `${name}-${index}`
          const optionDisabled = disabled || option.disabled
          return (
            <label
              key={option.value}
              htmlFor={optionId}
              className={cn('relative min-w-0 flex-1', index > 0 && 'border-l', error ? 'border-danger' : 'border-border')}
            >
              <input
                id={optionId}
                type="radio"
                name={name}
                value={option.value}
                checked={value === option.value}
                disabled={optionDisabled}
                onChange={() => onChange(option.value)}
                className="peer sr-only"
              />
              <span
                className={cn(
                  'flex h-full w-full cursor-pointer items-center justify-center whitespace-nowrap px-3 font-mono text-xs transition-colors',
                  'text-muted-fg hover:bg-muted/50',
                  'peer-checked:bg-primary peer-checked:text-primary-fg',
                  'peer-focus-visible:ring-2 peer-focus-visible:ring-inset peer-focus-visible:ring-ring',
                  'peer-disabled:cursor-not-allowed peer-disabled:opacity-50',
                )}
              >
                {option.label}
              </span>
            </label>
          )
        })}
      </div>

      {error ? (
        <p id={errorId} role="alert" className="mt-1 text-xs text-danger-fg">
          {error}
        </p>
      ) : hint ? (
        <p id={hintId} className="mt-1 text-xs text-muted-fg">
          {hint}
        </p>
      ) : null}
    </fieldset>
  )
}
