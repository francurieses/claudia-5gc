import { forwardRef } from 'react'
import type { SelectHTMLAttributes } from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '../../lib/cn'

/**
 * Select primitive — native `<select>` for full keyboard/screen-reader support,
 * with the browser chrome replaced by a token-styled chevron affordance.
 *
 * Accepts either `<option>` children or an `options` array.
 */

export interface SelectOption {
  value: string
  label: string
  disabled?: boolean
}

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  invalid?: boolean
  options?: SelectOption[]
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { invalid = false, options, className, children, ...rest },
  ref,
) {
  return (
    <span className="relative block">
      <select
        ref={ref}
        aria-invalid={invalid || undefined}
        className={cn(
          'h-10 w-full appearance-none rounded-control border bg-input py-0 pl-3 pr-9 text-sm text-fg transition-colors disabled:cursor-not-allowed disabled:opacity-50',
          invalid ? 'border-danger' : 'border-input-border focus:border-primary',
          className,
        )}
        {...rest}
      >
        {options ? options.map(o => <option key={o.value} value={o.value} disabled={o.disabled}>{o.label}</option>) : children}
      </select>
      <ChevronDown
        size={16}
        aria-hidden="true"
        className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-muted-fg"
      />
    </span>
  )
})
