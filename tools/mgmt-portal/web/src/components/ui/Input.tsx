import { forwardRef } from 'react'
import type { InputHTMLAttributes, TextareaHTMLAttributes } from 'react'
import { cn } from '../../lib/cn'

/**
 * Text input + textarea primitives.
 *
 * Pair with {@link Field} for the label/error/helper wiring. `invalid` sets
 * `aria-invalid` and the danger border; the error *message* still belongs to
 * the Field so it is announced once (see STYLE_GUIDE § Forms).
 */

const BASE =
  'w-full rounded-control border bg-input text-fg placeholder:text-muted-fg transition-colors disabled:cursor-not-allowed disabled:opacity-50'
const BORDER_OK = 'border-input-border focus:border-primary'
const BORDER_INVALID = 'border-danger'

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  invalid?: boolean
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { invalid = false, className, type = 'text', ...rest },
  ref,
) {
  return (
    <input
      ref={ref}
      type={type}
      aria-invalid={invalid || undefined}
      className={cn(BASE, 'h-10 px-3 text-sm', invalid ? BORDER_INVALID : BORDER_OK, className)}
      {...rest}
    />
  )
})

export interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  invalid?: boolean
}

/** Mono textarea — the log/filter surface (use with `.log-surface` when read-only). */
export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(function Textarea(
  { invalid = false, className, rows = 6, ...rest },
  ref,
) {
  return (
    <textarea
      ref={ref}
      rows={rows}
      aria-invalid={invalid || undefined}
      className={cn(BASE, 'px-3 py-2 font-mono text-xs', invalid ? BORDER_INVALID : BORDER_OK, className)}
      {...rest}
    />
  )
})
