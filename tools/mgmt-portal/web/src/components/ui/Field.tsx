import { useId } from 'react'
import type { ReactNode } from 'react'
import { cn } from '../../lib/cn'

/**
 * Form field wrapper — label + optional hint + optional error, with the
 * accessible wiring centralised so callers cannot forget it.
 *
 * Children may be a render prop that receives the ids/flags to spread onto the
 * control:
 *
 * ```tsx
 * <Field label="DNN" hint="From operator.yaml" error={error}>
 *   {({ id, describedBy, invalid }) => (
 *     <Input id={id} aria-describedby={describedBy} invalid={invalid} value={dnn} onChange={…} />
 *   )}
 * </Field>
 * ```
 *
 * The error message is announced with `role="alert"`; the hint is referenced by
 * `aria-describedby`. Only one of the two is rendered (error wins).
 */

export interface FieldControlProps {
  id: string
  describedBy?: string
  invalid: boolean
}

export interface FieldProps {
  label: string
  children: ReactNode | ((control: FieldControlProps) => ReactNode)
  hint?: string
  error?: string
  required?: boolean
  className?: string
}

export default function Field({ label, children, hint, error, required = false, className }: FieldProps) {
  const id = useId()
  const hintId = hint ? `${id}-hint` : undefined
  const errorId = error ? `${id}-error` : undefined
  const describedBy = [errorId, hintId].filter(Boolean).join(' ') || undefined
  const invalid = Boolean(error)

  return (
    <div className={cn('space-y-1', className)}>
      <label htmlFor={id} className="block text-xs font-medium text-muted-fg">
        {label}
        {required && (
          <>
            <span aria-hidden="true" className="ml-0.5 text-danger-fg">
              *
            </span>
            <span className="sr-only"> (required)</span>
          </>
        )}
      </label>

      {typeof children === 'function' ? children({ id, describedBy, invalid }) : children}

      {error ? (
        <p id={errorId} role="alert" className="text-xs text-danger-fg">
          {error}
        </p>
      ) : hint ? (
        <p id={hintId} className="text-xs text-muted-fg">
          {hint}
        </p>
      ) : null}
    </div>
  )
}
