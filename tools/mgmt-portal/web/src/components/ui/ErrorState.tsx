import type { ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'
import { cn } from '../../lib/cn'

/**
 * Error state for a failed *action* or a failed fetch that the page chooses to
 * present as an error (as opposed to {@link DegradedState}, used when an
 * optional backend is simply not configured). Announced assertively.
 */
export interface ErrorStateProps {
  title?: string
  description?: string
  action?: ReactNode
  className?: string
}

export default function ErrorState({
  title = 'Something went wrong',
  description,
  action,
  className,
}: ErrorStateProps) {
  return (
    <div
      role="alert"
      className={cn(
        'flex flex-col items-center justify-center gap-2 rounded-card border border-danger-border bg-danger-surface px-6 py-10 text-center',
        className,
      )}
    >
      <AlertTriangle size={28} className="text-danger-fg" aria-hidden="true" />
      <p className="text-sm font-semibold text-danger-fg">{title}</p>
      {description && <p className="max-w-sm text-xs text-danger-fg/90">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}
