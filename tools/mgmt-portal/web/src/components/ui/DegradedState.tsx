import type { ReactNode } from 'react'
import { ServerOff } from 'lucide-react'
import { cn } from '../../lib/cn'

/**
 * Degraded state — "the data source is not available" (Store/Docker/NRF/
 * Prometheus unconfigured, per `tools/mgmt-portal/CLAUDE.md` §10).
 *
 * This is deliberately NOT the same as {@link EmptyState}: an empty list means
 * the backend answered and there is nothing to show, whereas degraded means no
 * answer was possible. Rendering the wrong one misinforms the operator.
 */
export interface DegradedStateProps {
  title?: string
  description?: string
  action?: ReactNode
  className?: string
}

export default function DegradedState({
  title = 'Backend unavailable',
  description,
  action,
  className,
}: DegradedStateProps) {
  return (
    <div
      role="status"
      className={cn(
        'flex flex-col items-center justify-center gap-2 rounded-card border border-warning-border bg-warning-surface px-6 py-10 text-center',
        className,
      )}
    >
      <ServerOff size={28} className="text-warning-fg" aria-hidden="true" />
      <p className="text-sm font-semibold text-warning-fg">{title}</p>
      {description && <p className="max-w-sm text-xs text-warning-fg/90">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}
