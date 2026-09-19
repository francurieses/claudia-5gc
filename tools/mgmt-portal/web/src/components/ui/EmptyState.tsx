import type { ReactNode } from 'react'
import { Inbox } from 'lucide-react'
import { cn } from '../../lib/cn'

/**
 * "There is genuinely no data" state — distinct from {@link DegradedState}
 * (backend unavailable). Never render this when the cause is a failed fetch;
 * see STYLE_GUIDE § States.
 */
export interface EmptyStateProps {
  title: string
  description?: string
  icon?: ReactNode
  action?: ReactNode
  className?: string
}

export default function EmptyState({ title, description, icon, action, className }: EmptyStateProps) {
  return (
    <div
      role="status"
      className={cn('flex flex-col items-center justify-center gap-2 px-6 py-10 text-center', className)}
    >
      <span className="text-muted-fg" aria-hidden="true">
        {icon ?? <Inbox size={28} />}
      </span>
      <p className="text-sm font-medium text-fg">{title}</p>
      {description && <p className="max-w-sm text-xs text-muted-fg">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}
