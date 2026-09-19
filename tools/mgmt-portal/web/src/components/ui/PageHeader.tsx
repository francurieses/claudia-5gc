import type { ReactNode } from 'react'
import { cn } from '../../lib/cn'

/**
 * Page title block — one per page, placed directly under the app header.
 *
 * `eyebrow` carries the domain group (e.g. `Runtime`), `action` the primary
 * page action (usually a {@link Button}). Long titles truncate rather than wrap
 * so the header height stays stable.
 */
export interface PageHeaderProps {
  title: string
  subtitle?: string
  /** Small uppercase label above the title (domain group / breadcrumb). */
  eyebrow?: string
  action?: ReactNode
  className?: string
}

export default function PageHeader({ title, subtitle, eyebrow, action, className }: PageHeaderProps) {
  return (
    <header className={cn('mb-6 flex items-start justify-between gap-4', className)}>
      <div className="min-w-0">
        {eyebrow && (
          <p className="text-xs font-medium uppercase tracking-wider text-muted-fg">{eyebrow}</p>
        )}
        <h1 className="truncate text-xl font-semibold text-fg">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-muted-fg">{subtitle}</p>}
      </div>
      {action && <div className="flex flex-shrink-0 items-center gap-2">{action}</div>}
    </header>
  )
}
