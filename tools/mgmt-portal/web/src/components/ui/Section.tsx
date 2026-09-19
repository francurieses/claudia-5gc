import type { ReactNode } from 'react'
import { cn } from '../../lib/cn'

/**
 * Titled content section — a {@link Card} with a heading row and optional
 * actions. Use it for every logical block inside a page (the KPI row, a table
 * block, a form panel) so headings and spacing stay consistent.
 *
 * `bare` drops the card chrome, for nesting inside an existing Card.
 */
export interface SectionProps {
  title?: string
  description?: string
  actions?: ReactNode
  children: ReactNode
  className?: string
  bare?: boolean
  /** Heading level for the section title (default h3). */
  headingLevel?: 2 | 3 | 4
}

export default function Section({
  title,
  description,
  actions,
  children,
  className,
  bare = false,
  headingLevel = 3,
}: SectionProps) {
  const Heading = `h${headingLevel}` as 'h2' | 'h3' | 'h4'

  const body = (
    <>
      {(title || actions) && (
        <div className={cn('flex items-start justify-between gap-3', title && 'mb-4')}>
          <div className="min-w-0">
            {title && <Heading className="truncate text-sm font-semibold text-fg">{title}</Heading>}
            {description && <p className="mt-0.5 text-xs text-muted-fg">{description}</p>}
          </div>
          {actions && <div className="flex flex-shrink-0 items-center gap-2">{actions}</div>}
        </div>
      )}
      {children}
    </>
  )

  if (bare) return <section className={className}>{body}</section>

  return <section className={cn('rounded-card border border-border bg-card p-5 shadow-card', className)}>{body}</section>
}
