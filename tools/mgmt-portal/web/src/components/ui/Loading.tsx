import { Loader } from 'lucide-react'
import { cn } from '../../lib/cn'

/**
 * Loading primitives — a spinner for inline/busy affordances and a skeleton
 * block for content placeholders. Both announce politely to assistive tech
 * (`role="status"` / `aria-busy`).
 */

export interface SpinnerProps {
  size?: number
  /** Screen-reader label (visually hidden). */
  label?: string
  className?: string
}

export function Spinner({ size = 18, label = 'Loading', className }: SpinnerProps) {
  return (
    <span role="status" className={cn('inline-flex items-center gap-2 text-muted-fg', className)}>
      <Loader size={size} className="animate-spin" aria-hidden="true" />
      <span className="sr-only">{label}</span>
    </span>
  )
}

/** A single skeleton bar. Compose several to fake a table or card while loading. */
export function Skeleton({ className }: { className?: string }) {
  return <span aria-hidden="true" className={cn('block animate-pulse rounded bg-muted', className)} />
}

export interface LoadingProps {
  label?: string
  className?: string
  /** When set, render this many stacked skeleton rows instead of a spinner. */
  rows?: number
}

export default function Loading({ label = 'Loading…', className, rows }: LoadingProps) {
  if (!rows) {
    return (
      <div className={cn('flex items-center justify-center py-10', className)}>
        <Spinner size={22} label={label} />
      </div>
    )
  }

  return (
    <div className={cn('space-y-2', className)} aria-busy="true" aria-live="polite">
      <span className="sr-only">{label}</span>
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-9 w-full" />
      ))}
    </div>
  )
}
