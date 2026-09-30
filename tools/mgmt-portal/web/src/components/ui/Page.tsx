import type { ReactNode } from 'react'
import { cn } from '../../lib/cn'

/**
 * Page wrapper that declares who owns the scroll.
 *
 * - `scroll` (default): content flows and `<main>` is the single scroll region.
 * - `fill`: the page is exactly `<main>`'s height; exactly one inner region
 *   (`LogSurface`, `Table fill`, a map) takes `flex-1 min-h-0` and scrolls.
 *   Below 560 px of viewport height it reverts to `scroll` so content is
 *   never crushed.
 */
export interface PageProps {
  mode?: 'scroll' | 'fill'
  children: ReactNode
  className?: string
}

export default function Page({ mode = 'scroll', children, className }: PageProps) {
  return (
    <div
      className={cn(
        'p-6',
        mode === 'fill' && 'flex h-full min-h-0 flex-col [@media(max-height:560px)]:block [@media(max-height:560px)]:h-auto',
        className,
      )}
    >
      {children}
    </div>
  )
}
