import type { HTMLAttributes, ReactNode } from 'react'
import { cn } from '../../lib/cn'

/**
 * Surface container — the base panel used by every page and by {@link Section}.
 *
 * Token-only: `bg-card` surface, `border-border` outline, `shadow-card`
 * elevation. `interactive` adds a hover affordance for clickable cards.
 */
export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode
  /** Apply the standard inner padding (default `true`). */
  padded?: boolean
  interactive?: boolean
}

export default function Card({ children, padded = true, interactive = false, className, ...rest }: CardProps) {
  return (
    <div
      className={cn(
        'rounded-card border border-border bg-card text-card-fg shadow-card',
        padded && 'p-5',
        interactive && 'transition-colors hover:border-border-strong',
        className,
      )}
      {...rest}
    >
      {children}
    </div>
  )
}
