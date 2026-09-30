import { useRef } from 'react'
import type { ReactNode } from 'react'
import { useStickToBottom } from '../../lib/useStickToBottom'
import { cn } from '../../lib/cn'
import Button from './Button'

/**
 * Focusable, fill-height log region. Follows the tail only while the user is at
 * the bottom (see useStickToBottom) and offers "Jump to latest" otherwise.
 * `dep` is any value that changes when lines are added.
 */
export interface LogSurfaceProps {
  label: string
  dep: unknown
  paused?: boolean
  children: ReactNode
  className?: string
}

export default function LogSurface({ label, dep, paused = false, children, className }: LogSurfaceProps) {
  const ref = useRef<HTMLDivElement>(null)
  const { atBottom, jumpToLatest } = useStickToBottom(ref, dep, paused)

  return (
    <div className="relative flex min-h-0 flex-1 flex-col">
      <div
        ref={ref}
        role="log"
        aria-label={label}
        tabIndex={0}
        className={cn('log-surface scroll-thin min-h-0 flex-1 overflow-y-auto p-3', className)}
      >
        {children}
      </div>
      {!atBottom && (
        <div className="absolute bottom-3 right-5">
          <Button size="sm" onClick={jumpToLatest}>
            Jump to latest
          </Button>
        </div>
      )}
    </div>
  )
}
