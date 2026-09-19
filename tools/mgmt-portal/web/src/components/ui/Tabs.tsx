import { useRef } from 'react'
import type { KeyboardEvent, ReactNode } from 'react'
import { cn } from '../../lib/cn'

/**
 * Accessible tabs (ARIA tabs pattern): roving tabindex, Arrow/Home/End
 * keyboard navigation, `aria-selected` + `aria-controls` wiring, and a
 * focusable panel. Controlled — the owner holds the active id.
 *
 * Used by the PCAP / PacketRusher / Logs-style viewers during the page rollout.
 */
export interface TabItem {
  id: string
  label: string
  icon?: ReactNode
  badge?: ReactNode
  content?: ReactNode
}

export interface TabsProps {
  tabs: TabItem[]
  value: string
  onChange: (id: string) => void
  /** Accessible name for the tablist (required — e.g. "Log source"). */
  label: string
  className?: string
  panelClassName?: string
}

export default function Tabs({ tabs, value, onChange, label, className, panelClassName }: TabsProps) {
  const refs = useRef<Record<string, HTMLButtonElement | null>>({})
  const activeIndex = Math.max(
    0,
    tabs.findIndex(t => t.id === value),
  )

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    let next = -1
    if (event.key === 'ArrowRight') next = (activeIndex + 1) % tabs.length
    else if (event.key === 'ArrowLeft') next = (activeIndex - 1 + tabs.length) % tabs.length
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = tabs.length - 1
    if (next < 0) return
    event.preventDefault()
    const tab = tabs[next]
    onChange(tab.id)
    refs.current[tab.id]?.focus()
  }

  const active = tabs[activeIndex]

  return (
    <div className={className}>
      <div role="tablist" aria-label={label} onKeyDown={onKeyDown} className="flex flex-wrap gap-1 border-b border-border">
        {tabs.map(tab => {
          const selected = tab.id === value
          return (
            <button
              key={tab.id}
              ref={el => {
                refs.current[tab.id] = el
              }}
              type="button"
              role="tab"
              id={`tab-${tab.id}`}
              aria-selected={selected}
              aria-controls={`panel-${tab.id}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => onChange(tab.id)}
              className={cn(
                'inline-flex items-center gap-2 border-b-2 px-3 py-2 text-sm font-medium transition-colors',
                selected
                  ? 'border-primary text-fg'
                  : 'border-transparent text-muted-fg hover:text-fg',
              )}
            >
              {tab.icon && (
                <span aria-hidden="true" className="flex-shrink-0">
                  {tab.icon}
                </span>
              )}
              {tab.label}
              {tab.badge}
            </button>
          )
        })}
      </div>

      {active?.content !== undefined && (
        <div
          id={`panel-${active.id}`}
          role="tabpanel"
          aria-labelledby={`tab-${active.id}`}
          tabIndex={0}
          className={cn('pt-4', panelClassName)}
        >
          {active.content}
        </div>
      )}
    </div>
  )
}
