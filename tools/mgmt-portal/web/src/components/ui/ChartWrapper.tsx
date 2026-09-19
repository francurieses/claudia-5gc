import { useId, useMemo, useState } from 'react'
import type { ReactElement, ReactNode } from 'react'
import { ResponsiveContainer } from 'recharts'
import { BarChart3 } from 'lucide-react'
import { cn } from '../../lib/cn'
import { useTheme } from '../../lib/theme'
import Card from './Card'
import Button from './Button'
import Loading from './Loading'
import EmptyState from './EmptyState'
import DegradedState from './DegradedState'
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from './Table'

/**
 * Chart container for Recharts.
 *
 * Responsibilities:
 *  - theme-aware chart chrome via {@link useChartTheme} (axis/grid/tooltip read
 *    the CSS token variables, so they flip with light/dark);
 *  - four explicit states — `ready | loading | empty | unavailable` — so a
 *    stopped Prometheus renders "unavailable" and never a misleading zero line;
 *  - an accessible fallback: a toggle that swaps the SVG for an equivalent
 *    data table (screen-reader / colour-blind path).
 *
 * `children` must be a single Recharts chart element (e.g. `<LineChart>`); the
 * wrapper provides the `ResponsiveContainer`, so do not nest one yourself:
 *
 * ```tsx
 * <ChartWrapper title="UEs registered" state="ready" table={fallback} ariaLabel="UEs registered over time">
 *   <LineChart data={points}>
 *     <CartesianGrid stroke={chart.grid} strokeDasharray="3 3" />
 *     <XAxis dataKey="t" tick={{ fill: chart.tick }} stroke={chart.axis} />
 *     <YAxis tick={{ fill: chart.tick }} stroke={chart.axis} />
 *     <Tooltip contentStyle={{ ...chart.tooltip }} />
 *     <Line type="monotone" dataKey="v" stroke={chart.series[0]} />
 *   </LineChart>
 * </ChartWrapper>
 * ```
 */

export type ChartState = 'ready' | 'loading' | 'empty' | 'unavailable'

export interface ChartTableFallback {
  caption: string
  columns: string[]
  rows: Array<Array<string | number>>
}

export interface ChartTheme {
  /** Five series colours (chart-1..5), distinguishable by position and hue. */
  series: string[]
  grid: string
  axis: string
  tick: string
  tooltip: { backgroundColor: string; borderColor: string; color: string }
}

/** Light-theme defaults, used only if a CSS variable is unavailable. */
const FALLBACK_SERIES = ['rgb(37 99 235)', 'rgb(234 88 12)', 'rgb(21 128 61)', 'rgb(124 58 237)', 'rgb(8 145 178)']

function cssVar(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return value ? `rgb(${value})` : fallback
}

/**
 * Resolve the token-derived chart palette. Recomputes on theme change because
 * `useTheme()` re-renders the consumer when the `.dark` class flips.
 */
export function useChartTheme(): ChartTheme {
  const { theme } = useTheme()

  return useMemo<ChartTheme>(
    () => ({
      series: [1, 2, 3, 4, 5].map((i, index) => cssVar(`--c-chart-${i}`, FALLBACK_SERIES[index])),
      grid: cssVar('--c-border', 'rgb(226 232 240)'),
      axis: cssVar('--c-border-strong', 'rgb(203 213 225)'),
      tick: cssVar('--c-muted-fg', 'rgb(71 85 105)'),
      tooltip: {
        backgroundColor: cssVar('--c-card', 'rgb(255 255 255)'),
        borderColor: cssVar('--c-border', 'rgb(226 232 240)'),
        color: cssVar('--c-fg', 'rgb(30 41 59)'),
      },
    }),
    // `theme` is the invalidation signal — the tokens are read from the DOM.
    [theme],
  )
}

export interface ChartWrapperProps {
  children?: ReactElement
  title?: string
  description?: string
  /** Chart body height in px (default 280). */
  height?: number
  state?: ChartState
  emptyMessage?: string
  unavailableMessage?: string
  /** Accessible name for the chart region. */
  ariaLabel?: string
  /** Equivalent tabular view offered through the "Show table" toggle. */
  table?: ChartTableFallback
  /** Header action (range picker, refresh…). */
  action?: ReactNode
  className?: string
}

export default function ChartWrapper({
  children,
  title,
  description,
  height = 280,
  state = 'ready',
  emptyMessage = 'No data in the selected range',
  unavailableMessage = 'The metrics backend is not reachable. Start Prometheus and try again.',
  ariaLabel,
  table,
  action,
  className,
}: ChartWrapperProps) {
  const [showTable, setShowTable] = useState(false)
  const descriptionId = useId()

  return (
    <Card className={cn('flex flex-col', className)}>
      <div className="mb-3 flex items-start justify-between gap-3">
        <div className="min-w-0">
          {title && <h3 className="truncate text-sm font-semibold text-fg">{title}</h3>}
          {description && (
            <p id={descriptionId} className="mt-0.5 text-xs text-muted-fg">
              {description}
            </p>
          )}
        </div>
        <div className="flex flex-shrink-0 items-center gap-2">
          {action}
          {table && state !== 'unavailable' && (
            <Button variant="ghost" size="sm" aria-pressed={showTable} onClick={() => setShowTable(v => !v)}>
              {showTable ? 'Hide table' : 'Show table'}
            </Button>
          )}
        </div>
      </div>

      {state === 'loading' ? (
        <Loading rows={4} />
      ) : state === 'empty' ? (
        <EmptyState title={emptyMessage} icon={<BarChart3 size={28} />} />
      ) : state === 'unavailable' ? (
        <DegradedState title="Charts unavailable" description={unavailableMessage} />
      ) : showTable && table ? (
        <ChartDataTable table={table} />
      ) : children ? (
        <div
          role="img"
          aria-label={ariaLabel}
          aria-describedby={description ? descriptionId : undefined}
          style={{ height }}
          className="w-full"
        >
          <ResponsiveContainer width="100%" height="100%">
            {children}
          </ResponsiveContainer>
        </div>
      ) : null}
    </Card>
  )
}

function ChartDataTable({ table }: { table: ChartTableFallback }) {
  return (
    <Table caption={table.caption}>
      <TableHead>
        <TableRow>
          {table.columns.map(column => (
            <TableHeaderCell key={column}>{column}</TableHeaderCell>
          ))}
        </TableRow>
      </TableHead>
      <TableBody>
        {table.rows.map((row, rowIndex) => (
          <TableRow key={rowIndex}>
            {row.map((cell, cellIndex) => (
              <TableCell key={cellIndex} mono={typeof cell === 'number'}>
                {cell}
              </TableCell>
            ))}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
