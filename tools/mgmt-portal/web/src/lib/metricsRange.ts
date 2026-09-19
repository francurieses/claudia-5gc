/**
 * Time-range + series shaping for the Dashboard charts (PORTAL-UI-18).
 *
 * React-free so the window maths and the Recharts data shaping stay testable in
 * isolation — the same pattern as `lib/navigation.ts`. The wire types come from
 * `lib/api.ts` (`MetricsRange`, which mirrors the backend whitelist in
 * `internal/api/metrics.go`).
 */

import type { MetricsRangeSeries } from './api'

export type RangePresetId = '15m' | '1h' | '6h' | '24h'

/** A preset window, or a user-picked one (`custom`). */
export type RangeId = RangePresetId | 'custom'

/** A custom range as produced by `<input type="datetime-local">` (local time). */
export interface CustomRange {
  from: string
  to: string
}

export interface RangePreset {
  id: RangePresetId
  label: string
  /** Window length in milliseconds. */
  ms: number
}

/** PRD S17 presets. `1h` is the default. */
export const RANGE_PRESETS: readonly RangePreset[] = [
  { id: '15m', label: '15 m', ms: 15 * 60_000 },
  { id: '1h', label: '1 h', ms: 60 * 60_000 },
  { id: '6h', label: '6 h', ms: 6 * 60 * 60_000 },
  { id: '24h', label: '24 h', ms: 24 * 60 * 60_000 },
]

export const DEFAULT_RANGE_ID: RangeId = '1h'

/** Prometheus retains 15 days by default; the range endpoint rejects wider windows. */
export const MAX_RANGE_MS = 15 * 24 * 60 * 60 * 1000

/**
 * The Prometheus scrape interval (`observability/prometheus/prometheus.yml`).
 * A shorter window cannot hold two samples, so the range query would be empty.
 */
export const MIN_RANGE_MS = 10_000

export interface RangeWindow {
  from: Date
  to: Date
}

/**
 * Resolve the effective window. Presets are relative to `now`, so a polling
 * chart slides forward while the *selection* (the query key) stays put; a
 * custom range is fixed and the Dashboard stops polling it.
 */
export function resolveRangeWindow(id: RangeId, custom: CustomRange | null, now: Date = new Date()): RangeWindow {
  if (id === 'custom' && custom) {
    return { from: new Date(custom.from), to: new Date(custom.to) }
  }
  const preset = RANGE_PRESETS.find(p => p.id === id) ?? RANGE_PRESETS[1]
  return { from: new Date(now.getTime() - preset.ms), to: now }
}

/** Validate a custom range; returns an error message, or `null` when valid. */
export function validateCustomRange(custom: CustomRange): string | null {
  if (!custom.from || !custom.to) return 'Pick both a start and an end.'
  const from = new Date(custom.from).getTime()
  const to = new Date(custom.to).getTime()
  if (Number.isNaN(from) || Number.isNaN(to)) return 'Enter a valid date and time.'
  if (to <= from) return 'The end must be after the start.'
  if (to - from < MIN_RANGE_MS) return 'The range must be at least 10 seconds (the Prometheus scrape interval).'
  if (to - from > MAX_RANGE_MS) return 'The range exceeds the 15 day Prometheus retention and would return nothing.'
  return null
}

/** Format a Date for `<input type="datetime-local">` (local time, minute precision). */
export function toDateTimeLocal(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

/** Human label for the selected range (table captions, chart descriptions). */
export function rangeLabel(id: RangeId, custom: CustomRange | null): string {
  if (id === 'custom' && custom) {
    return `${custom.from.replace('T', ' ')} → ${custom.to.replace('T', ' ')}`
  }
  const preset = RANGE_PRESETS.find(p => p.id === id)
  return `last ${preset?.label ?? '1 h'}`
}

/**
 * Short label for a Prometheus-style series name: `key{result="OK"}` → `OK`.
 * Used as the Recharts dataKey (must be unique within a chart) and as the
 * legend text.
 */
export function seriesLabel(name: string): string {
  const open = name.indexOf('{')
  const close = name.lastIndexOf('}')
  if (open === -1 || close <= open) return name
  const values = name
    .slice(open + 1, close)
    .split(',')
    .map(pair => {
      const eq = pair.indexOf('=')
      return (eq === -1 ? pair : pair.slice(eq + 1)).trim().replace(/^"|"$/g, '')
    })
    .filter(Boolean)
  return values.length > 0 ? values.join(' ') : name
}

export interface ChartRow {
  /** Unix seconds — the shared X axis. */
  t: number
  [series: string]: number
}

export interface ChartData {
  rows: ChartRow[]
  /** Series dataKeys, in the order the API returned them. */
  keys: string[]
}

/**
 * Merge matrix series onto their shared timestamp grid. A sample missing from
 * one series stays absent (Recharts draws a gap), so a gap is never rendered as
 * a zero line (PRD §5.2).
 */
export function mergeSeries(series: MetricsRangeSeries[]): ChartData {
  const keys = series.map(s => seriesLabel(s.name))
  const byTime = new Map<number, ChartRow>()
  series.forEach((s, index) => {
    const key = keys[index]
    for (const [t, v] of s.points) {
      const row = byTime.get(t) ?? { t }
      row[key] = v
      byTime.set(t, row)
    }
  })
  return { rows: [...byTime.values()].sort((a, b) => a.t - b.t), keys }
}

/** True when no series carries a single sample — the "empty" chart state. */
export function isEmptySeries(series: MetricsRangeSeries[] | undefined): boolean {
  return !series?.some(s => s.points.length > 0)
}

/** Window length of the returned data, for tick-density decisions. */
export function chartSpanMs(rows: ChartRow[]): number {
  if (rows.length < 2) return 0
  return (rows[rows.length - 1].t - rows[0].t) * 1000
}

/** X-axis tick: time only for short windows, date + time beyond 12 h. */
export function formatTick(unixSeconds: number, spanMs: number): string {
  const date = new Date(unixSeconds * 1000)
  const time = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  if (spanMs <= 12 * 60 * 60 * 1000) return time
  return `${date.getMonth() + 1}/${date.getDate()} ${time}`
}

/** Tooltip / table title: full local timestamp. */
export function formatRangePoint(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString()
}

/** Fixed-precision value so rates read consistently; `—` for a missing sample. */
export function formatRangeValue(value: number | undefined, digits: number): string {
  if (value === undefined || Number.isNaN(value)) return '—'
  return value.toFixed(digits)
}
