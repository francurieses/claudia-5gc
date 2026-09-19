import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { CartesianGrid, Legend, Line, LineChart, Tooltip, XAxis, YAxis } from 'recharts'
import {
  getNFStatus, getMetricsRange, getMetricsSummary, getSessions, getUEContexts, getSubscribers,
} from '../lib/api'
import type { MetricsMetric } from '../lib/api'
import NFStatusCard from '../components/NFStatusCard'
import StatCard from '../components/StatCard'
import {
  Badge, Button, ChartWrapper, DegradedState, EmptyState, Loading, PageHeader, RangeControl, Section,
  Skeleton, Table, TableBody, TableCell, TableEmptyRow, TableHead, TableHeaderCell, TableRow,
  useChartTheme,
} from '../components/ui'
import type { ChartState, ChartTableFallback } from '../components/ui'
import {
  DEFAULT_RANGE_ID, chartSpanMs, formatRangePoint, formatTick, isEmptySeries,
  mergeSeries, rangeLabel, resolveRangeWindow,
} from '../lib/metricsRange'
import type { CustomRange, RangeId } from '../lib/metricsRange'
import { formatBitsPerSec } from '../lib/format'

/**
 * Poll interval for the preset (relative-window) charts. A custom range is
 * absolute, so polling stops while one is selected (PRD §5.2 — auto-refresh
 * must not reset the selection or flicker the chart).
 */
const RANGE_QUERY_INTERVAL_MS = 10_000

/**
 * Non-hue series identity (PRD §5.2 / S19): the first series is solid and the
 * rest dashed/dotted, so the chart survives greyscale and colour-vision
 * deficiency. The legend labels each series in `text-fg`.
 */
const LINE_DASH: Array<string | undefined> = [undefined, '6 3', '2 4']

export default function Dashboard() {
  const [rangeId, setRangeId] = useState<RangeId>(DEFAULT_RANGE_ID)
  const [customRange, setCustomRange] = useState<CustomRange | null>(null)

  function handleRangeChange(id: RangeId, next?: CustomRange) {
    setRangeId(id)
    if (next) setCustomRange(next)
  }

  const {
    data: nfStatus,
    isLoading: loadingNF,
    isError: nfError,
    error: nfErr,
    refetch: refetchNF,
  } = useQuery({
    queryKey: ['nf-status'],
    queryFn: getNFStatus,
    refetchInterval: 8_000,
  })

  const { data: metrics } = useQuery({
    queryKey: ['metrics-summary'],
    queryFn: getMetricsSummary,
    refetchInterval: 10_000,
  })

  const {
    data: sessions,
    isLoading: loadingSessions,
    isError: sessionsError,
    error: sessionsErr,
    refetch: refetchSessions,
  } = useQuery({
    queryKey: ['sessions'],
    queryFn: getSessions,
    refetchInterval: 10_000,
  })

  const { data: ueContexts } = useQuery({
    queryKey: ['ue-contexts'],
    queryFn: getUEContexts,
    refetchInterval: 10_000,
  })

  const { data: subscribers } = useQuery({
    queryKey: ['subscribers'],
    queryFn: getSubscribers,
    refetchInterval: 30_000,
  })

  const upCount = nfStatus?.filter(n => n.healthz_ok || n.metrics_ok).length ?? 0
  const totalNF = nfStatus?.length ?? 13
  const registeredCount = ueContexts?.filter(u => u.gmm_state === 1).length ?? 0
  const nfs = nfStatus ?? []
  const recentSessions = sessions?.slice(0, 8) ?? []

  return (
    <div className="space-y-8 p-6">
      <PageHeader eyebrow="Overview" title="Dashboard" subtitle="Real-time status of ClaudIA 5GC" />

      {/* KPI cards (PORTAL-UI-21 adds the two instant 5-minute success rates) */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
        <StatCard
          title="NFs Online"
          value={`${upCount} / ${totalNF}`}
          variant={upCount === totalNF ? 'success' : 'warning'}
        />
        <StatCard
          title="Provisioned Subscribers"
          value={subscribers?.length ?? '—'}
          sub={registeredCount > 0 ? `${registeredCount} currently registered` : 'none registered'}
          variant="info"
        />
        <StatCard
          title="Active PDU Sessions"
          value={sessions?.length ?? metrics?.pdu_sessions ?? '—'}
          variant="accent"
        />
        <StatCard
          title="NFs via NRF"
          value={nfStatus?.filter(n => n.registered).length ?? '—'}
          sub="registered instances"
        />
        <StatCard
          title="Registration Success"
          value={formatSuccessPct(metrics?.registration_success_pct)}
          sub="Initial Registration · last 5 min (TS 28.554 §5.1)"
          variant="info"
        />
        <StatCard
          title="PDU Session Success"
          value={formatSuccessPct(metrics?.pdu_session_establishment_success_pct)}
          sub="PDU session establishment · last 5 min (TS 28.554 §5.2)"
          variant="info"
        />
      </div>

      {/* Metrics — curated range queries (PORTAL-UI-17), six 3GPP-grounded KPIs (PORTAL-UI-20) */}
      <Section
        bare
        headingLevel={2}
        title="Metrics"
        description="Six 3GPP-grounded KPIs from the curated metrics backend — control plane (registration, sessions), security (5G-AKA) and user plane (N3 throughput). Presets are relative to now; a custom range is fixed."
      >
        <RangeControl value={rangeId} custom={customRange} onChange={handleRangeChange} className="mb-4" />
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <MetricChart
            metric="ue_registered"
            title="UEs registered"
            description="UEs in 5GMM-REGISTERED state (TS 28.554 §5.1)"
            axis="count"
            rangeId={rangeId}
            customRange={customRange}
          />
          <MetricChart
            metric="registration_success_rate"
            title="Registration success rate"
            description="Initial Registration OK / attempts × 100 (TS 28.554 §5.1)"
            axis="percent"
            emptyMessage="No registrations in this range — register a UE (UERANSIM page) to populate it."
            rangeId={rangeId}
            customRange={customRange}
          />
          <MetricChart
            metric="procedure_rates_by_result"
            title="Procedure results"
            description="Completions per second by result — watch REJECT / FAILURE"
            rangeId={rangeId}
            customRange={customRange}
          />
          <MetricChart
            metric="pdu_sessions_active"
            title="PDU sessions active"
            description="Active PDU sessions (SMF) (TS 28.554 §5.2)"
            axis="count"
            rangeId={rangeId}
            customRange={customRange}
          />
          <MetricChart
            metric="authentication_rate"
            title="5G-AKA authentications"
            description="Authentication completions per second by result (AUSF)"
            rangeId={rangeId}
            customRange={customRange}
          />
          <MetricChart
            metric="upf_gtp_throughput"
            title="User-plane throughput (N3)"
            description="GTP-U bits/s forwarded, uplink / downlink (TS 28.554 §5.3)"
            axis="throughput"
            emptyMessage="No user-plane traffic in this range — send real traffic, e.g. a ping from the UERANSIM page."
            rangeId={rangeId}
            customRange={customRange}
          />
        </div>
      </Section>

      {/* NF Status grid */}
      <Section bare headingLevel={2} title="Network Functions">
        {loadingNF ? (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
            {Array.from({ length: 9 }, (_, i) => (
              <Skeleton key={i} className="h-24 rounded-card" />
            ))}
          </div>
        ) : nfError ? (
          <DegradedState
            title="Network function status unavailable"
            description={`The portal could not reach NRF discovery: ${errMessage(nfErr)}. NF status needs the NRF and each NF's /healthz + /metrics endpoints (CLAUDE.md §10).`}
            action={
              <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetchNF()}>
                Retry
              </Button>
            }
          />
        ) : nfs.length === 0 ? (
          <EmptyState
            title="No network functions discovered"
            description="No NF is currently registered in the NRF. Start the core with make up and they will appear here."
          />
        ) : (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
            {nfs.map(nf => (
              <NFStatusCard key={nf.name} nf={nf} />
            ))}
          </div>
        )}
      </Section>

      {/* Active PDU Sessions table (latest 8) */}
      <Section
        bare
        headingLevel={2}
        title="Active PDU Sessions"
        description="Latest 8 active PDU sessions (SMF store)."
      >
        {sessionsError ? (
          <DegradedState
            title="Session data unavailable"
            description={`The portal could not read the session store: ${errMessage(sessionsErr)}. Session data needs PostgreSQL, which the portal degrades without (CLAUDE.md §10).`}
            action={
              <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetchSessions()}>
                Retry
              </Button>
            }
          />
        ) : !loadingSessions && recentSessions.length === 0 ? (
          <EmptyState
            title="No active PDU sessions"
            description="No PDU session currently has an assigned UE IP. A session appears here once a UE establishes one."
          />
        ) : (
          <Table caption="Latest active PDU sessions">
            <TableHead>
              <TableRow>
                <TableHeaderCell>SUPI</TableHeaderCell>
                <TableHeaderCell>DNN</TableHeaderCell>
                <TableHeaderCell>UE IP</TableHeaderCell>
                <TableHeaderCell>Slice</TableHeaderCell>
                <TableHeaderCell>Since</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loadingSessions ? (
                <TableEmptyRow colSpan={5}>
                  <Loading rows={3} label="Loading PDU sessions…" />
                </TableEmptyRow>
              ) : (
                recentSessions.map(s => (
                  <TableRow key={s.ref}>
                    <TableCell mono>{s.supi}</TableCell>
                    <TableCell>{s.dnn}</TableCell>
                    <TableCell mono>{s.ue_ip}</TableCell>
                    <TableCell>
                      <Badge
                        label={`SST:${s.sst}${s.sd ? '/SD:' + s.sd : ''}`}
                        variant="info"
                      />
                    </TableCell>
                    <TableCell className="text-xs text-muted-fg">
                      {new Date(s.created_at).toLocaleTimeString()}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        )}
      </Section>
    </div>
  )
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/**
 * Percentage for a nullable instant KPI (PORTAL-UI-21). `null`/`undefined`
 * means the 5-minute window had no data (or the backend is unreachable) —
 * render "—", never a fabricated 0% or 100%.
 */
function formatSuccessPct(value: number | null | undefined): string {
  return value == null ? '—' : `${value.toFixed(1)}%`
}

/** Chart axis modes: `count` integer ticks, `rate` fixed decimals, `percent` [0,100], `throughput` bits/s. */
type MetricAxis = 'rate' | 'count' | 'percent' | 'throughput'

interface MetricChartProps {
  metric: MetricsMetric
  title: string
  description: string
  axis?: MetricAxis
  /** Overrides ChartWrapper's default "no data" copy (e.g. when real traffic is needed). */
  emptyMessage?: string
  rangeId: RangeId
  customRange: CustomRange | null
}

/** Y-axis tick text per axis mode. */
function formatAxisTick(axis: MetricAxis, value: number): string {
  switch (axis) {
    case 'count':
      return String(Number(value))
    case 'percent':
      return `${Number(value).toFixed(0)}%`
    case 'throughput':
      return formatBitsPerSec(value)
    default:
      return Number(value).toFixed(3)
  }
}

/** Tooltip / table value text per axis mode; `—` for a missing sample. */
function formatAxisValue(axis: MetricAxis, value: number | undefined): string {
  if (value === undefined || Number.isNaN(value)) return '—'
  switch (axis) {
    case 'count':
      return value.toFixed(0)
    case 'percent':
      return `${value.toFixed(2)} %`
    case 'throughput':
      return formatBitsPerSec(value)
    default:
      return value.toFixed(3)
  }
}

/**
 * One dashboard trend chart. Owns its range query (keyed by metric + selection,
 * never by the resolved timestamps, so a relative preset keeps one query and
 * slides forward on each poll). ChartWrapper owns the four states and the
 * accessible table fallback.
 */
function MetricChart({ metric, title, description, axis = 'rate', emptyMessage, rangeId, customRange }: MetricChartProps) {
  const chart = useChartTheme()

  const query = useQuery({
    queryKey: ['metrics-range', metric, rangeId, customRange?.from ?? '', customRange?.to ?? ''],
    queryFn: () => {
      const { from, to } = resolveRangeWindow(rangeId, customRange)
      return getMetricsRange(metric, from, to)
    },
    refetchInterval: rangeId === 'custom' ? false : RANGE_QUERY_INTERVAL_MS,
  })

  const data = useMemo(() => mergeSeries(query.data?.series ?? []), [query.data])

  const state: ChartState = query.isLoading
    ? 'loading'
    : query.isError
      ? 'unavailable'
      : isEmptySeries(query.data?.series)
        ? 'empty'
        : 'ready'

  /**
   * A legend is needed whenever a series needs naming: several series, or a
   * single series whose name is not the metric itself (e.g. only "FAILURE"
   * present in the window).
   */
  const showLegend = data.keys.length > 0 && (data.keys.length > 1 || data.keys[0] !== metric)
  const table: ChartTableFallback | undefined =
    state === 'ready'
      ? {
          caption: `${title} (${rangeLabel(rangeId, customRange)})`,
          columns: ['Time', ...data.keys],
          rows: data.rows.map(row => [
            formatRangePoint(row.t),
            ...data.keys.map(key => formatAxisValue(axis, row[key])),
          ]),
        }
      : undefined

  return (
    <ChartWrapper
      title={title}
      description={description}
      height={220}
      state={state}
      ariaLabel={`${title} over time`}
      emptyMessage={emptyMessage}
      unavailableMessage={
        query.isError
          ? `The metrics backend could not serve this range: ${errMessage(query.error)}.`
          : undefined
      }
      table={table}
    >
      <LineChart data={data.rows} margin={{ top: 4, right: 8, bottom: 0, left: -8 }}>
        <CartesianGrid stroke={chart.grid} strokeDasharray="3 3" />
        <XAxis
          dataKey="t"
          tickFormatter={value => formatTick(Number(value), chartSpanMs(data.rows))}
          tick={{ fill: chart.tick, fontSize: 11 }}
          stroke={chart.axis}
          minTickGap={28}
        />
        <YAxis
          tick={{ fill: chart.tick, fontSize: 11 }}
          stroke={chart.axis}
          width={52}
          domain={axis === 'percent' ? [0, 100] : undefined}
          allowDecimals={axis !== 'count'}
          tickFormatter={value => formatAxisTick(axis, Number(value))}
        />
        <Tooltip
          contentStyle={chart.tooltip}
          labelFormatter={label => formatRangePoint(Number(label))}
          formatter={(value, name) => [formatAxisValue(axis, Number(value)), name]}
        />
        {showLegend && (
          <Legend wrapperStyle={{ fontSize: 12 }} formatter={value => <span className="text-fg">{value}</span>} />
        )}
        {data.keys.map((key, index) => (
          <Line
            key={key}
            type="monotone"
            dataKey={key}
            name={key}
            stroke={chart.series[index % chart.series.length]}
            strokeDasharray={LINE_DASH[index % LINE_DASH.length]}
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 3 }}
            connectNulls={false}
            isAnimationActive={false}
          />
        ))}
      </LineChart>
    </ChartWrapper>
  )
}
