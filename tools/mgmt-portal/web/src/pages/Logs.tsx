import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { Download, Loader, Pause, Play, Trash2, Wifi, WifiOff } from 'lucide-react'
import { getServices } from '../lib/api'
import {
  Badge,
  Button,
  Card,
  DegradedState,
  Field,
  Input,
  PageHeader,
  Select,
} from '../components/ui'
import type { BadgeVariant } from '../components/ui'
import { cn } from '../lib/cn'

const NF_CONTAINERS = ['nrf', 'amf', 'ausf', 'bsf', 'lmf', 'nef', 'nssf', 'pcf', 'smf', 'smsf', 'udm', 'udr', 'upf']

/** Keep at most this many lines in memory (matches the pre-redesign cap). */
const MAX_LINES = 2000
const RECONNECT_MS = 3_000

type LogLine = { raw: string; level: string; msg: string; ts: string }
type ConnState = 'connecting' | 'open' | 'closed'

function parseLogLine(raw: string): LogLine {
  try {
    const obj = JSON.parse(raw.trim())
    return {
      raw,
      level: (obj.level ?? '').toLowerCase(),
      msg: obj.msg ?? raw,
      ts: obj.time ?? '',
    }
  } catch {
    return { raw, level: 'info', msg: raw, ts: '' }
  }
}

/**
 * Log level → semantic token. The level word itself is always printed next to
 * the line, so meaning never depends on the colour alone (WCAG 1.4.1).
 */
const LEVEL_CLASS: Record<string, string> = {
  error: 'text-danger-fg',
  warn: 'text-warning-fg',
  warning: 'text-warning-fg',
  info: 'text-log-fg',
  debug: 'text-muted-fg',
}

function levelClass(level: string): string {
  return LEVEL_CLASS[level] ?? 'text-log-fg'
}

/** WebSocket lifecycle → always-visible status badge. */
const CONN: Record<ConnState, { variant: BadgeVariant; icon: ReactNode; label: string }> = {
  connecting: { variant: 'info', icon: <Loader size={12} className="animate-spin" />, label: 'Connecting' },
  open: { variant: 'success', icon: <Wifi size={12} />, label: 'Connected' },
  closed: { variant: 'danger', icon: <WifiOff size={12} />, label: 'Disconnected' },
}

export default function Logs() {
  const [container, setContainer] = useState('amf')
  const [lines, setLines] = useState<LogLine[]>([])
  const [paused, setPaused] = useState(false)
  const [filter, setFilter] = useState('')
  const [connState, setConnState] = useState<ConnState>('connecting')
  const wsRef = useRef<WebSocket | null>(null)
  const endRef = useRef<HTMLDivElement>(null)
  const pausedRef = useRef(false)

  pausedRef.current = paused

  const { data: services = [] } = useQuery({
    queryKey: ['services'],
    queryFn: getServices,
  })

  const containers = services
    .filter(s => NF_CONTAINERS.includes(s.name))
    .map(s => s.name)
    .sort()

  useEffect(() => {
    wsRef.current?.close()
    setLines([])
    setConnState('connecting')

    let dead = false
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null

    function connect() {
      if (dead) return
      setConnState('connecting')

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const ws = new WebSocket(`${protocol}//${window.location.host}/ws/logs/${container}?tail=200`)
      wsRef.current = ws

      ws.onopen = () => {
        if (!dead) setConnState('open')
      }
      ws.onmessage = (e) => {
        if (pausedRef.current) return
        const parsed = parseLogLine(e.data as string)
        setLines(prev => {
          const next = [...prev, parsed]
          return next.length > MAX_LINES ? next.slice(-MAX_LINES) : next
        })
      }
      ws.onclose = () => {
        if (dead) return
        setConnState('closed')
        reconnectTimer = setTimeout(connect, RECONNECT_MS)
      }
    }

    connect()
    return () => {
      dead = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      wsRef.current?.close()
    }
  }, [container])

  // Auto-scroll while streaming (suspended while paused so the operator can read).
  useEffect(() => {
    if (!paused) {
      endRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [lines, paused])

  const filtered = filter
    ? lines.filter(l => l.raw.toLowerCase().includes(filter.toLowerCase()))
    : lines

  const containerOptions = (containers.length > 0 ? containers : NF_CONTAINERS).map(c => ({
    value: c,
    label: c,
  }))

  const downloadLogs = () => {
    const blob = new Blob([lines.map(l => l.raw).join('\n')], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${container}-logs.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  const conn = CONN[connState]

  return (
    <div className="flex h-full flex-col p-6">
      <PageHeader
        eyebrow="Operations"
        title="Logs"
        subtitle="Real-time log streaming via Docker API"
        action={
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" icon={<Download size={14} />} onClick={downloadLogs}>
              Export
            </Button>
            <Button variant="secondary" size="sm" icon={<Trash2 size={14} />} onClick={() => setLines([])}>
              Clear
            </Button>
            <Button
              variant={paused ? 'primary' : 'secondary'}
              size="sm"
              icon={paused ? <Play size={14} /> : <Pause size={14} />}
              aria-pressed={paused}
              onClick={() => setPaused(p => !p)}
            >
              {paused ? 'Resume' : 'Pause'}
            </Button>
          </div>
        }
      />

      {/* Source + filter controls */}
      <Card className="mb-4">
        <div className="flex flex-wrap items-end gap-4">
          <Field label="Container" className="w-48">
            {({ id }) => (
              <Select
                id={id}
                value={container}
                options={containerOptions}
                onChange={e => setContainer(e.target.value)}
              />
            )}
          </Field>

          <Field label="Filter" className="min-w-[16rem] flex-1">
            {({ id }) => (
              <Input
                id={id}
                type="search"
                placeholder="Filter logs…"
                value={filter}
                onChange={e => setFilter(e.target.value)}
              />
            )}
          </Field>

          <div className="flex items-center gap-3 pb-2.5">
            <Badge label={conn.label} variant={conn.variant} icon={conn.icon} />
            <span className="text-xs tabular-nums text-muted-fg">{filtered.length} lines</span>
          </div>
        </div>
      </Card>

      {connState === 'closed' && (
        <DegradedState
          className="mb-4"
          title="Log stream disconnected"
          description={`The WebSocket to the portal dropped. Reconnecting every ${RECONNECT_MS / 1000} s; buffered lines stay visible below.`}
        />
      )}

      {/* monospace log surface — theme-aware via --c-log-bg / --c-log-fg */}
      <div className="log-surface max-h-[600px] min-h-[400px] flex-1 overflow-y-auto rounded-card border border-border p-3">
        {filtered.length === 0 ? (
          <p className="text-xs text-muted-fg">
            {filter && lines.length > 0 ? (
              <>No lines match “{filter}”.</>
            ) : (
              <>
                Waiting for log lines from{' '}
                <strong className="font-semibold text-log-fg">{container}</strong>…
              </>
            )}
          </p>
        ) : (
          filtered.map((line, i) => (
            <div key={i} className={cn('leading-relaxed', levelClass(line.level))}>
              {line.ts && (
                <span className="mr-2 text-xs text-muted-fg">
                  {new Date(line.ts).toISOString().slice(11, 23)}
                </span>
              )}
              {line.level && line.level !== 'info' && (
                <span className={cn('mr-2 text-xs font-bold uppercase', levelClass(line.level))}>
                  {line.level}
                </span>
              )}
              <span>{line.msg}</span>
            </div>
          ))
        )}
        <div ref={endRef} />
      </div>
    </div>
  )
}
