import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import type { ReactNode } from 'react'
import { Download, Loader, Pause, Play, Trash2, Wifi, WifiOff } from 'lucide-react'
import { getServices } from '../lib/api'
import type { Service } from '../lib/api'
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
import { useStickToBottom } from '../lib/useStickToBottom'
import { clearLogs, ensureStream, setLogsPaused, useLogStream } from '../lib/logStream'
import type { ConnState } from '../lib/logStream'

/**
 * Fallback list when the Services API is unavailable. Normally the list is
 * derived from the Docker `logging.5gc/nf` label, so new NFs (sepp, and the
 * roaming-profile hsepp/hnrf) appear without a code change (PORTAL-UI-22).
 */
const NF_CONTAINERS = ['nrf', 'amf', 'ausf', 'bsf', 'lmf', 'nef', 'nssf', 'pcf', 'smf', 'smsf', 'udm', 'udr', 'upf', 'sepp']

/** Label values that are not network functions (load generators). */
const NON_NF_LABELS = new Set(['PERF'])

interface ContainerGroup { label: string; names: string[] }

/** NF containers grouped by PLMN side; tooling (MCP) last. */
function groupContainers(services: Service[]): ContainerGroup[] {
  const nfs = services.filter(s => s.nf && !NON_NF_LABELS.has(s.nf))
  const pick = (f: (s: Service) => boolean) => nfs.filter(f).map(s => s.name).sort()
  return [
    { label: 'Local core', names: pick(s => s.side !== 'partner' && s.nf !== 'MCP') },
    { label: 'Roaming partner (test peer)', names: pick(s => s.side === 'partner') },
    { label: 'Tooling', names: pick(s => s.nf === 'MCP') },
  ].filter(g => g.names.length > 0)
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
  const [searchParams] = useSearchParams()
  const [container, setContainer] = useState(searchParams.get('container') || 'amf')
  const [paused, setPaused] = useState(false)
  const [filter, setFilter] = useState('')
  const logRef = useRef<HTMLDivElement>(null)

  // Buffers live in lib/logStream (module scope): they survive navigation and
  // container switches; only Clear or a container restart empties them.
  const { lines, conn: connState } = useLogStream(container)
  useEffect(() => { ensureStream(container) }, [container])
  useEffect(() => { setLogsPaused(paused) }, [paused])

  const { data: services = [] } = useQuery({
    queryKey: ['services'],
    queryFn: getServices,
  })

  const groups = groupContainers(services)

  // Auto-scroll while streaming (suspended while paused so the operator can read).
  const { atBottom, jumpToLatest } = useStickToBottom(logRef, lines, paused)

  const filtered = filter
    ? lines.filter(l => l.raw.toLowerCase().includes(filter.toLowerCase()))
    : lines

  const optionGroups: ContainerGroup[] = groups.length > 0 ? groups : [{ label: 'Network functions', names: NF_CONTAINERS }]
  // Keep a deep-linked or stopped container selectable even when it is not listed.
  const listed = optionGroups.some(g => g.names.includes(container))

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
    <div className="flex h-full min-h-0 flex-col p-6">
      <PageHeader
        eyebrow="Operations"
        title="Logs"
        subtitle="Real-time log streaming via Docker API"
        action={
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" icon={<Download size={14} />} onClick={downloadLogs}>
              Export
            </Button>
            <Button variant="secondary" size="sm" icon={<Trash2 size={14} />} onClick={() => clearLogs(container)}>
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
              <Select id={id} value={container} onChange={e => setContainer(e.target.value)}>
                {!listed && <option value={container}>{container}</option>}
                {optionGroups.map(g => (
                  <optgroup key={g.label} label={g.label}>
                    {g.names.map(n => (
                      <option key={n} value={n}>{n}</option>
                    ))}
                  </optgroup>
                ))}
              </Select>
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
          description={`The WebSocket to the portal dropped. Reconnecting every 3 s; buffered lines stay visible below.`}
        />
      )}

      {/* monospace log surface — theme-aware via --c-log-bg / --c-log-fg */}
      <div className="relative flex min-h-[12rem] flex-1 flex-col">
      <div
        ref={logRef}
        role="log"
        aria-label={`Logs for ${container}`}
        tabIndex={0}
        className="log-surface scroll-thin min-h-0 flex-1 overflow-y-auto rounded-card border border-border p-3"
      >
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
      </div>
      {!atBottom && (
        <div className="absolute bottom-3 right-5">
          <Button size="sm" onClick={jumpToLatest}>Jump to latest</Button>
        </div>
      )}
      </div>
    </div>
  )
}
