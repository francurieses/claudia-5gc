import { useState, useEffect, useRef, type ReactNode } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Play, Square, Pause, RefreshCw, Terminal, Radio,
  CheckCircle, CheckCircle2, Circle, XCircle, AlertCircle, Info, RotateCcw, Trash2,
} from 'lucide-react'
import {
  getPacketRusherStatus, prStart, prStop, prPause, prResume,
  type PacketRusherScenarioState,
} from '../lib/api'
import {
  Badge, Button, Card, ErrorState, Input, Loading, PageHeader, Section, Tabs, useToast,
} from '../components/ui'
import type { BadgeVariant, TabItem } from '../components/ui'

// ---- Types ------------------------------------------------------------------

type Tab = 'packetrusher' | 'packetrusher-n2' | 'amf' | 'smf'

interface StatusBadge {
  label: string
  variant: BadgeVariant
  icon: ReactNode
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

// ---- Mobility validation checkpoints ----------------------------------------
//
// Patterns are matched case-insensitively against the exact strings that our
// AMF logs (nf/amf/internal/ngap/handover.go + procedures/registration.go).
// Each checklist is evaluated against its own PacketRusher container logs PLUS
// a scenario-specific AMF stream that resets on Start — so AMF events from a
// previous run of the other scenario can never bleed into this checklist.

interface Checkpoint {
  id: string
  label: string
  patterns: string[]
  specRef: string
}

const XN_CHECKPOINTS: Checkpoint[] = [
  {
    id: 'ue_reg',
    label: 'UE Registered',
    // AMF logs exactly: "UE registered"  (registration.go:522)
    patterns: ['ue registered', 'registration complete', 'mm-registered'],
    specRef: 'TS 23.502 §4.2.2.2',
  },
  {
    id: 'pdu_est',
    label: 'PDU Session Established',
    // AMF logs: "PDU Session Establishment Request received"  (nas.go:1096)
    patterns: ['pdu session establishment', 'pdu session established', 'pdu session request received'],
    specRef: 'TS 23.502 §4.3.2',
  },
  {
    id: 'xn_trig',
    label: 'Xn Handover Triggered',
    // PacketRusher logs (tool-side); "xn" qualifier prevents N2 false positives
    patterns: ['xn handover', 'xnhandover', 'triggering xn', 'xn ho'],
    specRef: 'TS 23.502 §4.9.1.2',
  },
  {
    id: 'path_sw',
    label: 'Path Switch Request (AMF)',
    // AMF logs exactly: "PathSwitchRequest received from target gNB"  (handover.go:57)
    patterns: ['pathswitchrequest received', 'path switch request received'],
    specRef: 'TS 38.413 §8.4.2',
  },
  {
    id: 'path_ack',
    label: 'Path Switch Acknowledged',
    // AMF logs exactly: "PathSwitchRequestAcknowledge sent"  (handover.go:99)
    patterns: ['pathswitchrequestacknowledge sent', 'path switch request acknowledge sent', 'path switch ack'],
    specRef: 'TS 38.413 §8.4.3',
  },
  {
    id: 'xn_done',
    label: 'Xn Handover Complete',
    // AMF logs exactly: "Xn Handover complete — UE context moved to target gNB"  (handover.go:140)
    patterns: ['xn handover complete', 'xn ho complete', 'xn ho success'],
    specRef: 'TS 23.502 §4.9.1.2',
  },
]

const N2_CHECKPOINTS: Checkpoint[] = [
  {
    id: 'ue_reg',
    label: 'UE Registered',
    patterns: ['ue registered', 'registration complete', 'mm-registered'],
    specRef: 'TS 23.502 §4.2.2.2',
  },
  {
    id: 'pdu_est',
    label: 'PDU Session Established',
    patterns: ['pdu session establishment', 'pdu session established', 'pdu session request received'],
    specRef: 'TS 23.502 §4.3.2',
  },
  {
    id: 'ho_req',
    label: 'HandoverRequired Received',
    // AMF logs exactly: "HandoverRequired received from source gNB"  (handover.go:198)
    patterns: ['handoverrequired received', 'handover required received'],
    specRef: 'TS 38.413 §8.4.1',
  },
  {
    id: 'ho_req_t',
    label: 'HandoverRequest Sent (target gNB)',
    // AMF logs exactly: "HandoverRequest sent to target gNB"  (handover.go:331)
    patterns: ['handoverrequest sent', 'handover request sent'],
    specRef: 'TS 38.413 §8.4.1',
  },
  {
    id: 'ho_cmd',
    label: 'HandoverCommand Sent',
    // AMF logs exactly: "HandoverCommand sent to source gNB"  (handover.go:409)
    patterns: ['handovercommand sent', 'handover command sent'],
    specRef: 'TS 38.413 §8.4.1',
  },
  {
    id: 'ho_nfy',
    label: 'HandoverNotify Received',
    // AMF logs exactly: "HandoverNotify received from target gNB — handover complete"  (handover.go:442)
    patterns: ['handovernotify received', 'handover notify received'],
    specRef: 'TS 38.413 §8.4.1',
  },
  {
    id: 'ho_done',
    label: 'N2 Handover Complete',
    // AMF logs exactly: "N2 Handover complete"  (handover.go:522)
    patterns: ['n2 handover complete', 'n2 ho complete', 'n2 ho success'],
    specRef: 'TS 23.502 §4.9.1.3',
  },
]

// ---- Log streaming ----------------------------------------------------------
//
// Two separate stream types serve different purposes:
//
//  useChecklistStream(container, resetKey)
//    - tail=0: only events emitted AFTER the hook (re)connects
//    - Lines freeze (are NOT cleared) when container → null so the checklist
//      remains visible after a scenario finishes
//    - Lines ARE cleared when resetKey increments (new run started)
//
//  LogPanel uses its own inline WebSocket with tail=300 so the display always
//  shows recent history regardless of checklist reset state.

type LogLine = { raw: string; level: string; msg: string; ts: string }

function parseLogLine(raw: string): LogLine {
  try {
    const obj = JSON.parse(raw.trim())
    return { raw, level: (obj.level ?? '').toLowerCase(), msg: obj.msg ?? raw, ts: obj.time ?? '' }
  } catch {
    return { raw, level: 'info', msg: raw, ts: '' }
  }
}

function useChecklistStream(container: string | null, resetKey: number): LogLine[] {
  const [lines, setLines] = useState<LogLine[]>([])

  // Clear lines when the reset key increments (new run started or manual reset).
  // This effect deliberately does NOT depend on container so that changing the
  // container (scenario starts/stops) does NOT wipe accumulated lines.
  useEffect(() => {
    setLines([])
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resetKey])

  // Connect a WebSocket when container is non-null; disconnect when null.
  // On null transition the lines are left intact (frozen = checklist stays green).
  useEffect(() => {
    if (!container) return

    let dead = false
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      // tail=0: we only want events from this run forward, not old log history
      const ws = new WebSocket(`${protocol}//${window.location.host}/ws/logs/${container}?tail=0`)
      ws.onmessage = e => {
        setLines(prev => {
          const next = [...prev, parseLogLine(e.data as string)]
          return next.length > 3000 ? next.slice(-3000) : next
        })
      }
      ws.onclose = () => {
        if (!dead) reconnectTimer = setTimeout(connect, 3000)
      }
      return ws
    }

    const ws = connect()
    return () => {
      dead = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      ws.close()
    }
  }, [container, resetKey]) // reconnect when scenario becomes active or a new run starts

  return lines
}

// ---- Log display panel (independent stream, not tied to checklist) ----------

type WSStatus = 'connecting' | 'open' | 'closed'

const levelColor: Record<string, string> = {
  error: 'text-danger-fg',
  warn: 'text-warning-fg',
  warning: 'text-warning-fg',
  info: 'text-log-fg',
  debug: 'text-muted-fg',
}

const MOBILITY_KEYWORDS = [
  'handover', 'pathswitch', 'path switch', 'xn ho', 'ho complete', 'ho success',
  'handoverrequired', 'handovercommand', 'handovernotify', 'handoverrequest',
  'ue registered', 'pdu session',
]

/**
 * Highlight mobility events. `text-info-fg` is measured at 5.96:1 (light) /
 * 7.41:1 (dark) against the log surface, so it stays AA on both themes.
 */
function highlightMobility(text: string): ReactNode {
  const lower = text.toLowerCase()
  const hit = MOBILITY_KEYWORDS.some(kw => lower.includes(kw))
  if (hit) return <span className="font-semibold text-info-fg">{text}</span>
  return <span>{text}</span>
}

function connectionStatus(status: WSStatus): StatusBadge {
  switch (status) {
    case 'open':
      return { label: 'Connected', variant: 'success', icon: <CheckCircle2 size={12} /> }
    case 'connecting':
      return { label: 'Connecting', variant: 'info', icon: <RefreshCw size={12} className="animate-spin" /> }
    default:
      return { label: 'Disconnected', variant: 'danger', icon: <XCircle size={12} /> }
  }
}

function LogPanel({ container, clearKey, onClear }: { container: string; clearKey: number; onClear: () => void }) {
  const [lines, setLines]   = useState<LogLine[]>([])
  const [filter, setFilter] = useState('')
  const [paused, setPaused] = useState(false)
  const endRef              = useRef<HTMLDivElement>(null)
  const [frozen, setFrozen] = useState<LogLine[]>([])
  const [status, setStatus] = useState<WSStatus>('connecting')

  // Reconnect WebSocket when the active tab (container) changes
  useEffect(() => {
    setLines([])
    setFrozen([])
    setStatus('connecting')

    let dead = false
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const ws = new WebSocket(`${protocol}//${window.location.host}/ws/logs/${container}?tail=300`)
      ws.onopen = () => {
        if (!dead) setStatus('open')
      }
      ws.onmessage = e => setLines(prev => {
        const next = [...prev, parseLogLine(e.data as string)]
        return next.length > 3000 ? next.slice(-3000) : next
      })
      ws.onclose = () => {
        if (dead) return
        setStatus('closed')
        reconnectTimer = setTimeout(() => {
          setStatus('connecting')
          connect()
        }, 3000)
      }
      return ws
    }

    const ws = connect()
    return () => {
      dead = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      ws.close()
    }
  }, [container])

  // Clear displayed lines when clearKey increments — WebSocket stays alive so new messages keep arriving
  useEffect(() => {
    setLines([])
    setFrozen([])
    setPaused(false)
  }, [clearKey])

  useEffect(() => { if (!paused) setFrozen(lines) }, [lines, paused])

  const display  = paused ? frozen : lines
  const filtered = filter ? display.filter(l => l.raw.toLowerCase().includes(filter.toLowerCase())) : display

  useEffect(() => { if (!paused) endRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [filtered, paused])

  const connection = connectionStatus(status)

  return (
    <Card padded={false} className="flex flex-col overflow-hidden bg-log-bg">
      <div className="flex flex-shrink-0 flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <Terminal size={13} aria-hidden="true" className="text-log-fg" />
          <span className="font-mono text-xs text-log-fg">{container}</span>
          <Badge label={connection.label} variant={connection.variant} icon={connection.icon} />
          <span className="text-xs text-muted-fg">{filtered.length} lines</span>
          {paused && <Badge label="PAUSED" variant="warning" icon={<Pause size={12} />} />}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Input
            aria-label={`Filter lines from ${container}`}
            placeholder="Filter…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="w-36 text-xs"
          />
          <Button
            size="sm"
            variant="secondary"
            icon={paused ? <Play size={12} /> : <Pause size={12} />}
            onClick={() => setPaused(p => !p)}
            aria-pressed={paused}
          >
            {paused ? 'Resume' : 'Pause'}
          </Button>
          <Button size="sm" variant="ghost" onClick={onClear}>
            Clear
          </Button>
        </div>
      </div>

      <div className="log-surface h-64 overflow-y-auto p-3">
        {filtered.length === 0
          ? (
            <span className="text-muted-fg">
              {filter ? 'No lines match the filter.' : `Waiting for logs from ${container}…`}
            </span>
          )
          : filtered.map((l, i) => (
            <div key={i} className={`leading-relaxed ${levelColor[l.level] ?? 'text-log-fg'}`}>
              {l.ts && <span className="mr-2 text-muted-fg">{new Date(l.ts).toISOString().slice(11, 23)}</span>}
              {l.level && l.level !== 'info' && (
                <span className={`mr-1 text-xs font-bold uppercase ${levelColor[l.level]}`}>{l.level}</span>
              )}
              {highlightMobility(l.msg)}
            </div>
          ))
        }
        <div ref={endRef} />
      </div>
    </Card>
  )
}

// ---- Validation checklist ---------------------------------------------------

function useCheckpoints(checkpoints: Checkpoint[], lines: LogLine[]) {
  return checkpoints.map(cp => {
    const hit = lines.some(l =>
      cp.patterns.some(p => l.raw.toLowerCase().includes(p.toLowerCase()))
    )
    return { ...cp, detected: hit }
  })
}

function Checklist({
  checkpoints,
  title,
  onReset,
}: {
  checkpoints: (Checkpoint & { detected: boolean })[]
  title: string
  onReset: () => void
}) {
  const done  = checkpoints.filter(c => c.detected).length
  const total = checkpoints.length
  const complete = done === total

  return (
    <Card>
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-fg">{title}</h3>
          <Badge
            label={`${done}/${total}`}
            variant={complete ? 'success' : 'neutral'}
            icon={complete ? <CheckCircle2 size={12} /> : <Circle size={12} />}
          />
        </div>
        <Button
          size="sm"
          variant="ghost"
          icon={<RotateCcw size={10} />}
          onClick={onReset}
          title="Reset checklist for a new validation run"
        >
          Reset
        </Button>
      </div>
      <ul className="space-y-2">
        {checkpoints.map(cp => (
          <li key={cp.id} className="flex items-start gap-2">
            {cp.detected
              ? <CheckCircle size={13} aria-hidden="true" className="mt-0.5 flex-shrink-0 text-success-fg" />
              : <Circle size={13} aria-hidden="true" className="mt-0.5 flex-shrink-0 text-muted-fg" />}
            <div className="min-w-0 flex-1">
              <span className={`text-xs ${cp.detected ? 'text-fg' : 'text-muted-fg'}`}>{cp.label}</span>
              <span className="ml-2 font-mono text-xs text-muted-fg">{cp.specRef}</span>
            </div>
            {cp.detected && (
              <span className="flex-shrink-0 text-xs font-semibold text-success-fg">DETECTED</span>
            )}
          </li>
        ))}
      </ul>
    </Card>
  )
}

// ---- State badge + helpers --------------------------------------------------

function prStatus(state: string): StatusBadge {
  switch (state) {
    case 'running':   return { label: 'running',     variant: 'success', icon: <CheckCircle2 size={12} /> }
    case 'paused':    return { label: 'paused',      variant: 'warning', icon: <Pause size={12} /> }
    case 'exited':    return { label: 'exited',      variant: 'neutral', icon: <Circle size={12} /> }
    case 'created':   return { label: 'ready',       variant: 'neutral', icon: <Circle size={12} /> }
    case 'not_found': return { label: 'not created', variant: 'danger',  icon: <XCircle size={12} /> }
    default:          return { label: state,         variant: 'neutral', icon: <Circle size={12} /> }
  }
}

function isStartable(state: string) {
  return state === 'exited' || state === 'created'
}

// ---- Scenario card ----------------------------------------------------------

interface ScenarioCardProps {
  s: PacketRusherScenarioState
  peerRunning: boolean
  peerName: string
  title: string
  subtitle: string
  specRef: string
  command: string
  logsActive: boolean
  onToggleLog: () => void
  onStart: () => void
  onStop: () => void
  onPause: () => void
  onResume: () => void
  isPending: boolean
}

function ScenarioCard({
  s, peerRunning, peerName,
  title, subtitle, specRef, command,
  logsActive, onToggleLog,
  onStart, onStop, onPause, onResume,
  isPending,
}: ScenarioCardProps) {
  const running   = s.state === 'running'
  const paused    = s.state === 'paused'
  const startable = isStartable(s.state)
  const notFound  = s.state === 'not_found'
  const status    = prStatus(s.state)

  return (
    <Card className="flex flex-col gap-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="mb-0.5 flex items-center gap-2">
            <Radio
              size={14}
              aria-hidden="true"
              className={running ? 'text-success-fg' : paused ? 'text-warning-fg' : 'text-muted-fg'}
            />
            <span className="text-sm font-semibold text-fg">{title}</span>
          </div>
          <p className="text-xs text-muted-fg">{subtitle}</p>
          <p className="mt-0.5 font-mono text-xs text-muted-fg">{specRef}</p>
        </div>
        <Badge label={status.label} variant={status.variant} icon={status.icon} />
      </div>

      <p className="font-mono text-xs text-muted-fg">
        container: <span className="text-fg">{s.container}</span>
        {s.uptime && <span className="ml-3">up {s.uptime}</span>}
        {s.status && <span className="ml-3">{s.status}</span>}
      </p>

      <p className="log-surface rounded-control border border-border px-3 py-2 leading-relaxed">
        <span className="text-muted-fg">cmd: </span>{command}
      </p>

      {peerRunning && !running && !paused && (
        <div className="flex items-start gap-2">
          <Badge label="Peer running" variant="info" icon={<Info size={12} />} />
          <p className="text-xs text-muted-fg">
            <span className="font-semibold text-fg">{peerName}</span> is running and holds the shared IPs.
            Starting this scenario stops it automatically.
          </p>
        </div>
      )}

      {notFound && (
        <div className="flex items-start gap-2">
          <Badge label="Container not created" variant="warning" icon={<AlertCircle size={12} />} />
          <p className="text-xs text-muted-fg">
            Run{' '}
            <code className="rounded bg-muted px-1 font-mono text-fg">
              make {s.scenario === 'xn' ? 'handover-test' : 'handover-n2-test'}
            </code>{' '}
            once to build the image.
          </p>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        {(startable || (peerRunning && !running && !paused)) && (
          <Button
            size="sm"
            icon={<Play size={11} />}
            loading={isPending}
            disabled={isPending || notFound}
            onClick={onStart}
          >
            {peerRunning ? 'Stop other & Start' : 'Start'}
          </Button>
        )}
        {running && (
          <>
            <Button size="sm" variant="secondary" icon={<Pause size={11} />} disabled={isPending} onClick={onPause}>
              Pause
            </Button>
            <Button size="sm" variant="destructive" icon={<Square size={11} />} disabled={isPending} onClick={onStop}>
              Stop
            </Button>
          </>
        )}
        {paused && (
          <>
            <Button size="sm" icon={<Play size={11} />} disabled={isPending} onClick={onResume}>
              Resume
            </Button>
            <Button size="sm" variant="destructive" icon={<Square size={11} />} disabled={isPending} onClick={onStop}>
              Stop
            </Button>
          </>
        )}
        <Button
          size="sm"
          variant={logsActive ? 'primary' : 'secondary'}
          icon={<Terminal size={11} />}
          onClick={onToggleLog}
          aria-expanded={logsActive}
        >
          Logs
        </Button>
      </div>
    </Card>
  )
}

// ---- Log tabs ---------------------------------------------------------------

const LOG_TABS: { id: Tab; label: string }[] = [
  { id: 'packetrusher',    label: 'PacketRusher (Xn)' },
  { id: 'packetrusher-n2', label: 'PacketRusher (N2)' },
  { id: 'amf',             label: 'AMF' },
  { id: 'smf',             label: 'SMF' },
]

// ---- Main page --------------------------------------------------------------

export default function PacketRusher() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [activeLogTab, setActiveLogTab] = useState<Tab>('packetrusher')
  const [showLogs, setShowLogs]         = useState(false)
  const [clearKey, setClearKey]         = useState(0)

  // Per-scenario reset keys — incrementing clears that scenario's checklist
  // streams and reconnects them from tail=0 for a clean validation run.
  const [xnResetKey, setXnResetKey] = useState(0)
  const [n2ResetKey, setN2ResetKey] = useState(0)

  const actionFailed = (verb: string) => (err: unknown) =>
    toast({ variant: 'error', title: `${verb} failed`, description: errMessage(err), duration: 0 })

  const {
    data,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['pr-status'],
    queryFn: getPacketRusherStatus,
    refetchInterval: 3_000,
  })

  const xnStartMut = useMutation({
    mutationFn: () => prStart('xn'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pr-status'] })
      setXnResetKey(k => k + 1)
      toast({ variant: 'success', title: 'Xn Handover started' })
    },
    onError: actionFailed('Start Xn Handover'),
  })
  const xnStopMut   = useMutation({
    mutationFn: () => prStop('xn'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pr-status'] })
      toast({ variant: 'success', title: 'Xn Handover stopped' })
    },
    onError: actionFailed('Stop Xn Handover'),
  })
  const xnPauseMut  = useMutation({
    mutationFn: () => prPause('xn'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pr-status'] }),
    onError: actionFailed('Pause Xn Handover'),
  })
  const xnResumeMut = useMutation({
    mutationFn: () => prResume('xn'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pr-status'] }),
    onError: actionFailed('Resume Xn Handover'),
  })

  const n2StartMut = useMutation({
    mutationFn: () => prStart('n2'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pr-status'] })
      setN2ResetKey(k => k + 1)
      toast({ variant: 'success', title: 'N2 Handover started' })
    },
    onError: actionFailed('Start N2 Handover'),
  })
  const n2StopMut   = useMutation({
    mutationFn: () => prStop('n2'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pr-status'] })
      toast({ variant: 'success', title: 'N2 Handover stopped' })
    },
    onError: actionFailed('Stop N2 Handover'),
  })
  const n2PauseMut  = useMutation({
    mutationFn: () => prPause('n2'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pr-status'] }),
    onError: actionFailed('Pause N2 Handover'),
  })
  const n2ResumeMut = useMutation({
    mutationFn: () => prResume('n2'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pr-status'] }),
    onError: actionFailed('Resume N2 Handover'),
  })

  const xnState = data?.scenarios.find(s => s.scenario === 'xn') ?? {
    scenario: 'xn' as const, container: 'packetrusher', state: 'unknown', status: '', uptime: '',
  }
  const n2State = data?.scenarios.find(s => s.scenario === 'n2') ?? {
    scenario: 'n2' as const, container: 'packetrusher-n2', state: 'unknown', status: '', uptime: '',
  }

  const xnRunning = xnState.state === 'running' || xnState.state === 'paused'
  const n2Running = n2State.state === 'running' || n2State.state === 'paused'

  const xnPending = xnStartMut.isPending || xnStopMut.isPending || xnPauseMut.isPending || xnResumeMut.isPending
  const n2Pending = n2StartMut.isPending || n2StopMut.isPending || n2PauseMut.isPending || n2ResumeMut.isPending

  // --- Checklist streams -------------------------------------------------------
  //
  // Each scenario has two isolated streams: its own PacketRusher container
  // (always connected) and AMF scoped to the window when that scenario is active.
  //
  // The AMF stream is only active while the scenario is running/paused so that
  // AMF events from the PEER scenario's run cannot contaminate this checklist.
  // When the scenario exits, the AMF stream disconnects and its accumulated
  // lines stay frozen — the checklist remains green until the user hits Reset
  // or starts a new run (which increments the reset key and wipes both streams).

  // PacketRusher container streams — always connected (container never changes)
  const xnPrLines = useChecklistStream('packetrusher',    xnResetKey)
  const n2PrLines = useChecklistStream('packetrusher-n2', n2ResetKey)

  // AMF streams scoped to each scenario's active window
  const xnAmfLines = useChecklistStream(xnRunning ? 'amf' : null, xnResetKey)
  const n2AmfLines = useChecklistStream(n2Running ? 'amf' : null, n2ResetKey)

  // Combine each scenario's own lines with its scoped AMF lines for evaluation
  const xnAllLines = [...xnPrLines, ...xnAmfLines]
  const n2AllLines = [...n2PrLines, ...n2AmfLines]

  const xnChecks = useCheckpoints(XN_CHECKPOINTS, xnAllLines)
  const n2Checks = useCheckpoints(N2_CHECKPOINTS, n2AllLines)

  const openLog = (tab: Tab) => { setShowLogs(true); setActiveLogTab(tab) }

  const clearAll = () => {
    setClearKey(k => k + 1)
    setXnResetKey(k => k + 1)
    setN2ResetKey(k => k + 1)
  }

  const logTabs: TabItem[] = LOG_TABS.map(t => ({
    id: t.id,
    label: t.label,
    content: (
      <LogPanel
        key={t.id}
        container={t.id}
        clearKey={clearKey}
        onClear={() => setClearKey(k => k + 1)}
      />
    ),
  }))

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Test UEs"
        title="PacketRusher"
        subtitle="5G mobility testing — Xn and N2 Handover scenarios"
        action={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant={showLogs ? 'primary' : 'secondary'}
              icon={<Terminal size={14} />}
              aria-pressed={showLogs}
              onClick={() => setShowLogs(v => !v)}
            >
              {showLogs ? 'Hide Logs' : 'Show Logs'}
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={<Trash2 size={14} />}
              onClick={clearAll}
              title="Clear all log panels and reset mobility validation checklists"
            >
              Clear All
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={<RefreshCw size={14} />}
              loading={isLoading}
              onClick={() => refetch()}
            >
              Refresh
            </Button>
          </div>
        }
      />

      {/* URSP incompatibility warning */}
      <Card>
        <div className="flex items-start gap-3">
          <Badge label="URSP incompatibility" variant="warning" icon={<AlertCircle size={12} />} />
          <p className="text-xs text-muted-fg">
            PacketRusher does not support URSP policy delivery. If URSP is enabled in your build,
            PacketRusher UEs will fail to register. To use these scenarios, disable URSP in{' '}
            <code className="rounded bg-muted px-1 font-mono text-fg">nf/amf/config/dev.yaml</code>{' '}
            (<code className="rounded bg-muted px-1 font-mono text-fg">ursp_enabled: false</code>)
            and rebuild with <code className="rounded bg-muted px-1 font-mono text-fg">make docker</code>.
          </p>
        </div>
      </Card>

      {/* Shared-IP constraint */}
      <Card>
        <div className="flex items-start gap-3">
          <Badge label="Shared IPs" variant="info" icon={<Info size={12} />} />
          <p className="text-xs text-muted-fg">
            Both scenarios share network IPs (172.30.1.20 / 172.30.3.10) — only one can run at a time.
            The portal auto-stops the other on Start. Checklists reset automatically on each run.
          </p>
        </div>
      </Card>

      {/* Scenario cards */}
      {isError ? (
        <ErrorState
          title="Failed to load PacketRusher status"
          description={errMessage(error)}
          action={
            <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : isLoading ? (
        <Loading rows={2} label="Loading scenarios…" />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <ScenarioCard
            s={xnState}
            peerRunning={n2Running}
            peerName="N2 Handover"
            title="Xn Handover"
            subtitle="Dual-gNB, source-initiated — no AMF preparation"
            specRef="TS 23.502 §4.9.1.2 / TS 38.413 §8.4.2"
            command="multi-ue-pdu -n 1 --timeBeforeXnHandover 5000"
            logsActive={showLogs && activeLogTab === 'packetrusher'}
            onToggleLog={() => openLog('packetrusher')}
            onStart={() => xnStartMut.mutate()}
            onStop={() => xnStopMut.mutate()}
            onPause={() => xnPauseMut.mutate()}
            onResume={() => xnResumeMut.mutate()}
            isPending={xnPending}
          />
          <ScenarioCard
            s={n2State}
            peerRunning={xnRunning}
            peerName="Xn Handover"
            title="N2 Handover"
            subtitle="AMF-mediated preparation — full NGAP HO flow"
            specRef="TS 23.502 §4.9.1.3 / TS 38.413 §8.4.1"
            command="multi-ue-pdu -n 1 --timeBeforeNgapHandover 5000"
            logsActive={showLogs && activeLogTab === 'packetrusher-n2'}
            onToggleLog={() => openLog('packetrusher-n2')}
            onStart={() => n2StartMut.mutate()}
            onStop={() => n2StopMut.mutate()}
            onPause={() => n2PauseMut.mutate()}
            onResume={() => n2ResumeMut.mutate()}
            isPending={n2Pending}
          />
        </div>
      )}

      {/* Log viewer */}
      {showLogs && (
        <Section
          bare
          headingLevel={2}
          title="Logs"
          description="Live container streams. Mobility events (handover, path switch, registration) are highlighted."
        >
          <Tabs
            label="Log source"
            tabs={logTabs}
            value={activeLogTab}
            onChange={id => setActiveLogTab(id as Tab)}
          />
        </Section>
      )}

      {/* Mobility validation */}
      <Section
        bare
        headingLevel={2}
        title="Mobility Validation"
        description="Evaluated against PacketRusher + AMF logs for each scenario independently. Resets on Start or the Reset button."
      >
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Checklist
            checkpoints={xnChecks}
            title="Xn Handover — TS 23.502 §4.9.1.2"
            onReset={() => setXnResetKey(k => k + 1)}
          />
          <Checklist
            checkpoints={n2Checks}
            title="N2 Handover — TS 23.502 §4.9.1.3"
            onReset={() => setN2ResetKey(k => k + 1)}
          />
        </div>
      </Section>

      {/* Quick reference */}
      <Section bare headingLevel={2} title="Quick Reference">
        <div className="grid grid-cols-1 gap-x-8 gap-y-1 text-xs text-muted-fg md:grid-cols-2">
          <p><span className="font-mono text-fg">make handover-test</span> — build image + start Xn scenario (required once)</p>
          <p><span className="font-mono text-fg">make handover-n2-test</span> — start N2 scenario (reuses built image)</p>
          <p><span className="font-mono text-fg">make handover-down</span> — stop Xn profile containers</p>
          <p><span className="font-mono text-fg">make handover-n2-down</span> — stop N2 profile containers</p>
        </div>
      </Section>
    </div>
  )
}
