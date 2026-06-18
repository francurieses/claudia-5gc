import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Play, Square, Pause, RefreshCw, Terminal,
  Radio, CheckCircle, Circle, AlertCircle, Info, RotateCcw, Trash2,
} from 'lucide-react'
import {
  getPacketRusherStatus, prStart, prStop, prPause, prResume,
  type PacketRusherScenarioState,
} from '../lib/api'
import PageHeader from '../components/PageHeader'
import Badge from '../components/Badge'

// ---- Types ------------------------------------------------------------------

type Tab = 'packetrusher' | 'packetrusher-n2' | 'amf' | 'smf'

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

const levelColor: Record<string, string> = {
  error: 'text-red-400', warn: 'text-yellow-400', warning: 'text-yellow-400',
  info: 'text-gray-300', debug: 'text-gray-500',
}

const MOBILITY_KEYWORDS = [
  'handover', 'pathswitch', 'path switch', 'xn ho', 'ho complete', 'ho success',
  'handoverrequired', 'handovercommand', 'handovernotify', 'handoverrequest',
  'ue registered', 'pdu session',
]

function highlightMobility(text: string): JSX.Element {
  const lower = text.toLowerCase()
  const hit = MOBILITY_KEYWORDS.some(kw => lower.includes(kw))
  if (hit) return <span className="text-cyan-300 font-semibold">{text}</span>
  return <span>{text}</span>
}

function LogPanel({ container, clearKey, onClear }: { container: string; clearKey: number; onClear: () => void }) {
  const [lines, setLines]   = useState<LogLine[]>([])
  const [filter, setFilter] = useState('')
  const [paused, setPaused] = useState(false)
  const endRef              = useRef<HTMLDivElement>(null)
  const [frozen, setFrozen] = useState<LogLine[]>([])

  // Reconnect WebSocket when the active tab (container) changes
  useEffect(() => {
    setLines([])
    setFrozen([])

    let dead = false
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const ws = new WebSocket(`${protocol}//${window.location.host}/ws/logs/${container}?tail=300`)
      ws.onmessage = e => setLines(prev => {
        const next = [...prev, parseLogLine(e.data as string)]
        return next.length > 3000 ? next.slice(-3000) : next
      })
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

  return (
    <div className="bg-gray-950 rounded-lg border border-gray-700 flex flex-col">
      <div className="flex items-center justify-between px-3 py-2 border-b border-gray-700 flex-shrink-0">
        <div className="flex items-center gap-2">
          <Terminal size={13} className="text-green-400" />
          <span className="text-xs font-mono text-green-400">{container}</span>
          <span className="text-xs text-gray-500">{filtered.length} lines</span>
          {paused && <span className="text-xs text-yellow-400 font-semibold">PAUSED</span>}
        </div>
        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Filter…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-2 py-0.5 text-xs text-white w-36"
          />
          <button onClick={() => setPaused(p => !p)} className="text-xs text-gray-400 hover:text-white">
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button onClick={onClear} className="text-xs text-gray-500 hover:text-white">Clear</button>
        </div>
      </div>
      <div className="font-mono text-xs p-3 h-64 overflow-y-auto">
        {filtered.length === 0
          ? <span className="text-gray-600">Waiting for logs from {container}…</span>
          : filtered.map((l, i) => (
              <div key={i} className={`leading-relaxed ${levelColor[l.level] ?? 'text-gray-300'}`}>
                {l.ts && <span className="text-gray-600 mr-2">{new Date(l.ts).toISOString().slice(11, 23)}</span>}
                {l.level && l.level !== 'info' && (
                  <span className={`mr-1 uppercase text-[0.6rem] font-bold ${levelColor[l.level]}`}>{l.level}</span>
                )}
                {highlightMobility(l.msg)}
              </div>
            ))
        }
        <div ref={endRef} />
      </div>
    </div>
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

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">{title}</h3>
          <span className={`text-xs font-semibold ${done === total ? 'text-green-400' : 'text-gray-500'}`}>
            {done}/{total}
          </span>
        </div>
        <button
          onClick={onReset}
          title="Reset checklist for a new validation run"
          className="flex items-center gap-1 px-2 py-0.5 text-[0.65rem] text-gray-500 hover:text-gray-300 hover:bg-gray-800 rounded"
        >
          <RotateCcw size={10} /> Reset
        </button>
      </div>
      <div className="space-y-2">
        {checkpoints.map(cp => (
          <div key={cp.id} className="flex items-start gap-2">
            {cp.detected
              ? <CheckCircle size={13} className="text-green-400 mt-0.5 flex-shrink-0" />
              : <Circle     size={13} className="text-gray-600 mt-0.5 flex-shrink-0" />}
            <div className="flex-1 min-w-0">
              <span className={`text-xs ${cp.detected ? 'text-green-300' : 'text-gray-400'}`}>{cp.label}</span>
              <span className="ml-2 text-[0.6rem] text-gray-600 font-mono">{cp.specRef}</span>
            </div>
            {cp.detected && (
              <span className="text-[0.6rem] text-green-500 font-semibold flex-shrink-0">DETECTED</span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ---- State badge + helpers --------------------------------------------------

function stateBadge(state: string) {
  switch (state) {
    case 'running':   return <Badge label="running"     variant="green"  />
    case 'paused':    return <Badge label="paused"      variant="yellow" />
    case 'exited':    return <Badge label="exited"      variant="gray"   />
    case 'created':   return <Badge label="ready"       variant="gray"   />
    case 'not_found': return <Badge label="not created" variant="red"    />
    default:          return <Badge label={state}       variant="gray"   />
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
  error: string | null
}

function ScenarioCard({
  s, peerRunning, peerName,
  title, subtitle, specRef, command,
  logsActive, onToggleLog,
  onStart, onStop, onPause, onResume,
  isPending, error,
}: ScenarioCardProps) {
  const running   = s.state === 'running'
  const paused    = s.state === 'paused'
  const startable = isStartable(s.state)
  const notFound  = s.state === 'not_found'

  return (
    <div className={`bg-gray-900 rounded-lg border p-5 flex flex-col gap-3 ${
      running ? 'border-green-700' : paused ? 'border-yellow-700' : 'border-gray-800'
    }`}>
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <Radio size={14} className={running ? 'text-green-400' : paused ? 'text-yellow-400' : 'text-gray-500'} />
            <span className="text-sm font-bold text-white">{title}</span>
          </div>
          <p className="text-xs text-gray-400">{subtitle}</p>
          <p className="text-xs text-gray-600 font-mono mt-0.5">{specRef}</p>
        </div>
        {stateBadge(s.state)}
      </div>

      <div className="text-xs text-gray-500 font-mono">
        container: <span className="text-gray-400">{s.container}</span>
        {s.uptime && <span className="ml-3 text-gray-600">up {s.uptime}</span>}
        {s.status && <span className="ml-3 text-gray-600">{s.status}</span>}
      </div>

      <div className="bg-gray-950 rounded px-3 py-2 text-xs font-mono text-gray-500 leading-relaxed">
        <span className="text-gray-600">cmd: </span>{command}
      </div>

      {peerRunning && !running && !paused && (
        <div className="flex items-start gap-2 px-3 py-2 bg-blue-950/40 border border-blue-800/50 rounded text-xs text-blue-300">
          <Info size={12} className="mt-0.5 flex-shrink-0" />
          <span>
            <span className="font-semibold">{peerName}</span> is running and holds the shared IPs.
            Clicking <span className="font-semibold">Start</span> will stop it automatically.
          </span>
        </div>
      )}

      {notFound && (
        <div className="flex items-start gap-2 px-3 py-2 bg-yellow-950/40 border border-yellow-800/50 rounded text-xs text-yellow-300">
          <AlertCircle size={12} className="mt-0.5 flex-shrink-0" />
          <span>
            Container not created. Run{' '}
            <code className="bg-gray-800 px-1 rounded font-mono">
              make {s.scenario === 'xn' ? 'handover-test' : 'handover-n2-test'}
            </code>{' '}
            once to build the image.
          </span>
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 px-3 py-2 bg-red-950/40 border border-red-800/50 rounded text-xs text-red-300">
          <AlertCircle size={12} className="flex-shrink-0" />{error}
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        {(startable || (peerRunning && !running && !paused)) && (
          <button
            onClick={onStart}
            disabled={isPending || notFound}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-green-700 hover:bg-green-600 disabled:opacity-40 text-white text-xs rounded"
          >
            {isPending ? <RefreshCw size={11} className="animate-spin" /> : <Play size={11} />}
            {peerRunning ? 'Stop other & Start' : 'Start'}
          </button>
        )}
        {running && (
          <>
            <button onClick={onPause} disabled={isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-yellow-700 hover:bg-yellow-600 disabled:opacity-40 text-white text-xs rounded">
              <Pause size={11} /> Pause
            </button>
            <button onClick={onStop} disabled={isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-red-800 hover:bg-red-700 disabled:opacity-40 text-white text-xs rounded">
              <Square size={11} /> Stop
            </button>
          </>
        )}
        {paused && (
          <>
            <button onClick={onResume} disabled={isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-green-700 hover:bg-green-600 disabled:opacity-40 text-white text-xs rounded">
              <Play size={11} /> Resume
            </button>
            <button onClick={onStop} disabled={isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-red-800 hover:bg-red-700 disabled:opacity-40 text-white text-xs rounded">
              <Square size={11} /> Stop
            </button>
          </>
        )}
        <button onClick={onToggleLog}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded ${
            logsActive ? 'bg-blue-600 text-white' : 'bg-gray-700 hover:bg-gray-600 text-white'
          }`}>
          <Terminal size={11} /> Logs
        </button>
      </div>
    </div>
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
  const [activeLogTab, setActiveLogTab] = useState<Tab>('packetrusher')
  const [showLogs, setShowLogs]         = useState(false)
  const [clearKey, setClearKey]         = useState(0)

  // Per-scenario reset keys — incrementing clears that scenario's checklist
  // streams and reconnects them from tail=0 for a clean validation run.
  const [xnResetKey, setXnResetKey] = useState(0)
  const [n2ResetKey, setN2ResetKey] = useState(0)

  const { data, isLoading } = useQuery({
    queryKey: ['pr-status'],
    queryFn: getPacketRusherStatus,
    refetchInterval: 3_000,
  })

  const xnStartMut = useMutation({
    mutationFn: () => prStart('xn'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pr-status'] })
      setXnResetKey(k => k + 1)
    },
  })
  const xnStopMut   = useMutation({ mutationFn: () => prStop('xn'),   onSuccess: () => qc.invalidateQueries({ queryKey: ['pr-status'] }) })
  const xnPauseMut  = useMutation({ mutationFn: () => prPause('xn'),  onSuccess: () => qc.invalidateQueries({ queryKey: ['pr-status'] }) })
  const xnResumeMut = useMutation({ mutationFn: () => prResume('xn'), onSuccess: () => qc.invalidateQueries({ queryKey: ['pr-status'] }) })

  const n2StartMut = useMutation({
    mutationFn: () => prStart('n2'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pr-status'] })
      setN2ResetKey(k => k + 1)
    },
  })
  const n2StopMut   = useMutation({ mutationFn: () => prStop('n2'),   onSuccess: () => qc.invalidateQueries({ queryKey: ['pr-status'] }) })
  const n2PauseMut  = useMutation({ mutationFn: () => prPause('n2'),  onSuccess: () => qc.invalidateQueries({ queryKey: ['pr-status'] }) })
  const n2ResumeMut = useMutation({ mutationFn: () => prResume('n2'), onSuccess: () => qc.invalidateQueries({ queryKey: ['pr-status'] }) })

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

  const xnError = xnStartMut.error?.message ?? xnStopMut.error?.message ?? xnPauseMut.error?.message ?? xnResumeMut.error?.message ?? null
  const n2Error = n2StartMut.error?.message ?? n2StopMut.error?.message ?? n2PauseMut.error?.message ?? n2ResumeMut.error?.message ?? null

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

  return (
    <div className="p-6">
      <PageHeader
        title="PacketRusher"
        subtitle="5G mobility testing — Xn and N2 Handover scenarios"
        action={
          <div className="flex gap-2">
            <button
              onClick={() => setShowLogs(v => !v)}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-md ${
                showLogs ? 'bg-blue-600 text-white' : 'bg-gray-700 hover:bg-gray-600 text-white'
              }`}
            >
              <Terminal size={14} /> {showLogs ? 'Hide Logs' : 'Show Logs'}
            </button>
            <button
              onClick={() => {
                setClearKey(k => k + 1)
                setXnResetKey(k => k + 1)
                setN2ResetKey(k => k + 1)
              }}
              title="Clear all log panels and reset mobility validation checklists"
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-md"
            >
              <Trash2 size={14} /> Clear All
            </button>
            <button
              onClick={() => qc.invalidateQueries({ queryKey: ['pr-status'] })}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-md"
            >
              <RefreshCw size={14} className={isLoading ? 'animate-spin' : ''} /> Refresh
            </button>
          </div>
        }
      />

      <div className="mb-3 flex items-start gap-2 px-3 py-2.5 bg-yellow-950/50 border border-yellow-700/60 rounded-lg text-xs text-yellow-200">
        <AlertCircle size={13} className="mt-0.5 flex-shrink-0 text-yellow-400" />
        <span>
          <span className="font-semibold text-yellow-300">URSP incompatibility:</span>{' '}
          PacketRusher does not support URSP policy delivery. If URSP is enabled in your build,
          PacketRusher UEs will fail to register. To use these scenarios, disable URSP in{' '}
          <code className="bg-yellow-900/50 px-1 rounded font-mono text-yellow-100">nf/amf/config/dev.yaml</code>{' '}
          (<code className="bg-yellow-900/50 px-1 rounded font-mono text-yellow-100">ursp_enabled: false</code>)
          and rebuild with <code className="bg-yellow-900/50 px-1 rounded font-mono text-yellow-100">make docker</code>.
        </span>
      </div>

      <div className="mb-4 flex items-start gap-2 px-3 py-2 bg-gray-800/60 border border-gray-700 rounded-lg text-xs text-gray-400">
        <Info size={12} className="mt-0.5 flex-shrink-0 text-blue-400" />
        Both scenarios share network IPs (172.30.1.20 / 172.30.3.10) — only one can run at a time.
        The portal auto-stops the other on Start. Checklists reset automatically on each run.
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
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
          error={xnError}
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
          error={n2Error}
        />
      </div>

      {showLogs && (
        <div className="mb-6">
          <div className="flex gap-1 mb-2 border-b border-gray-800 pb-1">
            {LOG_TABS.map(t => (
              <button
                key={t.id}
                onClick={() => setActiveLogTab(t.id)}
                className={`px-3 py-1.5 text-xs rounded-t transition-colors ${
                  activeLogTab === t.id
                    ? 'bg-gray-800 text-white border border-b-0 border-gray-700'
                    : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                {t.label}
              </button>
            ))}
            <button
              onClick={() => { setClearKey(k => k + 1); setXnResetKey(k => k + 1); setN2ResetKey(k => k + 1) }}
              className="ml-auto flex items-center gap-1 text-xs text-gray-600 hover:text-gray-400 px-2"
            >
              <Trash2 size={11} /> Clear all
            </button>
          </div>
          <LogPanel key={activeLogTab} container={activeLogTab} clearKey={clearKey} onClear={() => setClearKey(k => k + 1)} />
        </div>
      )}

      <div className="mb-2 flex items-center gap-2">
        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Mobility Validation</h3>
        <span className="text-xs text-gray-600">—</span>
        <span className="text-xs text-gray-600">
          Evaluated against PacketRusher + AMF logs for each scenario independently. Resets on Start or Reset button.
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
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

      <div className="mt-6 p-4 bg-gray-900/50 border border-gray-800 rounded-lg">
        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Quick Reference</p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1 text-xs text-gray-600">
          <span><span className="text-gray-400 font-mono">make handover-test</span> — build image + start Xn scenario (required once)</span>
          <span><span className="text-gray-400 font-mono">make handover-n2-test</span> — start N2 scenario (reuses built image)</span>
          <span><span className="text-gray-400 font-mono">make handover-down</span> — stop Xn profile containers</span>
          <span><span className="text-gray-400 font-mono">make handover-n2-down</span> — stop N2 profile containers</span>
        </div>
      </div>
    </div>
  )
}
