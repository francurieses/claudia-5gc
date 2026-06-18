import { useState, useEffect, useRef, type ReactNode } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Play, Square, RefreshCw, Terminal, ChevronDown, ChevronRight,
  Signal, SignalZero, Wifi, WifiOff, LogOut, Plus, Globe, Layers,
} from 'lucide-react'
import {
  getUERANSIMStatus, nrCLI, pingUE, startService, stopService,
  getUERANSIMScenarios, startUERANSIMScenario, stopUERANSIMScenario,
  type UEEntry, type UEContainer, type UERANSIMScenarioState,
} from '../lib/api'
import PageHeader from '../components/PageHeader'
import Badge from '../components/Badge'

// ---- GMM state labels -------------------------------------------------------
const GMM: Record<number, { label: string; color: 'green' | 'red' | 'yellow' | 'gray' }> = {
  0: { label: 'DEREGISTERED', color: 'red' },
  1: { label: 'REGISTERED', color: 'green' },
  2: { label: 'REGISTERING', color: 'yellow' },
  3: { label: 'DEREGISTERING', color: 'yellow' },
}

// ---- Log terminal (WebSocket) -----------------------------------------------

type LogLine = { raw: string; level: string; msg: string; ts: string }

function parseLogLine(raw: string): LogLine {
  try {
    const obj = JSON.parse(raw.trim())
    return { raw, level: (obj.level ?? '').toLowerCase(), msg: obj.msg ?? raw, ts: obj.time ?? '' }
  } catch {
    return { raw, level: 'info', msg: raw, ts: '' }
  }
}

const levelColor: Record<string, string> = {
  error: 'text-red-400', warn: 'text-yellow-400', warning: 'text-yellow-400',
  info: 'text-gray-300', debug: 'text-gray-500',
}

function LogPanel({ container, onClose }: { container: string; onClose: () => void }) {
  const [lines, setLines] = useState<LogLine[]>([])
  const [filter, setFilter] = useState('')
  const wsRef = useRef<WebSocket | null>(null)
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    wsRef.current?.close()
    setLines([])

    let dead = false
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const ws = new WebSocket(`${protocol}//${window.location.host}/ws/logs/${container}?tail=200`)
      wsRef.current = ws
      ws.onmessage = e => {
        const parsed = parseLogLine(e.data as string)
        setLines(prev => {
          const next = [...prev, parsed]
          return next.length > 2000 ? next.slice(-2000) : next
        })
      }
      ws.onclose = () => {
        if (!dead) reconnectTimer = setTimeout(connect, 3000)
      }
    }

    connect()
    return () => {
      dead = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      wsRef.current?.close()
    }
  }, [container])

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [lines])

  const filtered = filter
    ? lines.filter(l => l.raw.toLowerCase().includes(filter.toLowerCase()))
    : lines

  return (
    <div className="mt-4 bg-gray-950 rounded-lg border border-gray-700">
      <div className="flex items-center justify-between px-3 py-2 border-b border-gray-700">
        <div className="flex items-center gap-2">
          <Terminal size={13} className="text-green-400" />
          <span className="text-xs font-mono text-green-400">{container}</span>
          <span className="text-xs text-gray-500">{filtered.length} lines</span>
        </div>
        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Filter…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-2 py-0.5 text-xs text-white w-40"
          />
          <button onClick={() => setLines([])} className="text-xs text-gray-500 hover:text-white">Clear</button>
          <button onClick={onClose} className="text-xs text-gray-500 hover:text-white">✕ Close</button>
        </div>
      </div>
      <div className="font-mono text-xs p-3 h-56 overflow-y-auto">
        {filtered.length === 0 ? (
          <span className="text-gray-600">Waiting for logs from {container}…</span>
        ) : (
          filtered.map((l, i) => (
            <div key={i} className={`leading-relaxed ${levelColor[l.level] ?? 'text-gray-300'}`}>
              {l.ts && <span className="text-gray-600 mr-2">{new Date(l.ts).toISOString().slice(11, 23)}</span>}
              {l.level && l.level !== 'info' && (
                <span className={`mr-1 uppercase text-[0.6rem] font-bold ${levelColor[l.level]}`}>{l.level}</span>
              )}
              <span>{l.msg}</span>
            </div>
          ))
        )}
        <div ref={endRef} />
      </div>
    </div>
  )
}

// ---- NR-CLI action dialog ---------------------------------------------------

function Btn({
  label, color = 'gray', onClick, disabled,
}: {
  label: string
  color?: 'gray' | 'blue' | 'orange' | 'red' | 'green' | 'purple' | 'indigo'
  onClick: () => void
  disabled: boolean
}) {
  const cls: Record<string, string> = {
    gray:   'bg-gray-700 hover:bg-gray-600',
    blue:   'bg-blue-700 hover:bg-blue-600',
    orange: 'bg-orange-800 hover:bg-orange-700',
    red:    'bg-red-800 hover:bg-red-700',
    green:  'bg-green-800 hover:bg-green-700',
    purple: 'bg-purple-800 hover:bg-purple-700',
    indigo: 'bg-indigo-800 hover:bg-indigo-700',
  }
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`px-3 py-1.5 ${cls[color]} disabled:opacity-40 text-xs text-white rounded font-mono`}
    >{label}</button>
  )
}

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <p className="text-[0.6rem] text-gray-500 mb-1.5 uppercase tracking-widest font-semibold">
      {children}
    </p>
  )
}

function NRCLIDialog({
  ue,
  onClose,
}: {
  ue: UEEntry
  onClose: () => void
}) {
  const [customCmd, setCustomCmd] = useState('')
  const [output, setOutput] = useState('')
  // ps-modify state — PSI is UERANSIM's sequential 1-based index per session
  const [psModifyPsi, setPsModifyPsi] = useState<number>(1)
  const [psModify5qi, setPsModify5qi] = useState('')
  // URSP target state
  const [urspTarget, setUrspTarget] = useState('')
  // ps-establish DNN
  const [establishDnn, setEstablishDnn] = useState('internet')

  const execMut = useMutation({
    mutationFn: ({ cmd }: { cmd: string }) => nrCLI(ue.container, ue.supi, cmd),
    onSuccess: r => setOutput(r.output || '(no output)'),
    onError: (e: Error) => setOutput(`Error: ${e.message}`),
  })

  const busy = execMut.isPending || !ue.container
  const quick = (cmd: string) => execMut.mutate({ cmd })

  // UERANSIM allocates PSIs sequentially from 1 for each UE.
  // Use index+1 as PSI; this matches the UE's allocation in the overwhelming majority of cases.
  const availablePsis = ue.sessions.length > 0
    ? ue.sessions.map((_, i) => i + 1)
    : [1]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-2xl mx-4 p-5 max-h-[90vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-white">NR-CLI — {ue.supi}</h3>
            <p className="text-xs text-gray-400">container: {ue.container || 'unknown'}</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white text-lg leading-none">✕</button>
        </div>

        {!ue.container && (
          <div className="mb-4 px-3 py-2 bg-yellow-950/50 border border-yellow-800 rounded text-xs text-yellow-300">
            No running UE container matched for this SUPI. Commands are disabled.
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">

          {/* ── Info & Status ── */}
          <div>
            <SectionLabel>Info & Status</SectionLabel>
            <div className="flex flex-wrap gap-1.5">
              <Btn label="info"     color="gray"  onClick={() => quick('info')}      disabled={busy} />
              <Btn label="status"   color="gray"  onClick={() => quick('status')}    disabled={busy} />
              <Btn label="timers"   color="gray"  onClick={() => quick('timers')}    disabled={busy} />
              <Btn label="rls-state"color="gray"  onClick={() => quick('rls-state')} disabled={busy} />
              <Btn label="coverage" color="gray"  onClick={() => quick('coverage')}  disabled={busy} />
              <Btn label="ps-list"  color="indigo" onClick={() => quick('ps-list')}  disabled={busy} />
            </div>
          </div>

          {/* ── Deregistration ── */}
          <div>
            <SectionLabel>Deregistration</SectionLabel>
            <div className="flex flex-wrap gap-1.5">
              <Btn label="normal"     color="red" onClick={() => quick('deregister normal')}     disabled={busy} />
              <Btn label="switch-off" color="red" onClick={() => quick('deregister switch-off')} disabled={busy} />
              <Btn label="disable-5g" color="red" onClick={() => quick('deregister disable-5g')} disabled={busy} />
              <Btn label="remove-sim" color="red" onClick={() => quick('deregister remove-sim')} disabled={busy} />
            </div>
          </div>
        </div>

        {/* ── PDU Session Establish ── */}
        <div className="mb-4">
          <SectionLabel>PDU Session — Establish</SectionLabel>
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500 font-mono">dnn:</span>
            <input
              value={establishDnn}
              onChange={e => setEstablishDnn(e.target.value)}
              placeholder="internet"
              disabled={!ue.container}
              className="w-28 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-white disabled:opacity-40"
            />
            <Btn
              label="ps-establish IPv4"
              color="blue"
              onClick={() => quick(`ps-establish IPv4${establishDnn ? ` --dnn ${establishDnn}` : ''}`)}
              disabled={busy}
            />
          </div>
        </div>

        {/* ── PDU Session Release ── */}
        <div className="mb-4">
          <SectionLabel>PDU Session — Release</SectionLabel>
          <div className="flex flex-wrap gap-1.5">
            {ue.sessions.length === 0 && (
              <span className="text-xs text-gray-600">No active sessions</span>
            )}
            {ue.sessions.map((s, idx) => (
              <Btn
                key={s.ref}
                label={`ps-release PSI:${idx + 1} (${s.dnn})`}
                color="orange"
                onClick={() => quick(`ps-release ${idx + 1}`)}
                disabled={busy}
              />
            ))}
            <Btn label="ps-release-all" color="orange" onClick={() => quick('ps-release-all')} disabled={busy} />
          </div>
        </div>

        {/* ── PDU Session Modify (UE-requested QoS) ── */}
        <div className="mb-4">
          <SectionLabel>PDU Session — QoS Modify (UE-requested, TS 23.502 §4.3.3.1)</SectionLabel>
          <div className="flex items-end gap-2 flex-wrap">
            <div>
              <p className="text-[0.6rem] text-gray-600 mb-0.5">PSI</p>
              <select
                value={psModifyPsi}
                onChange={e => setPsModifyPsi(Number(e.target.value))}
                disabled={!ue.container}
                className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-white disabled:opacity-40"
              >
                {availablePsis.map(id => (
                  <option key={id} value={id}>{id}</option>
                ))}
              </select>
            </div>
            <div>
              <p className="text-[0.6rem] text-gray-600 mb-0.5">5QI (optional)</p>
              <input
                value={psModify5qi}
                onChange={e => setPsModify5qi(e.target.value)}
                placeholder="e.g. 7"
                disabled={!ue.container}
                className="w-20 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-white disabled:opacity-40"
              />
            </div>
            <Btn
              label={psModify5qi ? `ps-modify ${psModifyPsi} --5qi ${psModify5qi}` : `ps-modify ${psModifyPsi}`}
              color="purple"
              onClick={() => quick(psModify5qi
                ? `ps-modify ${psModifyPsi} --5qi ${psModify5qi}`
                : `ps-modify ${psModifyPsi}`
              )}
              disabled={busy}
            />
          </div>
        </div>

        {/* ── URSP (3GPP Rel-17 mod) ── */}
        <div className="mb-4">
          <SectionLabel>URSP — TS 23.503 / TS 24.526 (5GC Rel-17 mod)</SectionLabel>
          <div className="flex flex-wrap gap-1.5 mb-2">
            <Btn label="ursp-show" color="green" onClick={() => quick('ursp-show')} disabled={busy} />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <input
              value={urspTarget}
              onChange={e => setUrspTarget(e.target.value)}
              placeholder="DNN / app / FQDN"
              disabled={!ue.container}
              className="flex-1 min-w-[10rem] bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-white disabled:opacity-40"
            />
            <Btn
              label="ursp-match"
              color="green"
              onClick={() => urspTarget && quick(`ursp-match ${urspTarget}`)}
              disabled={busy || !urspTarget}
            />
            <Btn
              label="ursp-establish"
              color="green"
              onClick={() => urspTarget && quick(`ursp-establish ${urspTarget}`)}
              disabled={busy || !urspTarget}
            />
          </div>
        </div>

        {/* ── Custom command ── */}
        <div className="mb-4">
          <SectionLabel>Custom command</SectionLabel>
          <div className="flex gap-2">
            <input
              value={customCmd}
              onChange={e => setCustomCmd(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && customCmd && quick(customCmd)}
              placeholder="e.g. timers"
              disabled={!ue.container}
              className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-white disabled:opacity-40"
            />
            <button
              onClick={() => customCmd && quick(customCmd)}
              disabled={execMut.isPending || !customCmd || !ue.container}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-xs text-white rounded"
            >
              {execMut.isPending ? <RefreshCw size={12} className="animate-spin" /> : 'Run'}
            </button>
          </div>
        </div>

        {/* ── Output ── */}
        {output && (
          <div>
            <div className="flex items-center justify-between mb-1">
              <SectionLabel>Output</SectionLabel>
              <button onClick={() => setOutput('')} className="text-[0.6rem] text-gray-600 hover:text-gray-400">
                clear
              </button>
            </div>
            <pre className="bg-gray-950 rounded p-3 text-xs font-mono text-green-300 whitespace-pre-wrap max-h-64 overflow-y-auto">
              {output}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

// ---- Ping dialog ------------------------------------------------------------

function PingDialog({ ue, onClose }: { ue: UEEntry; onClose: () => void }) {
  const [sourceIP, setSourceIP] = useState(ue.sessions[0]?.ue_ip ?? '')
  const [target, setTarget] = useState('8.8.8.8')
  const [count, setCount] = useState(4)
  const [output, setOutput] = useState('')

  const pingMut = useMutation({
    mutationFn: () => pingUE(ue.container, sourceIP, target, count),
    onSuccess: r => setOutput(r.output || '(no output)'),
    onError: (e: Error) => setOutput(`Error: ${e.message}`),
  })

  const colorLine = (line: string) => {
    if (line.includes('time=')) return 'text-green-300'
    if (line.includes('100% packet loss') || line.toLowerCase().includes('unreachable')) return 'text-red-400'
    if (line.includes('packet loss')) return 'text-yellow-400'
    if (line.startsWith('PING') || line.includes('ping statistics')) return 'text-blue-300'
    return 'text-gray-300'
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-lg mx-4 p-5"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Globe size={14} className="text-blue-400" /> Ping Test — {ue.supi}
            </h3>
            <p className="text-xs text-gray-400">container: {ue.container || 'unknown'}</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white text-lg leading-none">✕</button>
        </div>

        <div className="space-y-3 mb-4">
          {/* Source IP */}
          <div>
            <label className="text-xs text-gray-400 uppercase tracking-wider block mb-1">Source (UE IP)</label>
            {ue.sessions.length > 1 ? (
              <select
                value={sourceIP}
                onChange={e => setSourceIP(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-white"
              >
                {ue.sessions.map(s => (
                  <option key={s.ref} value={s.ue_ip}>{s.ue_ip} ({s.dnn} SST:{s.sst}{s.sd ? `/SD:${s.sd}` : ''})</option>
                ))}
              </select>
            ) : (
              <div className="px-2 py-1.5 bg-gray-800 border border-gray-700 rounded text-xs font-mono text-green-300">
                {sourceIP || <span className="text-gray-600">no PDU session active</span>}
              </div>
            )}
          </div>

          {/* Target + Count */}
          <div className="flex gap-2">
            <div className="flex-1">
              <label className="text-xs text-gray-400 uppercase tracking-wider block mb-1">Target</label>
              <input
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && sourceIP && target && pingMut.mutate()}
                placeholder="8.8.8.8"
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-white"
              />
            </div>
            <div className="w-20">
              <label className="text-xs text-gray-400 uppercase tracking-wider block mb-1">Count</label>
              <select
                value={count}
                onChange={e => setCount(Number(e.target.value))}
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-white"
              >
                {[4, 8, 16].map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
          </div>
        </div>

        <button
          onClick={() => pingMut.mutate()}
          disabled={pingMut.isPending || !sourceIP || !target || !ue.container}
          className="w-full flex items-center justify-center gap-2 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white text-sm rounded mb-4"
        >
          {pingMut.isPending
            ? <><RefreshCw size={13} className="animate-spin" /> Pinging…</>
            : <><Globe size={13} /> Ping</>}
        </button>

        {output && (
          <div>
            <p className="text-xs text-gray-400 mb-1 uppercase tracking-wider">Output</p>
            <pre className="bg-gray-950 rounded p-3 text-xs font-mono whitespace-pre-wrap max-h-56 overflow-y-auto">
              {output.split('\n').map((line, i) => (
                <span key={i} className={`block leading-relaxed ${colorLine(line)}`}>{line}</span>
              ))}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

// ---- Scenario card ----------------------------------------------------------

const stateVariant = (s: string) => {
  if (s === 'running') return 'green'
  if (s === 'partial') return 'yellow'
  return 'gray'
}

const stateLabel = (s: string) => {
  if (s === 'not_found') return 'not created'
  return s
}

function ScenarioCard({
  scenario,
  onStart,
  onStop,
  loading,
}: {
  scenario: UERANSIMScenarioState
  onStart: () => void
  onStop: () => void
  loading: boolean
}) {
  const active = scenario.state === 'running' || scenario.state === 'partial'
  const notFound = scenario.state === 'not_found'

  return (
    <div className={`bg-gray-900 rounded-lg border p-4 flex flex-col gap-3 ${active ? 'border-blue-700' : 'border-gray-800'}`}>
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="text-sm font-bold text-white leading-tight">{scenario.label}</p>
        </div>
        <Badge label={stateLabel(scenario.state)} variant={stateVariant(scenario.state)} />
      </div>

      <div className="space-y-1">
        {scenario.containers.map(c => (
          <div key={c.name} className="flex items-center gap-2 text-xs">
            <span className={`inline-block w-1.5 h-1.5 rounded-full flex-shrink-0 ${c.state === 'running' ? 'bg-green-400' : c.state === 'not_found' ? 'bg-gray-700' : 'bg-gray-500'}`} />
            <span className={`font-mono ${c.state === 'running' ? 'text-gray-300' : 'text-gray-600'}`}>{c.name}</span>
          </div>
        ))}
      </div>

      <div className="mt-auto">
        {active ? (
          <button
            onClick={onStop}
            disabled={loading}
            className="flex items-center gap-1 px-3 py-1.5 bg-red-800 hover:bg-red-700 disabled:opacity-40 text-white text-xs rounded w-full justify-center"
          >
            <Square size={10} /> Stop
          </button>
        ) : (
          <button
            onClick={onStart}
            disabled={loading || notFound}
            title={notFound ? `Run "${scenario.hint}" first to create containers` : undefined}
            className="flex items-center gap-1 px-3 py-1.5 bg-green-700 hover:bg-green-600 disabled:opacity-40 text-white text-xs rounded w-full justify-center"
          >
            <Play size={10} /> Start
          </button>
        )}
        {notFound && (
          <p className="mt-1.5 text-[0.65rem] text-gray-600 text-center">
            Run <code className="font-mono">{scenario.hint}</code> first
          </p>
        )}
      </div>
    </div>
  )
}

// ---- Container card ---------------------------------------------------------

function ContainerCard({
  ctr,
  onLogs,
  onStart,
  onStop,
}: {
  ctr: UEContainer
  onLogs: () => void
  onStart: () => void
  onStop: () => void
}) {
  const running = ctr.state === 'running'
  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          {ctr.role === 'gnb'
            ? (running ? <Signal size={14} className="text-green-400" /> : <SignalZero size={14} className="text-red-400" />)
            : (running ? <Wifi size={14} className="text-blue-400" /> : <WifiOff size={14} className="text-gray-500" />)}
          <span className="text-sm font-bold text-white">{ctr.name}</span>
        </div>
        <Badge
          label={running ? 'running' : ctr.state}
          variant={running ? 'green' : 'red'}
        />
      </div>
      {running && ctr.uptime && (
        <p className="text-xs text-gray-500 mb-3">up {ctr.uptime}</p>
      )}
      <div className="flex gap-2 flex-wrap">
        {running ? (
          <button
            onClick={onStop}
            className="flex items-center gap-1 px-2 py-1 bg-red-800 hover:bg-red-700 text-white text-xs rounded"
          >
            <Square size={10} /> Stop
          </button>
        ) : (
          <button
            onClick={onStart}
            className="flex items-center gap-1 px-2 py-1 bg-green-800 hover:bg-green-700 text-white text-xs rounded"
          >
            <Play size={10} /> Start
          </button>
        )}
        <button
          onClick={onLogs}
          className="flex items-center gap-1 px-2 py-1 bg-gray-700 hover:bg-gray-600 text-white text-xs rounded"
        >
          <Terminal size={10} /> Logs
        </button>
      </div>
    </div>
  )
}

// ---- UE row -----------------------------------------------------------------

function UERow({ ue, onAction, onPing }: { ue: UEEntry; onAction: (ue: UEEntry) => void; onPing: (ue: UEEntry) => void }) {
  const [expanded, setExpanded] = useState(false)
  const gmm = GMM[ue.gmm_state] ?? { label: `State ${ue.gmm_state}`, color: 'gray' as const }

  return (
    <>
      <tr
        className="border-b border-gray-800/50 hover:bg-gray-800/20 cursor-pointer"
        onClick={() => setExpanded(e => !e)}
      >
        <td className="px-4 py-3 w-6">
          {expanded ? <ChevronDown size={13} className="text-gray-500" /> : <ChevronRight size={13} className="text-gray-500" />}
        </td>
        <td className="px-4 py-3 font-mono text-xs text-blue-300">{ue.supi}</td>
        <td className="px-4 py-3">
          <Badge label={gmm.label} variant={gmm.color} />
        </td>
        <td className="px-4 py-3 text-xs text-gray-400">
          {ue.tmsi ? `0x${ue.tmsi.toString(16).toUpperCase().padStart(8, '0')}` : '—'}
        </td>
        <td className="px-4 py-3">
          {ue.sessions.length === 0
            ? <span className="text-xs text-gray-600">none</span>
            : ue.sessions.map(s => (
                <span key={s.ref} className="inline-block font-mono text-xs text-green-300 mr-2">
                  {s.ue_ip}
                </span>
              ))
          }
        </td>
        <td className="px-4 py-3 text-xs text-gray-500">
          {ue.container
            ? <span className="text-gray-400">{ue.container}</span>
            : <span className="text-gray-600">—</span>}
        </td>
        <td className="px-4 py-3 text-right">
          <div className="flex items-center justify-end gap-1">
            <button
              onClick={e => { e.stopPropagation(); onPing(ue) }}
              disabled={!ue.container || ue.sessions.length === 0}
              className="flex items-center gap-1 px-2 py-1 bg-gray-700 hover:bg-blue-800 disabled:opacity-30 text-white text-xs rounded"
              title="Ping test from UE"
            >
              <Globe size={11} /> Ping
            </button>
            <button
              onClick={e => { e.stopPropagation(); onAction(ue) }}
              disabled={!ue.container}
              className="flex items-center gap-1 px-2 py-1 bg-gray-700 hover:bg-blue-700 disabled:opacity-30 text-white text-xs rounded"
              title="Open NR-CLI console"
            >
              <Terminal size={11} /> NR-CLI
            </button>
          </div>
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-gray-800/50 bg-gray-800/10">
          <td />
          <td colSpan={6} className="px-4 pb-4 pt-2">
            <div className="text-xs text-gray-400 mb-2 uppercase tracking-wider">PDU Sessions</div>
            {ue.sessions.length === 0 ? (
              <p className="text-xs text-gray-600">No active PDU sessions</p>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500 uppercase">
                    <th className="pr-4 py-1 text-left">PSI</th>
                    <th className="pr-6 py-1 text-left">DNN</th>
                    <th className="pr-6 py-1 text-left">UE IP</th>
                    <th className="pr-6 py-1 text-left">Slice</th>
                    <th className="pr-6 py-1 text-left">UL TEID</th>
                    <th className="py-1 text-left">Since</th>
                  </tr>
                </thead>
                <tbody>
                  {ue.sessions.map((s, idx) => (
                    <tr key={s.ref}>
                      <td className="pr-4 py-1 font-mono text-yellow-400">
                        {idx + 1}
                      </td>
                      <td className="pr-6 py-1 text-gray-300">{s.dnn}</td>
                      <td className="pr-6 py-1 font-mono text-green-300">{s.ue_ip}</td>
                      <td className="pr-6 py-1 text-gray-300">SST:{s.sst}{s.sd ? `/SD:${s.sd}` : ''}</td>
                      <td className="pr-6 py-1 font-mono text-gray-400">
                        0x{s.ul_teid.toString(16).toUpperCase().padStart(8, '0')}
                      </td>
                      <td className="py-1 text-gray-500">
                        {new Date(s.created_at).toLocaleTimeString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <div className="mt-2 text-xs text-gray-500">
              Registered at: {new Date(ue.created_at).toLocaleString()}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ---- Main page --------------------------------------------------------------

export default function UERANSim() {
  const qc = useQueryClient()
  const [logContainer, setLogContainer] = useState<string | null>(null)
  const [activeUE, setActiveUE] = useState<UEEntry | null>(null)
  const [pingTarget, setPingTarget] = useState<UEEntry | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['ueransim-status'],
    queryFn: getUERANSIMStatus,
    refetchInterval: 5_000,
  })

  const { data: scenariosData } = useQuery({
    queryKey: ['ueransim-scenarios'],
    queryFn: getUERANSIMScenarios,
    refetchInterval: 5_000,
  })

  const startMut = useMutation({
    mutationFn: startService,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ueransim-status'] }),
  })
  const stopMut = useMutation({
    mutationFn: stopService,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ueransim-status'] }),
  })

  const scenarioStartMut = useMutation({
    mutationFn: startUERANSIMScenario,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ueransim-status'] })
      qc.invalidateQueries({ queryKey: ['ueransim-scenarios'] })
    },
  })
  const scenarioStopMut = useMutation({
    mutationFn: stopUERANSIMScenario,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ueransim-status'] })
      qc.invalidateQueries({ queryKey: ['ueransim-scenarios'] })
    },
  })

  const containers = data?.containers ?? []
  const ues = data?.ues ?? []
  const scenarios = scenariosData?.scenarios ?? []

  const gnbRunning = containers.some(c => c.role === 'gnb' && c.state === 'running')
  const anyUERunning = containers.some(c => c.role === 'ue' && c.state === 'running')
  const scenarioPending = scenarioStartMut.isPending || scenarioStopMut.isPending

  return (
    <div className="p-6">
      {activeUE && <NRCLIDialog ue={activeUE} onClose={() => setActiveUE(null)} />}
      {pingTarget && <PingDialog ue={pingTarget} onClose={() => setPingTarget(null)} />}

      <PageHeader
        title="UERANSIM"
        subtitle="gNB and UE lifecycle management"
        action={
          <div className="flex gap-2">
            {!gnbRunning && (
              <button
                onClick={() => startMut.mutate('ueransim-gnb')}
                disabled={startMut.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-green-700 hover:bg-green-600 text-white text-sm rounded-md"
              >
                <Signal size={14} /> Launch gNB
              </button>
            )}
            {gnbRunning && !anyUERunning && (
              <button
                onClick={() => startMut.mutate('ueransim-ue')}
                disabled={startMut.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md"
              >
                <Plus size={14} /> Launch UE
              </button>
            )}
            <button
              onClick={() => {
                qc.invalidateQueries({ queryKey: ['ueransim-status'] })
                qc.invalidateQueries({ queryKey: ['ueransim-scenarios'] })
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-md"
            >
              <RefreshCw size={14} /> Refresh
            </button>
          </div>
        }
      />

      {/* Test Scenarios */}
      {scenarios.length > 0 && (
        <div className="mb-8">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Layers size={13} /> Test Scenarios
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {scenarios.map(sc => (
              <ScenarioCard
                key={sc.name}
                scenario={sc}
                loading={scenarioPending}
                onStart={() => scenarioStartMut.mutate(sc.name)}
                onStop={() => scenarioStopMut.mutate(sc.name)}
              />
            ))}
          </div>
        </div>
      )}

      {/* Container grid */}
      {containers.length === 0 && !isLoading ? (
        <div className="mb-8 p-6 bg-gray-900 border border-gray-800 rounded-lg text-center text-gray-500 text-sm">
          No UERANSIM containers found. Use <code className="font-mono bg-gray-800 px-1 rounded">make ueransim</code> to start them.
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3 mb-8">
          {containers.map(ctr => (
            <ContainerCard
              key={ctr.name}
              ctr={ctr}
              onLogs={() => setLogContainer(l => l === ctr.name ? null : ctr.name)}
              onStart={() => startMut.mutate(ctr.name)}
              onStop={() => stopMut.mutate(ctr.name)}
            />
          ))}
        </div>
      )}

      {/* Live log panel */}
      {logContainer && (
        <LogPanel container={logContainer} onClose={() => setLogContainer(null)} />
      )}

      {/* Registered UEs */}
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 mt-8">
        Registered UEs ({ues.length})
      </h3>
      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
              <th className="px-4 py-3 w-6" />
              <th className="px-4 py-3 text-left">SUPI</th>
              <th className="px-4 py-3 text-left">GMM State</th>
              <th className="px-4 py-3 text-left">TMSI</th>
              <th className="px-4 py-3 text-left">UE IP(s)</th>
              <th className="px-4 py-3 text-left">Container</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                  Loading…
                </td>
              </tr>
            ) : ues.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                  <div className="flex flex-col items-center gap-2">
                    <LogOut size={24} className="text-gray-700" />
                    <span>No UEs registered. Launch UERANSIM and wait for registration.</span>
                  </div>
                </td>
              </tr>
            ) : (
              ues.map(ue => (
                <UERow key={ue.supi} ue={ue} onAction={setActiveUE} onPing={setPingTarget} />
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Deregister note */}
      {ues.length > 0 && (
        <p className="mt-3 text-xs text-gray-600">
          Click a row to expand PDU session details (PSI column = PDU Session ID for nr-cli ps-release).
          Use <span className="font-mono">NR-CLI</span> to send commands: ps-establish, ps-release, ps-modify, ursp-show, ursp-match, ursp-establish, deregister.
        </p>
      )}
    </div>
  )
}
