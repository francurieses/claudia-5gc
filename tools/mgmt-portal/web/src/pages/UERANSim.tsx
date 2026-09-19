import { useState, useEffect, useRef, type ReactNode } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Play, Square, RefreshCw, Terminal, ChevronDown, ChevronRight, X,
  Signal, SignalZero, Wifi, WifiOff, LogOut, Plus, Globe, Layers,
  CheckCircle2, XCircle, Circle, Clock, AlertTriangle,
} from 'lucide-react'
import {
  getUERANSIMStatus, nrCLI, pingUE, startService, stopService,
  getUERANSIMScenarios, startUERANSIMScenario, stopUERANSIMScenario,
  type UEEntry, type UEContainer, type UERANSIMScenarioState,
} from '../lib/api'
import { formatHex32 } from '../lib/format'
import {
  Badge, Button, Card, Dialog, EmptyState, ErrorState, Field, IconButton, Input, Loading,
  PageHeader, Section, SegmentedControl, Select, Spinner, Table, TableBody, TableCell,
  TableEmptyRow, TableHead, TableHeaderCell, TableRow, useToast,
} from '../components/ui'
import type { BadgeVariant, SelectOption } from '../components/ui'

// ---- Status → semantic badge (colour + icon + text; never colour-only) ------

interface StatusBadge {
  label: string
  variant: BadgeVariant
  icon: ReactNode
}

/** 5GMM state (TS 24.501 §5) — the label word carries the state, the icon repeats it. */
const GMM: Record<number, StatusBadge> = {
  0: { label: 'DEREGISTERED', variant: 'danger', icon: <XCircle size={12} /> },
  1: { label: 'REGISTERED', variant: 'success', icon: <CheckCircle2 size={12} /> },
  2: { label: 'REGISTERING', variant: 'warning', icon: <Clock size={12} /> },
  3: { label: 'DEREGISTERING', variant: 'warning', icon: <Clock size={12} /> },
}

const gmmStatus = (state: number): StatusBadge =>
  GMM[state] ?? { label: `State ${state}`, variant: 'neutral', icon: <Circle size={12} /> }

const stateLabel = (s: string) => (s === 'not_found' ? 'not created' : s)

function scenarioStatus(state: string): StatusBadge {
  switch (state) {
    case 'running':
      return { label: stateLabel(state), variant: 'success', icon: <CheckCircle2 size={12} /> }
    case 'partial':
      return { label: stateLabel(state), variant: 'warning', icon: <AlertTriangle size={12} /> }
    case 'stopped':
      return { label: stateLabel(state), variant: 'danger', icon: <XCircle size={12} /> }
    default:
      return { label: stateLabel(state), variant: 'neutral', icon: <Circle size={12} /> }
  }
}

function containerStatus(state: string): StatusBadge {
  if (state === 'running') return { label: 'running', variant: 'success', icon: <CheckCircle2 size={12} /> }
  if (state === 'not_found') return { label: 'not created', variant: 'neutral', icon: <Circle size={12} /> }
  return { label: state, variant: 'danger', icon: <XCircle size={12} /> }
}

// ---- Log terminal (WebSocket) ----------------------------------------------

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
  error: 'text-danger-fg',
  warn: 'text-warning-fg',
  warning: 'text-warning-fg',
  info: 'text-log-fg',
  debug: 'text-muted-fg',
}

type WSStatus = 'connecting' | 'open' | 'closed'

/**
 * Inline container log stream. The surface is the theme-aware `.log-surface`
 * component class, and the socket state is always visible — a dropped stream
 * used to be indistinguishable from an idle one.
 */
function LogPanel({ container, onClose }: { container: string; onClose: () => void }) {
  const [lines, setLines] = useState<LogLine[]>([])
  const [filter, setFilter] = useState('')
  const [status, setStatus] = useState<WSStatus>('connecting')
  const wsRef = useRef<WebSocket | null>(null)
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    wsRef.current?.close()
    setLines([])
    setStatus('connecting')

    let dead = false
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const ws = new WebSocket(`${protocol}//${window.location.host}/ws/logs/${container}?tail=200`)
      wsRef.current = ws
      ws.onopen = () => {
        if (!dead) setStatus('open')
      }
      ws.onmessage = e => {
        const parsed = parseLogLine(e.data as string)
        setLines(prev => {
          const next = [...prev, parsed]
          return next.length > 2000 ? next.slice(-2000) : next
        })
      }
      ws.onclose = () => {
        if (dead) return
        setStatus('closed')
        reconnectTimer = setTimeout(() => {
          setStatus('connecting')
          connect()
        }, 3000)
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

  const connection: StatusBadge =
    status === 'open'
      ? { label: 'Connected', variant: 'success', icon: <CheckCircle2 size={12} /> }
      : status === 'connecting'
        ? { label: 'Connecting', variant: 'info', icon: <RefreshCw size={12} className="animate-spin" /> }
        : { label: 'Disconnected', variant: 'danger', icon: <XCircle size={12} /> }

  return (
    <Card padded={false} className="mt-4 overflow-hidden bg-log-bg">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <Terminal size={13} aria-hidden="true" className="text-log-fg" />
          <span className="font-mono text-xs text-log-fg">{container}</span>
          <Badge label={connection.label} variant={connection.variant} icon={connection.icon} />
          <span className="text-xs text-muted-fg">{filtered.length} lines</span>
        </div>
        <div className="flex items-center gap-2">
          <Input
            aria-label={`Filter lines from ${container}`}
            placeholder="Filter…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="w-40 text-xs"
          />
          <Button size="sm" variant="ghost" onClick={() => setLines([])}>
            Clear
          </Button>
          <Button size="sm" variant="ghost" icon={<X size={12} />} onClick={onClose}>
            Close
          </Button>
        </div>
      </div>

      <div className="log-surface h-56 overflow-y-auto p-3">
        {filtered.length === 0 ? (
          <span className="text-muted-fg">
            {filter ? 'No lines match the filter.' : `Waiting for logs from ${container}…`}
          </span>
        ) : (
          filtered.map((l, i) => (
            <div key={i} className={`leading-relaxed ${levelColor[l.level] ?? 'text-log-fg'}`}>
              {l.ts && <span className="mr-2 text-muted-fg">{new Date(l.ts).toISOString().slice(11, 23)}</span>}
              {l.level && l.level !== 'info' && (
                <span className={`mr-1 text-xs font-bold uppercase ${levelColor[l.level]}`}>{l.level}</span>
              )}
              <span>{l.msg}</span>
            </div>
          ))
        )}
        <div ref={endRef} />
      </div>
    </Card>
  )
}

// ---- NR-CLI action dialog ---------------------------------------------------

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-widest text-muted-fg">
      {children}
    </h3>
  )
}

/**
 * nr-cli command chip — a mono Button. The command families keep a visible
 * distinction through the Button variant (deregistration is destructive; the
 * PDU-session establish is the primary action) and through their group heading,
 * so nothing depends on the old per-colour chips.
 */
function CommandButton({
  label, tone = 'default', onClick, disabled, title,
}: {
  label: string
  tone?: 'default' | 'primary' | 'destructive'
  onClick: () => void
  disabled?: boolean
  title?: string
}) {
  return (
    <Button
      size="sm"
      variant={tone === 'primary' ? 'primary' : tone === 'destructive' ? 'destructive' : 'secondary'}
      className="font-mono"
      onClick={onClick}
      disabled={disabled}
      title={title}
    >
      {label}
    </Button>
  )
}

const PS_TYPES = ['IPv4', 'IPv6', 'IPv4v6'] as const
type PSType = typeof PS_TYPES[number]

function NRCLIDialog({ ue, onClose }: { ue: UEEntry; onClose: () => void }) {
  const [customCmd, setCustomCmd] = useState('')
  const [output, setOutput] = useState('')
  const [exitCode, setExitCode] = useState<number | null>(null)
  // ps-modify state — PSI is UERANSIM's sequential 1-based index per session
  const [psModifyPsi, setPsModifyPsi] = useState<number>(1)
  const [psModify5qi, setPsModify5qi] = useState('')
  // URSP target state
  const [urspTarget, setUrspTarget] = useState('')
  // ps-establish DNN + PDU session type (IPv4 | IPv6 | IPv4v6 — patch 0060)
  const [establishDnn, setEstablishDnn] = useState('internet')
  const [establishType, setEstablishType] = useState<PSType>('IPv4')

  const execMut = useMutation({
    mutationFn: ({ cmd }: { cmd: string }) => nrCLI(ue.container, ue.supi, cmd),
    onSuccess: r => {
      setExitCode(r.exit_code)
      setOutput(r.output || '(no output)')
    },
    onError: (e: Error) => {
      setExitCode(-1)
      setOutput(`Error: ${e.message}`)
    },
  })

  const busy = execMut.isPending || !ue.container
  const quick = (cmd: string) => {
    setOutput('')
    setExitCode(null)
    execMut.mutate({ cmd })
  }

  // UERANSIM allocates PSIs sequentially from 1 for each UE.
  // Use index+1 as PSI; this matches the UE's allocation in the overwhelming majority of cases.
  const availablePsis = ue.sessions.length > 0
    ? ue.sessions.map((_, i) => i + 1)
    : [1]

  const psiOptions: SelectOption[] = availablePsis.map(id => ({ value: String(id), label: String(id) }))

  const failed = exitCode !== null && exitCode !== 0

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={`NR-CLI — ${ue.supi}`}
      description={`container: ${ue.container || 'unknown'}`}
    >
      <div className="space-y-4">
        {!ue.container && (
          <div className="flex flex-wrap items-center gap-2">
            <Badge label="Commands disabled" variant="warning" icon={<AlertTriangle size={12} />} />
            <span className="text-xs text-muted-fg">
              No running UE container matched for this SUPI.
            </span>
          </div>
        )}

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {/* ── Info & Status ── */}
          <div>
            <SectionLabel>Info &amp; Status</SectionLabel>
            <div className="flex flex-wrap gap-1.5">
              <CommandButton label="info" onClick={() => quick('info')} disabled={busy} />
              <CommandButton label="status" onClick={() => quick('status')} disabled={busy} />
              <CommandButton label="timers" onClick={() => quick('timers')} disabled={busy} />
              <CommandButton label="rls-state" onClick={() => quick('rls-state')} disabled={busy} />
              <CommandButton label="coverage" onClick={() => quick('coverage')} disabled={busy} />
              <CommandButton label="ps-list" onClick={() => quick('ps-list')} disabled={busy} />
            </div>
          </div>

          {/* ── Deregistration ── */}
          <div>
            <SectionLabel>Deregistration</SectionLabel>
            <div className="flex flex-wrap gap-1.5">
              <CommandButton label="normal" tone="destructive" onClick={() => quick('deregister normal')} disabled={busy} />
              <CommandButton label="switch-off" tone="destructive" onClick={() => quick('deregister switch-off')} disabled={busy} />
              <CommandButton label="disable-5g" tone="destructive" onClick={() => quick('deregister disable-5g')} disabled={busy} />
              <CommandButton label="remove-sim" tone="destructive" onClick={() => quick('deregister remove-sim')} disabled={busy} />
            </div>
          </div>
        </div>

        {/* ── PDU Session Establish ── */}
        <div>
          <SectionLabel>PDU Session — Establish (IPv4 / IPv6 / IPv4v6, TS 23.501 §5.8.2.2)</SectionLabel>
          <div className="flex flex-wrap items-end gap-3">
            <SegmentedControl
              label="Type"
              value={establishType}
              onChange={setEstablishType}
              options={PS_TYPES.map(t => ({ value: t, label: t }))}
              disabled={!ue.container}
            />
            <Field label="DNN" className="w-32">
              {({ id }) => (
                <Input
                  id={id}
                  value={establishDnn}
                  onChange={e => setEstablishDnn(e.target.value)}
                  placeholder="internet"
                  disabled={!ue.container}
                  className="font-mono text-xs"
                />
              )}
            </Field>
            <CommandButton
              label={`ps-establish ${establishType}`}
              tone="primary"
              onClick={() => quick(`ps-establish ${establishType}${establishDnn ? ` --dnn ${establishDnn}` : ''}`)}
              disabled={busy}
            />
          </div>
          {establishType !== 'IPv4' && (
            <p className="mt-1.5 text-xs text-muted-fg">
              IPv6/IPv4v6 need the patched UERANSIM (patch 0060). The UE gets an IPv6 address via
              SLAAC from the UPF Router Advertisement; ping the N6 gateway with{' '}
              <span className="font-mono">fd00:6::1</span>.
            </p>
          )}
        </div>

        {/* ── PDU Session Release ── */}
        <div>
          <SectionLabel>PDU Session — Release</SectionLabel>
          <div className="flex flex-wrap gap-1.5">
            {ue.sessions.length === 0 && (
              <span className="text-xs text-muted-fg">No active sessions</span>
            )}
            {ue.sessions.map((s, idx) => (
              <CommandButton
                key={s.ref}
                label={`ps-release PSI:${idx + 1} (${s.dnn})`}
                onClick={() => quick(`ps-release ${idx + 1}`)}
                disabled={busy}
              />
            ))}
            <CommandButton label="ps-release-all" onClick={() => quick('ps-release-all')} disabled={busy} />
          </div>
        </div>

        {/* ── PDU Session Modify (UE-requested QoS) ── */}
        <div>
          <SectionLabel>PDU Session — QoS Modify (UE-requested, TS 23.502 §4.3.3.1)</SectionLabel>
          <div className="flex flex-wrap items-end gap-3">
            <Field label="PSI" className="w-20">
              {({ id }) => (
                <Select
                  id={id}
                  value={String(psModifyPsi)}
                  options={psiOptions}
                  onChange={e => setPsModifyPsi(Number(e.target.value))}
                  disabled={!ue.container}
                  className="font-mono text-xs"
                />
              )}
            </Field>
            <Field label="5QI (optional)" className="w-28">
              {({ id }) => (
                <Input
                  id={id}
                  value={psModify5qi}
                  onChange={e => setPsModify5qi(e.target.value)}
                  placeholder="e.g. 7"
                  disabled={!ue.container}
                  className="font-mono text-xs"
                />
              )}
            </Field>
            <CommandButton
              label={psModify5qi ? `ps-modify ${psModifyPsi} --5qi ${psModify5qi}` : `ps-modify ${psModifyPsi}`}
              onClick={() => quick(psModify5qi
                ? `ps-modify ${psModifyPsi} --5qi ${psModify5qi}`
                : `ps-modify ${psModifyPsi}`
              )}
              disabled={busy}
            />
          </div>
        </div>

        {/* ── URSP (3GPP Rel-17 mod) ── */}
        <div>
          <SectionLabel>URSP — TS 23.503 / TS 24.526 (5GC Rel-17 mod)</SectionLabel>
          <div className="mb-2 flex flex-wrap gap-1.5">
            <CommandButton label="ursp-show" onClick={() => quick('ursp-show')} disabled={busy} />
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <Field label="Target" className="min-w-[10rem] flex-1">
              {({ id }) => (
                <Input
                  id={id}
                  value={urspTarget}
                  onChange={e => setUrspTarget(e.target.value)}
                  placeholder="DNN / app / FQDN"
                  disabled={!ue.container}
                  className="font-mono text-xs"
                />
              )}
            </Field>
            <CommandButton
              label="ursp-match"
              onClick={() => urspTarget && quick(`ursp-match ${urspTarget}`)}
              disabled={busy || !urspTarget}
            />
            <CommandButton
              label="ursp-establish"
              onClick={() => urspTarget && quick(`ursp-establish ${urspTarget}`)}
              disabled={busy || !urspTarget}
            />
          </div>
        </div>

        {/* ── Custom command ── */}
        <div>
          <SectionLabel>Custom command</SectionLabel>
          <div className="flex items-end gap-2">
            <Field label="nr-cli command" className="flex-1">
              {({ id }) => (
                <Input
                  id={id}
                  value={customCmd}
                  onChange={e => setCustomCmd(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && customCmd && quick(customCmd)}
                  placeholder="e.g. timers"
                  disabled={!ue.container}
                  className="font-mono text-xs"
                />
              )}
            </Field>
            <Button
              size="sm"
              loading={execMut.isPending}
              disabled={execMut.isPending || !customCmd || !ue.container}
              onClick={() => customCmd && quick(customCmd)}
            >
              Run
            </Button>
          </div>
        </div>

        {/* ── Output ── */}
        {(execMut.isPending || output) && (
          <div>
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <SectionLabel>Output</SectionLabel>
                {failed && <span className="font-mono text-xs text-danger-fg">(exit {exitCode})</span>}
              </div>
              <Button size="sm" variant="ghost" onClick={() => { setOutput(''); setExitCode(null) }}>
                clear
              </Button>
            </div>
            {execMut.isPending ? (
              <div className="log-surface flex items-center gap-2 rounded-control border border-border p-3">
                <Spinner size={12} label="Running command" />
                <span>Running…</span>
              </div>
            ) : (
              <pre
                className={`log-surface max-h-64 overflow-y-auto whitespace-pre-wrap rounded-control border border-border p-3 ${failed ? 'text-danger-fg' : ''}`}
              >
                {output}
              </pre>
            )}
          </div>
        )}
      </div>
    </Dialog>
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
    // Successful replies use `text-fg`, not `success-fg`: on the *light* log
    // surface (#EEF2F7) success-fg measures 4.46:1, just under the 4.5:1 body
    // bar. `text-fg` (13.0:1) still lifts a reply above the default log text,
    // and the `time=` field carries the meaning (STYLE_GUIDE §3 caveat).
    if (line.includes('time=')) return 'text-fg'
    if (line.includes('100% packet loss') || line.toLowerCase().includes('unreachable')) return 'text-danger-fg'
    if (line.includes('packet loss')) return 'text-warning-fg'
    if (line.startsWith('PING') || line.includes('ping statistics')) return 'text-fg'
    return 'text-log-fg'
  }

  const sourceOptions: SelectOption[] = ue.sessions.map(s => ({
    value: s.ue_ip,
    label: `${s.ue_ip} (${s.dnn} SST:${s.sst}${s.sd ? `/SD:${s.sd}` : ''})`,
  }))

  return (
    <Dialog
      open
      onClose={onClose}
      size="md"
      title={`Ping Test — ${ue.supi}`}
      description={`container: ${ue.container || 'unknown'}`}
    >
      <div className="space-y-3">
        {/* Source IP — pick one when the UE has several sessions */}
        <Field label="Source (UE IP)">
          {({ id }) => (
            ue.sessions.length > 1 ? (
              <Select
                id={id}
                value={sourceIP}
                options={sourceOptions}
                onChange={e => setSourceIP(e.target.value)}
                className="font-mono text-xs"
              />
            ) : (
              <div className="flex h-10 items-center rounded-control border border-border bg-muted/40 px-3 font-mono text-xs text-fg">
                {sourceIP || <span className="font-sans text-muted-fg">no PDU session active</span>}
              </div>
            )
          )}
        </Field>

        <div className="flex flex-wrap items-end gap-3">
          <Field label="Target" className="min-w-[8rem] flex-1">
            {({ id }) => (
              <Input
                id={id}
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && sourceIP && target && pingMut.mutate()}
                placeholder="8.8.8.8"
                className="font-mono text-xs"
              />
            )}
          </Field>
          <Field label="Count" className="w-24">
            {({ id }) => (
              <Select
                id={id}
                value={String(count)}
                options={[4, 8, 16].map(n => ({ value: String(n), label: String(n) }))}
                onChange={e => setCount(Number(e.target.value))}
              />
            )}
          </Field>
        </div>

        <Button
          icon={<Globe size={13} />}
          loading={pingMut.isPending}
          disabled={pingMut.isPending || !sourceIP || !target || !ue.container}
          onClick={() => pingMut.mutate()}
          className="w-full"
        >
          Ping
        </Button>

        {output && (
          <div>
            <SectionLabel>Output</SectionLabel>
            <pre className="log-surface max-h-56 overflow-y-auto whitespace-pre-wrap rounded-control border border-border p-3">
              {output.split('\n').map((line, i) => (
                <span key={i} className={`block leading-relaxed ${colorLine(line)}`}>{line}</span>
              ))}
            </pre>
          </div>
        )}
      </div>
    </Dialog>
  )
}

// ---- Scenario card ----------------------------------------------------------

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
  const status = scenarioStatus(scenario.state)

  return (
    <Card className="flex flex-col gap-3">
      <div className="flex items-start justify-between gap-2">
        <p className="text-sm font-semibold leading-tight text-fg">{scenario.label}</p>
        <Badge label={status.label} variant={status.variant} icon={status.icon} />
      </div>

      <ul className="space-y-1">
        {scenario.containers.map(c => (
          <li key={c.name} className="flex items-center gap-1.5 text-xs">
            {c.state === 'running'
              ? <CheckCircle2 size={12} aria-hidden="true" className="flex-shrink-0 text-success-fg" />
              : c.state === 'not_found'
                ? <Circle size={12} aria-hidden="true" className="flex-shrink-0 text-muted-fg" />
                : <XCircle size={12} aria-hidden="true" className="flex-shrink-0 text-danger-fg" />}
            <span className={`font-mono ${c.state === 'running' ? 'text-fg' : 'text-muted-fg'}`}>{c.name}</span>
            <span className="sr-only">{stateLabel(c.state)}</span>
          </li>
        ))}
      </ul>

      <div className="mt-auto">
        {active ? (
          <Button size="sm" variant="destructive" icon={<Square size={10} />} loading={loading} onClick={onStop} className="w-full">
            Stop
          </Button>
        ) : (
          <Button
            size="sm"
            icon={<Play size={10} />}
            loading={loading}
            disabled={loading || notFound}
            onClick={onStart}
            title={notFound ? `Run "${scenario.hint}" first to create containers` : undefined}
            className="w-full"
          >
            Start
          </Button>
        )}
        {notFound && (
          <p className="mt-1.5 text-center text-xs text-muted-fg">
            Run <code className="font-mono">{scenario.hint}</code> first
          </p>
        )}
      </div>
    </Card>
  )
}

// ---- Container card ---------------------------------------------------------

function ContainerCard({
  ctr,
  onLogs,
  onStart,
  onStop,
  logsOpen,
}: {
  ctr: UEContainer
  onLogs: () => void
  onStart: () => void
  onStop: () => void
  logsOpen: boolean
}) {
  const running = ctr.state === 'running'
  const status = containerStatus(ctr.state)

  return (
    <Card>
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          {ctr.role === 'gnb'
            ? (running
              ? <Signal size={14} aria-hidden="true" className="flex-shrink-0 text-success-fg" />
              : <SignalZero size={14} aria-hidden="true" className="flex-shrink-0 text-danger-fg" />)
            : (running
              ? <Wifi size={14} aria-hidden="true" className="flex-shrink-0 text-info-fg" />
              : <WifiOff size={14} aria-hidden="true" className="flex-shrink-0 text-muted-fg" />)}
          <span className="truncate font-mono text-sm font-semibold text-fg">{ctr.name}</span>
        </div>
        <Badge label={status.label} variant={status.variant} icon={status.icon} />
      </div>

      {running && ctr.uptime && (
        <p className="mb-3 text-xs text-muted-fg">up {ctr.uptime}</p>
      )}

      <div className="flex flex-wrap gap-2">
        {running ? (
          <Button size="sm" variant="destructive" icon={<Square size={10} />} onClick={onStop}>
            Stop
          </Button>
        ) : (
          <Button size="sm" icon={<Play size={10} />} onClick={onStart}>
            Start
          </Button>
        )}
        <Button
          size="sm"
          variant="secondary"
          icon={<Terminal size={10} />}
          onClick={onLogs}
          aria-expanded={logsOpen}
        >
          Logs
        </Button>
      </div>
    </Card>
  )
}

// ---- UE row -----------------------------------------------------------------

function UERow({ ue, onAction, onPing }: { ue: UEEntry; onAction: (ue: UEEntry) => void; onPing: (ue: UEEntry) => void }) {
  const [expanded, setExpanded] = useState(false)
  const gmm = gmmStatus(ue.gmm_state)
  const detailId = `ue-sessions-${ue.supi}`

  const toggle = () => setExpanded(e => !e)

  return (
    <>
      <TableRow className="cursor-pointer" onClick={toggle}>
        <TableCell>
          <IconButton
            label={`${expanded ? 'Hide' : 'Show'} PDU sessions for ${ue.supi}`}
            variant="ghost"
            aria-expanded={expanded}
            aria-controls={expanded ? detailId : undefined}
            onClick={e => {
              e.stopPropagation()
              toggle()
            }}
          >
            {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </IconButton>
        </TableCell>
        <TableCell mono>{ue.supi}</TableCell>
        <TableCell>
          <Badge label={gmm.label} variant={gmm.variant} icon={gmm.icon} />
        </TableCell>
        <TableCell mono className="text-muted-fg">
          {ue.tmsi ? `0x${ue.tmsi.toString(16).toUpperCase().padStart(8, '0')}` : '—'}
        </TableCell>
        <TableCell>
          {ue.sessions.length === 0
            ? <span className="text-xs text-muted-fg">none</span>
            : ue.sessions.map(s => (
              <span key={s.ref} className="mr-2 inline-block font-mono text-xs text-fg">{s.ue_ip}</span>
            ))}
        </TableCell>
        <TableCell mono className="text-muted-fg">{ue.container || '—'}</TableCell>
        <TableCell className="text-right">
          <div className="flex items-center justify-end gap-1">
            <Button
              size="sm"
              variant="secondary"
              icon={<Globe size={11} />}
              disabled={!ue.container || ue.sessions.length === 0}
              onClick={e => {
                e.stopPropagation()
                onPing(ue)
              }}
              title="Ping test from UE"
            >
              Ping
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={<Terminal size={11} />}
              disabled={!ue.container}
              onClick={e => {
                e.stopPropagation()
                onAction(ue)
              }}
              title="Open NR-CLI console"
            >
              NR-CLI
            </Button>
          </div>
        </TableCell>
      </TableRow>

      {expanded && (
        <TableRow id={detailId}>
          <TableCell colSpan={7} className="bg-muted/40">
            <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-fg">PDU Sessions</p>
            {ue.sessions.length === 0 ? (
              <p className="text-xs text-muted-fg">No active PDU sessions</p>
            ) : (
              <Table caption={`PDU sessions for ${ue.supi}`}>
                <TableHead>
                  <TableRow>
                    <TableHeaderCell>PSI</TableHeaderCell>
                    <TableHeaderCell>DNN</TableHeaderCell>
                    <TableHeaderCell>UE IP</TableHeaderCell>
                    <TableHeaderCell>Slice</TableHeaderCell>
                    <TableHeaderCell>UL TEID</TableHeaderCell>
                    <TableHeaderCell>Since</TableHeaderCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {ue.sessions.map((s, idx) => (
                    <TableRow key={s.ref}>
                      <TableCell mono>{idx + 1}</TableCell>
                      <TableCell>{s.dnn}</TableCell>
                      <TableCell mono>{s.ue_ip}</TableCell>
                      <TableCell className="text-muted-fg">
                        SST:{s.sst}{s.sd ? `/SD:${s.sd}` : ''}
                      </TableCell>
                      <TableCell mono className="text-muted-fg">
                        {formatHex32(s.ul_teid)}
                      </TableCell>
                      <TableCell className="text-muted-fg">
                        {new Date(s.created_at).toLocaleTimeString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            <p className="mt-2 text-xs text-muted-fg">
              Registered at: {new Date(ue.created_at).toLocaleString()}
            </p>
          </TableCell>
        </TableRow>
      )}
    </>
  )
}

// ---- Main page --------------------------------------------------------------

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

export default function UERANSim() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [logContainer, setLogContainer] = useState<string | null>(null)
  const [activeUE, setActiveUE] = useState<UEEntry | null>(null)
  const [pingTarget, setPingTarget] = useState<UEEntry | null>(null)

  const actionFailed = (verb: string) => (err: unknown) =>
    toast({ variant: 'error', title: `${verb} failed`, description: errMessage(err), duration: 0 })

  const {
    data,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['ueransim-status'],
    queryFn: getUERANSIMStatus,
    refetchInterval: 5_000,
  })

  const {
    data: scenariosData,
    isLoading: scenariosLoading,
    isError: scenariosError,
    error: scenariosErr,
    refetch: refetchScenarios,
  } = useQuery({
    queryKey: ['ueransim-scenarios'],
    queryFn: getUERANSIMScenarios,
    refetchInterval: 5_000,
  })

  const startMut = useMutation({
    mutationFn: startService,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ueransim-status'] }),
    onError: actionFailed('Start container'),
  })
  const stopMut = useMutation({
    mutationFn: stopService,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ueransim-status'] }),
    onError: actionFailed('Stop container'),
  })

  const scenarioStartMut = useMutation({
    mutationFn: startUERANSIMScenario,
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['ueransim-status'] })
      qc.invalidateQueries({ queryKey: ['ueransim-scenarios'] })
      toast({ variant: 'success', title: `Scenario "${r.scenario}" started` })
    },
    onError: actionFailed('Start scenario'),
  })
  const scenarioStopMut = useMutation({
    mutationFn: stopUERANSIMScenario,
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['ueransim-status'] })
      qc.invalidateQueries({ queryKey: ['ueransim-scenarios'] })
      toast({ variant: 'success', title: `Scenario "${r.scenario}" stopped` })
    },
    onError: actionFailed('Stop scenario'),
  })

  const containers = data?.containers ?? []
  const ues = data?.ues ?? []
  const scenarios = scenariosData?.scenarios ?? []

  const gnbRunning = containers.some(c => c.role === 'gnb' && c.state === 'running')
  const anyUERunning = containers.some(c => c.role === 'ue' && c.state === 'running')
  const scenarioPending = scenarioStartMut.isPending || scenarioStopMut.isPending
  const runningContainers = containers.filter(c => c.state === 'running').length

  return (
    <div className="space-y-8 p-6">
      {activeUE && <NRCLIDialog ue={activeUE} onClose={() => setActiveUE(null)} />}
      {pingTarget && <PingDialog ue={pingTarget} onClose={() => setPingTarget(null)} />}

      <PageHeader
        eyebrow="Test UEs"
        title="UERANSIM"
        subtitle="gNB and UE lifecycle management"
        action={
          <div className="flex flex-wrap items-center gap-2">
            {!gnbRunning && (
              <Button
                size="sm"
                icon={<Signal size={14} />}
                loading={startMut.isPending}
                disabled={startMut.isPending}
                onClick={() => startMut.mutate('ueransim-gnb')}
              >
                Launch gNB
              </Button>
            )}
            {gnbRunning && !anyUERunning && (
              <Button
                size="sm"
                icon={<Plus size={14} />}
                loading={startMut.isPending}
                disabled={startMut.isPending}
                onClick={() => startMut.mutate('ueransim-ue')}
              >
                Launch UE
              </Button>
            )}
            <Button
              size="sm"
              variant="secondary"
              icon={<RefreshCw size={14} />}
              onClick={() => {
                refetch()
                refetchScenarios()
              }}
            >
              Refresh
            </Button>
          </div>
        }
      />

      {/* Test Scenarios */}
      <Section
        bare
        headingLevel={2}
        title={scenarios.length > 0 ? `Test Scenarios (${scenarios.length})` : 'Test Scenarios'}
        description="One-click slice / SUCI test topologies — starting a scenario stops the conflicting ones and (re)creates its containers."
      >
        {scenariosError ? (
          <ErrorState
            title="Failed to load test scenarios"
            description={errMessage(scenariosErr)}
            action={
              <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetchScenarios()}>
                Retry
              </Button>
            }
          />
        ) : scenariosLoading ? (
          <Loading rows={2} label="Loading scenarios…" />
        ) : scenarios.length === 0 ? (
          <EmptyState
            icon={<Layers size={28} />}
            title="No test scenarios"
            description="Create the UERANSIM containers with make ueransim to make the scenario set available."
          />
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
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
        )}
      </Section>

      {/* Container grid */}
      <Section
        bare
        headingLevel={2}
        title={containers.length > 0 ? `Containers (${runningContainers}/${containers.length} running)` : 'Containers'}
      >
        {isError ? (
          <ErrorState
            title="Failed to load UERANSIM status"
            description={errMessage(error)}
            action={
              <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>
                Retry
              </Button>
            }
          />
        ) : isLoading ? (
          <Loading rows={2} label="Loading containers…" />
        ) : containers.length === 0 ? (
          <EmptyState
            title="No UERANSIM containers"
            description="Run make ueransim to create the gNB and UE containers, or start a test scenario above."
          />
        ) : (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-5">
            {containers.map(ctr => (
              <ContainerCard
                key={ctr.name}
                ctr={ctr}
                logsOpen={logContainer === ctr.name}
                onLogs={() => setLogContainer(l => l === ctr.name ? null : ctr.name)}
                onStart={() => startMut.mutate(ctr.name)}
                onStop={() => stopMut.mutate(ctr.name)}
              />
            ))}
          </div>
        )}
      </Section>

      {/* Live log panel */}
      {logContainer && (
        <LogPanel container={logContainer} onClose={() => setLogContainer(null)} />
      )}

      {/* Registered UEs */}
      <Section
        bare
        headingLevel={2}
        title={`Registered UEs (${ues.length})`}
      >
        {isError ? (
          <ErrorState
            title="Failed to load UE contexts"
            description={errMessage(error)}
            action={
              <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>
                Retry
              </Button>
            }
          />
        ) : !isLoading && ues.length === 0 ? (
          <EmptyState
            icon={<LogOut size={28} />}
            title="No UEs registered"
            description="Launch UERANSIM and wait for registration."
          />
        ) : (
          <Table caption="Registered UERANSIM UEs">
            <TableHead>
              <TableRow>
                <TableHeaderCell>
                  <span className="sr-only">PDU sessions</span>
                </TableHeaderCell>
                <TableHeaderCell>SUPI</TableHeaderCell>
                <TableHeaderCell>GMM State</TableHeaderCell>
                <TableHeaderCell>TMSI</TableHeaderCell>
                <TableHeaderCell>UE IP(s)</TableHeaderCell>
                <TableHeaderCell>Container</TableHeaderCell>
                <TableHeaderCell className="text-right">Actions</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {isLoading ? (
                <TableEmptyRow colSpan={7}>
                  <Loading rows={3} label="Loading UEs…" />
                </TableEmptyRow>
              ) : (
                ues.map(ue => (
                  <UERow key={ue.supi} ue={ue} onAction={setActiveUE} onPing={setPingTarget} />
                ))
              )}
            </TableBody>
          </Table>
        )}
      </Section>

      {/* Deregister note */}
      {ues.length > 0 && (
        <p className="text-xs text-muted-fg">
          Click a row to expand PDU session details (PSI column = PDU Session ID for nr-cli ps-release).
          Use <span className="font-mono">NR-CLI</span> to send commands: ps-establish, ps-release, ps-modify, ursp-show, ursp-match, ursp-establish, deregister.
        </p>
      )}
    </div>
  )
}
