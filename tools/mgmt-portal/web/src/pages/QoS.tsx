import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  RefreshCw,
  SlidersHorizontal,
  Search,
  ChevronDown,
  ChevronRight,
  PlayCircle,
  CheckCircle2,
  XCircle,
  Loader2,
  Circle,
  X,
  Radio,
} from 'lucide-react'
import {
  getQoSSessions,
  getSubscriptionQoS,
  getUEContexts,
  getSlices,
  modifySessionQoS,
  triggerNWSession,
  type QoSSession,
  type QoSModifyResult,
  type SMSubscriptionEntry,
  type NWSessionResult,
  type NWSessionStep,
} from '../lib/api'
import PageHeader from '../components/PageHeader'
import Badge from '../components/Badge'

// ---- 5QI helpers (TS 23.501 Table 5.7.4-1) --------------------------------

const FIVEQI_NAMES: Record<number, string> = {
  1: 'Conversational voice',
  2: 'Conversational live video',
  3: 'Real-time gaming / V2X',
  4: 'Non-conversational video',
  5: 'IMS signalling',
  6: 'Video buffered streaming (priority)',
  7: 'Voice + video interactive',
  8: 'Video buffered streaming',
  9: 'Default internet (best-effort)',
  65: 'MC-PTT voice',
  66: 'Non-MC PTT voice',
  69: 'MC signalling',
  70: 'MC data',
  82: 'Discrete automation (10 ms)',
  83: 'Discrete automation (10 ms, V2X)',
  84: 'Intelligent transport systems',
  85: 'Electricity distribution (HV)',
}

type QoSCategory = 'GBR' | 'Delay-critical GBR' | 'Non-GBR' | 'Operator-defined'

function fiveQICategory(q: number): QoSCategory {
  if (q >= 1 && q <= 4) return 'GBR'
  if (q >= 82 && q <= 85) return 'Delay-critical GBR'
  if ((q >= 5 && q <= 9) || q === 65 || q === 66 || q === 69 || q === 70) return 'Non-GBR'
  return 'Operator-defined'
}

function fiveQIBadgeVariant(q: number): 'green' | 'yellow' | 'blue' | 'gray' {
  switch (fiveQICategory(q)) {
    case 'GBR':
      return 'green'
    case 'Delay-critical GBR':
      return 'yellow'
    case 'Non-GBR':
      return 'blue'
    default:
      return 'gray'
  }
}

function fiveQILabel(q: number): string {
  return FIVEQI_NAMES[q] ? `${q} — ${FIVEQI_NAMES[q]}` : `${q}`
}

const SELECTOR_GROUPS: { group: string; values: number[] }[] = [
  { group: 'Non-GBR', values: [5, 6, 7, 8, 9] },
  { group: 'GBR', values: [1, 2, 3, 4] },
  { group: 'Delay-critical GBR', values: [82, 83, 84, 85] },
]

function truncSUPI(supi: string): string {
  return supi.length > 18 ? supi.slice(0, 10) + '…' + supi.slice(-4) : supi
}

// Extract the subscription default QoS matching a session's slice + DNN.
function subscribedDefaultFor(
  entries: SMSubscriptionEntry[] | undefined,
  s: QoSSession,
): { fiveQi: number; arp: number; ambrUl: string; ambrDl: string } | null {
  if (!entries) return null
  for (const e of entries) {
    const sliceMatch =
      e.singleNssai.sst === s.sNssai.sst && (e.singleNssai.sd ?? '') === (s.sNssai.sd ?? '')
    const cfg = e.dnnConfigurations?.[s.dnn]
    if (sliceMatch && cfg) {
      return {
        fiveQi: cfg['5gQosProfile']['5qi'],
        arp: cfg['5gQosProfile'].arp.priorityLevel,
        ambrUl: cfg.sessionAmbr.uplink,
        ambrDl: cfg.sessionAmbr.downlink,
      }
    }
  }
  return null
}

// ---- Toast -----------------------------------------------------------------

interface Toast {
  kind: 'success' | 'error'
  text: string
}

// ---- Modify QoS drawer -------------------------------------------------------

function ModifyDrawer({
  session,
  onClose,
  onResult,
}: {
  session: QoSSession
  onClose: () => void
  onResult: (t: Toast) => void
}) {
  const [new5qi, setNew5qi] = useState<number>(session.current5qi === 9 ? 7 : 9)
  const [reason, setReason] = useState('')
  const [confirming, setConfirming] = useState(false)
  const qc = useQueryClient()

  const { data: subEntries } = useQuery({
    queryKey: ['qos-subscription', session.supi],
    queryFn: () => getSubscriptionQoS(session.supi),
    retry: false,
  })
  const subDefault = subscribedDefaultFor(subEntries, session)

  const modify = useMutation({
    mutationFn: () =>
      modifySessionQoS(session.pduSessionId, {
        '5qi': new5qi,
        reason,
        supi: session.supi,
      }),
    onSuccess: (res: QoSModifyResult) => {
      onResult({
        kind: 'success',
        text: `5QI changed ${res.previous5qi} → ${res.new5qi} on session ${res.pduSessionId} (${res.supi})`,
      })
      qc.invalidateQueries({ queryKey: ['qos-sessions'] })
      onClose()
    },
    onError: (err: Error) => {
      onResult({ kind: 'error', text: `QoS modification failed: ${err.message}` })
      setConfirming(false)
    },
  })

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60" onClick={onClose}>
      <div
        className="w-[28rem] h-full bg-gray-900 border-l border-gray-800 p-6 overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <SlidersHorizontal size={18} className="text-blue-400" /> Modify QoS
          </h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300">
            <X size={18} />
          </button>
        </div>

        {/* Current session (read-only) */}
        <div className="bg-gray-800/50 rounded-lg p-4 mb-4 space-y-1.5 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-400">SUPI</span>
            <span className="font-mono text-xs text-blue-300">{session.supi}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">PDU Session / DNN</span>
            <span className="text-gray-200">
              {session.pduSessionId} · {session.dnn}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">S-NSSAI</span>
            <span className="text-gray-200">
              {session.sNssai.sst}:{session.sNssai.sd || '—'}
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Current 5QI</span>
            <Badge label={fiveQILabel(session.current5qi)} variant={fiveQIBadgeVariant(session.current5qi)} />
          </div>
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Subscribed default 5QI</span>
            {subDefault ? (
              <Badge label={fiveQILabel(subDefault.fiveQi)} variant={fiveQIBadgeVariant(subDefault.fiveQi)} />
            ) : (
              <span className="text-gray-600 text-xs">not provisioned</span>
            )}
          </div>
        </div>

        {/* 5QI selector */}
        <label className="block text-xs text-gray-400 uppercase tracking-wider mb-1.5">New 5QI</label>
        <select
          value={new5qi}
          onChange={e => setNew5qi(Number(e.target.value))}
          className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm text-gray-100 mb-4"
        >
          {SELECTOR_GROUPS.map(g => (
            <optgroup key={g.group} label={g.group}>
              {g.values.map(v => (
                <option key={v} value={v}>
                  {fiveQILabel(v)}
                </option>
              ))}
            </optgroup>
          ))}
        </select>

        {/* Reason */}
        <label className="block text-xs text-gray-400 uppercase tracking-wider mb-1.5">
          Reason <span className="text-red-400">*</span>
        </label>
        <textarea
          value={reason}
          onChange={e => setReason(e.target.value)}
          rows={2}
          placeholder="e.g. upgrade subscriber to interactive video"
          className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm text-gray-100 mb-4"
        />

        {!confirming ? (
          <button
            disabled={!reason.trim() || new5qi === session.current5qi}
            onClick={() => setConfirming(true)}
            className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-md py-2 text-sm font-medium"
          >
            Apply
          </button>
        ) : (
          <div className="bg-yellow-900/30 border border-yellow-800 rounded-lg p-4">
            <p className="text-sm text-yellow-200 mb-3">
              You are about to change 5QI from <b>{session.current5qi}</b> to <b>{new5qi}</b> on session{' '}
              <b>{session.pduSessionId}</b> for <span className="font-mono text-xs">{session.supi}</span>. This
              will trigger a network-initiated PDU Session Modification (TS 23.502 §4.3.3.2). Confirm?
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => modify.mutate()}
                disabled={modify.isPending}
                className="flex-1 bg-yellow-600 hover:bg-yellow-500 text-white rounded-md py-1.5 text-sm font-medium"
              >
                {modify.isPending ? 'Applying…' : 'Confirm'}
              </button>
              <button
                onClick={() => setConfirming(false)}
                className="flex-1 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-md py-1.5 text-sm"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ---- Subscription QoS inspector ---------------------------------------------

function SubscriptionInspector({
  sessions,
  initialSupi,
  onClose,
}: {
  sessions: QoSSession[]
  initialSupi: string
  onClose: () => void
}) {
  const [supi, setSupi] = useState(initialSupi)
  const [lookup, setLookup] = useState(initialSupi)

  const { data: entries, error, isFetching } = useQuery({
    queryKey: ['qos-subscription', lookup],
    queryFn: () => getSubscriptionQoS(lookup),
    enabled: !!lookup,
    retry: false,
  })

  const session = sessions.find(s => s.supi === lookup)

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60" onClick={onClose}>
      <div
        className="w-[30rem] h-full bg-gray-900 border-l border-gray-800 p-6 overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <Search size={18} className="text-blue-400" /> Subscription QoS inspector
          </h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300">
            <X size={18} />
          </button>
        </div>

        <div className="flex gap-2 mb-5">
          <input
            value={supi}
            onChange={e => setSupi(e.target.value)}
            placeholder="imsi-001010000000001"
            className="flex-1 bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm font-mono text-gray-100"
          />
          <button
            onClick={() => setLookup(supi.trim())}
            className="bg-blue-600 hover:bg-blue-500 text-white rounded-md px-4 text-sm"
          >
            {isFetching ? '…' : 'Lookup'}
          </button>
        </div>

        {error && (
          <p className="text-sm text-red-400 mb-4">No SM subscription found for {lookup}</p>
        )}

        {entries?.map((e, i) => {
          const cfgs = Object.entries(e.dnnConfigurations || {})
          return (
            <div key={i} className="bg-gray-800/50 rounded-lg p-4 mb-3">
              <div className="flex items-center gap-2 mb-2">
                <Badge label={`SST:${e.singleNssai.sst}${e.singleNssai.sd ? '/SD:' + e.singleNssai.sd : ''}`} variant="blue" />
              </div>
              {cfgs.map(([dnn, cfg]) => {
                const q = cfg['5gQosProfile']
                const sessionMatches =
                  session &&
                  session.dnn === dnn &&
                  session.sNssai.sst === e.singleNssai.sst &&
                  (session.sNssai.sd ?? '') === (e.singleNssai.sd ?? '')
                const diff = sessionMatches && session.current5qi !== q['5qi']
                return (
                  <div key={dnn} className="text-sm space-y-1.5 border-t border-gray-800 pt-2 mt-2">
                    <div className="flex justify-between">
                      <span className="text-gray-400">DNN</span>
                      <span className="text-gray-200">{dnn}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-400">Default 5QI</span>
                      <Badge label={fiveQILabel(q['5qi'])} variant={fiveQIBadgeVariant(q['5qi'])} />
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">ARP priority</span>
                      <span className="text-gray-200">{q.arp.priorityLevel}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Preemption cap / vuln</span>
                      <span className="text-gray-200 text-xs">
                        {q.arp.preemptCap} / {q.arp.preemptVuln}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Session AMBR UL / DL</span>
                      <span className="text-gray-200 text-xs">
                        {cfg.sessionAmbr.uplink} / {cfg.sessionAmbr.downlink}
                      </span>
                    </div>
                    {sessionMatches && (
                      <div
                        className={`rounded-md px-3 py-2 mt-2 text-xs ${
                          diff
                            ? 'bg-yellow-900/40 border border-yellow-800 text-yellow-200'
                            : 'bg-green-900/30 border border-green-800 text-green-300'
                        }`}
                      >
                        {diff ? (
                          <>
                            Active session 5QI <b>{session.current5qi}</b> differs from subscribed default{' '}
                            <b>{q['5qi']}</b> (source: {session.qosSource})
                          </>
                        ) : (
                          <>Active session 5QI matches the subscribed default ({q['5qi']})</>
                        )}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ---- NW-triggered additional PDU session panel ------------------------------
//
// Simulates the network detecting a new app/service and steering the UE to an
// additional PDU session via URSP (TS 23.503 §6.6.2). All network-side steps are
// standard; the UE-side URSP evaluation is simulated (UERANSIM has no URSP).

const NW_STEP_LABELS: Record<string, string> = {
  pcf_qos_override: 'PCF: DNN-scoped QoS override (TS 29.512 §5.2.2.2)',
  ursp_rule_store: 'UDR: URSP rule stored (TS 24.526 §5.2/§5.3)',
  ursp_push: 'AMF: UE Policy delivery — DL NAS container 0x05 (TS 23.502 §4.2.4.3)',
  ue_establish: 'UE: URSP evaluation → additional PDU Session Establishment (TS 24.501 §6.4.1.2)',
  verify: 'SMF: additional PSI ACTIVE with requested 5QI',
}

const APP_PRESETS: { app: string; '5qi': number; hint: string }[] = [
  { app: 'cloud-gaming', '5qi': 3, hint: 'real-time gaming' },
  { app: 'voice-call', '5qi': 1, hint: 'conversational voice' },
  { app: 'video-stream', '5qi': 8, hint: 'buffered streaming' },
  { app: 'ims-signalling', '5qi': 5, hint: 'IMS' },
]

function NWSessionPanel({
  sessions,
  onResult,
}: {
  sessions: QoSSession[]
  onResult: (t: Toast) => void
}) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [supi, setSupi] = useState('')
  const [app, setApp] = useState('cloud-gaming')
  const [dnn, setDnn] = useState('internet')
  const [sliceKey, setSliceKey] = useState('') // "sst:sd"
  const [fiveQi, setFiveQi] = useState(3)
  const [ambrUl, setAmbrUl] = useState('')
  const [ambrDl, setAmbrDl] = useState('')
  const [result, setResult] = useState<NWSessionResult | null>(null)

  const { data: ues } = useQuery({ queryKey: ['ue-contexts'], queryFn: getUEContexts, refetchInterval: 15_000 })
  const { data: slices } = useQuery({ queryKey: ['slices'], queryFn: getSlices })

  const effSupi = supi || ues?.[0]?.supi || ''
  const [sst, sd] = useMemo(() => {
    if (sliceKey) {
      const [s, d] = sliceKey.split(':')
      return [Number(s), d === '—' ? '' : d]
    }
    return [slices?.[0]?.sst ?? 1, slices?.[0]?.sd ?? '000001']
  }, [sliceKey, slices])

  const trigger = useMutation({
    mutationFn: () =>
      triggerNWSession({
        supi: effSupi,
        app,
        dnn,
        sst,
        sd,
        '5qi': fiveQi,
        ambr_uplink: ambrUl || undefined,
        ambr_downlink: ambrDl || undefined,
      }),
    onSuccess: (res: NWSessionResult) => {
      setResult(res)
      qc.invalidateQueries({ queryKey: ['qos-sessions'] })
      if (res.success) {
        onResult({
          kind: 'success',
          text: `Additional PDU session established: PSI ${res.pdu_session_id}, 5QI ${res['5qi']}, UE IP ${res.ue_ip}`,
        })
      } else {
        onResult({ kind: 'error', text: res.error || 'NW-triggered session failed' })
      }
    },
    onError: (err: Error) => onResult({ kind: 'error', text: err.message }),
  })

  const stepIcon = (s: NWSessionStep) =>
    s.success ? (
      <CheckCircle2 size={16} className="text-green-400 shrink-0" />
    ) : (
      <XCircle size={16} className="text-red-400 shrink-0" />
    )

  return (
    <div className="mt-8 bg-gray-900 rounded-lg border border-gray-800">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 text-sm font-semibold text-gray-300"
      >
        <span className="flex items-center gap-2">
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          <Radio size={16} className="text-purple-400" />
          NW-Triggered PDU Session
        </span>
        <span className="text-xs text-gray-500 font-normal">
          app detected → URSP delivery → additional UE-requested session — TS 23.503 §6.6.2
        </span>
      </button>

      {open && (
        <div className="px-4 pb-4">
          <p className="text-xs text-gray-500 mb-4">
            Simulates the network detecting that the subscriber opened a new app/service. The core
            stores a DNN-scoped QoS override in the PCF, delivers an updated URSP rule (DL NAS
            payload container 0x05), and the UE establishes an <b>additional</b> PDU session
            (new PSI) carrying the requested 5QI. UE-side URSP evaluation is simulated via nr-cli
            (UERANSIM v3.2.8 has no URSP support).
          </p>

          <div className="grid grid-cols-2 lg:grid-cols-3 gap-3 mb-3">
            <div>
              <label className="block text-xs text-gray-400 uppercase tracking-wider mb-1">UE (registered)</label>
              <select
                value={effSupi}
                onChange={e => setSupi(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm font-mono text-gray-100"
              >
                {(ues ?? []).map(u => (
                  <option key={u.supi} value={u.supi}>
                    {u.supi}
                  </option>
                ))}
                {(ues ?? []).length === 0 && <option value="">no registered UEs</option>}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 uppercase tracking-wider mb-1">Detected app</label>
              <div className="flex gap-1.5">
                <input
                  value={app}
                  onChange={e => setApp(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm text-gray-100"
                />
              </div>
              <div className="flex gap-1 mt-1 flex-wrap">
                {APP_PRESETS.map(p => (
                  <button
                    key={p.app}
                    title={`${p.hint} → 5QI ${p['5qi']}`}
                    onClick={() => {
                      setApp(p.app)
                      setFiveQi(p['5qi'])
                    }}
                    className={`text-[10px] rounded px-1.5 py-0.5 border ${
                      app === p.app
                        ? 'bg-purple-900/50 border-purple-700 text-purple-200'
                        : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'
                    }`}
                  >
                    {p.app}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-xs text-gray-400 uppercase tracking-wider mb-1">DNN</label>
              <input
                value={dnn}
                onChange={e => setDnn(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm text-gray-100"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 uppercase tracking-wider mb-1">S-NSSAI</label>
              <select
                value={sliceKey || `${sst}:${sd || '—'}`}
                onChange={e => setSliceKey(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm text-gray-100"
              >
                {(slices ?? [{ sst: 1, sd: '000001' }]).map(s => (
                  <option key={`${s.sst}:${s.sd}`} value={`${s.sst}:${s.sd || '—'}`}>
                    SST {s.sst} / SD {s.sd || '—'}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 uppercase tracking-wider mb-1">5QI for the new session</label>
              <select
                value={fiveQi}
                onChange={e => setFiveQi(Number(e.target.value))}
                className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm text-gray-100"
              >
                {SELECTOR_GROUPS.map(g => (
                  <optgroup key={g.group} label={g.group}>
                    {g.values.map(v => (
                      <option key={v} value={v}>
                        {fiveQILabel(v)}
                      </option>
                    ))}
                  </optgroup>
                ))}
              </select>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-xs text-gray-400 uppercase tracking-wider mb-1">AMBR UL</label>
                <input
                  value={ambrUl}
                  onChange={e => setAmbrUl(e.target.value)}
                  placeholder="100 Mbps"
                  className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm text-gray-100"
                />
              </div>
              <div>
                <label className="block text-xs text-gray-400 uppercase tracking-wider mb-1">AMBR DL</label>
                <input
                  value={ambrDl}
                  onChange={e => setAmbrDl(e.target.value)}
                  placeholder="100 Mbps"
                  className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm text-gray-100"
                />
              </div>
            </div>
          </div>

          <button
            onClick={() => {
              setResult(null)
              trigger.mutate()
            }}
            disabled={trigger.isPending || !effSupi || !dnn}
            className="flex items-center gap-2 bg-purple-600 hover:bg-purple-500 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-md px-4 py-2 text-sm font-medium"
          >
            {trigger.isPending ? (
              <>
                <Loader2 size={16} className="animate-spin" /> Triggering…
              </>
            ) : (
              <>
                <Radio size={16} /> Trigger NW session setup
              </>
            )}
          </button>

          {/* Existing sessions hint for the selected UE */}
          {effSupi && (
            <p className="text-xs text-gray-600 mt-2">
              {sessions.filter(s => s.supi === effSupi).length} existing session(s) for {effSupi} — the new
              one is additional (new PSI), it does not replace them.
            </p>
          )}

          {/* Step results */}
          {result && (
            <ol className="mt-4 space-y-2">
              {result.steps.map((s, i) => (
                <li key={i} className="flex items-start gap-2 text-sm">
                  {stepIcon(s)}
                  <div>
                    <span className={s.success ? 'text-gray-200' : 'text-red-300'}>
                      {NW_STEP_LABELS[s.step] ?? s.step}
                      <span className="text-gray-600 text-xs ml-2">{s.duration_ms} ms</span>
                    </span>
                    {s.detail && <p className="text-xs text-gray-500 mt-0.5">{s.detail}</p>}
                  </div>
                </li>
              ))}
              {result.success && (
                <li className="mt-3 bg-green-900/30 border border-green-800 rounded-md px-3 py-2 text-sm text-green-200">
                  Additional PDU session up: PSI <b>{result.pdu_session_id}</b> · 5QI{' '}
                  <b>{result['5qi']}</b> ({result.qos_source}) · UE IP{' '}
                  <span className="font-mono text-xs">{result.ue_ip}</span>
                </li>
              )}
              {!result.success && result.error && (
                <li className="mt-3 bg-red-900/30 border border-red-800 rounded-md px-3 py-2 text-sm text-red-200">
                  {result.error}
                </li>
              )}
            </ol>
          )}
        </div>
      )}
    </div>
  )
}

// ---- E2E validation panel -----------------------------------------------------

type StepState = 'pending' | 'running' | 'pass' | 'fail' | 'skipped'

interface ValidationStep {
  label: string
  state: StepState
  detail?: string
}

const VALIDATION_STEPS: string[] = [
  'SMF management API reachable (GET /nsmf-management/v1/sessions)',
  'At least one ACTIVE PDU session exists',
  'UDM subscription QoS readable (GET /nudm-sdm/v2/{supi}/sm-data)',
  'NW-initiated 5QI modification applied (TS 23.502 §4.3.3.2)',
  'Session reflects new 5QI with source MANUAL_OVERRIDE',
  'Original 5QI restored',
]

function ValidationPanel({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false)
  const [steps, setSteps] = useState<ValidationStep[]>(
    VALIDATION_STEPS.map(label => ({ label, state: 'pending' })),
  )
  const [running, setRunning] = useState(false)

  const set = (i: number, state: StepState, detail?: string) =>
    setSteps(prev => prev.map((s, j) => (j === i ? { ...s, state, detail } : s)))

  const run = async () => {
    setRunning(true)
    setSteps(VALIDATION_STEPS.map(label => ({ label, state: 'pending' })))
    let failed = false
    const failFrom = (i: number, detail: string) => {
      set(i, 'fail', detail)
      for (let j = i + 1; j < VALIDATION_STEPS.length; j++) set(j, 'skipped')
      failed = true
    }

    // Step 1+2: list sessions
    set(0, 'running')
    let target: QoSSession | undefined
    try {
      const { sessions } = await getQoSSessions()
      set(0, 'pass', `${sessions.length} session(s)`)
      set(1, 'running')
      target = sessions.find(s => s.sessionState === 'ACTIVE') ?? sessions[0]
      if (!target) {
        failFrom(1, 'No PDU sessions. Use UERANSIM to register a UE and establish a session.')
      } else {
        set(1, 'pass', `${target.supi} PSI ${target.pduSessionId}, 5QI ${target.current5qi}`)
      }
    } catch (e) {
      failFrom(0, (e as Error).message)
    }

    // Step 3: subscription QoS
    if (!failed && target) {
      set(2, 'running')
      try {
        const entries = await getSubscriptionQoS(target.supi)
        const sub = subscribedDefaultFor(entries, target)
        set(2, 'pass', sub ? `subscribed default 5QI ${sub.fiveQi}` : 'sm-data present (no matching DNN entry)')
      } catch (e) {
        set(2, 'fail', (e as Error).message) // non-fatal: continue
      }
    }

    // Step 4: modify
    const original = target?.current5qi ?? 9
    const testQi = original === 7 ? 8 : 7
    if (!failed && target) {
      set(3, 'running')
      try {
        const res = await modifySessionQoS(target.pduSessionId, {
          '5qi': testQi,
          reason: 'portal e2e validation',
          supi: target.supi,
        })
        set(3, 'pass', `${res.previous5qi} → ${res.new5qi} at ${res.modifiedAt}`)
      } catch (e) {
        failFrom(3, (e as Error).message)
      }
    }

    // Step 5: verify
    if (!failed && target) {
      set(4, 'running')
      try {
        const { sessions } = await getQoSSessions()
        const cur = sessions.find(
          s => s.supi === target!.supi && s.pduSessionId === target!.pduSessionId,
        )
        if (cur && cur.current5qi === testQi && cur.qosSource === 'MANUAL_OVERRIDE') {
          set(4, 'pass', `5QI ${cur.current5qi}, source ${cur.qosSource}`)
        } else {
          failFrom(4, `expected 5QI ${testQi}/MANUAL_OVERRIDE, got ${cur?.current5qi}/${cur?.qosSource}`)
        }
      } catch (e) {
        failFrom(4, (e as Error).message)
      }
    }

    // Step 6: revert
    if (!failed && target) {
      set(5, 'running')
      try {
        const res = await modifySessionQoS(target.pduSessionId, {
          '5qi': original,
          reason: 'portal e2e validation (revert)',
          supi: target.supi,
        })
        set(5, 'pass', `restored 5QI ${res.new5qi}`)
      } catch (e) {
        set(5, 'fail', (e as Error).message)
      }
    }

    setRunning(false)
    onDone()
  }

  const icon = (s: StepState) => {
    switch (s) {
      case 'pass':
        return <CheckCircle2 size={16} className="text-green-400" />
      case 'fail':
        return <XCircle size={16} className="text-red-400" />
      case 'running':
        return <Loader2 size={16} className="text-blue-400 animate-spin" />
      case 'skipped':
        return <Circle size={16} className="text-gray-700" />
      default:
        return <Circle size={16} className="text-gray-600" />
    }
  }

  return (
    <div className="mt-8 bg-gray-900 rounded-lg border border-gray-800">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 text-sm font-semibold text-gray-300"
      >
        <span className="flex items-center gap-2">
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          End-to-end validation
        </span>
        <span className="text-xs text-gray-500 font-normal">
          establishment → subscription → NW-initiated modification → revert
        </span>
      </button>
      {open && (
        <div className="px-4 pb-4">
          <button
            onClick={run}
            disabled={running}
            className="mb-4 flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 text-white rounded-md px-4 py-2 text-sm"
          >
            <PlayCircle size={16} /> {running ? 'Running…' : 'Run validation'}
          </button>
          <ol className="space-y-2">
            {steps.map((s, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                {icon(s.state)}
                <div>
                  <span
                    className={
                      s.state === 'fail'
                        ? 'text-red-300'
                        : s.state === 'pass'
                          ? 'text-gray-200'
                          : 'text-gray-400'
                    }
                  >
                    {s.label}
                  </span>
                  {s.detail && <p className="text-xs text-gray-500 mt-0.5">{s.detail}</p>}
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  )
}

// ---- Page ---------------------------------------------------------------------

export default function QoS() {
  const qc = useQueryClient()
  const [modifyTarget, setModifyTarget] = useState<QoSSession | null>(null)
  const [inspectSupi, setInspectSupi] = useState<string | null>(null)
  const [toast, setToast] = useState<Toast | null>(null)

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['qos-sessions'],
    queryFn: getQoSSessions,
    refetchInterval: 10_000,
  })
  const sessions = useMemo(() => data?.sessions ?? [], [data])

  const showToast = (t: Toast) => {
    setToast(t)
    setTimeout(() => setToast(null), 6000)
  }

  return (
    <div className="p-6">
      <PageHeader
        title="QoS / PDU Sessions"
        subtitle="5QI assignment and network-initiated QoS modification — TS 23.501 §5.7 · TS 23.502 §4.3.3.2"
        action={
          <button
            onClick={() => refetch()}
            className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-md px-3 py-2 text-sm border border-gray-700"
          >
            <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} /> Refresh
          </button>
        }
      />

      {/* View A — session table */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
              <th className="px-4 py-3 text-left">SUPI</th>
              <th className="px-4 py-3 text-left">PSI</th>
              <th className="px-4 py-3 text-left">DNN</th>
              <th className="px-4 py-3 text-left">S-NSSAI</th>
              <th className="px-4 py-3 text-left">5QI</th>
              <th className="px-4 py-3 text-left">Source</th>
              <th className="px-4 py-3 text-left">AMBR UL/DL</th>
              <th className="px-4 py-3 text-left">State</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={9} className="px-4 py-6 text-center text-gray-500">
                  Loading…
                </td>
              </tr>
            ) : sessions.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-4 py-8 text-center text-gray-500">
                  No active PDU sessions. Use UERANSIM to register a UE and establish a session.
                </td>
              </tr>
            ) : (
              sessions.map(s => (
                <tr
                  key={`${s.supi}-${s.pduSessionId}`}
                  className="border-b border-gray-800/50 hover:bg-gray-800/30"
                >
                  <td className="px-4 py-3 font-mono text-xs text-blue-300" title={s.supi}>
                    {truncSUPI(s.supi)}
                  </td>
                  <td className="px-4 py-3 text-gray-300">{s.pduSessionId}</td>
                  <td className="px-4 py-3 text-gray-300">{s.dnn}</td>
                  <td className="px-4 py-3 text-xs">
                    <Badge label={`${s.sNssai.sst}:${s.sNssai.sd || '—'}`} variant="blue" />
                  </td>
                  <td className="px-4 py-3" title={fiveQILabel(s.current5qi)}>
                    <Badge
                      label={`5QI ${s.current5qi} · ${fiveQICategory(s.current5qi)}`}
                      variant={fiveQIBadgeVariant(s.current5qi)}
                    />
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-400">{s.qosSource}</td>
                  <td className="px-4 py-3 text-xs text-gray-300">
                    {s.sessionAmbrUlMbps} / {s.sessionAmbrDlMbps} Mbps
                  </td>
                  <td className="px-4 py-3">
                    <Badge label={s.sessionState} variant={s.sessionState === 'ACTIVE' ? 'green' : 'yellow'} />
                  </td>
                  <td className="px-4 py-3 text-right whitespace-nowrap">
                    <button
                      onClick={() => setModifyTarget(s)}
                      className="text-xs bg-blue-600 hover:bg-blue-500 text-white rounded px-2.5 py-1.5 mr-2"
                    >
                      Modify QoS
                    </button>
                    <button
                      onClick={() => setInspectSupi(s.supi)}
                      className="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 rounded px-2.5 py-1.5"
                    >
                      Subscription
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-gray-600 mt-2">
        Auto-refresh every 10 s · 5QI categories per TS 23.501 Table 5.7.4-1: GBR (1–4) green ·
        delay-critical GBR (82–85) amber · non-GBR (5–9, 65–70) blue · operator-defined grey
      </p>

      {/* NW-triggered additional PDU session */}
      <NWSessionPanel sessions={sessions} onResult={showToast} />

      {/* E2E validation */}
      <ValidationPanel onDone={() => qc.invalidateQueries({ queryKey: ['qos-sessions'] })} />

      {/* Drawers */}
      {modifyTarget && (
        <ModifyDrawer session={modifyTarget} onClose={() => setModifyTarget(null)} onResult={showToast} />
      )}
      {inspectSupi !== null && (
        <SubscriptionInspector
          sessions={sessions}
          initialSupi={inspectSupi}
          onClose={() => setInspectSupi(null)}
        />
      )}

      {/* Toast */}
      {toast && (
        <div
          className={`fixed bottom-6 right-6 z-[60] rounded-lg px-4 py-3 text-sm shadow-lg border ${
            toast.kind === 'success'
              ? 'bg-green-900/90 border-green-700 text-green-100'
              : 'bg-red-900/90 border-red-700 text-red-100'
          }`}
        >
          {toast.text}
        </div>
      )}
    </div>
  )
}
