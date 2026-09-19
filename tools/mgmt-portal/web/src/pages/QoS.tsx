import { useMemo, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  RefreshCw, SlidersHorizontal, Search, PlayCircle,
  CheckCircle2, XCircle, Circle, Radio, RotateCcw, Clock,
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
  type PDUSessionType,
} from '../lib/api'
import {
  Badge, Button, Card, Dialog, Disclosure, EmptyState, ErrorState, Field, Input, Loading,
  PageHeader, SegmentedControl, Select, Spinner, Table, TableBody, TableCell, TableEmptyRow,
  TableHead, TableHeaderCell, TableRow, Textarea, useToast,
} from '../components/ui'
import type { BadgeVariant } from '../components/ui'

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

/**
 * 5QI category → semantic badge variant. The badge label always spells the
 * category out (`5QI 9 · Non-GBR`), so the encoding survives greyscale; the
 * variant only reinforces it.
 */
function fiveQIBadgeVariant(q: number): BadgeVariant {
  switch (fiveQICategory(q)) {
    case 'GBR':
      return 'success'
    case 'Delay-critical GBR':
      return 'warning'
    case 'Non-GBR':
      return 'info'
    default:
      return 'neutral'
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

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
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

// ---- Shared bits ------------------------------------------------------------

/** Label/value row used by the drawers' read-only summaries. */
function KV({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3">
      <span className="text-xs text-muted-fg">{label}</span>
      <span className="text-right text-xs text-fg">{children}</span>
    </div>
  )
}

/** Select options with 5QI groups (optgroups are not expressible via `options`). */
function FiveQIGroupOptions() {
  return (
    <>
      {SELECTOR_GROUPS.map(g => (
        <optgroup key={g.group} label={g.group}>
          {g.values.map(v => (
            <option key={v} value={v}>
              {fiveQILabel(v)}
            </option>
          ))}
        </optgroup>
      ))}
    </>
  )
}

// ---- Modify QoS dialog -------------------------------------------------------

function ModifyDialog({
  session,
  onClose,
}: {
  session: QoSSession
  onClose: () => void
}) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [new5qi, setNew5qi] = useState<number>(session.current5qi === 9 ? 7 : 9)
  const [reason, setReason] = useState('')
  const [confirming, setConfirming] = useState(false)

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
      toast({
        variant: 'success',
        title: 'QoS modification applied',
        description: `5QI changed ${res.previous5qi} → ${res.new5qi} on session ${res.pduSessionId} (${res.supi})`,
      })
      qc.invalidateQueries({ queryKey: ['qos-sessions'] })
      onClose()
    },
    onError: (err: Error) => {
      toast({
        variant: 'error',
        title: 'QoS modification failed',
        description: err.message,
        duration: 0,
      })
      setConfirming(false)
    },
  })

  const canApply = reason.trim().length > 0 && new5qi !== session.current5qi

  return (
    <Dialog
      open
      onClose={onClose}
      size="md"
      title="Modify QoS"
      description={`PSI ${session.pduSessionId} · ${session.dnn} · ${session.supi}`}
    >
      <div className="space-y-4">
        {/* Current session (read-only) */}
        <Card>
          <div className="mb-3 flex items-center gap-2">
            <Badge label={`Current 5QI ${session.current5qi}`} variant={fiveQIBadgeVariant(session.current5qi)} />
            <span className="text-xs text-muted-fg">{fiveQICategory(session.current5qi)}</span>
          </div>
          <div className="space-y-1.5">
            <KV label="SUPI"><span className="font-mono">{session.supi}</span></KV>
            <KV label="PDU Session / DNN">{session.pduSessionId} · {session.dnn}</KV>
            <KV label="S-NSSAI">{session.sNssai.sst}:{session.sNssai.sd || '—'}</KV>
            <KV label="Subscribed default 5QI">
              {subDefault ? (
                <Badge label={fiveQILabel(subDefault.fiveQi)} variant={fiveQIBadgeVariant(subDefault.fiveQi)} />
              ) : (
                <span className="text-muted-fg">not provisioned</span>
              )}
            </KV>
          </div>
        </Card>

        <Field label="New 5QI" hint="Grouped by TS 23.501 Table 5.7.4-1 category">
          {({ id }) => (
            <Select id={id} value={new5qi} onChange={e => setNew5qi(Number(e.target.value))}>
              <FiveQIGroupOptions />
            </Select>
          )}
        </Field>

        <Field label="Reason" required hint="Recorded in the portal log with the modification.">
          {({ id, invalid }) => (
            <Textarea
              id={id}
              invalid={invalid}
              rows={2}
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder="e.g. upgrade subscriber to interactive video"
            />
          )}
        </Field>

        {!confirming ? (
          <Button
            className="w-full"
            icon={<SlidersHorizontal size={15} />}
            disabled={!canApply}
            onClick={() => setConfirming(true)}
          >
            Apply
          </Button>
        ) : (
          <Card>
            <div className="mb-3 flex items-start gap-2">
              <Badge label="Confirm change" variant="warning" />
              <p className="text-xs text-muted-fg">
                You are about to change 5QI from <span className="font-semibold text-fg">{session.current5qi}</span> to{' '}
                <span className="font-semibold text-fg">{new5qi}</span> on session{' '}
                <span className="font-semibold text-fg">{session.pduSessionId}</span> for{' '}
                <span className="font-mono text-fg">{session.supi}</span>. This will trigger a
                network-initiated PDU Session Modification (TS 23.502 §4.3.3.2). Confirm?
              </p>
            </div>
            <div className="flex gap-2">
              <Button className="flex-1" loading={modify.isPending} onClick={() => modify.mutate()}>
                Confirm
              </Button>
              <Button className="flex-1" variant="secondary" disabled={modify.isPending} onClick={() => setConfirming(false)}>
                Cancel
              </Button>
            </div>
          </Card>
        )}
      </div>
    </Dialog>
  )
}

// ---- Subscription QoS inspector ---------------------------------------------

function SubscriptionDialog({
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
  const notFound = Boolean(error)
  const empty = !notFound && !isFetching && (entries?.length ?? 0) === 0

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title="Subscription QoS inspector"
      description="UDM sm-data (subscribed default QoS) compared with the active session"
    >
      <div className="space-y-4">
        <div className="flex flex-wrap items-end gap-2">
          <Field label="SUPI" className="min-w-[14rem] flex-1">
            {({ id }) => (
              <Input
                id={id}
                value={supi}
                onChange={e => setSupi(e.target.value)}
                placeholder="imsi-001010000000001"
                onKeyDown={e => e.key === 'Enter' && setLookup(supi.trim())}
                className="font-mono text-xs"
              />
            )}
          </Field>
          <Button
            icon={<Search size={15} />}
            loading={isFetching}
            disabled={isFetching || !supi.trim()}
            onClick={() => setLookup(supi.trim())}
          >
            Lookup
          </Button>
        </div>

        {notFound && (
          <div className="flex items-center gap-2">
            <Badge label="Not found" variant="danger" icon={<XCircle size={12} />} />
            <span className="text-xs text-muted-fg">No SM subscription found for {lookup}</span>
          </div>
        )}

        {empty && (
          <EmptyState
            icon={<Search size={28} />}
            title="No subscription QoS"
            description={`No SM subscription data was returned for ${lookup}.`}
          />
        )}

        {entries?.map((e, i) => {
          const cfgs = Object.entries(e.dnnConfigurations || {})
          return (
            <Card key={i}>
              <div className="mb-3 flex items-center gap-2">
                <Badge
                  label={`SST:${e.singleNssai.sst}${e.singleNssai.sd ? '/SD:' + e.singleNssai.sd : ''}`}
                  variant="info"
                />
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
                  <div key={dnn} className="space-y-1.5 border-t border-border pt-2 mt-2 first:border-0 first:pt-0 first:mt-0">
                    <KV label="DNN">{dnn}</KV>
                    <div className="flex items-start justify-between gap-3">
                      <span className="text-xs text-muted-fg">Default 5QI</span>
                      <Badge label={fiveQILabel(q['5qi'])} variant={fiveQIBadgeVariant(q['5qi'])} />
                    </div>
                    <KV label="ARP priority">{q.arp.priorityLevel}</KV>
                    <KV label="Preemption cap / vuln">{q.arp.preemptCap} / {q.arp.preemptVuln}</KV>
                    <KV label="Session AMBR UL / DL">{cfg.sessionAmbr.uplink} / {cfg.sessionAmbr.downlink}</KV>

                    {sessionMatches && (
                      <div className="mt-2 flex items-start gap-2">
                        <Badge
                          label={diff ? 'Differs from subscription' : 'Matches subscription'}
                          variant={diff ? 'warning' : 'success'}
                          icon={diff ? <Clock size={12} /> : <CheckCircle2 size={12} />}
                        />
                        <p className="text-xs text-muted-fg">
                          {diff ? (
                            <>
                              Active session 5QI <span className="font-semibold text-fg">{session.current5qi}</span> differs
                              from subscribed default <span className="font-semibold text-fg">{q['5qi']}</span>{' '}
                              (source: {session.qosSource})
                            </>
                          ) : (
                            <>Active session 5QI matches the subscribed default ({q['5qi']})</>
                          )}
                        </p>
                      </div>
                    )}
                  </div>
                )
              })}
            </Card>
          )
        })}
      </div>
    </Dialog>
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

const PDU_TYPES: PDUSessionType[] = ['IPv4', 'IPv6', 'IPv4v6']

function NWStepIcon({ step }: { step: NWSessionStep }) {
  if (step.success) return <CheckCircle2 size={16} className="text-success-fg" />
  return <XCircle size={16} className="text-danger-fg" />
}

function NWSessionPanel({ sessions }: { sessions: QoSSession[] }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [supi, setSupi] = useState('')
  const [app, setApp] = useState('cloud-gaming')
  const [dnn, setDnn] = useState('internet')
  const [sliceKey, setSliceKey] = useState('') // "sst:sd"
  const [fiveQi, setFiveQi] = useState(3)
  const [ambrUl, setAmbrUl] = useState('')
  const [ambrDl, setAmbrDl] = useState('')
  const [pduType, setPduType] = useState<PDUSessionType>('IPv4')
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
        pdu_session_type: pduType,
      }),
    onSuccess: (res: NWSessionResult) => {
      setResult(res)
      qc.invalidateQueries({ queryKey: ['qos-sessions'] })
      if (res.success) {
        toast({
          variant: 'success',
          title: 'Additional PDU session established',
          description: `PSI ${res.pdu_session_id}, 5QI ${res['5qi']}, UE IP ${res.ue_ip}`,
        })
      } else {
        toast({
          variant: 'error',
          title: 'NW-triggered session failed',
          description: res.error || 'The orchestration stopped before the session became ACTIVE.',
          duration: 0,
        })
      }
    },
    onError: (err: Error) =>
      toast({ variant: 'error', title: 'NW-triggered session failed', description: err.message, duration: 0 }),
  })

  const sliceOptions = (slices ?? [{ sst: 1, sd: '000001' }]).map(s => ({
    value: `${s.sst}:${s.sd || '—'}`,
    label: `SST ${s.sst} / SD ${s.sd || '—'}`,
  }))

  return (
    <Disclosure
      title="NW-Triggered PDU Session"
      icon={<Radio size={16} className="text-fg" />}
      hint="app detected → URSP delivery → additional UE-requested session — TS 23.503 §6.6.2"
    >
      <p className="mb-4 text-xs text-muted-fg">
        Simulates the network detecting that the subscriber opened a new app/service. The core
        stores a DNN-scoped QoS override in the PCF, delivers an updated URSP rule (DL NAS
        payload container 0x05), and the UE establishes an <span className="font-semibold text-fg">additional</span> PDU
        session (new PSI) carrying the requested 5QI. UE-side URSP evaluation is simulated via
        nr-cli (UERANSIM v3.2.8 has no URSP support).
      </p>

      <div className="mb-3 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="UE (registered)">
          {({ id }) => (
            <Select
              id={id}
              value={effSupi}
              onChange={e => setSupi(e.target.value)}
              disabled={(ues ?? []).length === 0}
              options={
                (ues ?? []).length === 0
                  ? [{ value: '', label: 'no registered UEs' }]
                  : (ues ?? []).map(u => ({ value: u.supi, label: u.supi }))
              }
              className="font-mono text-xs"
            />
          )}
        </Field>

        <div>
          <Field label="Detected app">
            {({ id }) => (
              <Input
                id={id}
                value={app}
                onChange={e => setApp(e.target.value)}
                className="font-mono text-xs"
              />
            )}
          </Field>
          <div className="mt-1.5 flex flex-wrap gap-1">
            {APP_PRESETS.map(p => (
              <Button
                key={p.app}
                size="sm"
                variant={app === p.app ? 'primary' : 'secondary'}
                aria-pressed={app === p.app}
                title={`${p.hint} → 5QI ${p['5qi']}`}
                onClick={() => {
                  setApp(p.app)
                  setFiveQi(p['5qi'])
                }}
              >
                {p.app}
              </Button>
            ))}
          </div>
        </div>

        <Field label="DNN">
          {({ id }) => (
            <Input id={id} value={dnn} onChange={e => setDnn(e.target.value)} className="font-mono text-xs" />
          )}
        </Field>

        <SegmentedControl
          label="PDU session type"
          value={pduType}
          onChange={setPduType}
          options={PDU_TYPES.map(t => ({ value: t, label: t }))}
          hint="IPv6/IPv4v6 need patch 0060 + a DNN ue_ipv6_prefix"
        />

        <Field label="S-NSSAI">
          {({ id }) => (
            <Select
              id={id}
              value={sliceKey || `${sst}:${sd || '—'}`}
              onChange={e => setSliceKey(e.target.value)}
              options={sliceOptions}
            />
          )}
        </Field>

        <Field label="5QI for the new session">
          {({ id }) => (
            <Select id={id} value={fiveQi} onChange={e => setFiveQi(Number(e.target.value))}>
              <FiveQIGroupOptions />
            </Select>
          )}
        </Field>

        <div className="grid grid-cols-2 gap-2">
          <Field label="AMBR UL">
            {({ id }) => (
              <Input id={id} value={ambrUl} onChange={e => setAmbrUl(e.target.value)} placeholder="100 Mbps" />
            )}
          </Field>
          <Field label="AMBR DL">
            {({ id }) => (
              <Input id={id} value={ambrDl} onChange={e => setAmbrDl(e.target.value)} placeholder="100 Mbps" />
            )}
          </Field>
        </div>
      </div>

      <Button
        icon={<Radio size={15} />}
        loading={trigger.isPending}
        disabled={trigger.isPending || !effSupi || !dnn}
        onClick={() => {
          setResult(null)
          trigger.mutate()
        }}
      >
        Trigger NW session setup
      </Button>

      {/* Existing sessions hint for the selected UE */}
      {effSupi && (
        <p className="mt-2 text-xs text-muted-fg">
          {sessions.filter(s => s.supi === effSupi).length} existing session(s) for {effSupi} — the new
          one is additional (new PSI), it does not replace them.
        </p>
      )}

      {/* Step results */}
      {result && (
        <ol className="mt-4 space-y-2">
          {result.steps.map((s, i) => (
            <li key={i} className="flex items-start gap-2 text-sm">
              <span aria-hidden="true" className="mt-0.5 flex-shrink-0">
                <NWStepIcon step={s} />
              </span>
              <div className="min-w-0">
                <span className={s.success ? 'text-fg' : 'text-danger-fg'}>
                  {NW_STEP_LABELS[s.step] ?? s.step}
                  <span className="ml-2 text-xs text-muted-fg">{s.duration_ms} ms</span>
                  <span className="sr-only">{s.success ? ' — succeeded' : ' — failed'}</span>
                </span>
                {s.detail && <p className="mt-0.5 text-xs text-muted-fg">{s.detail}</p>}
              </div>
            </li>
          ))}

          {result.success ? (
            <li className="mt-3 flex flex-wrap items-center gap-2">
              <Badge label="Session up" variant="success" icon={<CheckCircle2 size={12} />} />
              <span className="text-xs text-muted-fg">
                Additional PDU session: PSI <span className="font-semibold text-fg">{result.pdu_session_id}</span> · 5QI{' '}
                <span className="font-semibold text-fg">{result['5qi']}</span> ({result.qos_source}) · UE IP{' '}
                <span className="font-mono text-fg">{result.ue_ip}</span>
              </span>
            </li>
          ) : (
            <li className="mt-3 flex flex-wrap items-center gap-2">
              <Badge label="Orchestration failed" variant="danger" icon={<XCircle size={12} />} />
              {result.error && <span className="text-xs text-danger-fg">{result.error}</span>}
              <Button
                size="sm"
                variant="secondary"
                icon={<RotateCcw size={12} />}
                loading={trigger.isPending}
                disabled={trigger.isPending}
                onClick={() => trigger.mutate()}
              >
                Retry
              </Button>
            </li>
          )}
        </ol>
      )}
    </Disclosure>
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

const STEP_STATE_WORD: Record<StepState, string> = {
  pending: 'pending',
  running: 'running',
  pass: 'passed',
  fail: 'failed',
  skipped: 'skipped',
}

function ValidationPanel({ onDone }: { onDone: () => void }) {
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

  const passed = steps.filter(s => s.state === 'pass').length
  const failed = steps.some(s => s.state === 'fail')

  const icon = (s: StepState) => {
    switch (s) {
      case 'pass':
        return <CheckCircle2 size={16} className="text-success-fg" />
      case 'fail':
        return <XCircle size={16} className="text-danger-fg" />
      case 'running':
        return <Spinner size={16} label="Step running" />
      case 'skipped':
        return <Circle size={16} className="text-muted-fg" />
      default:
        return <Circle size={16} className="text-muted-fg" />
    }
  }

  return (
    <Disclosure
      title="End-to-end validation"
      hint="establishment → subscription → NW-initiated modification → revert"
    >
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Button
          icon={<PlayCircle size={15} />}
          loading={running}
          disabled={running}
          onClick={run}
        >
          Run validation
        </Button>
        <Badge
          label={`${passed}/${VALIDATION_STEPS.length} passed`}
          variant={failed ? 'danger' : passed === VALIDATION_STEPS.length ? 'success' : 'neutral'}
          icon={failed ? <XCircle size={12} /> : passed === VALIDATION_STEPS.length ? <CheckCircle2 size={12} /> : <Circle size={12} />}
        />
      </div>
      <ol className="space-y-2">
        {steps.map((s, i) => (
          <li key={i} className="flex items-start gap-2 text-sm">
            <span aria-hidden="true" className="mt-0.5 flex-shrink-0">{icon(s.state)}</span>
            <div className="min-w-0">
              <span className={s.state === 'fail' ? 'text-danger-fg' : s.state === 'pass' ? 'text-fg' : 'text-muted-fg'}>
                {s.label}
              </span>
              <span className="sr-only"> — {STEP_STATE_WORD[s.state]}</span>
              {s.detail && <p className="mt-0.5 text-xs text-muted-fg">{s.detail}</p>}
            </div>
          </li>
        ))}
      </ol>
    </Disclosure>
  )
}

// ---- Page ---------------------------------------------------------------------

export default function QoS() {
  const qc = useQueryClient()
  const [modifyTarget, setModifyTarget] = useState<QoSSession | null>(null)
  const [inspectSupi, setInspectSupi] = useState<string | null>(null)

  const {
    data,
    isLoading,
    isFetching,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['qos-sessions'],
    queryFn: getQoSSessions,
    refetchInterval: 10_000,
  })
  const sessions = useMemo(() => data?.sessions ?? [], [data])

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Runtime"
        title="QoS / PDU Sessions"
        subtitle="5QI assignment and network-initiated QoS modification — TS 23.501 §5.7 · TS 23.502 §4.3.3.2"
        action={
          <Button
            size="sm"
            variant="secondary"
            icon={<RefreshCw size={14} />}
            loading={isFetching}
            onClick={() => refetch()}
          >
            Refresh
          </Button>
        }
      />

      {/* Session table */}
      {isError ? (
        <ErrorState
          title="Failed to load PDU sessions"
          description={errMessage(error)}
          action={
            <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : (
        <Table caption="Active PDU sessions with QoS state">
          <TableHead>
            <TableRow>
              <TableHeaderCell>SUPI</TableHeaderCell>
              <TableHeaderCell>PSI</TableHeaderCell>
              <TableHeaderCell>DNN</TableHeaderCell>
              <TableHeaderCell>S-NSSAI</TableHeaderCell>
              <TableHeaderCell>5QI</TableHeaderCell>
              <TableHeaderCell>Source</TableHeaderCell>
              <TableHeaderCell>AMBR UL/DL</TableHeaderCell>
              <TableHeaderCell>State</TableHeaderCell>
              <TableHeaderCell className="text-right">Actions</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {isLoading ? (
              <TableEmptyRow colSpan={9}>
                <Loading rows={3} label="Loading PDU sessions…" />
              </TableEmptyRow>
            ) : sessions.length === 0 ? (
              <TableEmptyRow colSpan={9}>
                No active PDU sessions. Use UERANSIM to register a UE and establish a session.
              </TableEmptyRow>
            ) : (
              sessions.map(s => (
                <TableRow key={`${s.supi}-${s.pduSessionId}`}>
                  <TableCell mono title={s.supi}>
                    <span aria-hidden="true">{truncSUPI(s.supi)}</span>
                    <span className="sr-only">{s.supi}</span>
                  </TableCell>
                  <TableCell>{s.pduSessionId}</TableCell>
                  <TableCell>{s.dnn}</TableCell>
                  <TableCell>
                    <Badge label={`${s.sNssai.sst}:${s.sNssai.sd || '—'}`} variant="info" />
                  </TableCell>
                  <TableCell>
                    <span title={fiveQILabel(s.current5qi)}>
                      <Badge
                        label={`5QI ${s.current5qi} · ${fiveQICategory(s.current5qi)}`}
                        variant={fiveQIBadgeVariant(s.current5qi)}
                      />
                    </span>
                  </TableCell>
                  <TableCell className="text-xs text-muted-fg">{s.qosSource}</TableCell>
                  <TableCell className="text-xs tabular-nums text-fg">
                    {s.sessionAmbrUlMbps} / {s.sessionAmbrDlMbps} Mbps
                  </TableCell>
                  <TableCell>
                    <Badge
                      label={s.sessionState}
                      variant={s.sessionState === 'ACTIVE' ? 'success' : 'warning'}
                      icon={s.sessionState === 'ACTIVE' ? <CheckCircle2 size={12} /> : <Clock size={12} />}
                    />
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    <div className="flex items-center justify-end gap-2">
                      <Button size="sm" onClick={() => setModifyTarget(s)}>
                        Modify QoS
                      </Button>
                      <Button size="sm" variant="secondary" onClick={() => setInspectSupi(s.supi)}>
                        Subscription
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      )}

      <p className="text-xs text-muted-fg">
        Auto-refresh every 10 s · 5QI badges carry the label and the TS 23.501 Table 5.7.4-1
        category: GBR (1–4), delay-critical GBR (82–85), non-GBR (5–9, 65–70) and operator-defined.
      </p>

      {/* NW-triggered additional PDU session */}
      <NWSessionPanel sessions={sessions} />

      {/* E2E validation */}
      <ValidationPanel onDone={() => qc.invalidateQueries({ queryKey: ['qos-sessions'] })} />

      {/* Dialogs */}
      {modifyTarget && (
        <ModifyDialog session={modifyTarget} onClose={() => setModifyTarget(null)} />
      )}
      {inspectSupi !== null && (
        <SubscriptionDialog
          sessions={sessions}
          initialSupi={inspectSupi}
          onClose={() => setInspectSupi(null)}
        />
      )}
    </div>
  )
}
