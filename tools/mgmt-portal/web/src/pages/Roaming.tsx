import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle, ArrowLeftRight, CheckCircle2, CircleDashed, FileText, Handshake, Play, Power, Radio,
  RefreshCw, RotateCw, Unplug, XCircle,
} from 'lucide-react'
import { getRoamingPartners, getRoamingStatus, putRoamingPartners, roamingLifecycle, roamingN32Action } from '../lib/api'
import type { RoamingPartner, N32LinkState, N32Partner, RoamingNF, RoamingSEPP, RoamingStatus } from '../lib/api'
import StatCard from '../components/StatCard'
import {
  Badge, Button, Card, ConfirmDialog, DegradedState, EmptyState, ErrorState, Field, Input, Loading, Page, PageHeader, Section,
  Table, TableBody, TableCell, TableEmptyRow, TableHead, TableHeaderCell, TableRow, useToast,
} from '../components/ui'
import type { BadgeVariant } from '../components/ui'

/** Poll period of the roaming view (N32 state + Prometheus rates). */
const ROAMING_REFETCH_MS = 5_000

const LINK: Record<N32LinkState, { variant: BadgeVariant; icon: ReactNode; label: string; stat: 'success' | 'warning' | 'danger' | 'default' }> = {
  UP: { variant: 'success', icon: <CheckCircle2 size={12} />, label: 'N32 up', stat: 'success' },
  DEGRADED: { variant: 'warning', icon: <AlertTriangle size={12} />, label: 'N32 degraded', stat: 'warning' },
  DOWN: { variant: 'danger', icon: <Unplug size={12} />, label: 'N32 down', stat: 'danger' },
  NOT_DEPLOYED: { variant: 'neutral', icon: <CircleDashed size={12} />, label: 'Not deployed', stat: 'default' },
}

function fmtRate(v: number | null | undefined, unit = '/s'): string {
  if (v === null || v === undefined) return '—'
  return `${v < 10 ? v.toFixed(2) : v.toFixed(0)}${unit}`
}

function since(iso?: string): string {
  if (!iso) return '—'
  const secs = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (secs < 60) return `${secs}s ago`
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m ago`
}

/** "001/002" -> "001-002" (the admin route accepts either MNC width). */
const plmnParam = (plmn: string) => plmn.replace('/', '-')

function NFHealthBadge({ nf }: { nf: RoamingNF }) {
  if (!nf.deployed) return <Badge label="Not deployed" variant="neutral" icon={<CircleDashed size={12} />} />
  if (nf.state !== 'running') return <Badge label={nf.state ?? 'stopped'} variant="danger" icon={<XCircle size={12} />} />
  const ok = nf.healthz_ok && nf.metrics_ok && nf.health !== 'unhealthy'
  if (nf.health === 'starting') return <Badge label="Starting" variant="info" icon={<RefreshCw size={12} />} />
  return ok
    ? <Badge label="Healthy" variant="success" icon={<CheckCircle2 size={12} />} />
    : <Badge label={nf.health === 'unhealthy' ? 'Unhealthy' : 'Degraded'} variant="warning" icon={<AlertTriangle size={12} />} />
}

function PLMNBox({ title, plmn, nfs }: { title: string; plmn?: string; nfs: RoamingNF[] }) {
  return (
    <Card className="flex-1">
      <p className="mb-1 text-xs uppercase tracking-wider text-muted-fg">{title}</p>
      <p className="mb-3 text-lg font-semibold tabular-nums text-fg">PLMN {plmn ?? '—'}</p>
      <ul className="space-y-2">
        {nfs.map(nf => (
          <li key={nf.name} className="flex items-center justify-between gap-2 text-sm">
            <span className="font-medium text-fg">
              {nf.role} <span className="text-xs text-muted-fg">({nf.name}{nf.uptime ? ` · up ${nf.uptime}` : ''})</span>
            </span>
            <NFHealthBadge nf={nf} />
          </li>
        ))}
      </ul>
    </Card>
  )
}

interface PendingAction { sepp: string; plmn: string; action: 'handshake' | 'teardown' }

function N32Table({ sepp, onAction, busy }: { sepp: RoamingSEPP; onAction: (a: PendingAction) => void; busy: boolean }) {
  const v = sepp.n32
  const caption = `${sepp.role} (${sepp.name})${v ? ` — PLMN ${v.local_plmn}, ${v.local_fqdn}, ${v.release_profile}, topology hiding ${v.topology_hiding ? 'on' : 'off'}` : ''}`
  if (!v) {
    return (
      <DegradedState
        title={`${sepp.role} N32 view unavailable`}
        description={sepp.error ?? 'No answer from the SEPP admin route (metrics port).'}
      />
    )
  }
  return (
    <Table caption={caption}>
      <TableHead>
        <TableRow>
          <TableHeaderCell>Partner PLMN</TableHeaderCell>
          <TableHeaderCell>N32 context</TableHeaderCell>
          <TableHeaderCell>Peer SEPP</TableHeaderCell>
          <TableHeaderCell>Negotiated</TableHeaderCell>
          <TableHeaderCell>Established</TableHeaderCell>
          <TableHeaderCell>Last N32-c attempt</TableHeaderCell>
          <TableHeaderCell>Actions</TableHeaderCell>
        </TableRow>
      </TableHead>
      <TableBody>
        {v.partners.length === 0 ? (
          <TableEmptyRow colSpan={7}>No roaming partner configured (n32.roaming_partners).</TableEmptyRow>
        ) : (
          v.partners.map((p: N32Partner) => (
            <TableRow key={p.plmn}>
              <TableCell className="font-medium tabular-nums">{p.plmn}</TableCell>
              <TableCell>
                {p.state === 'ESTABLISHED'
                  ? <Badge label={`Established (${p.security ?? 'TLS'})`} variant="success" icon={<CheckCircle2 size={12} />} />
                  : <Badge label="None" variant="danger" icon={<Unplug size={12} />} />}
              </TableCell>
              <TableCell className="text-xs">
                <div>{p.peer_fqdn ?? '—'}</div>
                {p.peer_address && <div className="text-muted-fg">{p.peer_address}</div>}
              </TableCell>
              <TableCell className="text-xs">
                {p.state === 'ESTABLISHED' ? (
                  <>
                    <div>apiRoot header: {p.target_api_root_header ? 'yes' : 'no (telescopic FQDN)'}</div>
                    <div className="text-muted-fg">NFTLST {p.nftlst ? 'yes' : 'no'} · features {p.negotiated_features || '—'}</div>
                  </>
                ) : '—'}
              </TableCell>
              <TableCell className="text-xs tabular-nums">{since(p.established_at)}</TableCell>
              <TableCell className="text-xs">
                {p.last_attempt ? (
                  <>
                    <Badge
                      label={`${p.last_attempt.result} · ${p.last_attempt.role}`}
                      variant={p.last_attempt.result === 'OK' ? 'success' : p.last_attempt.result === 'REJECT' ? 'warning' : 'danger'}
                    />
                    <div className="mt-1 text-muted-fg">
                      {since(p.last_attempt.at)}{p.last_attempt.cause ? ` — ${p.last_attempt.cause}` : ''}
                    </div>
                  </>
                ) : '—'}
              </TableCell>
              <TableCell>
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    icon={<Handshake size={14} />}
                    disabled={!p.initiator || busy}
                    title={p.initiator ? 'Re-run exchange-capability (TS 29.573 §5.2.2)' : 'No n32.peers entry: this SEPP only answers'}
                    onClick={() => onAction({ sepp: sepp.name, plmn: p.plmn, action: 'handshake' })}
                  >
                    Handshake
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    icon={<Power size={14} />}
                    disabled={!p.initiator || !p.nftlst || p.state !== 'ESTABLISHED' || busy}
                    title="N32-f TLS teardown (NONE) — needs feature NFTLST"
                    onClick={() => onAction({ sepp: sepp.name, plmn: p.plmn, action: 'teardown' })}
                  >
                    Teardown
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))
        )}
      </TableBody>
    </Table>
  )
}

const EMPTY_PARTNER: RoamingPartner = { plmn: { mcc: '', mnc: '' }, n32: { ca_file: '' } }

/** Partners editor: edits partners.yaml, then restarts sepp and amf (they read it at startup). */
function PartnersEditor() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const { data, error } = useQuery({ queryKey: ['roaming-partners'], queryFn: getRoamingPartners })
  const [rows, setRows] = useState<RoamingPartner[]>([])
  const [draft, setDraft] = useState<RoamingPartner>(EMPTY_PARTNER)
  const [confirm, setConfirm] = useState(false)

  useEffect(() => { if (data) setRows(data.file) }, [data])

  const save = useMutation({
    mutationFn: () => putRoamingPartners(rows),
    onSuccess: r => {
      const failed = Object.entries(r.restart).filter(([, v]) => v !== 'ok')
      toast({
        title: `Partners saved${failed.length ? ' — restart partial' : ''}`,
        description: Object.entries(r.restart).map(([k, v]) => `${k}: ${v}`).join(' · '),
        variant: failed.length ? 'warning' : 'success',
      })
      qc.invalidateQueries({ queryKey: ['roaming-partners'] })
    },
    onError: (e: Error) => toast({ title: 'Saving partners failed', description: e.message, variant: 'error', duration: 0 }),
    onSettled: () => setConfirm(false),
  })

  const addDraft = () => {
    const d: RoamingPartner = {
      plmn: draft.plmn,
      n32: { ca_file: `/etc/5gc/pki/n32/peers/${draft.plmn.mcc}-${draft.plmn.mnc}/ca.crt`, ...(draft.n32.address ? { address: draft.n32.address } : {}) },
    }
    setRows([...rows, d])
    setDraft(EMPTY_PARTNER)
  }

  return (
    <Section title="Roaming partners" description={`Partners file ${data?.path ?? ''}; saving restarts sepp and amf (read at startup).`}>
      {error && <ErrorState title="Failed to load partners" description={(error as Error).message} />}
      {data && data.effective === null && (
        <DegradedState title="Effective list unavailable" description={data.effective_reason ?? 'SEPP admin API not reachable.'} />
      )}
      <Table caption="Configured roaming partners">
        <TableHead>
          <TableRow>
            <TableHeaderCell>PLMN</TableHeaderCell>
            <TableHeaderCell>N32 CA file</TableHeaderCell>
            <TableHeaderCell>N32 address</TableHeaderCell>
            <TableHeaderCell>Effective</TableHeaderCell>
            <TableHeaderCell><span className="sr-only">Actions</span></TableHeaderCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.length === 0 ? (
            <TableEmptyRow colSpan={5}>No roaming partners configured.</TableEmptyRow>
          ) : (
            rows.map((p, i) => {
              const key = `${p.plmn.mcc}-${p.plmn.mnc}`
              const eff = data?.effective?.partners.find(e => e.plmn === key)
              return (
                <TableRow key={`${key}-${i}`}>
                  <TableCell>{key}</TableCell>
                  <TableCell>{p.n32.ca_file}</TableCell>
                  <TableCell>{p.n32.address ?? '—'}</TableCell>
                  <TableCell>{data?.effective ? (eff ? <Badge variant="success" label={eff.source} /> : <Badge variant="neutral" label="pending restart" />) : '—'}</TableCell>
                  <TableCell>
                    <Button size="sm" variant="secondary" aria-label={`Remove partner ${key}`} onClick={() => setRows(rows.filter((_, j) => j !== i))}>
                      Remove
                    </Button>
                  </TableCell>
                </TableRow>
              )
            })
          )}
        </TableBody>
      </Table>
      <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Field label="MCC">{c => <Input {...c} value={draft.plmn.mcc} onChange={e => setDraft({ ...draft, plmn: { ...draft.plmn, mcc: e.target.value } })} />}</Field>
        <Field label="MNC">{c => <Input {...c} value={draft.plmn.mnc} onChange={e => setDraft({ ...draft, plmn: { ...draft.plmn, mnc: e.target.value } })} />}</Field>
        <Field label="N32 address (host:port, optional)">{c => <Input {...c} value={draft.n32.address ?? ''} onChange={e => setDraft({ ...draft, n32: { ...draft.n32, address: e.target.value } })} />}</Field>
        <div className="flex items-end">
          <Button size="sm" variant="secondary" onClick={addDraft} disabled={!draft.plmn.mcc || !draft.plmn.mnc}>Add partner</Button>
        </div>
      </div>
      <p className="mt-2 text-xs text-muted-fg">
        The partner CA is fixed per PLMN: drop it on the host at pki/n32/peers/&lt;mcc&gt;-&lt;mnc&gt;/ca.crt (in the container /etc/5gc/pki/n32/peers/&lt;mcc&gt;-&lt;mnc&gt;/ca.crt).
      </p>
      <div className="mt-3">
        <Button size="sm" icon={<RotateCw size={14} />} disabled={save.isPending} onClick={() => setConfirm(true)}>Save and restart</Button>
      </div>
      <ConfirmDialog
        open={confirm}
        title="Save partners and restart sepp and amf?"
        description="Registered UEs may be dropped while the AMF restarts."
        confirmLabel="Save and restart"
        onConfirm={() => save.mutate()}
        onCancel={() => setConfirm(false)}
      />
    </Section>
  )
}

function Body({ data }: { data: RoamingStatus }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [pending, setPending] = useState<PendingAction | null>(null)
  const [lifecycle, setLifecycle] = useState<'start' | 'stop' | 'restart' | null>(null)

  const n32Mut = useMutation({
    mutationFn: (a: PendingAction) => roamingN32Action(a.sepp, plmnParam(a.plmn), a.action),
    onSuccess: (_d, a) => {
      toast({ title: `N32 ${a.action} completed`, description: `${a.sepp} ↔ PLMN ${a.plmn}`, variant: 'success' })
      qc.invalidateQueries({ queryKey: ['roaming-status'] })
    },
    onError: (e: Error, a) => toast({ title: `N32 ${a.action} failed`, description: e.message, variant: 'error', duration: 0 }),
    onSettled: () => setPending(null),
  })
  const lifeMut = useMutation({
    mutationFn: roamingLifecycle,
    onSuccess: r => {
      const failed = Object.entries(r.results).filter(([, v]) => v !== 'ok')
      toast({
        title: `Test peer ${r.action}${failed.length ? ' — partial' : ''}`,
        description: Object.entries(r.results).map(([k, v]) => `${k}: ${v}`).join(' · '),
        variant: failed.length ? 'warning' : 'success',
      })
      qc.invalidateQueries({ queryKey: ['roaming-status'] })
    },
    onError: (e: Error) => toast({ title: 'Test peer action failed', description: e.message, variant: 'error', duration: 0 }),
    onSettled: () => setLifecycle(null),
  })

  const link = LINK[data.link.state]
  const local = data.nfs.filter(n => n.side === 'local')
  const partner = data.nfs.filter(n => n.side === 'partner')
  const t = data.traffic

  return (
    <>
      <PartnersEditor />
      {/* Topology: local core <-> N32 <-> test peer */}
      <div className="flex flex-col items-stretch gap-3 lg:flex-row lg:items-center">
        <PLMNBox title="Local core" plmn={data.link.local_plmn} nfs={local} />
        <div className="flex flex-col items-center gap-2 px-2 text-center" role="status" aria-label={`N32 link ${link.label}`}>
          <ArrowLeftRight size={20} aria-hidden="true" className="text-muted-fg" />
          <Badge label={link.label} variant={link.variant} icon={link.icon} />
          <span className="max-w-[14rem] text-xs text-muted-fg">{data.link.reason}</span>
        </div>
        <PLMNBox title="Roaming partner (test peer)" plmn={data.link.partner_plmn} nfs={partner} />
      </div>

      {!data.deployed && (
        <EmptyState
          title="Test peer not deployed"
          description={`hSEPP and hNRF run under the compose profile "roaming". Create them once with: ${data.deploy_hint ?? ''} — then they can be started and stopped from here. make sepp-e2e also brings them up.`}
        />
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        <StatCard title="N32 link" value={link.label} variant={link.stat} sub={data.link.state} />
        <StatCard title="N32-f out" value={fmtRate(t.out_per_sec)} sub="vPLMN → peer, 5 min" />
        <StatCard title="N32-f in" value={fmtRate(t.in_per_sec)} sub="peer → local NF, 5 min" />
        <StatCard
          title="N32-f errors"
          value={fmtRate(t.error_per_sec)}
          variant={t.error_per_sec ? 'danger' : 'default'}
          sub="REJECT + FAILURE, 5 min"
        />
        <StatCard title="N32-f p95" value={fmtRate(t.p95_ms, ' ms')} sub="SEPP handling + round trip" />
        <StatCard title="Handshakes OK" value={t.handshakes_ok_15m === null ? '—' : Math.round(t.handshakes_ok_15m)} sub="N32-c, last 15 min" />
      </div>
      {!t.available && (
        <DegradedState title="N32-f rates unavailable" description={t.error ?? 'Prometheus did not answer.'} />
      )}

      <Section
        title="N32 contexts"
        description="PLMN to N32 connection mapping held by each SEPP (TS 29.573 §5.2.2). Read from the SEPP admin route on the metrics port."
      >
        <div className="space-y-4">
          {data.sepps.map(s => (
            <N32Table key={s.name} sepp={s} onAction={setPending} busy={n32Mut.isPending} />
          ))}
        </div>
      </Section>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Section title="Test-peer NRF registrations" description="NF profiles registered in hNRF (test peer).">
          {!data.partner_nrf.reachable ? (
            <DegradedState title="hNRF not reachable" description={data.partner_nrf.error ?? 'hnrf is not running.'} />
          ) : (
            <Table caption="NFs registered in the test-peer NRF">
              <TableHead>
                <TableRow>
                  <TableHeaderCell>NF type</TableHeaderCell>
                  <TableHeaderCell>Instance</TableHeaderCell>
                  <TableHeaderCell>Status</TableHeaderCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.partner_nrf.instances.length === 0 ? (
                  <TableEmptyRow colSpan={3}>No NF registered in hNRF.</TableEmptyRow>
                ) : (
                  data.partner_nrf.instances.map(i => (
                    <TableRow key={i.nfInstanceId}>
                      <TableCell className="font-medium">{i.nfType}</TableCell>
                      <TableCell className="text-xs tabular-nums">{i.nfInstanceId}</TableCell>
                      <TableCell>
                        <Badge label={i.nfStatus || '—'} variant={i.nfStatus === 'REGISTERED' ? 'success' : 'warning'} />
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          )}
        </Section>

        <Section
          title="Recent roaming warnings"
          description="WARN/ERROR lines of local SEPP, hSEPP and hNRF (last 400 lines each)."
          actions={
            <div className="flex flex-wrap gap-3 text-xs">
              {['sepp', 'hsepp', 'hnrf'].map(c => (
                <Link key={c} to={`/logs?container=${c}`} className="inline-flex items-center gap-1 text-primary-text underline">
                  <FileText size={12} aria-hidden="true" /> {c} logs
                </Link>
              ))}
              <Link to="/pcap" className="inline-flex items-center gap-1 text-primary-text underline">
                <Radio size={12} aria-hidden="true" /> PCAP
              </Link>
            </div>
          }
        >
          <Table caption="Recent roaming warnings and errors">
            <TableHead>
              <TableRow>
                <TableHeaderCell>When</TableHeaderCell>
                <TableHeaderCell>NF</TableHeaderCell>
                <TableHeaderCell>Level</TableHeaderCell>
                <TableHeaderCell>Message</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.recent_errors.length === 0 ? (
                <TableEmptyRow colSpan={4}>No warnings or errors.</TableEmptyRow>
              ) : (
                data.recent_errors.map((l, i) => (
                  <TableRow key={`${l.container}-${l.time}-${i}`}>
                    <TableCell className="text-xs tabular-nums">{l.time ? new Date(l.time).toISOString().slice(11, 19) : '—'}</TableCell>
                    <TableCell className="text-xs">{l.container}</TableCell>
                    <TableCell>
                      <Badge label={l.level.toUpperCase()} variant={l.level === 'error' ? 'danger' : 'warning'} />
                    </TableCell>
                    <TableCell className="text-xs">
                      {l.msg}
                      {(l.procedure || l.cause) && (
                        <div className="text-muted-fg">{[l.procedure, l.cause].filter(Boolean).join(' — ')}</div>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          <p className="mt-2 text-xs text-muted-fg">
            N32 is TLS: to decrypt it in Wireshark, start the stack with SEPP_KEYLOG_DIR=1 (keys under pcaps/sepp-keys).
          </p>
        </Section>
      </div>

      {data.deployed && (
        <Section title="Test peer lifecycle" description="Start, stop or restart hNRF and hSEPP (and the hSEPP PCAP sidecar).">
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="secondary" icon={<Play size={14} />} disabled={lifeMut.isPending} onClick={() => setLifecycle('start')}>
              Start
            </Button>
            <Button size="sm" variant="secondary" icon={<RotateCw size={14} />} disabled={lifeMut.isPending} onClick={() => setLifecycle('restart')}>
              Restart
            </Button>
            <Button size="sm" variant="destructive" icon={<Power size={14} />} disabled={lifeMut.isPending} onClick={() => setLifecycle('stop')}>
              Stop
            </Button>
          </div>
        </Section>
      )}

      <ConfirmDialog
        open={pending !== null}
        title={pending?.action === 'teardown' ? 'Tear down the N32-f TLS connection?' : 'Re-run the N32-c handshake?'}
        description={
          pending
            ? pending.action === 'teardown'
              ? `${pending.sepp} asks PLMN ${pending.plmn} to drop the N32 context (exchange-capability NONE). Roaming signalling stops until a new handshake.`
              : `${pending.sepp} sends exchange-capability to PLMN ${pending.plmn}. The existing context is replaced and its N32-f connections are closed.`
            : undefined
        }
        destructive={pending?.action === 'teardown'}
        confirmLabel={pending?.action === 'teardown' ? 'Tear down' : 'Run handshake'}
        loading={n32Mut.isPending}
        onConfirm={() => pending && n32Mut.mutate(pending)}
        onCancel={() => setPending(null)}
      />
      <ConfirmDialog
        open={lifecycle !== null}
        title={`${lifecycle ?? ''} the test peer?`}
        description="Applies to hnrf and hsepp. Stopping them takes the N32 link down for the local core."
        destructive={lifecycle === 'stop'}
        confirmLabel={lifecycle ?? 'Confirm'}
        loading={lifeMut.isPending}
        onConfirm={() => lifecycle && lifeMut.mutate(lifecycle)}
        onCancel={() => setLifecycle(null)}
      />
    </>
  )
}

export default function Roaming() {
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['roaming-status'],
    queryFn: getRoamingStatus,
    refetchInterval: ROAMING_REFETCH_MS,
  })

  return (
    <Page className="space-y-4">
      <PageHeader
        eyebrow="Runtime"
        title="Roaming (N32)"
        subtitle="local SEPP ↔ hSEPP interconnect: N32-c contexts, N32-f traffic, test-peer NRF (TS 23.501 §6.2.17, TS 29.573)"
        action={
          <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} disabled={isFetching} onClick={() => refetch()}>
            Refresh
          </Button>
        }
      />
      {error ? (
        <ErrorState
          title="Failed to load roaming status"
          description={(error as Error).message}
          action={
            <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : isLoading || !data ? (
        <Loading label="Loading roaming status…" />
      ) : (
        <Body data={data} />
      )}
    </Page>
  )
}
