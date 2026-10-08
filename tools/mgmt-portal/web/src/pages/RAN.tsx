import { Fragment, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, ChevronDown, Hourglass, RefreshCw, Unplug } from 'lucide-react'
import { getRanGnbs } from '../lib/api'
import type { GnbState, RanGnb } from '../lib/api'
import StatCard from '../components/StatCard'
import {
  Badge, Button, DegradedState, EmptyState, ErrorState, Loading, Page, PageHeader, Table, TableBody,
  TableCell, TableEmptyRow, TableHead, TableHeaderCell, TableRow,
} from '../components/ui'

/** Poll period of the gNB list — same cadence as the Location and PWS pages. */
const RAN_REFETCH_MS = 3_000

/** Disconnected gNBs stay listed this long on the AMF (nf/amf gnbHistoryRetention). */
const RETENTION_LABEL = 'last 15 min'

function StateBadge({ g }: { g: RanGnb }) {
  switch (g.state as GnbState) {
    case 'NG_READY':
      return <Badge label="Ready — NG Setup complete" variant="success" icon={<CheckCircle2 size={12} />} />
    case 'SCTP_UP':
      return <Badge label="Connected — awaiting NG Setup" variant="warning" icon={<Hourglass size={12} />} />
    default:
      return (
        <Badge
          label={`Disconnected${g.disconnect_reason ? ` (${g.disconnect_reason})` : ''}`}
          variant="danger"
          icon={<Unplug size={12} />}
        />
      )
  }
}

function since(iso?: string): string {
  if (!iso) return '—'
  const secs = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (secs < 60) return `${secs}s ago`
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`
  if (secs < 86_400) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m ago`
  return `${Math.floor(secs / 86_400)}d ago`
}

function sliceLabel(sst: number, sd: string): string {
  return sd ? `${sst}/${sd}` : `${sst}`
}

/** Distinct S-NSSAIs across all TAs of the gNB. */
function uniqueSlices(g: RanGnb): string[] {
  const set = new Set<string>()
  for (const ta of g.supported_tas)
    for (const p of ta.broadcast_plmns) for (const s of p.slices) set.add(sliceLabel(s.sst, s.sd))
  return [...set]
}

function gnbIdLabel(g: RanGnb): string {
  const n = g.ran_node
  if (n.type !== 'gNB') return n.type || '—'
  return `${n.gnb_id_hex} (${n.gnb_id}) /${n.gnb_id_bit_length}`
}

export default function RAN() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['ran-gnbs'],
    queryFn: getRanGnbs,
    refetchInterval: RAN_REFETCH_MS,
  })
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})

  const gnbs = data?.gnbs ?? []
  const sources = data?.sources ?? []
  const failedSources = sources.filter(s => !s.ok)
  const allFailed = sources.length > 0 && failedSources.length === sources.length
  const multiAmf = sources.length > 1
  const n2Addr = sources.find(s => s.n2_addr)?.n2_addr

  const ready = gnbs.filter(g => g.state === 'NG_READY').length
  const awaiting = gnbs.filter(g => g.state === 'SCTP_UP').length
  const disconnected = gnbs.filter(g => g.state === 'DISCONNECTED').length
  const ues = gnbs.reduce((n, g) => n + g.ues.connected + g.ues.idle, 0)
  const columns = multiAmf ? 10 : 9

  return (
    <Page mode="fill" className="gap-4">
      <PageHeader
        eyebrow="Runtime"
        title="gNBs (RAN)"
        subtitle={`RAN nodes attached to the AMF over N2 (NG Setup — TS 38.413 §8.7.1)${n2Addr ? ` · listening on ${n2Addr}` : ''}`}
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard title="Ready" value={ready} variant="success" sub="NG Setup complete" />
        <StatCard title="Awaiting NG Setup" value={awaiting} variant="warning" sub="SCTP up" />
        <StatCard title="Disconnected" value={disconnected} variant="danger" sub={RETENTION_LABEL} />
        <StatCard title="UEs" value={ues} sub="connected + idle" />
      </div>

      {failedSources.length > 0 && !allFailed && (
        <div
          role="status"
          className="flex items-start gap-2 rounded-card border border-warning-border bg-warning-surface px-4 py-2 text-xs text-warning-fg"
        >
          <AlertTriangle size={14} aria-hidden="true" className="mt-0.5 flex-shrink-0" />
          <span>
            Some AMFs did not answer — the list may be incomplete:{' '}
            {failedSources.map(s => `${s.amf_url} (${s.error})`).join('; ')}
          </span>
        </div>
      )}

      {error ? (
        <ErrorState
          title="Failed to load gNBs"
          description={(error as Error).message}
          action={
            <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : allFailed ? (
        <DegradedState
          title="AMF management API unavailable"
          description={failedSources.map(s => `${s.amf_url}: ${s.error}`).join(' · ')}
          action={
            <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : !isLoading && gnbs.length === 0 ? (
        <EmptyState
          title="No gNB connected"
          description={`Point a gNB at ${n2Addr ?? 'the AMF N2 address'} (port 38412/sctp, PPID 60), or start a simulator with make up RAN=ueransim.`}
        />
      ) : (
        <Table fill caption="gNBs connected to the AMF">
          <TableHead sticky>
            <TableRow>
              <TableHeaderCell>Status</TableHeaderCell>
              <TableHeaderCell>gNB</TableHeaderCell>
              <TableHeaderCell>Global gNB ID</TableHeaderCell>
              <TableHeaderCell>PLMN</TableHeaderCell>
              <TableHeaderCell>SCTP peer</TableHeaderCell>
              <TableHeaderCell>TAC</TableHeaderCell>
              <TableHeaderCell>S-NSSAI</TableHeaderCell>
              <TableHeaderCell>UEs</TableHeaderCell>
              <TableHeaderCell>Connected since</TableHeaderCell>
              {multiAmf && <TableHeaderCell>AMF</TableHeaderCell>}
            </TableRow>
          </TableHead>
          <TableBody>
            {isLoading ? (
              <TableEmptyRow colSpan={columns}>
                <Loading rows={3} label="Loading gNBs…" />
              </TableEmptyRow>
            ) : (
              gnbs.map(g => {
                const open = expanded[`${g.amf?.url}|${g.id}`] ?? false
                const key = `${g.amf?.url}|${g.id}`
                const slices = uniqueSlices(g)
                return (
                  <Fragment key={key}>
                    <TableRow>
                      <TableCell>
                        <StateBadge g={g} />
                        {g.ng_reset_count > 0 && (
                          <p className="mt-1 text-xs text-warning-fg">
                            NG Reset ×{g.ng_reset_count} (last {since(g.last_ng_reset_at)})
                          </p>
                        )}
                      </TableCell>
                      <TableCell>
                        <button
                          type="button"
                          aria-expanded={open}
                          aria-label={`${open ? 'Hide' : 'Show'} supported tracking areas of ${g.ran_node_name || g.id}`}
                          onClick={() => setExpanded(p => ({ ...p, [key]: !open }))}
                          className="inline-flex items-center gap-1 text-left text-fg hover:text-primary-text"
                        >
                          <ChevronDown
                            size={14}
                            aria-hidden="true"
                            className={`flex-shrink-0 transition-transform ${open ? '' : '-rotate-90'}`}
                          />
                          <span className="font-medium">{g.ran_node_name || '—'}</span>
                        </button>
                      </TableCell>
                      <TableCell mono>{gnbIdLabel(g)}</TableCell>
                      <TableCell mono className="text-muted-fg">
                        {g.ran_node.plmn.mcc ? `${g.ran_node.plmn.mcc}/${g.ran_node.plmn.mnc}` : '—'}
                      </TableCell>
                      <TableCell mono>
                        {g.sctp.remote_addrs.join(', ') || '—'}
                        {g.sctp.remote_port ? `:${g.sctp.remote_port}` : ''}
                      </TableCell>
                      <TableCell mono className="text-muted-fg">
                        {g.supported_tas.map(t => t.tac).join(', ') || '—'}
                      </TableCell>
                      <TableCell>
                        {slices.length === 0 ? (
                          <span className="text-muted-fg">—</span>
                        ) : (
                          <span className="flex flex-wrap gap-1">
                            {slices.map(s => (
                              <Badge key={s} label={s} variant="neutral" />
                            ))}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="tabular-nums">
                        {g.state === 'DISCONNECTED' ? '—' : `${g.ues.connected} / ${g.ues.idle}`}
                      </TableCell>
                      <TableCell className="text-xs text-muted-fg">
                        <span title={new Date(g.connected_at).toLocaleString()}>{since(g.connected_at)}</span>
                      </TableCell>
                      {multiAmf && <TableCell className="text-xs text-muted-fg">{g.amf?.name || g.amf_name}</TableCell>}
                    </TableRow>
                    {open && (
                      <tr className="border-b border-border/60 bg-muted/30">
                        <td colSpan={columns} className="px-4 py-3 text-xs text-muted-fg">
                          {g.supported_tas.length === 0 ? (
                            'No supported TA reported yet (NG Setup not completed).'
                          ) : (
                            <ul className="space-y-1">
                              {g.supported_tas.map(ta => (
                                <li key={ta.tac}>
                                  <span className="font-mono text-fg">TAC {ta.tac}</span>
                                  {ta.broadcast_plmns.map(p => (
                                    <span key={`${p.mcc}${p.mnc}`} className="ml-3">
                                      PLMN {p.mcc}/{p.mnc} · slices{' '}
                                      <span className="font-mono">
                                        {p.slices.map(s => sliceLabel(s.sst, s.sd)).join(', ') || '—'}
                                      </span>
                                    </span>
                                  ))}
                                </li>
                              ))}
                            </ul>
                          )}
                          <p className="mt-2">
                            Local association id <span className="font-mono">{g.id}</span>
                            {g.disconnected_at && <> · disconnected {since(g.disconnected_at)}</>}
                          </p>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })
            )}
          </TableBody>
        </Table>
      )}
    </Page>
  )
}
