import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { CheckCircle2, Circle, Clock, RefreshCw, XCircle } from 'lucide-react'
import { getSessions, getUEContexts } from '../lib/api'
import { formatHex32 } from '../lib/format'
import {
  Badge,
  Button,
  DegradedState,
  EmptyState,
  Loading,
  PageHeader,
  Section,
  Table,
  TableBody,
  TableCell,
  TableEmptyRow,
  TableHead,
  TableHeaderCell,
  TableRow,
} from '../components/ui'
import type { BadgeVariant } from '../components/ui'

/** 5GMM states persisted by the AMF (TS 24.501 §5.1.3.2). */
const GMM_STATES: Record<number, string> = {
  0: 'DEREGISTERED',
  1: 'REGISTERED',
  2: 'REGISTERED-INITIATED',
  3: 'DEREGISTERED-INITIATED',
}

const REFETCH_MS = 5_000

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/**
 * 5GMM state → semantic badge.
 *
 * Status carries colour **and** an icon **and** the text label so the meaning
 * survives greyscale / colour-vision deficiency (WCAG 1.4.1).
 */
function gmmBadge(state: number): { variant: BadgeVariant; icon: ReactNode; label: string } {
  switch (state) {
    case 1:
      return { variant: 'success', icon: <CheckCircle2 size={12} />, label: GMM_STATES[1] }
    case 0:
      return { variant: 'danger', icon: <XCircle size={12} />, label: GMM_STATES[0] }
    case 2:
    case 3:
      return { variant: 'warning', icon: <Clock size={12} />, label: GMM_STATES[state] }
    default:
      return { variant: 'neutral', icon: <Circle size={12} />, label: `State ${state}` }
  }
}

export default function Sessions() {
  const {
    data: sessions = [],
    isLoading: loadSess,
    isError: sessError,
    error: sessErr,
    refetch: refetchSess,
  } = useQuery({
    queryKey: ['sessions'],
    queryFn: getSessions,
    refetchInterval: REFETCH_MS,
  })

  const {
    data: ueContexts = [],
    isLoading: loadUE,
    isError: ueError,
    error: ueErr,
    refetch: refetchUE,
  } = useQuery({
    queryKey: ['ue-contexts'],
    queryFn: getUEContexts,
    refetchInterval: REFETCH_MS,
  })

  return (
    <div className="p-6">
      <PageHeader
        eyebrow="Runtime"
        title="Sessions & UE Contexts"
        subtitle="Live data from PostgreSQL"
      />

      {/* Active PDU sessions (SMF store) */}
      <Section
        bare
        headingLevel={2}
        className="mb-8"
        title={sessError ? 'Active PDU Sessions' : `Active PDU Sessions (${sessions.length})`}
      >
        {sessError ? (
          <DegradedState
            title="Session data unavailable"
            description={`The portal could not read the session store: ${errMessage(sessErr)}. Session data needs PostgreSQL, which the portal degrades without (CLAUDE.md §10).`}
            action={
              <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetchSess()}>
                Retry
              </Button>
            }
          />
        ) : !loadSess && sessions.length === 0 ? (
          <EmptyState
            title="No active PDU sessions"
            description="No PDU session currently has an assigned UE IP. A session appears here once a UE establishes one."
          />
        ) : (
          <Table caption="Active PDU sessions">
            <TableHead>
              <TableRow>
                <TableHeaderCell>SUPI</TableHeaderCell>
                <TableHeaderCell>DNN</TableHeaderCell>
                <TableHeaderCell>UE IP</TableHeaderCell>
                <TableHeaderCell>Slice</TableHeaderCell>
                <TableHeaderCell>UL TEID</TableHeaderCell>
                <TableHeaderCell>Since</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loadSess ? (
                <TableEmptyRow colSpan={6}>
                  <Loading rows={3} label="Loading sessions…" />
                </TableEmptyRow>
              ) : (
                sessions.map(s => (
                  <TableRow key={s.ref}>
                    <TableCell mono>{s.supi}</TableCell>
                    <TableCell>{s.dnn}</TableCell>
                    <TableCell mono>{s.ue_ip}</TableCell>
                    <TableCell>
                      <Badge
                        label={`SST:${s.sst}${s.sd ? '/SD:' + s.sd : ''}`}
                        variant="info"
                      />
                    </TableCell>
                    <TableCell mono>{formatHex32(s.ul_teid)}</TableCell>
                    <TableCell className="text-xs text-muted-fg">
                      {new Date(s.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        )}
      </Section>

      {/* UE contexts (AMF store) */}
      <Section
        bare
        headingLevel={2}
        title={ueError ? 'UE Contexts — AMF' : `UE Contexts — AMF (${ueContexts.length})`}
      >
        {ueError ? (
          <DegradedState
            title="UE context data unavailable"
            description={`The portal could not read the AMF UE context store: ${errMessage(ueErr)}. UE context data needs PostgreSQL, which the portal degrades without (CLAUDE.md §10).`}
            action={
              <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetchUE()}>
                Retry
              </Button>
            }
          />
        ) : !loadUE && ueContexts.length === 0 ? (
          <EmptyState
            title="No UE contexts"
            description="The AMF has no UE contexts. A UE appears here after it registers."
          />
        ) : (
          <Table caption="AMF UE contexts">
            <TableHead>
              <TableRow>
                <TableHeaderCell>SUPI</TableHeaderCell>
                <TableHeaderCell>TMSI</TableHeaderCell>
                <TableHeaderCell>GMM State</TableHeaderCell>
                <TableHeaderCell>Last Seen</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loadUE ? (
                <TableEmptyRow colSpan={4}>
                  <Loading rows={3} label="Loading UE contexts…" />
                </TableEmptyRow>
              ) : (
                ueContexts.map(ue => {
                  const badge = gmmBadge(ue.gmm_state)
                  return (
                    <TableRow key={ue.supi}>
                      <TableCell mono>{ue.supi}</TableCell>
                      <TableCell mono>{ue.tmsi ? formatHex32(ue.tmsi) : '—'}</TableCell>
                      <TableCell>
                        <Badge label={badge.label} variant={badge.variant} icon={badge.icon} />
                      </TableCell>
                      <TableCell className="text-xs text-muted-fg">
                        {new Date(ue.created_at).toLocaleString()}
                      </TableCell>
                    </TableRow>
                  )
                })
              )}
            </TableBody>
          </Table>
        )}
      </Section>
    </div>
  )
}
