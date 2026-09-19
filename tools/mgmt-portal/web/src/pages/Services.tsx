import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { CheckCircle2, Circle, Loader, Play, RefreshCw, RotateCcw, Square, XCircle } from 'lucide-react'
import { getServices, startService, stopService, restartService } from '../lib/api'
import {
  Badge,
  Button,
  DegradedState,
  EmptyState,
  IconButton,
  Loading,
  PageHeader,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableEmptyRow,
  TableHead,
  TableHeaderCell,
  TableRow,
  useToast,
} from '../components/ui'
import type { BadgeVariant } from '../components/ui'

const NF_ORDER = ['nrf', 'amf', 'ausf', 'udm', 'udr', 'smf', 'pcf', 'upf', 'nssf',
  'postgres', 'redis', 'prometheus', 'loki', 'grafana', 'jaeger', 'mgmt-portal']

function sortSvcs(a: { name: string }, b: { name: string }) {
  const ai = NF_ORDER.indexOf(a.name)
  const bi = NF_ORDER.indexOf(b.name)
  if (ai === -1 && bi === -1) return a.name.localeCompare(b.name)
  if (ai === -1) return 1
  if (bi === -1) return -1
  return ai - bi
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/**
 * Map a Docker container state onto a semantic badge.
 *
 * Status is carried by colour **and** an icon **and** the text label, never by
 * colour alone (WCAG 1.4.1 — see `web/STYLE_GUIDE.md` § Components/Badge).
 * While a start/stop/restart mutation is in flight the pending verb replaces the
 * state so the operator sees which action is running.
 */
function stateBadge(state: string, pendingLabel?: string): { variant: BadgeVariant; icon: ReactNode; label: string } {
  if (pendingLabel) {
    return {
      variant: 'warning',
      icon: <Loader size={12} className="animate-spin" />,
      label: pendingLabel,
    }
  }
  switch (state) {
    case 'running':
      return { variant: 'success', icon: <CheckCircle2 size={12} />, label: state }
    case 'exited':
    case 'dead':
      return { variant: 'danger', icon: <XCircle size={12} />, label: state }
    default:
      return { variant: 'neutral', icon: <Circle size={12} />, label: state }
  }
}

export default function Services() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [pending, setPending] = useState<Record<string, string>>({})

  const { data: services = [], isLoading, isError, error, refetch } = useQuery({
    queryKey: ['services'],
    queryFn: getServices,
    refetchInterval: 5_000,
  })

  const clearPending = (name: string) =>
    setPending(p => { const copy = { ...p }; delete copy[name]; return copy })

  const failed = (verb: string) => (err: unknown, name: string) =>
    toast({
      variant: 'error',
      title: `${verb} failed`,
      description: `${name}: ${errMessage(err)}`,
      duration: 0,
    })

  const startMut = useMutation({
    mutationFn: (name: string) => startService(name),
    onMutate: (name) => setPending(p => ({ ...p, [name]: 'starting' })),
    onError: failed('Start'),
    onSettled: (_, __, name) => {
      clearPending(name)
      qc.invalidateQueries({ queryKey: ['services'] })
    },
  })

  const stopMut = useMutation({
    mutationFn: (name: string) => stopService(name),
    onMutate: (name) => setPending(p => ({ ...p, [name]: 'stopping' })),
    onError: failed('Stop'),
    onSettled: (_, __, name) => {
      clearPending(name)
      qc.invalidateQueries({ queryKey: ['services'] })
    },
  })

  const restartMut = useMutation({
    mutationFn: (name: string) => restartService(name),
    onMutate: (name) => setPending(p => ({ ...p, [name]: 'restarting' })),
    onError: failed('Restart'),
    onSettled: (_, __, name) => {
      clearPending(name)
      qc.invalidateQueries({ queryKey: ['services'] })
    },
  })

  const sorted = [...services].sort(sortSvcs)
  const running = services.filter(s => s.state === 'running').length

  return (
    <div className="p-6">
      <PageHeader
        eyebrow="Runtime"
        title="Services"
        subtitle={isError ? 'Container list unavailable' : `${running} / ${services.length} containers running`}
        action={
          <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>
            Refresh
          </Button>
        }
      />

      {isError ? (
        <DegradedState
          title="Docker socket unavailable"
          description={`The portal could not list containers: ${errMessage(error)}. Container control needs the Docker socket mounted (CLAUDE.md §10).`}
          action={
            <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : !isLoading && sorted.length === 0 ? (
        <EmptyState
          title="No containers found"
          description="Docker returned no containers. Check that the Docker socket is mounted and the stack is running (CLAUDE.md §10)."
          action={
            <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>
              Refresh
            </Button>
          }
        />
      ) : (
        <Table caption="Containers">
          <TableHead>
            <TableRow>
              <TableHeaderCell>Container</TableHeaderCell>
              <TableHeaderCell>Image</TableHeaderCell>
              <TableHeaderCell>State</TableHeaderCell>
              <TableHeaderCell>Status</TableHeaderCell>
              <TableHeaderCell>Uptime</TableHeaderCell>
              <TableHeaderCell className="text-right">Actions</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {isLoading ? (
              <TableEmptyRow colSpan={6}>
                <Loading rows={4} label="Loading containers…" />
              </TableEmptyRow>
            ) : (
              sorted.map(svc => {
                const p = pending[svc.name]
                const badge = stateBadge(svc.state, p)
                return (
                  <TableRow key={svc.name}>
                    <TableCell className="font-medium text-fg">{svc.name}</TableCell>
                    <TableCell mono className="max-w-[200px] truncate">{svc.image}</TableCell>
                    <TableCell>
                      <Badge label={badge.label} variant={badge.variant} icon={badge.icon} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-fg">{svc.status}</TableCell>
                    <TableCell className="text-xs text-muted-fg">{svc.uptime || '—'}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        {p ? (
                          <Spinner size={16} label={`${p}: ${svc.name}`} />
                        ) : (
                          <>
                            {svc.state !== 'running' && (
                              <IconButton
                                label={`Start ${svc.name}`}
                                variant="ghost"
                                onClick={() => startMut.mutate(svc.name)}
                              >
                                <Play size={14} />
                              </IconButton>
                            )}
                            {svc.state === 'running' && (
                              <IconButton
                                label={`Stop ${svc.name}`}
                                variant="ghost"
                                onClick={() => stopMut.mutate(svc.name)}
                              >
                                <Square size={14} />
                              </IconButton>
                            )}
                            <IconButton
                              label={`Restart ${svc.name}`}
                              variant="ghost"
                              onClick={() => restartMut.mutate(svc.name)}
                            >
                              <RotateCcw size={14} />
                            </IconButton>
                          </>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                )
              })
            )}
          </TableBody>
        </Table>
      )}
    </div>
  )
}
