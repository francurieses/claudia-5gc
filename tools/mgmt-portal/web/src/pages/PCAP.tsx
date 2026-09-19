import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import {
  ArrowUpDown,
  FileDown,
  Network,
  Pause,
  Play,
  PlayCircle,
  Radio,
  RotateCcw,
  Square,
  Trash2,
} from 'lucide-react'
import {
  getPCAPStatus,
  getPCAPFiles,
  pcapStart,
  pcapStop,
  pcapPause,
  pcapResume,
  pcapRotate,
  pcapDownloadURL,
  pcapDeleteFile,
  pcapBulkDelete,
  pcapBulkDownload,
} from '../lib/api'
import type { PCAPFile, PCAPStatus } from '../lib/api'
import { formatBytes } from '../lib/format'
import {
  Badge,
  Button,
  Card,
  Checkbox,
  ConfirmDialog,
  DegradedState,
  ErrorState,
  IconButton,
  Loading,
  PageHeader,
  Table,
  TableBody,
  TableCell,
  TableEmptyRow,
  TableHead,
  TableHeaderCell,
  TableRow,
  Tabs,
  useToast,
} from '../components/ui'
import type { BadgeVariant, TabItem } from '../components/ui'

// NF display metadata — one tab per capture sidecar.
interface NFMeta {
  id: string
  label: string
  description: string
  group: 'core' | 'nf'
}

const NF_LIST: NFMeta[] = [
  { id: 'core', label: 'CORE', description: 'All 5GC networks — sbi · n2 · n4 · n3', group: 'core' },
  { id: 'nrf', label: 'NRF', description: 'NF Registration & Discovery', group: 'nf' },
  { id: 'amf', label: 'AMF', description: 'Access & Mobility Management', group: 'nf' },
  { id: 'ausf', label: 'AUSF', description: 'Authentication Server', group: 'nf' },
  { id: 'udm', label: 'UDM', description: 'Unified Data Management', group: 'nf' },
  { id: 'udr', label: 'UDR', description: 'Unified Data Repository', group: 'nf' },
  { id: 'smf', label: 'SMF', description: 'Session Management', group: 'nf' },
  { id: 'pcf', label: 'PCF', description: 'Policy Control', group: 'nf' },
  { id: 'upf', label: 'UPF', description: 'User Plane (N3/N4)', group: 'nf' },
  { id: 'nssf', label: 'NSSF', description: 'Network Slice Selection', group: 'nf' },
  { id: 'smsf', label: 'SMSF', description: 'SMS Function', group: 'nf' },
  { id: 'bsf', label: 'BSF', description: 'Binding Support', group: 'nf' },
  { id: 'nef', label: 'NEF', description: 'Network Exposure', group: 'nf' },
  { id: 'lmf', label: 'LMF', description: 'Location Management (Nlmf)', group: 'nf' },
]

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/**
 * Capture state → semantic badge. Always colour + icon + text, so the state is
 * readable without colour (WCAG 1.4.1).
 */
function statusBadge(status: PCAPStatus | undefined): { variant: BadgeVariant; icon: ReactNode; label: string } {
  if (status?.capturing) {
    return { variant: 'success', icon: <Radio size={12} />, label: 'Capturing' }
  }
  if (status?.paused) {
    return { variant: 'warning', icon: <Pause size={12} />, label: 'Paused' }
  }
  return { variant: 'neutral', icon: <Square size={12} />, label: 'Stopped' }
}

/** Compact per-tab marker — shown only for a live capture (REC / PAUSED). */
function tabBadge(status: PCAPStatus | undefined): ReactNode {
  if (status?.capturing) return <Badge label="REC" variant="success" icon={<Radio size={10} />} />
  if (status?.paused) return <Badge label="PAUSED" variant="warning" icon={<Pause size={10} />} />
  return null
}

interface CapturePanelProps {
  meta: NFMeta
  status: PCAPStatus | undefined
  pending: Record<string, boolean>
  onStart: () => void
  onStop: () => void
  onPause: () => void
  onResume: () => void
  onRotate: () => void
}

function CapturePanel({ meta, status, pending, onStart, onStop, onPause, onResume, onRotate }: CapturePanelProps) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [sortNewest, setSortNewest] = useState(true)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [confirmBulk, setConfirmBulk] = useState(false)
  const [confirmFile, setConfirmFile] = useState<string | null>(null)

  const capturing = status?.capturing ?? false
  const paused = status?.paused ?? false
  const fileCount = status?.files ?? 0
  const badge = statusBadge(status)

  const { data: files = [], isLoading, isError, error, refetch } = useQuery({
    queryKey: ['pcap-files', meta.id],
    queryFn: () => getPCAPFiles(meta.id),
    refetchInterval: 5_000,
  })

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['pcap-status'] })
    qc.invalidateQueries({ queryKey: ['pcap-files', meta.id] })
  }

  const actionFailed = (verb: string) => (err: unknown) =>
    toast({ variant: 'error', title: `${verb} failed`, description: errMessage(err), duration: 0 })

  const deleteMut = useMutation({
    mutationFn: (filename: string) => pcapDeleteFile(meta.id, filename),
    onSuccess: invalidate,
    onError: actionFailed('Delete'),
  })
  const bulkDeleteMut = useMutation({
    mutationFn: (fileList: string[]) => pcapBulkDelete(meta.id, fileList),
    onSuccess: () => {
      setSelected(new Set())
      invalidate()
    },
    onError: actionFailed('Bulk delete'),
  })
  const bulkDownloadMut = useMutation({
    mutationFn: (fileList: string[]) => pcapBulkDownload(meta.id, fileList),
    onError: actionFailed('Download'),
  })

  const sorted = useMemo(
    () =>
      [...files].sort((a: PCAPFile, b: PCAPFile) => {
        const d = new Date(b.mod_time).getTime() - new Date(a.mod_time).getTime()
        return sortNewest ? d : -d
      }),
    [files, sortNewest],
  )

  const allSelected = sorted.length > 0 && sorted.every((f: PCAPFile) => selected.has(f.name))
  const someSelected = !allSelected && sorted.some((f: PCAPFile) => selected.has(f.name))

  const toggle = (name: string) =>
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })

  const downloadFile = (name: string) => {
    const a = document.createElement('a')
    a.href = pcapDownloadURL(meta.id, name)
    a.download = name
    document.body.appendChild(a)
    a.click()
    a.remove()
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Header + capture controls */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-fg">
            {meta.label}
            <span className="ml-2 font-normal text-muted-fg">{meta.description}</span>
          </h2>
          <p className="mt-0.5 text-xs text-muted-fg">
            {fileCount} file{fileCount === 1 ? '' : 's'} saved · Rotate seals the current file without stopping the
            capture
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Badge label={badge.label} variant={badge.variant} icon={badge.icon} />

          {!capturing && !paused && (
            <Button size="sm" icon={<Play size={14} />} loading={pending.start} onClick={onStart}>
              Start
            </Button>
          )}
          {capturing && (
            <Button
              size="sm"
              variant="secondary"
              icon={<Pause size={14} />}
              loading={pending.pause}
              onClick={onPause}
            >
              Pause
            </Button>
          )}
          {paused && (
            <Button size="sm" icon={<PlayCircle size={14} />} loading={pending.resume} onClick={onResume}>
              Resume
            </Button>
          )}
          {capturing && (
            <Button
              size="sm"
              variant="secondary"
              icon={<RotateCcw size={14} />}
              loading={pending.rotate}
              onClick={onRotate}
              title="Seal the current file and start a new one without losing data"
            >
              Rotate file
            </Button>
          )}
          {(capturing || paused) && (
            <Button
              size="sm"
              variant="destructive"
              icon={<Square size={14} />}
              loading={pending.stop}
              onClick={onStop}
            >
              Stop
            </Button>
          )}
        </div>
      </div>

      {/* Bulk actions */}
      {selected.size > 0 && (
        <Card className="border-info-border bg-info-surface">
          <div className="flex flex-wrap items-center gap-3 text-info-fg">
            <span className="text-xs font-medium">{selected.size} selected</span>
            <Button
              size="sm"
              variant="secondary"
              icon={<FileDown size={14} />}
              loading={bulkDownloadMut.isPending}
              onClick={() => bulkDownloadMut.mutate(Array.from(selected))}
            >
              Download ({selected.size})
            </Button>
            <Button
              size="sm"
              variant="destructive"
              icon={<Trash2 size={14} />}
              loading={bulkDeleteMut.isPending}
              onClick={() => setConfirmBulk(true)}
            >
              Delete ({selected.size})
            </Button>
            <Button size="sm" variant="ghost" className="ml-auto" onClick={() => setSelected(new Set())}>
              Clear
            </Button>
          </div>
        </Card>
      )}

      {/* Capture files */}
      {isError ? (
        <ErrorState
          title="Could not list capture files"
          description={errMessage(error)}
          action={
            <Button variant="secondary" size="sm" icon={<RotateCcw size={14} />} onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : (
        <Table caption={`PCAP files for ${meta.label}`}>
          <TableHead>
            <TableRow>
              <TableHeaderCell className="w-10">
                <Checkbox
                  aria-label="Select all files"
                  checked={allSelected}
                  indeterminate={someSelected}
                  disabled={sorted.length === 0}
                  onChange={next =>
                    setSelected(next ? new Set(sorted.map((f: PCAPFile) => f.name)) : new Set())
                  }
                />
              </TableHeaderCell>
              <TableHeaderCell aria-sort={sortNewest ? 'descending' : 'ascending'}>
                <button
                  type="button"
                  onClick={() => setSortNewest(v => !v)}
                  title={sortNewest ? 'Sorted newest first' : 'Sorted oldest first'}
                  className="inline-flex items-center gap-1 transition-colors hover:text-fg"
                >
                  File <ArrowUpDown size={10} aria-hidden="true" />
                </button>
              </TableHeaderCell>
              <TableHeaderCell>Size</TableHeaderCell>
              <TableHeaderCell>Modified</TableHeaderCell>
              <TableHeaderCell className="text-right">Actions</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {isLoading ? (
              <TableEmptyRow colSpan={5}>
                <Loading rows={3} label="Loading capture files…" />
              </TableEmptyRow>
            ) : sorted.length === 0 ? (
              <TableEmptyRow colSpan={5}>
                No files yet. Start capture, then rotate to seal a file.
              </TableEmptyRow>
            ) : (
              sorted.map((f: PCAPFile) => (
                <TableRow key={f.name} className={selected.has(f.name) ? 'bg-info-surface/60' : undefined}>
                  <TableCell>
                    <Checkbox
                      aria-label={`Select ${f.name}`}
                      checked={selected.has(f.name)}
                      onChange={() => toggle(f.name)}
                    />
                  </TableCell>
                  <TableCell mono className="max-w-xs truncate">
                    {f.name}
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-xs text-muted-fg">
                    {formatBytes(f.size_bytes)}
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-xs text-muted-fg">
                    {new Date(f.mod_time).toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      <IconButton
                        label={`Download ${f.name}`}
                        variant="ghost"
                        onClick={() => downloadFile(f.name)}
                      >
                        <FileDown size={14} />
                      </IconButton>
                      <IconButton
                        label={`Delete ${f.name}`}
                        variant="ghost"
                        onClick={() => setConfirmFile(f.name)}
                      >
                        <Trash2 size={14} />
                      </IconButton>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      )}

      <ConfirmDialog
        open={confirmBulk}
        destructive
        title={`Delete ${selected.size} file${selected.size === 1 ? '' : 's'}?`}
        description="Deleted capture files cannot be recovered."
        confirmLabel={`Delete (${selected.size})`}
        loading={bulkDeleteMut.isPending}
        onConfirm={() =>
          bulkDeleteMut.mutate(Array.from(selected), { onSuccess: () => setConfirmBulk(false) })
        }
        onCancel={() => setConfirmBulk(false)}
      />

      <ConfirmDialog
        open={confirmFile !== null}
        destructive
        title="Delete capture file?"
        description={confirmFile ? `${confirmFile} will be permanently removed.` : undefined}
        confirmLabel="Delete"
        loading={deleteMut.isPending}
        onConfirm={() => {
          if (confirmFile) deleteMut.mutate(confirmFile, { onSuccess: () => setConfirmFile(null) })
        }}
        onCancel={() => setConfirmFile(null)}
      />
    </div>
  )
}

export default function PCAP() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [openNF, setOpenNF] = useState('core')

  const { data: statuses = [], isLoading, isError, error, refetch } = useQuery({
    queryKey: ['pcap-status'],
    queryFn: getPCAPStatus,
    refetchInterval: 5_000,
  })

  const getStatus = (nf: string) => statuses.find(s => s.nf === nf)

  const invalidateStatus = () => qc.invalidateQueries({ queryKey: ['pcap-status'] })

  const actionFailed = (verb: string) => (err: unknown) =>
    toast({ variant: 'error', title: `${verb} failed`, description: errMessage(err), duration: 0 })

  const startMut = useMutation({ mutationFn: pcapStart, onSuccess: invalidateStatus, onError: actionFailed('Start') })
  const stopMut = useMutation({ mutationFn: pcapStop, onSuccess: invalidateStatus, onError: actionFailed('Stop') })
  const pauseMut = useMutation({ mutationFn: pcapPause, onSuccess: invalidateStatus, onError: actionFailed('Pause') })
  const resumeMut = useMutation({
    mutationFn: pcapResume,
    onSuccess: invalidateStatus,
    onError: actionFailed('Resume'),
  })
  const rotateMut = useMutation({
    mutationFn: pcapRotate,
    onSuccess: invalidateStatus,
    onError: actionFailed('Rotate'),
  })

  const pending = {
    start: startMut.isPending,
    stop: stopMut.isPending,
    pause: pauseMut.isPending,
    resume: resumeMut.isPending,
    rotate: rotateMut.isPending,
  }

  const tabs: TabItem[] = NF_LIST.map(nf => {
    const st = getStatus(nf.id)
    return {
      id: nf.id,
      label: nf.label,
      icon: nf.group === 'core' ? <Network size={14} /> : <Radio size={14} />,
      badge: tabBadge(st),
      content: (
        <CapturePanel
          key={nf.id}
          meta={nf}
          status={st}
          pending={pending}
          onStart={() => startMut.mutate(nf.id)}
          onStop={() => stopMut.mutate(nf.id)}
          onPause={() => pauseMut.mutate(nf.id)}
          onResume={() => resumeMut.mutate(nf.id)}
          onRotate={() => rotateMut.mutate(nf.id)}
        />
      ),
    }
  })

  const activeCount = statuses.filter(s => s.capturing || s.paused).length

  return (
    <div className="p-6">
      <PageHeader
        eyebrow="Operations"
        title="PCAP Capture"
        subtitle="Start tcpdump on demand — off by default"
        action={
          <Badge
            label={
              activeCount > 0
                ? `${activeCount} capture${activeCount === 1 ? '' : 's'} running`
                : 'All captures stopped'
            }
            variant={activeCount > 0 ? 'success' : 'neutral'}
            icon={activeCount > 0 ? <Radio size={12} /> : <Square size={12} />}
          />
        }
      />

      {isLoading ? (
        <Loading label="Loading capture status…" />
      ) : isError ? (
        <DegradedState
          title="Capture status unavailable"
          description={`The portal could not read the capture sidecar status: ${errMessage(error)}. Sidecar control needs the Docker socket (CLAUDE.md §10).`}
          action={
            <Button variant="secondary" size="sm" icon={<RotateCcw size={14} />} onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : (
        <Tabs label="PCAP capture sidecar" tabs={tabs} value={openNF} onChange={setOpenNF} />
      )}
    </div>
  )
}
