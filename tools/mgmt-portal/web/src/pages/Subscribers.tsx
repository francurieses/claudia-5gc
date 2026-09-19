import { useId, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Check, Pencil, Plus, RefreshCw, RotateCcw, Signal, Trash2, X } from 'lucide-react'
import {
  getSubscribers,
  createSubscriber,
  updateSubscriber,
  deleteSubscriber,
  getSlices,
  getDNNs,
  getSubscriberRFSP,
  setSubscriberRFSP,
  resetSubscriberRFSP,
  type Subscriber,
  type SNSSAI,
} from '../lib/api'
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  ErrorState,
  Field,
  IconButton,
  Input,
  Loading,
  PageHeader,
  Select,
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
import type { BadgeVariant, SelectOption } from '../components/ui'

const SLICE_PRESETS: Record<string, SNSSAI> = {
  internet: { sst: 1, sd: '000001' },
  gold: { sst: 1, sd: '000002' },
  silver: { sst: 2, sd: '000001' },
  bronze: { sst: 3, sd: '000001' },
}

const sliceName = (s: SNSSAI) => {
  for (const [name, preset] of Object.entries(SLICE_PRESETS)) {
    if (preset.sst === s.sst && preset.sd === s.sd) return name
  }
  return `SST:${s.sst}${s.sd ? '/SD:' + s.sd : ''}`
}

/**
 * Slice identity → semantic badge variant. The badge label carries the slice
 * name (internet/gold/silver/bronze), so identity never depends on colour alone.
 */
const SLICE_VARIANT: Record<string, BadgeVariant> = {
  internet: 'info',
  gold: 'warning',
  silver: 'neutral',
  bronze: 'success',
}

function sliceVariant(name: string): BadgeVariant {
  return SLICE_VARIANT[name] ?? 'info'
}

type FormData = Omit<Subscriber, 'sqn' | 'amf'> & { sqn: string; amf: string }

const emptyForm = (): FormData => ({
  supi: '',
  k: '',
  opc: 'cd63cb71954a9f4e48a5994e37a02baf',
  amf: 'b9b9',
  sqn: '000000000020',
  slices: [SLICE_PRESETS.internet],
  ambr_ul: 100000,
  ambr_dl: 100000,
})

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

export default function Subscribers() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const slicesLabelId = useId()
  const [showForm, setShowForm] = useState(false)
  const [editSUPI, setEditSUPI] = useState<string | null>(null)
  const [form, setForm] = useState<FormData>(emptyForm())
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)

  const { data: subscribers = [], isLoading, isError, error, refetch } = useQuery({
    queryKey: ['subscribers'],
    queryFn: getSubscribers,
    staleTime: 0,
  })

  const { data: availableSlices = [] } = useQuery({
    queryKey: ['slices'],
    queryFn: getSlices,
  })

  const { data: dnnResponse } = useQuery({
    queryKey: ['dnns'],
    queryFn: getDNNs,
  })
  const availableDNNs = dnnResponse?.dnns ?? []

  const resetForm = () => {
    setShowForm(false)
    setEditSUPI(null)
    setForm(emptyForm())
  }

  const actionFailed = (verb: string) => (err: unknown) =>
    toast({ variant: 'error', title: `${verb} failed`, description: errMessage(err), duration: 0 })

  const createMut = useMutation({
    mutationFn: createSubscriber,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['subscribers'] })
      resetForm()
    },
    onError: actionFailed('Create subscriber'),
  })

  const updateMut = useMutation({
    mutationFn: ({ supi, data }: { supi: string; data: Partial<Subscriber> }) =>
      updateSubscriber(supi, data),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['subscribers'] })
      resetForm()
      toast({
        variant: result.deregistered ? 'success' : 'warning',
        title: `${result.supi} updated`,
        description: result.deregistered
          ? 'UE has been deregistered and will re-register with the new subscription.'
          : 'UE is not currently registered — the new subscription will apply on next registration.',
      })
    },
    onError: actionFailed('Update subscriber'),
  })

  const deleteMut = useMutation({
    mutationFn: deleteSubscriber,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['subscribers'] }),
    onError: actionFailed('Delete subscriber'),
  })

  const openEdit = (sub: Subscriber) => {
    setForm({ ...sub, sqn: sub.sqn || '000000000001', amf: sub.amf || '8000' })
    setEditSUPI(sub.supi)
    setShowForm(true)
  }

  const submit = () => {
    if (editSUPI) {
      updateMut.mutate({ supi: editSUPI, data: form })
    } else {
      createMut.mutate(form)
    }
  }

  const notifyDereg = (supi: string, deregistered: boolean, what: string) => {
    toast({
      variant: deregistered ? 'success' : 'warning',
      title: `${supi} updated`,
      description: deregistered
        ? `UE has been deregistered and will re-register with the new ${what}.`
        : `UE is not currently registered — the new ${what} will apply on next registration.`,
    })
  }

  // Toggle a slice on/off. When toggling on, assign the first available DNN by default.
  const toggleSlice = (slice: SNSSAI) => {
    const exists = form.slices.some(s => s.sst === slice.sst && s.sd === slice.sd)
    setForm(f => ({
      ...f,
      slices: exists
        ? f.slices.filter(s => !(s.sst === slice.sst && s.sd === slice.sd))
        : [...f.slices, { ...slice, dnn: availableDNNs[0]?.name ?? '' }],
    }))
  }

  // Update the DNN assigned to a specific slice.
  const setSliceDNN = (slice: SNSSAI, dnn: string) => {
    setForm(f => ({
      ...f,
      slices: f.slices.map(s =>
        s.sst === slice.sst && s.sd === slice.sd ? { ...s, dnn } : s,
      ),
    }))
  }

  const dnnOptions: SelectOption[] = [
    { value: '', label: '— select DNN —' },
    ...availableDNNs.map(d => ({
      value: d.name,
      label: d.ue_ip_pool ? `${d.name} (${d.ue_ip_pool})` : d.name,
    })),
  ]

  const saving = createMut.isPending || updateMut.isPending

  return (
    <div className="p-6">
      <PageHeader
        eyebrow="Data & Config"
        title="Subscribers"
        subtitle={`${subscribers.length} provisioned`}
        action={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              icon={<RefreshCw size={14} />}
              onClick={() => refetch()}
              title="Refresh subscriber list"
            >
              Refresh
            </Button>
            <Button size="sm" icon={<Plus size={14} />} onClick={() => setShowForm(true)}>
              New Subscriber
            </Button>
          </div>
        }
      />

      {/* Create / edit form */}
      {showForm && (
        <Card className="mb-6">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="text-sm font-semibold text-fg">
              {editSUPI ? `Edit ${editSUPI}` : 'New Subscriber'}
            </h2>
            <IconButton label="Close form" variant="ghost" onClick={resetForm}>
              <X size={16} />
            </IconButton>
          </div>

          <div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="SUPI (imsi-...)" hint="e.g. imsi-001010000000001">
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  aria-describedby={describedBy}
                  invalid={invalid}
                  value={form.supi}
                  onChange={e => setForm(f => ({ ...f, supi: e.target.value }))}
                  disabled={!!editSUPI}
                  placeholder="imsi-001010000000001"
                  className="font-mono text-xs"
                />
              )}
            </Field>

            <Field label="K (hex 32)">
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  aria-describedby={describedBy}
                  invalid={invalid}
                  value={form.k}
                  onChange={e => setForm(f => ({ ...f, k: e.target.value }))}
                  className="font-mono text-xs"
                />
              )}
            </Field>

            <Field label="OPc (hex 32)">
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  aria-describedby={describedBy}
                  invalid={invalid}
                  value={form.opc}
                  onChange={e => setForm(f => ({ ...f, opc: e.target.value }))}
                  className="font-mono text-xs"
                />
              )}
            </Field>

            <Field label="AMF (hex 4)">
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  aria-describedby={describedBy}
                  invalid={invalid}
                  value={form.amf}
                  onChange={e => setForm(f => ({ ...f, amf: e.target.value }))}
                  className="font-mono text-xs"
                />
              )}
            </Field>

            <Field
              label={editSUPI ? 'SQN (read-only)' : 'SQN (hex 12)'}
              hint={
                editSUPI
                  ? 'Network-managed: the UDM increments it per authentication. It is preserved on update — writing a stale value back would break UE re-registration.'
                  : undefined
              }
            >
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  aria-describedby={describedBy}
                  invalid={invalid}
                  value={form.sqn}
                  onChange={e => setForm(f => ({ ...f, sqn: e.target.value }))}
                  disabled={!!editSUPI}
                  className="font-mono text-xs"
                />
              )}
            </Field>

            <Field label="AMBR UL (kbps)">
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  aria-describedby={describedBy}
                  invalid={invalid}
                  type="number"
                  value={form.ambr_ul}
                  onChange={e => setForm(f => ({ ...f, ambr_ul: +e.target.value }))}
                />
              )}
            </Field>

            <Field label="AMBR DL (kbps)">
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  aria-describedby={describedBy}
                  invalid={invalid}
                  type="number"
                  value={form.ambr_dl}
                  onChange={e => setForm(f => ({ ...f, ambr_dl: +e.target.value }))}
                />
              )}
            </Field>
          </div>

          {/* Slice + DNN assignment */}
          <div className="mb-4" role="group" aria-labelledby={slicesLabelId}>
            <p id={slicesLabelId} className="mb-2 text-xs font-medium text-muted-fg">
              Authorized Slices (NSSAI) — select DNN per slice
            </p>
            {availableSlices.length === 0 ? (
              <p className="text-xs text-muted-fg">
                No slices configured — add slices on the Slices page first
              </p>
            ) : (
              <div className="flex flex-col gap-3">
                {availableSlices.map(slice => {
                  const active = form.slices.some(s => s.sst === slice.sst && s.sd === slice.sd)
                  const name = sliceName(slice)
                  const assigned = form.slices.find(s => s.sst === slice.sst && s.sd === slice.sd)
                  const key = `${slice.sst}:${slice.sd}`
                  return (
                    <div key={key} className="flex flex-wrap items-end gap-3">
                      <Button
                        variant={active ? 'primary' : 'secondary'}
                        size="sm"
                        aria-pressed={active}
                        onClick={() => toggleSlice(slice)}
                        className="min-w-[10rem]"
                      >
                        {name} (SST:{slice.sst} SD:{slice.sd})
                      </Button>

                      {active &&
                        (availableDNNs.length === 0 ? (
                          <p className="pb-2 text-xs text-warning-fg">
                            No DNNs configured — add on the Slices page
                          </p>
                        ) : (
                          <Field label={`DNN for ${name}`} className="w-56">
                            {({ id }) => (
                              <Select
                                id={id}
                                value={assigned?.dnn ?? ''}
                                options={dnnOptions}
                                onChange={e => setSliceDNN(slice, e.target.value)}
                              />
                            )}
                          </Field>
                        ))}
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          <div className="flex items-center gap-3">
            <Button icon={<Check size={14} />} loading={saving} onClick={submit}>
              {editSUPI ? 'Update' : 'Create'}
            </Button>
            <Button variant="ghost" onClick={resetForm}>
              Cancel
            </Button>
          </div>
        </Card>
      )}

      {/* Subscribers */}
      {isError ? (
        <ErrorState
          title="Failed to load subscribers"
          description={errMessage(error)}
          action={
            <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : (
        <Table caption="Provisioned subscribers">
          <TableHead>
            <TableRow>
              <TableHeaderCell>SUPI</TableHeaderCell>
              <TableHeaderCell>K (partial)</TableHeaderCell>
              <TableHeaderCell>Slices / DNN</TableHeaderCell>
              <TableHeaderCell>AMBR UL/DL</TableHeaderCell>
              <TableHeaderCell>RFSP</TableHeaderCell>
              <TableHeaderCell className="text-right">Actions</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {isLoading ? (
              <TableEmptyRow colSpan={6}>
                <Loading rows={3} label="Loading subscribers…" />
              </TableEmptyRow>
            ) : subscribers.length === 0 ? (
              <TableEmptyRow colSpan={6}>No subscribers provisioned</TableEmptyRow>
            ) : (
              subscribers.map(sub => (
                <TableRow key={sub.supi}>
                  <TableCell mono>{sub.supi}</TableCell>
                  <TableCell mono className="text-muted-fg">
                    {sub.k ? sub.k.slice(0, 8) + '…' : '—'}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap items-center gap-1">
                      {(sub.slices ?? []).map((s, i) => {
                        const name = sliceName(s)
                        return (
                          <span key={i} className="inline-flex items-center gap-1">
                            <Badge label={name} variant={sliceVariant(name)} />
                            {s.dnn && <span className="font-mono text-xs text-muted-fg">{s.dnn}</span>}
                          </span>
                        )
                      })}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs tabular-nums">
                    {(sub.ambr_ul / 1000).toFixed(0)} / {(sub.ambr_dl / 1000).toFixed(0)} Mbps
                  </TableCell>
                  <TableCell>
                    <RFSPCell supi={sub.supi} onApplied={deregistered => notifyDereg(sub.supi, deregistered, 'RFSP')} />
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      <IconButton label={`Edit ${sub.supi}`} variant="ghost" onClick={() => openEdit(sub)}>
                        <Pencil size={14} />
                      </IconButton>
                      <IconButton
                        label={`Delete ${sub.supi}`}
                        variant="ghost"
                        onClick={() => setDeleteTarget(sub.supi)}
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
        open={deleteTarget !== null}
        destructive
        title="Delete subscriber?"
        description={
          deleteTarget
            ? `${deleteTarget} will be cascade-deleted from the authentication, access-mobility, session-management and policy subscription tables. This cannot be undone.`
            : undefined
        }
        confirmLabel="Delete subscriber"
        loading={deleteMut.isPending}
        onConfirm={() => {
          if (deleteTarget) {
            deleteMut.mutate(deleteTarget, { onSuccess: () => setDeleteTarget(null) })
          }
        }}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  )
}

// RFSPCell renders the per-subscriber RFSP (Radio Frequency Selection Priority) box.
// It reads the effective value (per-subscriber override or operator default) and lets
// the operator set a value (1-256) or reset to default. Both actions trigger a
// NW-initiated re-registration so the new RFSP reaches the gNB in the next
// InitialContextSetupRequest (TS 38.413 §9.3.1.27).
function RFSPCell({ supi, onApplied }: { supi: string; onApplied: (deregistered: boolean) => void }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [editing, setEditing] = useState(false)
  const [val, setVal] = useState(1)

  const { data, isLoading } = useQuery({
    queryKey: ['rfsp', supi],
    queryFn: () => getSubscriberRFSP(supi),
    staleTime: 15_000,
  })

  const actionFailed = (verb: string) => (err: unknown) =>
    toast({ variant: 'error', title: `${verb} failed`, description: errMessage(err), duration: 0 })

  const setMut = useMutation({
    mutationFn: (rfsp: number) => setSubscriberRFSP(supi, rfsp),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['rfsp', supi] })
      setEditing(false)
      onApplied(!!r.deregistered)
    },
    onError: actionFailed('Set RFSP'),
  })

  const resetMut = useMutation({
    mutationFn: () => resetSubscriberRFSP(supi),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['rfsp', supi] })
      setEditing(false)
      onApplied(!!r.deregistered)
    },
    onError: actionFailed('Reset RFSP'),
  })

  const isOverride = data?.source === 'override'
  const busy = setMut.isPending || resetMut.isPending
  const invalid = val < 1 || val > 256

  if (isLoading) {
    return <Spinner size={14} label={`Loading RFSP for ${supi}`} />
  }

  if (!editing) {
    return (
      <div className="flex items-center gap-2">
        <Button
          size="sm"
          variant={isOverride ? 'primary' : 'secondary'}
          icon={<Signal size={12} />}
          onClick={() => {
            setVal(data?.rfsp ?? 1)
            setEditing(true)
          }}
          title="Change RFSP for this subscriber"
        >
          {data?.rfsp ?? 1}
        </Button>
        <span className="text-xs text-muted-fg">{isOverride ? 'override' : '(default)'}</span>
      </div>
    )
  }

  return (
    <div className="flex flex-wrap items-start justify-end gap-1.5">
      <Field label="RFSP" error={invalid ? 'Enter 1–256' : undefined} className="w-24">
        {({ id, describedBy, invalid: fieldInvalid }) => (
          <Input
            id={id}
            aria-describedby={describedBy}
            invalid={fieldInvalid}
            type="number"
            min={1}
            max={256}
            value={val}
            autoFocus
            onChange={e => setVal(+e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !invalid) setMut.mutate(val)
              if (e.key === 'Escape') setEditing(false)
            }}
          />
        )}
      </Field>
      <div className="mt-5 flex items-center gap-1">
        <IconButton
          label="Save RFSP"
          variant="ghost"
          disabled={busy || invalid}
          loading={setMut.isPending}
          onClick={() => setMut.mutate(val)}
          title="Save (1–256) — UE re-registers to apply"
        >
          <Check size={14} />
        </IconButton>
        {isOverride && (
          <IconButton
            label="Reset RFSP to operator default"
            variant="ghost"
            disabled={busy}
            loading={resetMut.isPending}
            onClick={() => resetMut.mutate()}
            title="Reset to operator default"
          >
            <RotateCcw size={14} />
          </IconButton>
        )}
        <IconButton label="Cancel RFSP edit" variant="ghost" disabled={busy} onClick={() => setEditing(false)}>
          <X size={14} />
        </IconButton>
      </div>
    </div>
  )
}
