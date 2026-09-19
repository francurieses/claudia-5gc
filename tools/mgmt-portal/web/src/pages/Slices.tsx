import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Pencil, Plus, RefreshCw, Trash2, X } from 'lucide-react'
import {
  addDNN, addSlice, deleteDNN, deleteSlice, getDNNs, getSlices, updateDNN,
  type DNNInfo, type SNSSAI,
} from '../lib/api'
import {
  Badge, Button, Card, Checkbox, ConfirmDialog, ErrorState, Field, IconButton, Input, Loading,
  PageHeader, Section, Select, Table, TableBody, TableCell, TableEmptyRow, TableHead,
  TableHeaderCell, TableRow, useToast,
} from '../components/ui'
import type { SelectOption } from '../components/ui'

const SST_NAMES: Record<number, string> = { 1: 'eMBB', 2: 'URLLC', 3: 'MIoT', 4: 'V2X' }

const SST_OPTIONS: SelectOption[] = Object.entries(SST_NAMES).map(([value, name]) => ({
  value,
  label: `${value} — ${name}`,
}))

type DNNForm = {
  name: string
  description: string
  ue_ip_pool: string
  n6_network: string
  ue_ipv6_prefix: string
}

const emptyDNNForm = (uePool = '', n6Net = ''): DNNForm => ({
  name: '',
  description: '',
  ue_ip_pool: uePool,
  n6_network: n6Net,
  ue_ipv6_prefix: '',
})

// Standard IPv6 literal (no zone id) — same shape `net.ParseCIDR` accepts on the
// backend before `validateIPv6Prefix` (nfconfig.go) inspects the mask.
const IPV6_ADDRESS =
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/

/**
 * Client-side mirror of the portal's `validateIPv6Prefix` (internal/config/nfconfig.go):
 * an optional IPv6 base prefix in CIDR form whose length is a multiple of 8 in
 * [8,64] — the constraint the SMF IPv6Pool enforces when delegating per-session
 * /64s (TS 23.501 §5.8.2.2). Empty is valid and means IPv4-only.
 */
function validateIPv6Prefix(value: string): string | undefined {
  if (!value) return undefined
  const parts = value.split('/')
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return 'Use CIDR notation, e.g. 2001:db8:60::/56'
  }
  if (!IPV6_ADDRESS.test(parts[0])) {
    return 'Not a valid IPv6 address'
  }
  if (!/^\d+$/.test(parts[1])) {
    return 'Prefix length must be a whole number'
  }
  const length = Number(parts[1])
  if (length < 8 || length > 64 || length % 8 !== 0) {
    return 'Prefix length must be a multiple of 8 between 8 and 64'
  }
  return undefined
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/** Outcome line shared by the slice/DNN toasts: what restarted, or what to do. */
function restartNotice(restarted: string[] | undefined): string {
  return restarted?.length
    ? `Containers restarted: ${restarted.join(', ')}.`
    : 'Saved to NF config — restart the NFs to apply.'
}

export default function Slices() {
  const qc = useQueryClient()
  const { toast } = useToast()

  // ---- Slice state --------------------------------------------------------
  const [showSliceForm, setShowSliceForm] = useState(false)
  const [sliceForm, setSliceForm] = useState<SNSSAI>({ sst: 1, sd: '' })
  const [restartNFs, setRestartNFs] = useState(true)
  const [deleteSliceTarget, setDeleteSliceTarget] = useState<SNSSAI | null>(null)
  const [restartOnDeleteSlice, setRestartOnDeleteSlice] = useState(true)

  // ---- DNN state ----------------------------------------------------------
  const [showDNNForm, setShowDNNForm] = useState(false)
  const [editDNNName, setEditDNNName] = useState<string | null>(null)
  const [dnnForm, setDNNForm] = useState<DNNForm>(emptyDNNForm())
  const [ipv6Touched, setIpv6Touched] = useState(false)
  const [restartDNN, setRestartDNN] = useState(true)
  const [deleteDNNTarget, setDeleteDNNTarget] = useState<string | null>(null)
  const [restartOnDeleteDNN, setRestartOnDeleteDNN] = useState(true)

  // ---- Queries ------------------------------------------------------------
  const {
    data: slices = [],
    isLoading: slicesLoading,
    isError: slicesError,
    error: slicesErr,
    refetch: refetchSlices,
  } = useQuery({
    queryKey: ['slices'],
    queryFn: getSlices,
  })

  const {
    data: dnnResponse,
    isLoading: dnnsLoading,
    isError: dnnsError,
    error: dnnsErr,
    refetch: refetchDNNs,
  } = useQuery({
    queryKey: ['dnns'],
    queryFn: getDNNs,
  })
  const dnns = dnnResponse?.dnns ?? []
  const nextUEPool = dnnResponse?.next_ue_pool ?? ''
  const nextN6Net = dnnResponse?.next_n6_network ?? ''

  const actionFailed = (verb: string) => (err: unknown) =>
    toast({ variant: 'error', title: `${verb} failed`, description: errMessage(err), duration: 0 })

  // ---- Slice mutations ----------------------------------------------------
  const addSliceMut = useMutation({
    mutationFn: ({ slice, restart }: { slice: SNSSAI; restart: boolean }) =>
      addSlice(slice, restart),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['slices'] })
      setShowSliceForm(false)
      setSliceForm({ sst: 1, sd: '' })
      toast({
        variant: 'success',
        title: `Slice SST ${result.slice.sst} added`,
        description: restartNotice(result.restarted),
      })
    },
    onError: actionFailed('Add slice'),
  })

  const deleteSliceMut = useMutation({
    mutationFn: ({ sst, sd, restart }: { sst: number; sd: string; restart: boolean }) =>
      deleteSlice(sst, sd, restart),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['slices'] })
      setDeleteSliceTarget(null)
      toast({
        variant: 'success',
        title: 'Slice deleted',
        description: restartNotice(result.restarted),
      })
    },
    onError: actionFailed('Delete slice'),
  })

  // ---- DNN mutations -------------------------------------------------------
  const addDNNMut = useMutation({
    mutationFn: (req: { form: DNNForm; restart: boolean }) =>
      addDNN({
        name: req.form.name,
        ue_ip_pool: req.form.ue_ip_pool,
        n6_network: req.form.n6_network,
        description: req.form.description,
        ue_ipv6_prefix: req.form.ue_ipv6_prefix.trim() || undefined,
      }, req.restart),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['dnns'] })
      setShowDNNForm(false)
      setDNNForm(emptyDNNForm())
      setIpv6Touched(false)
      const errors = result.docker_errors ?? []
      if (errors.length) {
        toast({
          variant: 'warning',
          title: `DNN "${result.dnn.name}" created`,
          description: `Docker warnings: ${errors.join('; ')}`,
          duration: 0,
        })
      } else {
        toast({
          variant: 'success',
          title: `DNN "${result.dnn.name}" created`,
          description: restartNotice(result.restarted),
        })
      }
    },
    onError: actionFailed('Create DNN'),
  })

  const updateDNNMut = useMutation({
    mutationFn: ({ name, description, ue_ipv6_prefix, restart }: { name: string; description: string; ue_ipv6_prefix: string; restart: boolean }) =>
      updateDNN(name, { description, ue_ipv6_prefix, restart }),
    onSuccess: (result, vars) => {
      qc.invalidateQueries({ queryKey: ['dnns'] })
      setShowDNNForm(false)
      setEditDNNName(null)
      setIpv6Touched(false)
      const errors = result.docker_errors ?? []
      if (errors.length) {
        toast({
          variant: 'warning',
          title: `DNN "${vars.name}" updated`,
          description: `Docker warnings: ${errors.join('; ')}`,
          duration: 0,
        })
      } else {
        toast({
          variant: 'success',
          title: `DNN "${vars.name}" updated`,
          description: restartNotice(result.restarted),
        })
      }
    },
    onError: actionFailed('Update DNN'),
  })

  const deleteDNNMut = useMutation({
    mutationFn: ({ name, restart }: { name: string; restart: boolean }) =>
      deleteDNN(name, restart),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['dnns'] })
      setDeleteDNNTarget(null)
      const errors = result.docker_errors ?? []
      if (errors.length) {
        toast({
          variant: 'warning',
          title: `DNN "${result.name}" deleted`,
          description: `Docker warnings: ${errors.join('; ')}`,
          duration: 0,
        })
      } else {
        toast({
          variant: 'success',
          title: `DNN "${result.name}" deleted`,
          description: restartNotice(result.restarted),
        })
      }
    },
    onError: actionFailed('Delete DNN'),
  })

  const sliceKey = (s: SNSSAI) => `${s.sst}:${s.sd}`

  const openAddDNN = () => {
    setEditDNNName(null)
    setDNNForm(emptyDNNForm(nextUEPool, nextN6Net))
    setIpv6Touched(false)
    setShowDNNForm(true)
  }

  const openEditDNN = (d: DNNInfo) => {
    setEditDNNName(d.name)
    setDNNForm({
      name: d.name,
      description: d.description ?? '',
      ue_ip_pool: d.ue_ip_pool,
      n6_network: d.n6_network ?? '',
      ue_ipv6_prefix: d.ue_ipv6_prefix ?? '',
    })
    setIpv6Touched(false)
    setShowDNNForm(true)
  }

  const closeDNNForm = () => {
    setShowDNNForm(false)
    setEditDNNName(null)
    setIpv6Touched(false)
  }

  // Submitted value is trimmed so a stray space cannot reach the backend, which
  // rejects anything `net.ParseCIDR` cannot read.
  const ipv6Prefix = dnnForm.ue_ipv6_prefix.trim()
  const ipv6Error = validateIPv6Prefix(ipv6Prefix)
  const dnnSaving = addDNNMut.isPending || updateDNNMut.isPending

  const submitDNN = () => {
    if (ipv6Error) {
      setIpv6Touched(true)
      return
    }
    if (editDNNName) {
      updateDNNMut.mutate({
        name: editDNNName,
        description: dnnForm.description,
        ue_ipv6_prefix: ipv6Prefix,
        restart: restartDNN,
      })
    } else {
      addDNNMut.mutate({ form: dnnForm, restart: restartDNN })
    }
  }

  return (
    <div className="space-y-8 p-6">

      {/* ================================================================
          NETWORK SLICES (S-NSSAI)
      ================================================================ */}
      <PageHeader
        eyebrow="Data & Config"
        title="Network Slices"
        subtitle="Configured S-NSSAIs across AMF, SMF, and NSSF"
        action={
          <Button size="sm" icon={<Plus size={14} />} onClick={() => setShowSliceForm(true)}>
            Add Slice
          </Button>
        }
      />

      {/* Add slice form */}
      {showSliceForm && (
        <Card className="max-w-sm">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="text-sm font-semibold text-fg">New Network Slice</h2>
            <IconButton label="Close new slice form" variant="ghost" onClick={() => setShowSliceForm(false)}>
              <X size={16} />
            </IconButton>
          </div>

          <div className="mb-4 space-y-3">
            <Field label="SST (Slice/Service Type)">
              {({ id }) => (
                <Select
                  id={id}
                  value={String(sliceForm.sst)}
                  options={SST_OPTIONS}
                  onChange={e => setSliceForm(f => ({ ...f, sst: +e.target.value }))}
                />
              )}
            </Field>

            <Field label="SD (Slice Differentiator)" hint="6 hex digits (optional)">
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  aria-describedby={describedBy}
                  invalid={invalid}
                  value={sliceForm.sd}
                  onChange={e => setSliceForm(f => ({ ...f, sd: e.target.value }))}
                  placeholder="000001"
                  maxLength={6}
                  className="font-mono"
                />
              )}
            </Field>

            <Checkbox
              checked={restartNFs}
              onChange={setRestartNFs}
              label="Restart AMF, SMF and NSSF after saving"
            />
          </div>

          <div className="flex items-center gap-3">
            <Button
              icon={<Check size={14} />}
              loading={addSliceMut.isPending}
              disabled={addSliceMut.isPending}
              onClick={() => addSliceMut.mutate({ slice: sliceForm, restart: restartNFs })}
            >
              {restartNFs ? 'Save & Restart NFs' : 'Save Slice'}
            </Button>
            <Button variant="ghost" onClick={() => setShowSliceForm(false)}>
              Cancel
            </Button>
          </div>
        </Card>
      )}

      {slicesError ? (
        <ErrorState
          title="Failed to load slices"
          description={errMessage(slicesErr)}
          action={
            <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetchSlices()}>
              Retry
            </Button>
          }
        />
      ) : (
        <Table caption="Configured network slices (S-NSSAI)">
          <TableHead>
            <TableRow>
              <TableHeaderCell>SST</TableHeaderCell>
              <TableHeaderCell>SD</TableHeaderCell>
              <TableHeaderCell>Type</TableHeaderCell>
              <TableHeaderCell>Note</TableHeaderCell>
              <TableHeaderCell className="text-right">Actions</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {slicesLoading ? (
              <TableEmptyRow colSpan={5}>
                <Loading rows={3} label="Loading slices…" />
              </TableEmptyRow>
            ) : slices.length === 0 ? (
              <TableEmptyRow colSpan={5}>No slices configured</TableEmptyRow>
            ) : (
              slices.map(s => (
                <TableRow key={sliceKey(s)}>
                  <TableCell mono>{s.sst}</TableCell>
                  <TableCell mono className="text-muted-fg">
                    {s.sd || '—'}
                  </TableCell>
                  <TableCell>
                    <Badge label={SST_NAMES[s.sst] ?? 'Unknown'} variant="info" />
                  </TableCell>
                  <TableCell className="text-xs text-muted-fg">
                    Restart NFs to apply changes
                  </TableCell>
                  <TableCell className="text-right">
                    <IconButton
                      label={`Delete slice SST ${s.sst} SD ${s.sd || '—'}`}
                      variant="ghost"
                      onClick={() => setDeleteSliceTarget(s)}
                    >
                      <Trash2 size={14} />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      )}

      {/* ================================================================
          DATA NETWORKS (DNNs)
      ================================================================ */}
      <Section
        bare
        title="Data Networks (DNNs)"
        description="Per-DNN UE IP pools and N6 Docker bridge networks — edit configs + subnet lifecycle"
        actions={
          <Button size="sm" icon={<Plus size={14} />} onClick={openAddDNN}>
            Add DNN
          </Button>
        }
      >
        {/* Add / Edit DNN form */}
        {showDNNForm && (
          <Card className="mb-4 max-w-lg">
            <div className="mb-4 flex items-center justify-between gap-3">
              <h2 className="text-sm font-semibold text-fg">
                {editDNNName ? `Edit DNN: ${editDNNName}` : 'New Data Network (DNN)'}
              </h2>
              <IconButton label="Close DNN form" variant="ghost" onClick={closeDNNForm}>
                <X size={16} />
              </IconButton>
            </div>

            <div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field
                label="DNN Name"
                hint="Lowercase letters, digits and hyphens"
                className={editDNNName ? 'sm:col-span-2' : ''}
              >
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    aria-describedby={describedBy}
                    invalid={invalid}
                    value={dnnForm.name}
                    onChange={e => setDNNForm(f => ({ ...f, name: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '') }))}
                    placeholder="e.g. mms"
                    disabled={!!editDNNName}
                    className="font-mono"
                  />
                )}
              </Field>

              {!editDNNName && (
                <>
                  <Field label="UE IP Pool (CIDR)">
                    {({ id, describedBy, invalid }) => (
                      <Input
                        id={id}
                        aria-describedby={describedBy}
                        invalid={invalid}
                        value={dnnForm.ue_ip_pool}
                        onChange={e => setDNNForm(f => ({ ...f, ue_ip_pool: e.target.value }))}
                        placeholder="10.62.0.0/24"
                        className="font-mono"
                      />
                    )}
                  </Field>
                  <Field label="N6 Docker Network (CIDR)">
                    {({ id, describedBy, invalid }) => (
                      <Input
                        id={id}
                        aria-describedby={describedBy}
                        invalid={invalid}
                        value={dnnForm.n6_network}
                        onChange={e => setDNNForm(f => ({ ...f, n6_network: e.target.value }))}
                        placeholder="172.30.8.0/24"
                        className="font-mono"
                      />
                    )}
                  </Field>
                </>
              )}

              <Field label="Description (optional)" className="sm:col-span-2">
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    aria-describedby={describedBy}
                    invalid={invalid}
                    value={dnnForm.description}
                    onChange={e => setDNNForm(f => ({ ...f, description: e.target.value }))}
                    placeholder="e.g. Multimedia messaging service"
                  />
                )}
              </Field>

              <Field
                label="IPv6 Prefix (optional)"
                className="sm:col-span-2"
                error={ipv6Touched ? ipv6Error : undefined}
                hint="Base /8–/64 (multiple of 8) the SMF delegates per-session /64s from; empty = IPv4-only. Requires SMF/UPF restart to take effect (TS 23.501 §5.8.2.2)."
              >
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    aria-describedby={describedBy}
                    invalid={invalid}
                    value={dnnForm.ue_ipv6_prefix}
                    onChange={e => setDNNForm(f => ({ ...f, ue_ipv6_prefix: e.target.value }))}
                    onBlur={() => setIpv6Touched(true)}
                    placeholder="2001:db8:60::/56"
                    className="font-mono"
                  />
                )}
              </Field>
            </div>

            {!editDNNName && (
              <p className="mb-3 text-xs text-muted-fg">
                TUN device, gateway IP, and Docker network will be derived automatically.
                SMF and UPF configs will be updated.
              </p>
            )}

            <Checkbox
              className="mb-4"
              checked={restartDNN}
              onChange={setRestartDNN}
              label="Restart SMF and UPF after saving"
            />

            <div className="flex items-center gap-3">
              <Button
                icon={<Check size={14} />}
                loading={dnnSaving}
                disabled={dnnSaving}
                onClick={submitDNN}
              >
                {editDNNName
                  ? (restartDNN ? 'Update & Restart NFs' : 'Update DNN')
                  : (restartDNN ? 'Save & Restart NFs' : 'Save DNN')}
              </Button>
              <Button variant="ghost" onClick={closeDNNForm}>
                Cancel
              </Button>
            </div>
          </Card>
        )}

        {dnnsError ? (
          <ErrorState
            title="Failed to load data networks"
            description={errMessage(dnnsErr)}
            action={
              <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetchDNNs()}>
                Retry
              </Button>
            }
          />
        ) : (
          <Table caption="Configured data networks (DNNs)">
            <TableHead>
              <TableRow>
                <TableHeaderCell>Name</TableHeaderCell>
                <TableHeaderCell>UE IP Pool</TableHeaderCell>
                <TableHeaderCell>IPv6 Prefix</TableHeaderCell>
                <TableHeaderCell>N6 Network</TableHeaderCell>
                <TableHeaderCell>TUN / Docker Net</TableHeaderCell>
                <TableHeaderCell>Description</TableHeaderCell>
                <TableHeaderCell className="text-right">Actions</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {dnnsLoading ? (
                <TableEmptyRow colSpan={7}>
                  <Loading rows={3} label="Loading data networks…" />
                </TableEmptyRow>
              ) : dnns.length === 0 ? (
                <TableEmptyRow colSpan={7}>No DNNs configured</TableEmptyRow>
              ) : (
                dnns.map(dnn => (
                  <TableRow key={dnn.name}>
                    <TableCell mono>{dnn.name}</TableCell>
                    <TableCell mono>{dnn.ue_ip_pool}</TableCell>
                    <TableCell mono>
                      {dnn.ue_ipv6_prefix || <span className="text-muted-fg">—</span>}
                    </TableCell>
                    <TableCell mono className="text-muted-fg">
                      {dnn.n6_network || '—'}
                    </TableCell>
                    <TableCell className="text-xs text-muted-fg">
                      {dnn.tun_name && <span className="font-mono">{dnn.tun_name}</span>}
                      {dnn.tun_name && dnn.docker_network && <span> · </span>}
                      {dnn.docker_network && <span>{dnn.docker_network}</span>}
                    </TableCell>
                    <TableCell className="max-w-[180px] truncate text-xs text-muted-fg">
                      {dnn.description || '—'}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <IconButton label={`Edit DNN ${dnn.name}`} variant="ghost" onClick={() => openEditDNN(dnn)}>
                          <Pencil size={14} />
                        </IconButton>
                        <IconButton
                          label={`Delete DNN ${dnn.name}`}
                          variant="ghost"
                          onClick={() => setDeleteDNNTarget(dnn.name)}
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
      </Section>

      {/* Delete slice — cascade into AMF/SMF/NSSF config, optionally restarting */}
      <ConfirmDialog
        open={deleteSliceTarget !== null}
        destructive
        title="Delete network slice?"
        description={
          deleteSliceTarget
            ? `SST ${deleteSliceTarget.sst}${deleteSliceTarget.sd ? ` / SD ${deleteSliceTarget.sd}` : ''} will be removed from the AMF, SMF and NSSF slice config. This cannot be undone.`
            : undefined
        }
        confirmLabel="Delete slice"
        loading={deleteSliceMut.isPending}
        onConfirm={() => {
          if (deleteSliceTarget) {
            deleteSliceMut.mutate({
              sst: deleteSliceTarget.sst,
              sd: deleteSliceTarget.sd,
              restart: restartOnDeleteSlice,
            })
          }
        }}
        onCancel={() => setDeleteSliceTarget(null)}
      >
        <Checkbox
          checked={restartOnDeleteSlice}
          onChange={setRestartOnDeleteSlice}
          label="Restart AMF, SMF and NSSF after deleting"
        />
      </ConfirmDialog>

      {/* Delete DNN — removes config + Docker network, optionally restarting */}
      <ConfirmDialog
        open={deleteDNNTarget !== null}
        destructive
        title="Delete data network?"
        description={
          deleteDNNTarget
            ? `"${deleteDNNTarget}" will be removed from operator.yaml, SMF and UPF config, and its Docker network disconnected and removed. This cannot be undone.`
            : undefined
        }
        confirmLabel="Delete DNN"
        loading={deleteDNNMut.isPending}
        onConfirm={() => {
          if (deleteDNNTarget) {
            deleteDNNMut.mutate({ name: deleteDNNTarget, restart: restartOnDeleteDNN })
          }
        }}
        onCancel={() => setDeleteDNNTarget(null)}
      >
        <Checkbox
          checked={restartOnDeleteDNN}
          onChange={setRestartOnDeleteDNN}
          label="Restart SMF and UPF after deleting"
        />
      </ConfirmDialog>
    </div>
  )
}
