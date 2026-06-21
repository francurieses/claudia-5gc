import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, X, Check, RefreshCw, AlertCircle, RotateCcw, Signal } from 'lucide-react'
import {
  getSubscribers, createSubscriber, updateSubscriber, deleteSubscriber, getSlices, getDNNs,
  getSubscriberRFSP, setSubscriberRFSP, resetSubscriberRFSP,
  type Subscriber, type SNSSAI,
} from '../lib/api'
import PageHeader from '../components/PageHeader'
import Badge from '../components/Badge'

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

const sliceColor = (name: string): 'blue' | 'yellow' | 'gray' | 'green' => {
  if (name === 'internet') return 'blue'
  if (name === 'gold') return 'yellow'
  if (name === 'silver') return 'gray'
  return 'green'
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

export default function Subscribers() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [editSUPI, setEditSUPI] = useState<string | null>(null)
  const [form, setForm] = useState<FormData>(emptyForm())
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [updateNotice, setUpdateNotice] = useState<{ supi: string; deregistered: boolean; what?: string } | null>(null)

  const { data: subscribers = [], isLoading, isError, refetch } = useQuery({
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

  const createMut = useMutation({
    mutationFn: createSubscriber,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['subscribers'] }); resetForm() },
  })

  const updateMut = useMutation({
    mutationFn: ({ supi, data }: { supi: string; data: Partial<Subscriber> }) =>
      updateSubscriber(supi, data),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['subscribers'] })
      resetForm()
      setUpdateNotice({ supi: result.supi, deregistered: result.deregistered })
      setTimeout(() => setUpdateNotice(null), 6_000)
    },
  })

  const deleteMut = useMutation({
    mutationFn: deleteSubscriber,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['subscribers'] }); setDeleteConfirm(null) },
  })

  const resetForm = () => {
    setShowForm(false)
    setEditSUPI(null)
    setForm(emptyForm())
  }

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

  return (
    <div className="p-6">
      <PageHeader
        title="Subscribers"
        subtitle={`${subscribers.length} provisioned`}
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => refetch()}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-200 text-sm rounded-md transition-colors"
              title="Refresh subscriber list"
            >
              <RefreshCw size={13} /> Refresh
            </button>
            <button
              onClick={() => setShowForm(true)}
              className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md transition-colors"
            >
              <Plus size={14} /> New Subscriber
            </button>
          </div>
        }
      />

      {/* Slice-update notification */}
      {updateNotice && (
        <div className={`flex items-center gap-2 rounded-lg px-4 py-3 mb-4 text-sm border ${
          updateNotice.deregistered
            ? 'bg-green-950/40 border-green-800 text-green-300'
            : 'bg-yellow-950/40 border-yellow-800 text-yellow-300'
        }`}>
          {updateNotice.deregistered
            ? <><RotateCcw size={14} /> <span><strong>{updateNotice.supi}</strong> updated. UE has been deregistered and will re-register with the new {updateNotice.what ?? 'slices'}.</span></>
            : <><AlertCircle size={14} /> <span><strong>{updateNotice.supi}</strong> updated. UE is not currently registered — new {updateNotice.what ?? 'slices'} will apply on next registration.</span></>
          }
        </div>
      )}

      {/* Subscriber form */}
      {showForm && (
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-5 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-white">
              {editSUPI ? `Edit ${editSUPI}` : 'New Subscriber'}
            </h3>
            <button onClick={resetForm}><X size={16} className="text-gray-400 hover:text-white" /></button>
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
            <Field label="SUPI (imsi-...)" value={form.supi} onChange={v => setForm(f => ({ ...f, supi: v }))}
              disabled={!!editSUPI} placeholder="imsi-001010000000001" mono />
            <Field label="K (hex 32)" value={form.k} onChange={v => setForm(f => ({ ...f, k: v }))} mono />
            <Field label="OPc (hex 32)" value={form.opc} onChange={v => setForm(f => ({ ...f, opc: v }))} mono />
            <Field label="AMF (hex 4)" value={form.amf} onChange={v => setForm(f => ({ ...f, amf: v }))} mono />
            <Field label="SQN (hex 12)" value={form.sqn} onChange={v => setForm(f => ({ ...f, sqn: v }))} mono />
            <div>
              <label className="block text-xs text-gray-400 mb-1">AMBR UL / DL (kbps)</label>
              <div className="flex gap-2">
                <input type="number" value={form.ambr_ul}
                  onChange={e => setForm(f => ({ ...f, ambr_ul: +e.target.value }))}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white" />
                <input type="number" value={form.ambr_dl}
                  onChange={e => setForm(f => ({ ...f, ambr_dl: +e.target.value }))}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white" />
              </div>
            </div>
          </div>

          {/* Slice + DNN assignment */}
          <div className="mb-4">
            <label className="block text-xs text-gray-400 mb-2">
              Authorized Slices (NSSAI) — select DNN per slice
            </label>
            {availableSlices.length === 0 ? (
              <span className="text-xs text-gray-500">
                No slices configured — add slices on the Slices page first
              </span>
            ) : (
              <div className="flex flex-col gap-2">
                {availableSlices.map(slice => {
                  const active = form.slices.some(s => s.sst === slice.sst && s.sd === slice.sd)
                  const name = sliceName(slice)
                  const assigned = form.slices.find(s => s.sst === slice.sst && s.sd === slice.sd)
                  return (
                    <div key={`${slice.sst}:${slice.sd}`} className="flex items-center gap-3">
                      <button
                        onClick={() => toggleSlice(slice)}
                        className={`px-3 py-1 rounded text-xs font-medium border transition-colors min-w-[140px] text-left ${
                          active
                            ? 'bg-blue-600 border-blue-500 text-white'
                            : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500'
                        }`}
                      >
                        {name} (SST:{slice.sst} SD:{slice.sd})
                      </button>
                      {active && (
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-gray-500">DNN:</span>
                          {availableDNNs.length === 0 ? (
                            <span className="text-xs text-yellow-500">
                              No DNNs configured — add on Slices page
                            </span>
                          ) : (
                            <select
                              value={assigned?.dnn ?? ''}
                              onChange={e => setSliceDNN(slice, e.target.value)}
                              className="bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs text-white"
                            >
                              <option value="">— select DNN —</option>
                              {availableDNNs.map(dnn => (
                                <option key={dnn.name} value={dnn.name}>
                                  {dnn.name}
                                  {dnn.ue_ip_pool ? ` (${dnn.ue_ip_pool})` : ''}
                                </option>
                              ))}
                            </select>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={submit}
              disabled={createMut.isPending || updateMut.isPending}
              className="flex items-center gap-2 px-4 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm rounded-md"
            >
              <Check size={14} /> {editSUPI ? 'Update' : 'Create'}
            </button>
            <button onClick={resetForm} className="text-sm text-gray-400 hover:text-white">Cancel</button>
            {(createMut.error || updateMut.error) && (
              <span className="text-red-400 text-xs">
                {(createMut.error || updateMut.error)?.message}
              </span>
            )}
          </div>
        </div>
      )}

      {/* Subscribers table */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
              <th className="px-4 py-3 text-left">SUPI</th>
              <th className="px-4 py-3 text-left">K (partial)</th>
              <th className="px-4 py-3 text-left">Slices / DNN</th>
              <th className="px-4 py-3 text-left">AMBR UL/DL</th>
              <th className="px-4 py-3 text-left">RFSP</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr><td colSpan={6} className="px-4 py-6 text-center text-gray-500">Loading…</td></tr>
            ) : isError ? (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center">
                  <div className="flex items-center justify-center gap-3 text-red-400">
                    <AlertCircle size={16} />
                    <span className="text-sm">Failed to load subscribers</span>
                    <button
                      onClick={() => refetch()}
                      className="flex items-center gap-1 px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-200 text-xs rounded"
                    >
                      <RefreshCw size={11} /> Retry
                    </button>
                  </div>
                </td>
              </tr>
            ) : subscribers.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-6 text-center text-gray-500">No subscribers provisioned</td></tr>
            ) : (
              subscribers.map(sub => (
                <tr key={sub.supi} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-3 font-mono text-xs text-blue-300">{sub.supi}</td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-400">
                    {sub.k ? sub.k.slice(0, 8) + '…' : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {(sub.slices ?? []).map((s, i) => {
                        const name = sliceName(s)
                        return (
                          <span key={i} className="inline-flex items-center gap-1">
                            <Badge label={name} variant={sliceColor(name)} />
                            {s.dnn && (
                              <span className="text-xs text-gray-500 font-mono">{s.dnn}</span>
                            )}
                          </span>
                        )
                      })}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-300">
                    {(sub.ambr_ul / 1000).toFixed(0)} / {(sub.ambr_dl / 1000).toFixed(0)} Mbps
                  </td>
                  <td className="px-4 py-3">
                    <RFSPCell
                      supi={sub.supi}
                      onApplied={(deregistered) => {
                        setUpdateNotice({ supi: sub.supi, deregistered, what: 'RFSP' })
                        setTimeout(() => setUpdateNotice(null), 6_000)
                      }}
                    />
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button onClick={() => openEdit(sub)}
                        className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded">
                        <Pencil size={13} />
                      </button>
                      {deleteConfirm === sub.supi ? (
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => deleteMut.mutate(sub.supi)}
                            className="px-2 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded"
                          >Confirm</button>
                          <button onClick={() => setDeleteConfirm(null)}
                            className="px-2 py-1 bg-gray-700 text-gray-300 text-xs rounded">Cancel</button>
                        </div>
                      ) : (
                        <button onClick={() => setDeleteConfirm(sub.supi)}
                          className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-gray-700 rounded"
                          title="Delete subscriber">
                          <Trash2 size={13} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Field({
  label, value, onChange, placeholder, mono, disabled,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  mono?: boolean
  disabled?: boolean
}) {
  return (
    <div>
      <label className="block text-xs text-gray-400 mb-1">{label}</label>
      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className={`w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white
          disabled:opacity-50 ${mono ? 'font-mono text-xs' : ''}`}
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
  const [editing, setEditing] = useState(false)
  const [val, setVal] = useState(1)

  const { data, isLoading } = useQuery({
    queryKey: ['rfsp', supi],
    queryFn: () => getSubscriberRFSP(supi),
    staleTime: 15_000,
  })

  const setMut = useMutation({
    mutationFn: (rfsp: number) => setSubscriberRFSP(supi, rfsp),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['rfsp', supi] })
      setEditing(false)
      onApplied(!!r.deregistered)
    },
  })

  const resetMut = useMutation({
    mutationFn: () => resetSubscriberRFSP(supi),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['rfsp', supi] })
      setEditing(false)
      onApplied(!!r.deregistered)
    },
  })

  const isOverride = data?.source === 'override'
  const busy = setMut.isPending || resetMut.isPending
  const invalid = val < 1 || val > 256

  if (isLoading) {
    return <span className="text-xs text-gray-500">…</span>
  }

  if (!editing) {
    return (
      <div className="flex items-center gap-2">
        <button
          onClick={() => { setVal(data?.rfsp ?? 1); setEditing(true) }}
          title="Change RFSP for this subscriber"
          className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium border transition-colors ${
            isOverride
              ? 'bg-purple-600/20 border-purple-500 text-purple-200 hover:bg-purple-600/30'
              : 'bg-gray-800 border-gray-700 text-gray-300 hover:border-gray-500'
          }`}
        >
          <Signal size={12} />
          {data?.rfsp ?? 1}
          {!isOverride && <span className="text-gray-500">(default)</span>}
        </button>
      </div>
    )
  }

  return (
    <div className="flex items-center gap-1.5">
      <input
        type="number"
        min={1}
        max={256}
        value={val}
        autoFocus
        onChange={e => setVal(+e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter' && !invalid) setMut.mutate(val); if (e.key === 'Escape') setEditing(false) }}
        className={`w-16 bg-gray-800 border rounded px-2 py-1 text-xs text-white ${
          invalid ? 'border-red-500' : 'border-gray-600'
        }`}
      />
      <button
        onClick={() => setMut.mutate(val)}
        disabled={busy || invalid}
        title="Save (1-256) — UE re-registers to apply"
        className="p-1 text-green-400 hover:bg-gray-700 rounded disabled:opacity-40"
      >
        <Check size={13} />
      </button>
      {isOverride && (
        <button
          onClick={() => resetMut.mutate()}
          disabled={busy}
          title="Reset to operator default"
          className="p-1 text-gray-400 hover:text-yellow-300 hover:bg-gray-700 rounded disabled:opacity-40"
        >
          <RotateCcw size={13} />
        </button>
      )}
      <button
        onClick={() => setEditing(false)}
        disabled={busy}
        title="Cancel"
        className="p-1 text-gray-400 hover:text-white hover:bg-gray-700 rounded"
      >
        <X size={13} />
      </button>
      {(setMut.error || resetMut.error) && (
        <span className="text-red-400 text-[10px] max-w-[120px] truncate">
          {(setMut.error || resetMut.error)?.message}
        </span>
      )}
    </div>
  )
}
