import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Pencil, RotateCcw, X, Check, Network, AlertCircle } from 'lucide-react'
import {
  getSlices, addSlice, deleteSlice, getDNNs, addDNN, updateDNN, deleteDNN,
  type SNSSAI, type DNNInfo,
} from '../lib/api'
import PageHeader from '../components/PageHeader'
import Badge from '../components/Badge'

const SST_NAMES: Record<number, string> = { 1: 'eMBB', 2: 'URLLC', 3: 'MIoT', 4: 'V2X' }

type DNNForm = {
  name: string
  description: string
  ue_ip_pool: string
  n6_network: string
}

const emptyDNNForm = (uePool = '', n6Net = ''): DNNForm => ({
  name: '',
  description: '',
  ue_ip_pool: uePool,
  n6_network: n6Net,
})

export default function Slices() {
  const qc = useQueryClient()

  // ---- Slice state --------------------------------------------------------
  const [showSliceForm, setShowSliceForm] = useState(false)
  const [sliceForm, setSliceForm] = useState<SNSSAI>({ sst: 1, sd: '' })
  const [restartNFs, setRestartNFs] = useState(true)
  const [deleteSliceConfirm, setDeleteSliceConfirm] = useState<string | null>(null)
  const [restartOnDeleteSlice, setRestartOnDeleteSlice] = useState(true)
  const [lastRestartedSlice, setLastRestartedSlice] = useState<string[]>([])

  // ---- DNN state ----------------------------------------------------------
  const [showDNNForm, setShowDNNForm] = useState(false)
  const [editDNNName, setEditDNNName] = useState<string | null>(null)
  const [dnnForm, setDNNForm] = useState<DNNForm>(emptyDNNForm())
  const [restartDNN, setRestartDNN] = useState(true)
  const [deleteDNNConfirm, setDeleteDNNConfirm] = useState<string | null>(null)
  const [restartOnDeleteDNN, setRestartOnDeleteDNN] = useState(true)
  const [dnnNotice, setDNNNotice] = useState<{ msg: string; type: 'ok' | 'warn' } | null>(null)

  // ---- Queries ------------------------------------------------------------
  const { data: slices = [], isLoading: slicesLoading } = useQuery({
    queryKey: ['slices'],
    queryFn: getSlices,
  })

  const { data: dnnResponse, isLoading: dnnsLoading } = useQuery({
    queryKey: ['dnns'],
    queryFn: getDNNs,
  })
  const dnns = dnnResponse?.dnns ?? []
  const nextUEPool = dnnResponse?.next_ue_pool ?? ''
  const nextN6Net = dnnResponse?.next_n6_network ?? ''

  // ---- Slice mutations ----------------------------------------------------
  const addSliceMut = useMutation({
    mutationFn: ({ slice, restart }: { slice: SNSSAI; restart: boolean }) =>
      addSlice(slice, restart),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['slices'] })
      setShowSliceForm(false)
      setSliceForm({ sst: 1, sd: '' })
      if (result.restarted?.length) {
        setLastRestartedSlice(result.restarted)
        setTimeout(() => setLastRestartedSlice([]), 5_000)
      }
    },
  })

  const deleteSliceMut = useMutation({
    mutationFn: ({ sst, sd, restart }: { sst: number; sd: string; restart: boolean }) =>
      deleteSlice(sst, sd, restart),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['slices'] })
      setDeleteSliceConfirm(null)
      if (result.restarted?.length) {
        setLastRestartedSlice(result.restarted)
        setTimeout(() => setLastRestartedSlice([]), 5_000)
      }
    },
  })

  // ---- DNN mutations -------------------------------------------------------
  const addDNNMut = useMutation({
    mutationFn: (req: { form: DNNForm; restart: boolean }) =>
      addDNN({
        name: req.form.name,
        ue_ip_pool: req.form.ue_ip_pool,
        n6_network: req.form.n6_network,
        description: req.form.description,
      }, req.restart),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['dnns'] })
      setShowDNNForm(false)
      setDNNForm(emptyDNNForm())
      const restarted = result.restarted ?? []
      const errors = result.docker_errors ?? []
      if (errors.length) {
        setDNNNotice({ msg: `DNN created. Docker warnings: ${errors.join('; ')}`, type: 'warn' })
      } else {
        setDNNNotice({
          msg: `DNN "${result.dnn.name}" created${restarted.length ? ` · restarted: ${restarted.join(', ')}` : ''}.`,
          type: 'ok',
        })
      }
      setTimeout(() => setDNNNotice(null), 7_000)
    },
  })

  const updateDNNMut = useMutation({
    mutationFn: ({ name, description }: { name: string; description: string }) =>
      updateDNN(name, description),
    onSuccess: (_r, vars) => {
      qc.invalidateQueries({ queryKey: ['dnns'] })
      setShowDNNForm(false)
      setEditDNNName(null)
      setDNNNotice({ msg: `DNN "${vars.name}" description updated.`, type: 'ok' })
      setTimeout(() => setDNNNotice(null), 4_000)
    },
  })

  const deleteDNNMut = useMutation({
    mutationFn: ({ name, restart }: { name: string; restart: boolean }) =>
      deleteDNN(name, restart),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['dnns'] })
      setDeleteDNNConfirm(null)
      const errors = result.docker_errors ?? []
      const restarted = result.restarted ?? []
      if (errors.length) {
        setDNNNotice({ msg: `DNN deleted. Docker warnings: ${errors.join('; ')}`, type: 'warn' })
      } else {
        setDNNNotice({
          msg: `DNN "${result.name}" deleted${restarted.length ? ` · restarted: ${restarted.join(', ')}` : ''}.`,
          type: 'ok',
        })
      }
      setTimeout(() => setDNNNotice(null), 7_000)
    },
  })

  const sliceKey = (s: SNSSAI) => `${s.sst}:${s.sd}`

  const openAddDNN = () => {
    setEditDNNName(null)
    setDNNForm(emptyDNNForm(nextUEPool, nextN6Net))
    setShowDNNForm(true)
  }

  const openEditDNN = (d: DNNInfo) => {
    setEditDNNName(d.name)
    setDNNForm({ name: d.name, description: d.description ?? '', ue_ip_pool: d.ue_ip_pool, n6_network: d.n6_network ?? '' })
    setShowDNNForm(true)
  }

  const submitDNN = () => {
    if (editDNNName) {
      updateDNNMut.mutate({ name: editDNNName, description: dnnForm.description })
    } else {
      addDNNMut.mutate({ form: dnnForm, restart: restartDNN })
    }
  }

  return (
    <div className="p-6 space-y-10">

      {/* ================================================================
          NETWORK SLICES
      ================================================================ */}
      <section>
        <PageHeader
          title="Network Slices"
          subtitle="Configured S-NSSAIs across AMF, SMF, and NSSF"
          action={
            <button
              onClick={() => setShowSliceForm(true)}
              className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md"
            >
              <Plus size={14} /> Add Slice
            </button>
          }
        />

        {lastRestartedSlice.length > 0 && (
          <div className="flex items-center gap-2 bg-green-950/40 border border-green-800 rounded-lg px-4 py-3 mb-4 text-sm text-green-300">
            <RotateCcw size={14} />
            <span>Slice saved and containers restarted: <strong>{lastRestartedSlice.join(', ')}</strong></span>
          </div>
        )}

        {/* Add slice form */}
        {showSliceForm && (
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-5 mb-6 max-w-sm">
            <h3 className="text-sm font-semibold text-white mb-4">New Network Slice</h3>
            <div className="mb-3">
              <label className="block text-xs text-gray-400 mb-1">SST (Slice/Service Type)</label>
              <select
                value={sliceForm.sst}
                onChange={e => setSliceForm(f => ({ ...f, sst: +e.target.value }))}
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white"
              >
                {Object.entries(SST_NAMES).map(([v, name]) => (
                  <option key={v} value={v}>{v} — {name}</option>
                ))}
              </select>
            </div>
            <div className="mb-4">
              <label className="block text-xs text-gray-400 mb-1">SD (Slice Differentiator, 6 hex digits)</label>
              <input
                type="text"
                value={sliceForm.sd}
                onChange={e => setSliceForm(f => ({ ...f, sd: e.target.value }))}
                placeholder="000001"
                maxLength={6}
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-white"
              />
            </div>
            <label className="flex items-center gap-2 mb-4 cursor-pointer">
              <input
                type="checkbox"
                checked={restartNFs}
                onChange={e => setRestartNFs(e.target.checked)}
                className="w-4 h-4 rounded accent-blue-500"
              />
              <span className="text-sm text-gray-300">Restart AMF, SMF and NSSF after saving</span>
            </label>
            <div className="flex gap-3">
              <button
                onClick={() => addSliceMut.mutate({ slice: sliceForm, restart: restartNFs })}
                disabled={addSliceMut.isPending}
                className="flex items-center gap-2 px-4 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm rounded-md"
              >
                {addSliceMut.isPending && <RotateCcw size={13} className="animate-spin" />}
                {restartNFs ? 'Save & Restart NFs' : 'Save Slice'}
              </button>
              <button onClick={() => setShowSliceForm(false)} className="text-sm text-gray-400 hover:text-white">
                Cancel
              </button>
            </div>
            {addSliceMut.error && (
              <p className="text-red-400 text-xs mt-2">{addSliceMut.error.message}</p>
            )}
          </div>
        )}

        <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
                <th className="px-4 py-3 text-left">SST</th>
                <th className="px-4 py-3 text-left">SD</th>
                <th className="px-4 py-3 text-left">Type</th>
                <th className="px-4 py-3 text-left">Note</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {slicesLoading ? (
                <tr><td colSpan={5} className="px-4 py-6 text-center text-gray-500">Loading…</td></tr>
              ) : slices.length === 0 ? (
                <tr><td colSpan={5} className="px-4 py-6 text-center text-gray-500">No slices configured</td></tr>
              ) : (
                slices.map(s => {
                  const key = sliceKey(s)
                  return (
                    <tr key={key} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                      <td className="px-4 py-3 font-mono text-white">{s.sst}</td>
                      <td className="px-4 py-3 font-mono text-xs text-gray-300">{s.sd || '—'}</td>
                      <td className="px-4 py-3">
                        <Badge label={SST_NAMES[s.sst] ?? 'Unknown'} variant="blue" />
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-500">
                        Restart NFs to apply changes
                      </td>
                      <td className="px-4 py-3 text-right">
                        {deleteSliceConfirm === key ? (
                          <div className="flex items-center justify-end gap-2 flex-wrap">
                            <label className="flex items-center gap-1 text-xs text-gray-400 cursor-pointer">
                              <input
                                type="checkbox"
                                checked={restartOnDeleteSlice}
                                onChange={e => setRestartOnDeleteSlice(e.target.checked)}
                                className="accent-blue-500"
                              />
                              Restart NFs
                            </label>
                            <button
                              onClick={() => deleteSliceMut.mutate({ sst: s.sst, sd: s.sd, restart: restartOnDeleteSlice })}
                              disabled={deleteSliceMut.isPending}
                              className="px-2 py-1 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white text-xs rounded"
                            >Confirm delete</button>
                            <button onClick={() => setDeleteSliceConfirm(null)}
                              className="px-2 py-1 bg-gray-700 text-gray-300 text-xs rounded">Cancel</button>
                          </div>
                        ) : (
                          <button onClick={() => setDeleteSliceConfirm(key)}
                            className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-gray-700 rounded"
                            title="Delete slice">
                            <Trash2 size={13} />
                          </button>
                        )}
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* ================================================================
          DATA NETWORKS (DNNs)
      ================================================================ */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Network size={18} className="text-blue-400" /> Data Networks (DNNs)
            </h2>
            <p className="text-sm text-gray-400 mt-0.5">
              Per-DNN UE IP pools and N6 Docker bridge networks — edit configs + subnet lifecycle
            </p>
          </div>
          <button
            onClick={openAddDNN}
            className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md"
          >
            <Plus size={14} /> Add DNN
          </button>
        </div>

        {/* DNN notification */}
        {dnnNotice && (
          <div className={`flex items-center gap-2 rounded-lg px-4 py-3 mb-4 text-sm border ${
            dnnNotice.type === 'ok'
              ? 'bg-green-950/40 border-green-800 text-green-300'
              : 'bg-yellow-950/40 border-yellow-800 text-yellow-300'
          }`}>
            {dnnNotice.type === 'ok' ? <RotateCcw size={14} /> : <AlertCircle size={14} />}
            <span>{dnnNotice.msg}</span>
          </div>
        )}

        {/* Add / Edit DNN form */}
        {showDNNForm && (
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-5 mb-6 max-w-lg">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-white">
                {editDNNName ? `Edit DNN: ${editDNNName}` : 'New Data Network (DNN)'}
              </h3>
              <button onClick={() => { setShowDNNForm(false); setEditDNNName(null) }}>
                <X size={16} className="text-gray-400 hover:text-white" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-4">
              <div className={editDNNName ? 'col-span-2' : ''}>
                <label className="block text-xs text-gray-400 mb-1">DNN Name</label>
                <input
                  type="text"
                  value={dnnForm.name}
                  onChange={e => setDNNForm(f => ({ ...f, name: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '') }))}
                  placeholder="e.g. mms"
                  disabled={!!editDNNName}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white font-mono disabled:opacity-50"
                />
              </div>
              {!editDNNName && (
                <>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1">UE IP Pool (CIDR)</label>
                    <input
                      type="text"
                      value={dnnForm.ue_ip_pool}
                      onChange={e => setDNNForm(f => ({ ...f, ue_ip_pool: e.target.value }))}
                      placeholder="10.62.0.0/24"
                      className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1">N6 Docker Network (CIDR)</label>
                    <input
                      type="text"
                      value={dnnForm.n6_network}
                      onChange={e => setDNNForm(f => ({ ...f, n6_network: e.target.value }))}
                      placeholder="172.30.8.0/24"
                      className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white font-mono"
                    />
                  </div>
                </>
              )}
              <div className={!editDNNName ? 'col-span-2' : ''}>
                <label className="block text-xs text-gray-400 mb-1">Description (optional)</label>
                <input
                  type="text"
                  value={dnnForm.description}
                  onChange={e => setDNNForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="e.g. Multimedia messaging service"
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-white"
                />
              </div>
            </div>

            {!editDNNName && (
              <>
                <p className="text-xs text-gray-500 mb-3">
                  TUN device, gateway IP, and Docker network will be derived automatically.
                  SMF and UPF configs will be updated. Use "Restart NFs" to apply immediately.
                </p>
                <label className="flex items-center gap-2 mb-4 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={restartDNN}
                    onChange={e => setRestartDNN(e.target.checked)}
                    className="w-4 h-4 rounded accent-blue-500"
                  />
                  <span className="text-sm text-gray-300">Restart SMF and UPF after saving</span>
                </label>
              </>
            )}

            <div className="flex gap-3">
              <button
                onClick={submitDNN}
                disabled={addDNNMut.isPending || updateDNNMut.isPending}
                className="flex items-center gap-2 px-4 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm rounded-md"
              >
                {(addDNNMut.isPending || updateDNNMut.isPending) && <RotateCcw size={13} className="animate-spin" />}
                <Check size={14} /> {editDNNName ? 'Update Description' : (restartDNN ? 'Save & Restart NFs' : 'Save DNN')}
              </button>
              <button
                onClick={() => { setShowDNNForm(false); setEditDNNName(null) }}
                className="text-sm text-gray-400 hover:text-white"
              >
                Cancel
              </button>
            </div>
            {(addDNNMut.error || updateDNNMut.error) && (
              <p className="text-red-400 text-xs mt-2">{(addDNNMut.error || updateDNNMut.error)?.message}</p>
            )}
          </div>
        )}

        <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
                <th className="px-4 py-3 text-left">Name</th>
                <th className="px-4 py-3 text-left">UE IP Pool</th>
                <th className="px-4 py-3 text-left">N6 Network</th>
                <th className="px-4 py-3 text-left">TUN / Docker Net</th>
                <th className="px-4 py-3 text-left">Description</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {dnnsLoading ? (
                <tr><td colSpan={6} className="px-4 py-6 text-center text-gray-500">Loading…</td></tr>
              ) : dnns.length === 0 ? (
                <tr><td colSpan={6} className="px-4 py-6 text-center text-gray-500">No DNNs configured</td></tr>
              ) : (
                dnns.map(dnn => (
                  <tr key={dnn.name} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="px-4 py-3 font-mono text-white text-xs">{dnn.name}</td>
                    <td className="px-4 py-3 font-mono text-xs text-blue-300">{dnn.ue_ip_pool}</td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-400">{dnn.n6_network || '—'}</td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {dnn.tun_name && <span className="font-mono">{dnn.tun_name}</span>}
                      {dnn.tun_name && dnn.docker_network && <span className="text-gray-600"> · </span>}
                      {dnn.docker_network && <span className="text-gray-500">{dnn.docker_network}</span>}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500 max-w-[180px] truncate">
                      {dnn.description || '—'}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {deleteDNNConfirm === dnn.name ? (
                        <div className="flex items-center justify-end gap-2 flex-wrap">
                          <label className="flex items-center gap-1 text-xs text-gray-400 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={restartOnDeleteDNN}
                              onChange={e => setRestartOnDeleteDNN(e.target.checked)}
                              className="accent-blue-500"
                            />
                            Restart NFs
                          </label>
                          <button
                            onClick={() => deleteDNNMut.mutate({ name: dnn.name, restart: restartOnDeleteDNN })}
                            disabled={deleteDNNMut.isPending}
                            className="px-2 py-1 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white text-xs rounded"
                          >Confirm delete</button>
                          <button
                            onClick={() => setDeleteDNNConfirm(null)}
                            className="px-2 py-1 bg-gray-700 text-gray-300 text-xs rounded"
                          >Cancel</button>
                        </div>
                      ) : (
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => openEditDNN(dnn)}
                            className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded"
                            title="Edit description"
                          >
                            <Pencil size={13} />
                          </button>
                          <button
                            onClick={() => setDeleteDNNConfirm(dnn.name)}
                            className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-gray-700 rounded"
                            title="Delete DNN"
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
