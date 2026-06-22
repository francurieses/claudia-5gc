import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Play, Square, RotateCcw, FileDown, Pause, PlayCircle,
  Trash2, ArrowUpDown, Radio, X, Network,
} from 'lucide-react'
import {
  getPCAPStatus, getPCAPFiles,
  pcapStart, pcapStop, pcapPause, pcapResume, pcapRotate,
  pcapDownloadURL, pcapDeleteFile, pcapBulkDelete, pcapBulkDownload,
} from '../lib/api'
import PageHeader from '../components/PageHeader'
import type { PCAPStatus, PCAPFile } from '../lib/api'

// NF display metadata
interface NFMeta {
  id: string
  label: string
  description: string
  group: 'core' | 'nf'
}

const NF_LIST: NFMeta[] = [
  { id: 'core', label: 'CORE',  description: 'All 5GC networks — sbi · n2 · n4 · n3', group: 'core' },
  { id: 'nrf',  label: 'NRF',   description: 'NF Registration & Discovery',           group: 'nf' },
  { id: 'amf',  label: 'AMF',   description: 'Access & Mobility Management',           group: 'nf' },
  { id: 'ausf', label: 'AUSF',  description: 'Authentication Server',                  group: 'nf' },
  { id: 'udm',  label: 'UDM',   description: 'Unified Data Management',                group: 'nf' },
  { id: 'udr',  label: 'UDR',   description: 'Unified Data Repository',                group: 'nf' },
  { id: 'smf',  label: 'SMF',   description: 'Session Management',                     group: 'nf' },
  { id: 'pcf',  label: 'PCF',   description: 'Policy Control',                         group: 'nf' },
  { id: 'upf',  label: 'UPF',   description: 'User Plane (N3/N4)',                     group: 'nf' },
  { id: 'nssf', label: 'NSSF',  description: 'Network Slice Selection',                group: 'nf' },
  { id: 'smsf', label: 'SMSF',  description: 'SMS Function',                           group: 'nf' },
  { id: 'bsf',  label: 'BSF',   description: 'Binding Support',                        group: 'nf' },
  { id: 'nef',  label: 'NEF',   description: 'Network Exposure',                       group: 'nf' },
]

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

// Dot indicator: pulsing green = capturing, yellow = paused, dim gray = stopped
function StatusDot({ capturing, paused }: { capturing: boolean; paused: boolean }) {
  if (capturing) {
    return (
      <span className="relative flex h-2 w-2">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
        <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
      </span>
    )
  }
  if (paused) return <span className="h-2 w-2 rounded-full bg-yellow-400 inline-block" />
  return <span className="h-2 w-2 rounded-full bg-gray-600 inline-block" />
}

interface CaptureWindowProps {
  meta: NFMeta
  status: PCAPStatus | undefined
  onClose: () => void
  onStart: () => void
  onStop: () => void
  onPause: () => void
  onResume: () => void
  onRotate: () => void
  pending: Record<string, boolean>
}

function CaptureWindow({
  meta, status, onClose,
  onStart, onStop, onPause, onResume, onRotate,
  pending,
}: CaptureWindowProps) {
  const capturing = status?.capturing ?? false
  const paused    = status?.paused    ?? false
  const fileCount = status?.files     ?? 0

  const qc = useQueryClient()
  const [sortNewest, setSortNewest] = useState(true)
  const [selected, setSelected] = useState<Set<string>>(new Set())

  const { data: files = [], isLoading } = useQuery({
    queryKey: ['pcap-files', meta.id],
    queryFn: () => getPCAPFiles(meta.id),
    refetchInterval: 5_000,
  })

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['pcap-status'] })
    qc.invalidateQueries({ queryKey: ['pcap-files', meta.id] })
  }

  const deleteMut = useMutation({
    mutationFn: (filename: string) => pcapDeleteFile(meta.id, filename),
    onSuccess: invalidate,
  })
  const bulkDeleteMut = useMutation({
    mutationFn: (fileList: string[]) => pcapBulkDelete(meta.id, fileList),
    onSuccess: () => { setSelected(new Set()); invalidate() },
  })
  const bulkDownloadMut = useMutation({
    mutationFn: (fileList: string[]) => pcapBulkDownload(meta.id, fileList),
  })

  const sorted = useMemo(() => (
    [...files].sort((a: PCAPFile, b: PCAPFile) => {
      const d = new Date(b.mod_time).getTime() - new Date(a.mod_time).getTime()
      return sortNewest ? d : -d
    })
  ), [files, sortNewest])

  const allSelected  = sorted.length > 0 && sorted.every((f: PCAPFile) => selected.has(f.name))
  const someSelected = selected.size > 0

  const toggle = (name: string) => {
    const next = new Set(selected)
    next.has(name) ? next.delete(name) : next.add(name)
    setSelected(next)
  }

  return (
    <div className="flex flex-col h-full bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
      {/* Window title bar */}
      <div className={`flex items-center justify-between px-4 py-3 border-b border-gray-700 shrink-0 ${
        meta.id === 'core' ? 'bg-blue-950/60' : 'bg-gray-800/60'
      }`}>
        <div className="flex items-center gap-2.5">
          {meta.id === 'core'
            ? <Network size={14} className="text-blue-400" />
            : <Radio size={14} className="text-gray-400" />
          }
          <span className="text-sm font-bold text-white">{meta.label}</span>
          <span className="text-xs text-gray-400">{meta.description}</span>
        </div>
        <div className="flex items-center gap-3">
          <StatusDot capturing={capturing} paused={paused} />
          <span className="text-xs text-gray-500">
            {capturing ? 'Capturing' : paused ? 'Paused' : 'Stopped'}
          </span>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 transition-colors"
            title="Close"
          >
            <X size={14} />
          </button>
        </div>
      </div>

      {/* Controls row */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-gray-800 shrink-0 flex-wrap">
        {!capturing && !paused && (
          <button
            onClick={onStart}
            disabled={pending.start}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-green-700 hover:bg-green-600 text-white text-xs rounded disabled:opacity-50 transition-colors"
          >
            <Play size={12} /> Start
          </button>
        )}
        {capturing && (
          <button
            onClick={onPause}
            disabled={pending.pause}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-yellow-600 hover:bg-yellow-500 text-white text-xs rounded disabled:opacity-50 transition-colors"
          >
            <Pause size={12} /> Pause
          </button>
        )}
        {paused && (
          <button
            onClick={onResume}
            disabled={pending.resume}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-green-700 hover:bg-green-600 text-white text-xs rounded disabled:opacity-50 transition-colors"
          >
            <PlayCircle size={12} /> Resume
          </button>
        )}
        {(capturing || paused) && (
          <button
            onClick={onStop}
            disabled={pending.stop}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-red-700 hover:bg-red-600 text-white text-xs rounded disabled:opacity-50 transition-colors"
          >
            <Square size={12} /> Stop
          </button>
        )}
        {capturing && (
          <button
            onClick={onRotate}
            disabled={pending.rotate}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-xs rounded disabled:opacity-50 transition-colors"
            title="Seal current file and start a new one without losing data"
          >
            <RotateCcw size={12} /> Rotate file
          </button>
        )}

        <div className="ml-auto text-xs text-gray-500">
          {fileCount} file{fileCount !== 1 ? 's' : ''} saved
        </div>
      </div>

      {/* Bulk action bar */}
      {someSelected && (
        <div className="flex items-center gap-3 px-4 py-2 bg-blue-900/25 border-b border-blue-800/40 shrink-0">
          <span className="text-xs text-blue-300">{selected.size} selected</span>
          <button
            onClick={() => bulkDownloadMut.mutate(Array.from(selected))}
            disabled={bulkDownloadMut.isPending}
            className="flex items-center gap-1.5 px-3 py-1 bg-blue-700 hover:bg-blue-600 text-white text-xs rounded disabled:opacity-50"
          >
            <FileDown size={11} />
            {bulkDownloadMut.isPending ? 'Preparing…' : `Download (${selected.size})`}
          </button>
          <button
            onClick={() => {
              if (window.confirm(`Delete ${selected.size} file(s)?`)) {
                bulkDeleteMut.mutate(Array.from(selected))
              }
            }}
            disabled={bulkDeleteMut.isPending}
            className="flex items-center gap-1.5 px-3 py-1 bg-red-800 hover:bg-red-700 text-white text-xs rounded disabled:opacity-50"
          >
            <Trash2 size={11} />
            {bulkDeleteMut.isPending ? 'Deleting…' : `Delete (${selected.size})`}
          </button>
          <button onClick={() => setSelected(new Set())} className="ml-auto text-xs text-gray-500 hover:text-gray-300">
            Clear
          </button>
        </div>
      )}

      {/* File table — scrollable */}
      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-800 text-gray-500 text-xs uppercase">
              <th className="px-3 py-2 w-8">
                <input
                  type="checkbox"
                  checked={allSelected}
                  onChange={() => setSelected(allSelected ? new Set() : new Set(sorted.map((f: PCAPFile) => f.name)))}
                  disabled={sorted.length === 0}
                  className="rounded border-gray-600 bg-gray-800 cursor-pointer"
                />
              </th>
              <th className="px-3 py-2 text-left">
                <button
                  onClick={() => setSortNewest(v => !v)}
                  className="flex items-center gap-1 hover:text-gray-300 transition-colors"
                >
                  File <ArrowUpDown size={10} />
                </button>
              </th>
              <th className="px-3 py-2 text-left">Size</th>
              <th className="px-3 py-2 text-left">Modified</th>
              <th className="px-3 py-2 w-16" />
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-600 text-xs">Loading…</td>
              </tr>
            ) : sorted.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-600 text-xs">
                  No files yet. Start capture, then rotate to seal a file.
                </td>
              </tr>
            ) : sorted.map((f: PCAPFile) => (
              <tr
                key={f.name}
                className={`border-b border-gray-800/40 hover:bg-gray-800/30 transition-colors ${
                  selected.has(f.name) ? 'bg-blue-900/10' : ''
                }`}
              >
                <td className="px-3 py-2.5">
                  <input
                    type="checkbox"
                    checked={selected.has(f.name)}
                    onChange={() => toggle(f.name)}
                    className="rounded border-gray-600 bg-gray-800 cursor-pointer"
                  />
                </td>
                <td className="px-3 py-2.5 font-mono text-xs text-blue-300 max-w-xs truncate">{f.name}</td>
                <td className="px-3 py-2.5 text-xs text-gray-400 whitespace-nowrap">{formatBytes(f.size_bytes)}</td>
                <td className="px-3 py-2.5 text-xs text-gray-500 whitespace-nowrap">
                  {new Date(f.mod_time).toLocaleString()}
                </td>
                <td className="px-3 py-2.5">
                  <div className="flex items-center justify-end gap-3">
                    <a
                      href={pcapDownloadURL(meta.id, f.name)}
                      download={f.name}
                      className="text-blue-500 hover:text-blue-300 transition-colors"
                      title="Download"
                    >
                      <FileDown size={13} />
                    </a>
                    <button
                      onClick={() => {
                        if (window.confirm(`Delete ${f.name}?`)) deleteMut.mutate(f.name)
                      }}
                      disabled={deleteMut.isPending}
                      className="text-gray-600 hover:text-red-400 disabled:opacity-40 transition-colors"
                      title="Delete"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default function PCAP() {
  const qc = useQueryClient()
  const [openNF, setOpenNF] = useState<string | null>(null)

  const { data: statuses = [] } = useQuery({
    queryKey: ['pcap-status'],
    queryFn: getPCAPStatus,
    refetchInterval: 5_000,
  })

  const getStatus = (nf: string) => statuses.find(s => s.nf === nf)

  const invalidateStatus = () => qc.invalidateQueries({ queryKey: ['pcap-status'] })

  const startMut  = useMutation({ mutationFn: pcapStart,  onSuccess: invalidateStatus })
  const stopMut   = useMutation({ mutationFn: pcapStop,   onSuccess: invalidateStatus })
  const pauseMut  = useMutation({ mutationFn: pcapPause,  onSuccess: invalidateStatus })
  const resumeMut = useMutation({ mutationFn: pcapResume, onSuccess: invalidateStatus })
  const rotateMut = useMutation({ mutationFn: pcapRotate, onSuccess: invalidateStatus })

  const pending = {
    start:  startMut.isPending,
    stop:   stopMut.isPending,
    pause:  pauseMut.isPending,
    resume: resumeMut.isPending,
    rotate: rotateMut.isPending,
  }

  const openMeta = NF_LIST.find(n => n.id === openNF) ?? null

  const activeCount = statuses.filter(s => s.capturing || s.paused).length

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="px-6 pt-6 pb-4 shrink-0">
        <PageHeader
          title="PCAP Capture"
          subtitle="Start tcpdump on demand — off by default"
        />
        {activeCount > 0 && (
          <div className="mt-2 flex items-center gap-2 text-xs text-green-400">
            <span className="relative flex h-1.5 w-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-green-500" />
            </span>
            {activeCount} capture{activeCount !== 1 ? 's' : ''} running
          </div>
        )}
      </div>

      {/* Two-column layout: NF selector | capture window */}
      <div className="flex flex-1 min-h-0 px-6 pb-6 gap-4">

        {/* ── Left: NF selector ─────────────────────────────────── */}
        <div className="w-52 shrink-0 flex flex-col gap-1 overflow-y-auto">

          {/* CORE entry */}
          {NF_LIST.filter(n => n.group === 'core').map(nf => {
            const st = getStatus(nf.id)
            const active = openNF === nf.id
            return (
              <button
                key={nf.id}
                onClick={() => setOpenNF(active ? null : nf.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-left transition-colors border ${
                  active
                    ? 'bg-blue-900/40 border-blue-700/60 text-white'
                    : 'bg-gray-900 border-gray-800 hover:border-gray-700 text-gray-300 hover:text-white'
                }`}
              >
                <Network size={13} className={active ? 'text-blue-400' : 'text-gray-500'} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-bold">{nf.label}</div>
                  <div className="text-[10px] text-gray-500 truncate">All networks</div>
                </div>
                <StatusDot capturing={st?.capturing ?? false} paused={st?.paused ?? false} />
              </button>
            )
          })}

          <div className="border-t border-gray-800 my-1" />

          {/* Per-NF entries */}
          {NF_LIST.filter(n => n.group === 'nf').map(nf => {
            const st = getStatus(nf.id)
            const active = openNF === nf.id
            return (
              <button
                key={nf.id}
                onClick={() => setOpenNF(active ? null : nf.id)}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-left transition-colors border ${
                  active
                    ? 'bg-gray-800 border-gray-600 text-white'
                    : 'border-transparent hover:bg-gray-800/50 hover:border-gray-700/50 text-gray-400 hover:text-gray-200'
                }`}
              >
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-semibold">{nf.label}</div>
                  <div className="text-[10px] text-gray-600 truncate">{nf.description}</div>
                </div>
                <StatusDot capturing={st?.capturing ?? false} paused={st?.paused ?? false} />
              </button>
            )
          })}

          <div className="pt-2 text-[10px] text-gray-700 text-center leading-tight">
            <RotateCcw size={9} className="inline mr-1" />
            Rotate seals the current<br />file without stopping
          </div>
        </div>

        {/* ── Right: capture window ─────────────────────────────── */}
        <div className="flex-1 min-w-0">
          {openMeta ? (
            <CaptureWindow
              key={openMeta.id}
              meta={openMeta}
              status={getStatus(openMeta.id)}
              onClose={() => setOpenNF(null)}
              onStart={() => startMut.mutate(openMeta.id)}
              onStop={() => stopMut.mutate(openMeta.id)}
              onPause={() => pauseMut.mutate(openMeta.id)}
              onResume={() => resumeMut.mutate(openMeta.id)}
              onRotate={() => rotateMut.mutate(openMeta.id)}
              pending={pending}
            />
          ) : (
            <div className="flex flex-col items-center justify-center h-full rounded-lg border border-dashed border-gray-800 text-gray-600">
              <Radio size={32} className="mb-3 opacity-30" />
              <p className="text-sm">Select a network function</p>
              <p className="text-xs mt-1 text-gray-700">Choose from the list to control capture and browse files</p>
            </div>
          )}
        </div>

      </div>
    </div>
  )
}
