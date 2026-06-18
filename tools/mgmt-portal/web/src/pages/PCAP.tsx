import { useState, useMemo, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Play, Square, RotateCcw, FileDown, Pause, PlayCircle, Trash2, ArrowUpDown } from 'lucide-react'
import {
  getPCAPStatus, getPCAPFiles,
  pcapStart, pcapStop, pcapPause, pcapResume, pcapRotate,
  pcapDownloadURL, pcapDeleteFile, pcapBulkDelete, pcapBulkDownload,
} from '../lib/api'
import PageHeader from '../components/PageHeader'
import Badge from '../components/Badge'

const NFS = ['nrf', 'amf', 'nssf']

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

export default function PCAP() {
  const qc = useQueryClient()
  const [selectedNF, setSelectedNF] = useState<string | null>(null)
  const [sortNewest, setSortNewest] = useState(true)
  const [selected, setSelected] = useState<Set<string>>(new Set())

  useEffect(() => { setSelected(new Set()) }, [selectedNF])

  const { data: statuses = [] } = useQuery({
    queryKey: ['pcap-status'],
    queryFn: getPCAPStatus,
    refetchInterval: 5_000,
  })

  const { data: files = [], isLoading: loadingFiles } = useQuery({
    queryKey: ['pcap-files', selectedNF],
    queryFn: () => getPCAPFiles(selectedNF!),
    enabled: !!selectedNF,
    refetchInterval: 5_000,
  })

  const invalidateStatus = () => qc.invalidateQueries({ queryKey: ['pcap-status'] })

  const startMut = useMutation({ mutationFn: pcapStart, onSuccess: invalidateStatus })
  const stopMut = useMutation({ mutationFn: pcapStop, onSuccess: invalidateStatus })
  const pauseMut = useMutation({ mutationFn: pcapPause, onSuccess: invalidateStatus })
  const resumeMut = useMutation({ mutationFn: pcapResume, onSuccess: invalidateStatus })
  const rotateMut = useMutation({
    mutationFn: pcapRotate,
    onSuccess: () => {
      invalidateStatus()
      qc.invalidateQueries({ queryKey: ['pcap-files', selectedNF] })
    },
  })
  const deleteMut = useMutation({
    mutationFn: ({ nf, filename }: { nf: string; filename: string }) => pcapDeleteFile(nf, filename),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pcap-files', selectedNF] })
      invalidateStatus()
    },
  })
  const bulkDeleteMut = useMutation({
    mutationFn: ({ nf, fileList }: { nf: string; fileList: string[] }) => pcapBulkDelete(nf, fileList),
    onSuccess: () => {
      setSelected(new Set())
      qc.invalidateQueries({ queryKey: ['pcap-files', selectedNF] })
      invalidateStatus()
    },
  })
  const bulkDownloadMut = useMutation({
    mutationFn: ({ nf, fileList }: { nf: string; fileList: string[] }) => pcapBulkDownload(nf, fileList),
  })

  const sortedFiles = useMemo(() => (
    [...files].sort((a, b) => {
      const diff = new Date(b.mod_time).getTime() - new Date(a.mod_time).getTime()
      return sortNewest ? diff : -diff
    })
  ), [files, sortNewest])

  const allSelected = sortedFiles.length > 0 && sortedFiles.every(f => selected.has(f.name))
  const someSelected = selected.size > 0

  const toggleSelectAll = () => {
    setSelected(allSelected ? new Set() : new Set(sortedFiles.map(f => f.name)))
  }
  const toggleSelect = (name: string) => {
    const next = new Set(selected)
    next.has(name) ? next.delete(name) : next.add(name)
    setSelected(next)
  }

  const handleDelete = (filename: string) => {
    if (!selectedNF || !window.confirm(`Delete ${filename}?`)) return
    deleteMut.mutate({ nf: selectedNF, filename })
  }
  const handleBulkDelete = () => {
    if (!selectedNF || !window.confirm(`Delete ${selected.size} selected file(s)? This cannot be undone.`)) return
    bulkDeleteMut.mutate({ nf: selectedNF, fileList: Array.from(selected) })
  }
  const handleBulkDownload = () => {
    if (!selectedNF) return
    bulkDownloadMut.mutate({ nf: selectedNF, fileList: Array.from(selected) })
  }

  const getStatus = (nf: string) => statuses.find(s => s.nf === nf)

  return (
    <div className="p-6">
      <PageHeader
        title="PCAP Capture"
        subtitle="Start tcpdump on demand — off by default"
      />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        {NFS.map(nf => {
          const st = getStatus(nf)
          const capturing = st?.capturing ?? false
          const paused = st?.paused ?? false

          let badgeLabel: string
          let badgeVariant: 'green' | 'yellow' | 'red'
          if (capturing) {
            badgeLabel = 'capturing'
            badgeVariant = 'green'
          } else if (paused) {
            badgeLabel = 'paused'
            badgeVariant = 'yellow'
          } else {
            badgeLabel = 'stopped'
            badgeVariant = 'red'
          }

          return (
            <div key={nf} className="bg-gray-900 rounded-lg border border-gray-800 p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-bold text-white uppercase">{nf}-pcap</h3>
                <Badge label={badgeLabel} variant={badgeVariant} />
              </div>
              <p className="text-xs text-gray-400 mb-4">
                {st?.files ?? 0} capture file{st?.files !== 1 ? 's' : ''} saved
              </p>
              <div className="flex items-center flex-wrap gap-2">
                {/* Start — only when fully stopped */}
                {!capturing && !paused && (
                  <button
                    onClick={() => startMut.mutate(nf)}
                    disabled={startMut.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-green-700 hover:bg-green-600 text-white text-xs rounded disabled:opacity-50"
                  >
                    <Play size={12} /> Start
                  </button>
                )}

                {/* Pause — only when actively capturing */}
                {capturing && (
                  <button
                    onClick={() => pauseMut.mutate(nf)}
                    disabled={pauseMut.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-yellow-600 hover:bg-yellow-500 text-white text-xs rounded disabled:opacity-50"
                  >
                    <Pause size={12} /> Pause
                  </button>
                )}

                {/* Resume — only when paused */}
                {paused && (
                  <button
                    onClick={() => resumeMut.mutate(nf)}
                    disabled={resumeMut.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-green-700 hover:bg-green-600 text-white text-xs rounded disabled:opacity-50"
                  >
                    <PlayCircle size={12} /> Resume
                  </button>
                )}

                {/* Stop — when capturing or paused */}
                {(capturing || paused) && (
                  <button
                    onClick={() => stopMut.mutate(nf)}
                    disabled={stopMut.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-red-700 hover:bg-red-600 text-white text-xs rounded disabled:opacity-50"
                  >
                    <Square size={12} /> Stop
                  </button>
                )}

                {/* Rotate — only when actively capturing (not paused) */}
                {capturing && (
                  <button
                    onClick={() => rotateMut.mutate(nf)}
                    disabled={rotateMut.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-xs rounded disabled:opacity-50"
                    title="Close current file and start a new one"
                  >
                    <RotateCcw size={12} /> Rotate
                  </button>
                )}

                <button
                  onClick={() => setSelectedNF(selectedNF === nf ? null : nf)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded transition-colors ${
                    selectedNF === nf
                      ? 'bg-blue-700 text-white'
                      : 'bg-gray-700 hover:bg-gray-600 text-white'
                  }`}
                >
                  <FileDown size={12} /> Files ({st?.files ?? 0})
                </button>
              </div>
            </div>
          )
        })}
      </div>

      {selectedNF && (
        <div>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
              Capture files — {selectedNF}-pcap
            </h3>
            <button
              onClick={() => setSortNewest(prev => !prev)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs rounded border border-gray-700 transition-colors"
            >
              <ArrowUpDown size={12} />
              {sortNewest ? 'Newest first' : 'Oldest first'}
            </button>
          </div>

          {someSelected && (
            <div className="flex items-center gap-3 px-4 py-2.5 mb-2 bg-blue-900/30 border border-blue-700/50 rounded-lg">
              <span className="text-xs text-blue-300 font-medium">
                {selected.size} file{selected.size !== 1 ? 's' : ''} selected
              </span>
              <div className="flex items-center gap-2 ml-auto">
                <button
                  onClick={handleBulkDownload}
                  disabled={bulkDownloadMut.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-700 hover:bg-blue-600 text-white text-xs rounded disabled:opacity-50"
                >
                  <FileDown size={12} />
                  {bulkDownloadMut.isPending ? 'Preparing ZIP…' : `Download (${selected.size})`}
                </button>
                <button
                  onClick={handleBulkDelete}
                  disabled={bulkDeleteMut.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-red-700 hover:bg-red-600 text-white text-xs rounded disabled:opacity-50"
                >
                  <Trash2 size={12} />
                  {bulkDeleteMut.isPending ? 'Deleting…' : `Delete (${selected.size})`}
                </button>
                <button
                  onClick={() => setSelected(new Set())}
                  className="px-2 py-1.5 text-gray-400 hover:text-gray-200 text-xs"
                >
                  Clear
                </button>
              </div>
            </div>
          )}

          <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
                  <th className="px-4 py-3 w-8">
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={toggleSelectAll}
                      disabled={sortedFiles.length === 0}
                      className="rounded border-gray-600 bg-gray-800 cursor-pointer"
                    />
                  </th>
                  <th className="px-4 py-3 text-left">File</th>
                  <th className="px-4 py-3 text-left">Size</th>
                  <th className="px-4 py-3 text-left">Modified</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {loadingFiles ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-6 text-center text-gray-500">Loading…</td>
                  </tr>
                ) : sortedFiles.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-6 text-center text-gray-500">
                      No capture files. Start capture and rotate to save files.
                    </td>
                  </tr>
                ) : (
                  sortedFiles.map(f => (
                    <tr
                      key={f.name}
                      className={`border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors ${
                        selected.has(f.name) ? 'bg-blue-900/10' : ''
                      }`}
                    >
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={selected.has(f.name)}
                          onChange={() => toggleSelect(f.name)}
                          className="rounded border-gray-600 bg-gray-800 cursor-pointer"
                        />
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-blue-300">{f.name}</td>
                      <td className="px-4 py-3 text-xs text-gray-400">{formatBytes(f.size_bytes)}</td>
                      <td className="px-4 py-3 text-xs text-gray-500">
                        {new Date(f.mod_time).toLocaleString()}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-3">
                          <a
                            href={pcapDownloadURL(selectedNF, f.name)}
                            download={f.name}
                            className="text-blue-400 hover:text-blue-300"
                            title="Download"
                          >
                            <FileDown size={14} />
                          </a>
                          <button
                            onClick={() => handleDelete(f.name)}
                            disabled={deleteMut.isPending}
                            className="text-red-500 hover:text-red-400 disabled:opacity-40"
                            title="Delete"
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="mt-6 flex items-center gap-3 text-xs text-gray-500">
        <RotateCcw size={12} />
        <span>Tip: Use <strong>Rotate</strong> while capturing to close the current file and start a new one without stopping tcpdump.</span>
      </div>
    </div>
  )
}
