import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Play, Square, RotateCcw, Loader } from 'lucide-react'
import { getServices, startService, stopService, restartService } from '../lib/api'
import PageHeader from '../components/PageHeader'
import Badge from '../components/Badge'

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

export default function Services() {
  const qc = useQueryClient()
  const [pending, setPending] = useState<Record<string, string>>({})

  const { data: services = [], isLoading, refetch } = useQuery({
    queryKey: ['services'],
    queryFn: getServices,
    refetchInterval: 5_000,
  })

  const startMut = useMutation({
    mutationFn: (name: string) => startService(name),
    onMutate: (name) => setPending(p => ({ ...p, [name]: 'starting' })),
    onSettled: (_, __, name) => {
      setPending(p => { const copy = { ...p }; delete copy[name]; return copy })
      qc.invalidateQueries({ queryKey: ['services'] })
    },
  })

  const stopMut = useMutation({
    mutationFn: (name: string) => stopService(name),
    onMutate: (name) => setPending(p => ({ ...p, [name]: 'stopping' })),
    onSettled: (_, __, name) => {
      setPending(p => { const copy = { ...p }; delete copy[name]; return copy })
      qc.invalidateQueries({ queryKey: ['services'] })
    },
  })

  const restartMut = useMutation({
    mutationFn: (name: string) => restartService(name),
    onMutate: (name) => setPending(p => ({ ...p, [name]: 'restarting' })),
    onSettled: (_, __, name) => {
      setPending(p => { const copy = { ...p }; delete copy[name]; return copy })
      qc.invalidateQueries({ queryKey: ['services'] })
    },
  })

  const sorted = [...services].sort(sortSvcs)
  const running = services.filter(s => s.state === 'running').length

  return (
    <div className="p-6">
      <PageHeader
        title="Services"
        subtitle={`${running} / ${services.length} containers running`}
        action={
          <button
            onClick={() => refetch()}
            className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-md"
          >
            <RotateCcw size={14} /> Refresh
          </button>
        }
      />

      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
              <th className="px-4 py-3 text-left">Container</th>
              <th className="px-4 py-3 text-left">Image</th>
              <th className="px-4 py-3 text-left">State</th>
              <th className="px-4 py-3 text-left">Status</th>
              <th className="px-4 py-3 text-left">Uptime</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr><td colSpan={6} className="px-4 py-6 text-center text-gray-500">Loading…</td></tr>
            ) : sorted.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-gray-500">
                  No containers found. Is Docker socket mounted?
                </td>
              </tr>
            ) : (
              sorted.map(svc => {
                const p = pending[svc.name]
                return (
                  <tr key={svc.name} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="px-4 py-3 font-medium text-white">{svc.name}</td>
                    <td className="px-4 py-3 text-xs text-gray-400 font-mono truncate max-w-[200px]">
                      {svc.image}
                    </td>
                    <td className="px-4 py-3">
                      <Badge
                        label={p ?? svc.state}
                        variant={
                          p ? 'yellow' :
                          svc.state === 'running' ? 'green' :
                          svc.state === 'exited' ? 'red' : 'gray'
                        }
                      />
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">{svc.status}</td>
                    <td className="px-4 py-3 text-xs text-gray-400">{svc.uptime || '—'}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1.5">
                        {p ? (
                          <Loader size={14} className="animate-spin text-gray-400" />
                        ) : (
                          <>
                            {svc.state !== 'running' && (
                              <ActionBtn
                                onClick={() => startMut.mutate(svc.name)}
                                title="Start"
                                icon={<Play size={12} />}
                                color="text-green-400 hover:bg-green-900/30"
                              />
                            )}
                            {svc.state === 'running' && (
                              <ActionBtn
                                onClick={() => stopMut.mutate(svc.name)}
                                title="Stop"
                                icon={<Square size={12} />}
                                color="text-red-400 hover:bg-red-900/30"
                              />
                            )}
                            <ActionBtn
                              onClick={() => restartMut.mutate(svc.name)}
                              title="Restart"
                              icon={<RotateCcw size={12} />}
                              color="text-yellow-400 hover:bg-yellow-900/30"
                            />
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ActionBtn({
  onClick, title, icon, color,
}: {
  onClick: () => void
  title: string
  icon: React.ReactNode
  color: string
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      className={`p-1.5 rounded transition-colors ${color}`}
    >
      {icon}
    </button>
  )
}
