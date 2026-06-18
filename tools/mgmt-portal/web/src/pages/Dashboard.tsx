import { useQuery } from '@tanstack/react-query'
import { getNFStatus, getMetricsSummary, getSessions, getUEContexts, getSubscribers } from '../lib/api'
import NFStatusCard from '../components/NFStatusCard'
import StatCard from '../components/StatCard'
import PageHeader from '../components/PageHeader'

export default function Dashboard() {
  const { data: nfStatus, isLoading: loadingNF } = useQuery({
    queryKey: ['nf-status'],
    queryFn: getNFStatus,
    refetchInterval: 8_000,
  })

  const { data: metrics } = useQuery({
    queryKey: ['metrics-summary'],
    queryFn: getMetricsSummary,
    refetchInterval: 10_000,
  })

  const { data: sessions } = useQuery({
    queryKey: ['sessions'],
    queryFn: getSessions,
    refetchInterval: 10_000,
  })

  const { data: ueContexts } = useQuery({
    queryKey: ['ue-contexts'],
    queryFn: getUEContexts,
    refetchInterval: 10_000,
  })

  const { data: subscribers } = useQuery({
    queryKey: ['subscribers'],
    queryFn: getSubscribers,
    refetchInterval: 30_000,
  })

  const upCount = nfStatus?.filter(n => n.healthz_ok || n.metrics_ok).length ?? 0
  const totalNF = nfStatus?.length ?? 9
  const registeredCount = ueContexts?.filter(u => u.gmm_state === 1).length ?? 0

  return (
    <div className="p-6">
      <PageHeader title="Dashboard" subtitle="Real-time status of ClaudIA 5GC" />

      {/* KPI cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard
          title="NFs Online"
          value={`${upCount} / ${totalNF}`}
          color={upCount === totalNF ? 'text-green-400' : 'text-yellow-400'}
        />
        <StatCard
          title="Provisioned Subscribers"
          value={subscribers?.length ?? '—'}
          sub={registeredCount > 0 ? `${registeredCount} currently registered` : 'none registered'}
          color="text-blue-400"
        />
        <StatCard
          title="Active PDU Sessions"
          value={sessions?.length ?? metrics?.pdu_sessions ?? '—'}
          color="text-purple-400"
        />
        <StatCard
          title="NFs via NRF"
          value={nfStatus?.filter(n => n.registered).length ?? '—'}
          sub="registered instances"
        />
      </div>

      {/* NF Status grid */}
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
        Network Functions
      </h3>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3 mb-8">
        {loadingNF
          ? Array.from({ length: 9 }).map((_, i) => (
              <div key={i} className="bg-gray-900 rounded-lg p-4 border border-gray-800 animate-pulse h-24" />
            ))
          : (nfStatus ?? []).map(nf => (
              <NFStatusCard key={nf.name} nf={nf} loading={loadingNF} />
            ))}
      </div>

      {/* Active PDU Sessions table */}
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
        Active PDU Sessions
      </h3>
      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
              <th className="px-4 py-2 text-left">SUPI</th>
              <th className="px-4 py-2 text-left">DNN</th>
              <th className="px-4 py-2 text-left">UE IP</th>
              <th className="px-4 py-2 text-left">Slice</th>
              <th className="px-4 py-2 text-left">Since</th>
            </tr>
          </thead>
          <tbody>
            {sessions && sessions.length > 0 ? (
              sessions.slice(0, 8).map(s => (
                <tr key={s.ref} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-2 font-mono text-xs text-blue-300">{s.supi}</td>
                  <td className="px-4 py-2 text-gray-300">{s.dnn}</td>
                  <td className="px-4 py-2 font-mono text-xs text-green-300">{s.ue_ip}</td>
                  <td className="px-4 py-2 text-xs text-gray-300">
                    SST:{s.sst} {s.sd && `SD:${s.sd}`}
                  </td>
                  <td className="px-4 py-2 text-xs text-gray-500">
                    {new Date(s.created_at).toLocaleTimeString()}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={5} className="px-4 py-6 text-center text-gray-500 text-sm">
                  No active PDU sessions
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
