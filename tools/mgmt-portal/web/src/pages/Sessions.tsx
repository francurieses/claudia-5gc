import { useQuery } from '@tanstack/react-query'
import { getSessions, getUEContexts } from '../lib/api'
import PageHeader from '../components/PageHeader'
import Badge from '../components/Badge'

const GMM_STATES: Record<number, string> = {
  0: 'DEREGISTERED',
  1: 'REGISTERED',
  2: 'REGISTERED-INITIATED',
  3: 'DEREGISTERED-INITIATED',
}

export default function Sessions() {
  const { data: sessions = [], isLoading: loadSess } = useQuery({
    queryKey: ['sessions'],
    queryFn: getSessions,
    refetchInterval: 5_000,
  })

  const { data: ueContexts = [], isLoading: loadUE } = useQuery({
    queryKey: ['ue-contexts'],
    queryFn: getUEContexts,
    refetchInterval: 5_000,
  })

  return (
    <div className="p-6">
      <PageHeader title="Sessions & UE Contexts" subtitle="Live data from PostgreSQL" />

      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
        Active PDU Sessions ({sessions.length})
      </h3>
      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden mb-8">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
              <th className="px-4 py-3 text-left">SUPI</th>
              <th className="px-4 py-3 text-left">DNN</th>
              <th className="px-4 py-3 text-left">UE IP</th>
              <th className="px-4 py-3 text-left">Slice</th>
              <th className="px-4 py-3 text-left">UL TEID</th>
              <th className="px-4 py-3 text-left">Since</th>
            </tr>
          </thead>
          <tbody>
            {loadSess ? (
              <tr><td colSpan={6} className="px-4 py-6 text-center text-gray-500">Loading…</td></tr>
            ) : sessions.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-6 text-center text-gray-500">No active sessions</td></tr>
            ) : (
              sessions.map(s => (
                <tr key={s.ref} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-3 font-mono text-xs text-blue-300">{s.supi}</td>
                  <td className="px-4 py-3 text-gray-300">{s.dnn}</td>
                  <td className="px-4 py-3 font-mono text-xs text-green-300">{s.ue_ip}</td>
                  <td className="px-4 py-3 text-xs">
                    <Badge label={`SST:${s.sst}${s.sd ? '/SD:' + s.sd : ''}`} variant="blue" />
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-400">
                    0x{s.ul_teid.toString(16).toUpperCase().padStart(8, '0')}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">
                    {new Date(s.created_at).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
        UE Contexts — AMF ({ueContexts.length})
      </h3>
      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
              <th className="px-4 py-3 text-left">SUPI</th>
              <th className="px-4 py-3 text-left">TMSI</th>
              <th className="px-4 py-3 text-left">GMM State</th>
              <th className="px-4 py-3 text-left">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {loadUE ? (
              <tr><td colSpan={4} className="px-4 py-6 text-center text-gray-500">Loading…</td></tr>
            ) : ueContexts.length === 0 ? (
              <tr><td colSpan={4} className="px-4 py-6 text-center text-gray-500">No UE contexts</td></tr>
            ) : (
              ueContexts.map(ue => (
                <tr key={ue.supi} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-3 font-mono text-xs text-blue-300">{ue.supi}</td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-400">
                    {ue.tmsi ? `0x${ue.tmsi.toString(16).toUpperCase().padStart(8, '0')}` : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <Badge
                      label={GMM_STATES[ue.gmm_state] ?? `State ${ue.gmm_state}`}
                      variant={ue.gmm_state === 1 ? 'green' : ue.gmm_state === 0 ? 'red' : 'yellow'}
                    />
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">
                    {new Date(ue.created_at).toLocaleString()}
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
