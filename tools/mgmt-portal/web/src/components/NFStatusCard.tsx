import { CheckCircle, XCircle, Loader } from 'lucide-react'
import type { NFStatus } from '../lib/api'

const nfColors: Record<string, string> = {
  nrf: 'border-purple-700',
  amf: 'border-blue-700',
  ausf: 'border-cyan-700',
  udm: 'border-teal-700',
  udr: 'border-green-700',
  smf: 'border-yellow-700',
  pcf: 'border-orange-700',
  upf: 'border-red-700',
  nssf: 'border-pink-700',
}

interface Props {
  nf: NFStatus
  loading?: boolean
}

export default function NFStatusCard({ nf, loading }: Props) {
  const overall = nf.healthz_ok || nf.metrics_ok
  const borderColor = nfColors[nf.name] ?? 'border-gray-700'

  return (
    <div className={`bg-gray-900 rounded-lg p-4 border-l-4 ${borderColor}`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-bold text-white uppercase">{nf.name}</span>
        {loading ? (
          <Loader size={14} className="animate-spin text-gray-500" />
        ) : overall ? (
          <CheckCircle size={16} className="text-green-400" />
        ) : (
          <XCircle size={16} className="text-red-400" />
        )}
      </div>
      <div className="flex gap-2 flex-wrap">
        <StatusDot label="NRF" ok={nf.registered} />
        <StatusDot label="health" ok={nf.healthz_ok} />
        <StatusDot label="metrics" ok={nf.metrics_ok} />
      </div>
    </div>
  )
}

function StatusDot({ label, ok }: { label: string; ok: boolean }) {
  return (
    <span className="flex items-center gap-1 text-xs text-gray-400">
      <span className={`w-1.5 h-1.5 rounded-full ${ok ? 'bg-green-400' : 'bg-red-500'}`} />
      {label}
    </span>
  )
}
