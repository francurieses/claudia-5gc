import { Check, CheckCircle, Loader, X, XCircle } from 'lucide-react'
import type { NFStatus } from '../lib/api'
import Card from './ui/Card'
import Badge from './ui/Badge'
import { cn } from '../lib/cn'

/**
 * Per-NF status card, reworked onto {@link Card} + {@link Badge}.
 *
 * Per-NF identity accent uses the chart token ramp (theme-aware) purely as a
 * visual identifier. Status is always carried by an icon AND a text label
 * (plus an `sr-only` state word), never by colour alone (WCAG 1.4.1).
 *
 * Complete class strings are used so Tailwind's static extractor sees them.
 */
const NF_ACCENT: Record<string, string> = {
  nrf: 'border-l-chart-1',
  amf: 'border-l-chart-2',
  ausf: 'border-l-chart-3',
  udm: 'border-l-chart-4',
  udr: 'border-l-chart-5',
  smf: 'border-l-chart-1',
  pcf: 'border-l-chart-2',
  upf: 'border-l-chart-3',
  nssf: 'border-l-chart-4',
}

export interface NFStatusCardProps {
  nf: NFStatus
  loading?: boolean
}

export default function NFStatusCard({ nf, loading }: NFStatusCardProps) {
  const overall = nf.healthz_ok || nf.metrics_ok
  const accent = NF_ACCENT[nf.name.toLowerCase()] ?? 'border-l-border-strong'

  return (
    <Card className={cn('border-l-4', accent)}>
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="truncate text-sm font-bold uppercase text-card-fg">{nf.name}</span>
        {loading ? (
          <span className="flex items-center gap-1 text-muted-fg">
            <Loader size={16} className="animate-spin" aria-hidden="true" />
            <span className="sr-only">Checking status</span>
          </span>
        ) : overall ? (
          <span className="flex items-center gap-1 text-success-fg">
            <CheckCircle size={16} aria-hidden="true" />
            <span className="sr-only">Overall status: up</span>
          </span>
        ) : (
          <span className="flex items-center gap-1 text-danger-fg">
            <XCircle size={16} aria-hidden="true" />
            <span className="sr-only">Overall status: down</span>
          </span>
        )}
      </div>

      <div className="flex flex-wrap gap-2">
        <StatusChip label="NRF" ok={nf.registered} />
        <StatusChip label="health" ok={nf.healthz_ok} />
        <StatusChip label="metrics" ok={nf.metrics_ok} />
      </div>
    </Card>
  )
}

function StatusChip({ label, ok }: { label: string; ok: boolean }) {
  return (
    <span className="inline-flex items-center gap-1">
      <Badge
        label={label}
        variant={ok ? 'success' : 'danger'}
        icon={ok ? <Check size={12} /> : <X size={12} />}
      />
      <span className="sr-only">{ok ? 'available' : 'unavailable'}</span>
    </span>
  )
}
