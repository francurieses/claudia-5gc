import Card from './ui/Card'
import { cn } from '../lib/cn'

/**
 * KPI card — reworked onto {@link Card} and the semantic token palette.
 *
 * The former raw-colour `color` prop is gone: callers pick a semantic
 * `variant`, so the value flips correctly between light and dark themes.
 */
export type StatVariant = 'default' | 'primary' | 'success' | 'warning' | 'danger' | 'info' | 'accent'

const VALUE_VARIANTS: Record<StatVariant, string> = {
  default: 'text-fg',
  primary: 'text-primary-text',
  success: 'text-success-fg',
  warning: 'text-warning-fg',
  danger: 'text-danger-fg',
  info: 'text-info-fg',
  accent: 'text-accent-text',
}

export interface StatCardProps {
  title: string
  value: string | number
  sub?: string
  variant?: StatVariant
  className?: string
}

export default function StatCard({ title, value, sub, variant = 'default', className }: StatCardProps) {
  return (
    <Card className={cn(className)}>
      <p className="mb-1 text-xs uppercase tracking-wider text-muted-fg">{title}</p>
      <p className={cn('text-3xl font-bold tabular-nums', VALUE_VARIANTS[variant])}>{value}</p>
      {sub && <p className="mt-1 text-xs text-muted-fg">{sub}</p>}
    </Card>
  )
}
