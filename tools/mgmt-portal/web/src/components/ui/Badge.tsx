import type { ReactNode } from 'react'

/**
 * Badge primitive — compact semantic status/label chip.
 *
 * `neutral | primary | success | warning | danger | info` are the canonical
 * variants. The legacy `green | red | yellow | blue | gray` aliases that kept
 * the pages building during the rollout were removed at PORTAL-UI-19 once every
 * page was migrated (the raw-colour grep audit is the regression control).
 *
 * A status badge MUST pair colour with an icon or explicit text label so the
 * meaning survives greyscale / colour-vision deficiency (WCAG 1.4.1); pass the
 * `icon` slot for the icon (its `aria-hidden` marker is applied here).
 */
export type BadgeVariant =
  | 'neutral'
  | 'primary'
  | 'success'
  | 'warning'
  | 'danger'
  | 'info'

const VARIANTS: Record<BadgeVariant, string> = {
  neutral: 'bg-muted text-muted-fg border-border',
  // Badge text is small ⇒ reuse the contrast-verified status surfaces.
  primary: 'bg-info-surface text-info-fg border-info-border',
  success: 'bg-success-surface text-success-fg border-success-border',
  warning: 'bg-warning-surface text-warning-fg border-warning-border',
  danger: 'bg-danger-surface text-danger-fg border-danger-border',
  info: 'bg-info-surface text-info-fg border-info-border',
}

export interface BadgeProps {
  label: string
  variant?: BadgeVariant
  /** Leading glyph (lucide icon). The label must still carry the meaning. */
  icon?: ReactNode
}

export default function Badge({ label, variant = 'neutral', icon }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded border px-2 py-0.5 text-xs font-medium ${VARIANTS[variant]}`}
    >
      {icon && (
        <span aria-hidden="true" className="flex-shrink-0">
          {icon}
        </span>
      )}
      {label}
    </span>
  )
}
