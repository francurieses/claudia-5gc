import type { ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'
import Button from './Button'
import { Dialog } from './Modal'

/**
 * Confirmation dialog for destructive/irreversible actions (cascade delete,
 * cancel broadcast, network removal).
 *
 * Uses `role="alertdialog"` so assistive tech announces it immediately, and
 * keeps focus inside until confirmed or cancelled.
 */
export interface ConfirmDialogProps {
  open: boolean
  title: string
  description?: string
  /** Extra detail shown above the actions (defaults to a caution line when destructive). */
  children?: ReactNode
  confirmLabel?: string
  cancelLabel?: string
  destructive?: boolean
  loading?: boolean
  onConfirm: () => void
  onCancel: () => void
}

export default function ConfirmDialog({
  open,
  title,
  description,
  children,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  destructive = false,
  loading = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  return (
    <Dialog
      open={open}
      onClose={onCancel}
      role="alertdialog"
      size="sm"
      title={title}
      description={description}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={loading}>
            {cancelLabel}
          </Button>
          <Button variant={destructive ? 'destructive' : 'primary'} onClick={onConfirm} loading={loading}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      {children ?? (
        <div className="flex items-start gap-3 text-sm text-muted-fg">
          {destructive && (
            <AlertTriangle size={20} className="mt-0.5 flex-shrink-0 text-danger-fg" aria-hidden="true" />
          )}
          <p>
            {destructive
              ? 'This action cannot be undone.'
              : 'Please confirm you want to continue.'}
          </p>
        </div>
      )}
    </Dialog>
  )
}
