import { useEffect, useId } from 'react'
import { createPortal } from 'react-dom'
import type { ReactNode, RefObject } from 'react'
import { X } from 'lucide-react'
import { useFocusTrap } from './useFocusTrap'
import { IconButton } from './Button'
import { cn } from '../../lib/cn'

/**
 * Overlay framework: `Modal` (shell) + `Dialog` (titled, labelled content).
 *
 * Modal owns the overlay contract — backdrop, scroll lock, ESC, focus trap and
 * focus restore (via `useFocusTrap`) — so no page has to re-implement it.
 * Rendered through a portal into `document.body` to escape stacking contexts.
 */

const SIZES = {
  sm: 'max-w-sm',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
  xl: 'max-w-4xl',
} as const

export interface ModalProps {
  open: boolean
  onClose: () => void
  children: ReactNode
  size?: keyof typeof SIZES
  /** Clicking the backdrop dismisses (default `true`). ESC always dismisses. */
  closeOnBackdrop?: boolean
  /** Element focused on open (defaults to the first tabbable child). */
  initialFocus?: RefObject<HTMLElement | null>
  className?: string
  labelledBy?: string
  describedBy?: string
  /** `alertdialog` for destructive confirmations, `dialog` otherwise. */
  role?: 'dialog' | 'alertdialog'
}

export default function Modal({
  open,
  onClose,
  children,
  size = 'md',
  closeOnBackdrop = true,
  initialFocus,
  className,
  labelledBy,
  describedBy,
  role = 'dialog',
}: ModalProps) {
  // Lock background scroll while the overlay is open.
  useEffect(() => {
    if (!open) return
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = previous
    }
  }, [open])

  const panelRef = useFocusTrap<HTMLDivElement>({ enabled: open, onEscape: onClose, initialFocus })

  if (!open) return null

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        aria-hidden="true"
        onClick={closeOnBackdrop ? onClose : undefined}
        className="absolute inset-0 bg-overlay/60"
      />
      <div
        ref={panelRef}
        role={role}
        aria-modal="true"
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        tabIndex={-1}
        className={cn(
          'relative z-10 max-h-[85vh] w-full overflow-y-auto rounded-card border border-border bg-card text-card-fg shadow-overlay',
          SIZES[size],
          className,
        )}
      >
        {children}
      </div>
    </div>,
    document.body,
  )
}

export interface DialogProps extends Omit<ModalProps, 'children' | 'labelledBy' | 'describedBy'> {
  title: string
  description?: string
  children?: ReactNode
  footer?: ReactNode
  /** Show the top-right close button (default `true`). */
  showClose?: boolean
}

/** Titled dialog with a header (title/description), body and optional footer. */
export function Dialog({
  title,
  description,
  children,
  footer,
  showClose = true,
  onClose,
  ...modal
}: DialogProps) {
  const titleId = useId()
  const descriptionId = useId()

  return (
    <Modal {...modal} onClose={onClose} labelledBy={titleId} describedBy={description ? descriptionId : undefined}>
      <div className="flex items-start justify-between gap-4 border-b border-border p-5">
        <div className="min-w-0">
          <h2 id={titleId} className="truncate text-base font-semibold text-fg">
            {title}
          </h2>
          {description && (
            <p id={descriptionId} className="mt-0.5 text-xs text-muted-fg">
              {description}
            </p>
          )}
        </div>
        {showClose && (
          <IconButton label="Close dialog" variant="ghost" onClick={onClose}>
            <X size={18} />
          </IconButton>
        )}
      </div>

      {children && <div className="p-5">{children}</div>}

      {footer && <div className="flex items-center justify-end gap-2 border-t border-border p-5">{footer}</div>}
    </Modal>
  )
}
