import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { AlertTriangle, CheckCircle, Info, X, XCircle } from 'lucide-react'
import { cn } from '../../lib/cn'
import { IconButton } from './Button'

/**
 * Toast notifications — context-based, theme-aware, auto-dismissing.
 *
 * Accessibility: each toast is its own live region (`role="status"` for
 * non-errors, `role="alert"` for errors); the dismissal button is labelled.
 * Wrap the app once with `<ToastProvider>` and call `useToast()` anywhere.
 */

export type ToastVariant = 'success' | 'error' | 'warning' | 'info'

export interface ToastOptions {
  title: string
  description?: string
  variant?: ToastVariant
  /** Auto-dismiss delay in ms; `0` keeps the toast until dismissed manually. */
  duration?: number
}

interface ToastRecord {
  id: string
  title: string
  description?: string
  variant: ToastVariant
  duration: number
}

interface ToastContextValue {
  /** Show a toast; returns its id. */
  toast: (options: ToastOptions) => string
  dismiss: (id: string) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext)
  if (!context) throw new Error('useToast must be used within <ToastProvider>')
  return context
}

/** Cap concurrent toasts so a burst cannot cover the viewport. */
const MAX_TOASTS = 4

const ICONS: Record<ToastVariant, ReactNode> = {
  success: <CheckCircle size={18} />,
  error: <XCircle size={18} />,
  warning: <AlertTriangle size={18} />,
  info: <Info size={18} />,
}

const SURFACE: Record<ToastVariant, string> = {
  success: 'border-success-border bg-success-surface text-success-fg',
  error: 'border-danger-border bg-danger-surface text-danger-fg',
  warning: 'border-warning-border bg-warning-surface text-warning-fg',
  info: 'border-info-border bg-info-surface text-info-fg',
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastRecord[]>([])
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>())

  const dismiss = useCallback((id: string) => {
    const timer = timers.current.get(id)
    if (timer) {
      clearTimeout(timer)
      timers.current.delete(id)
    }
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const toast = useCallback(
    (options: ToastOptions) => {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
      const record: ToastRecord = {
        id,
        title: options.title,
        description: options.description,
        variant: options.variant ?? 'info',
        duration: options.duration ?? 6000,
      }
      setToasts(prev => [...prev.slice(-(MAX_TOASTS - 1)), record])
      if (record.duration > 0) {
        timers.current.set(id, setTimeout(() => dismiss(id), record.duration))
      }
      return id
    },
    [dismiss],
  )

  useEffect(() => {
    const pending = timers.current
    return () => {
      pending.forEach(clearTimeout)
      pending.clear()
    }
  }, [])

  const value = useMemo(() => ({ toast, dismiss }), [toast, dismiss])

  return (
    <ToastContext.Provider value={value}>
      {children}
      {createPortal(<ToastViewport toasts={toasts} onDismiss={dismiss} />, document.body)}
    </ToastContext.Provider>
  )
}

function ToastViewport({ toasts, onDismiss }: { toasts: ToastRecord[]; onDismiss: (id: string) => void }) {
  return (
    <div
      role="region"
      aria-label="Notifications"
      className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-full max-w-sm flex-col gap-2"
    >
      {toasts.map(t => (
        <div
          key={t.id}
          role={t.variant === 'error' ? 'alert' : 'status'}
          className={cn(
            'pointer-events-auto flex items-start gap-3 rounded-card border p-4 shadow-overlay',
            SURFACE[t.variant],
          )}
        >
          <span className="mt-0.5 flex-shrink-0" aria-hidden="true">
            {ICONS[t.variant]}
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold">{t.title}</p>
            {t.description && <p className="mt-0.5 text-xs">{t.description}</p>}
          </div>
          <IconButton label="Dismiss notification" variant="ghost" onClick={() => onDismiss(t.id)}>
            <X size={16} />
          </IconButton>
        </div>
      ))}
    </div>
  )
}
