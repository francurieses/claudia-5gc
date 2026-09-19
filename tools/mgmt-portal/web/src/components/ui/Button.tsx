import { forwardRef } from 'react'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { Loader } from 'lucide-react'
import { cn } from '../../lib/cn'

/**
 * Button primitive.
 *
 * - Colours come exclusively from semantic tokens (see STYLE_GUIDE § Components).
 * - Focus visibility is the global `:focus-visible` ring in `index.css`; never
 *   suppress it.
 * - `variant="icon"` renders a square 44×44 target — the accessible name MUST
 *   come from `aria-label` (use {@link IconButton}, which requires one).
 */

export type ButtonVariant = 'primary' | 'secondary' | 'destructive' | 'ghost' | 'icon'
export type ButtonSize = 'sm' | 'md' | 'lg' | 'icon'

const VARIANTS: Record<ButtonVariant, string> = {
  primary: 'bg-primary text-primary-fg hover:bg-primary/90',
  secondary: 'border border-border bg-card text-fg hover:bg-muted',
  destructive: 'bg-destructive text-destructive-fg hover:bg-destructive/90',
  ghost: 'text-muted-fg hover:bg-muted hover:text-fg',
  icon: 'border border-border bg-card text-muted-fg hover:bg-muted hover:text-fg',
}

const SIZES: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-xs',
  md: 'h-10 px-4 text-sm',
  lg: 'h-11 px-5 text-sm',
  icon: 'h-11 w-11 p-0',
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  /** Show a spinner and block interaction while an action is in flight. */
  loading?: boolean
  /** Leading icon (rendered `aria-hidden`; the label carries the meaning). */
  icon?: ReactNode
  trailingIcon?: ReactNode
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = 'primary',
    size = 'md',
    loading = false,
    icon,
    trailingIcon,
    className,
    children,
    disabled,
    type = 'button',
    ...rest
  },
  ref,
) {
  const effectiveSize: ButtonSize = variant === 'icon' ? 'icon' : size

  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cn(
        'inline-flex items-center justify-center gap-2 rounded-control font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50',
        SIZES[effectiveSize],
        VARIANTS[variant],
        className,
      )}
      {...rest}
    >
      {loading ? (
        <Loader size={16} className="animate-spin" aria-hidden="true" />
      ) : (
        icon && (
          <span aria-hidden="true" className="flex-shrink-0">
            {icon}
          </span>
        )
      )}
      {children}
      {trailingIcon && !loading && (
        <span aria-hidden="true" className="flex-shrink-0">
          {trailingIcon}
        </span>
      )}
    </button>
  )
})

export default Button

export type IconButtonVariant = Exclude<ButtonVariant, 'icon'> | 'icon'

export interface IconButtonProps extends Omit<ButtonProps, 'variant' | 'size' | 'icon' | 'children'> {
  /** Required accessible name — icon-only controls must never be unlabelled (WCAG 4.1.2). */
  label: string
  variant?: IconButtonVariant
  children: ReactNode
}

/**
 * Icon-only button. The `label` prop is mandatory so callers cannot ship an
 * unlabelled control; it is also reused as the native `title` tooltip.
 * Always 44×44 px (touch target, WCAG 2.5.8).
 *
 * Forwards its ref so a caller can move focus to it (e.g. the navigation
 * drawer returning focus to the menu button that opened it).
 */
export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { label, variant = 'secondary', title, className, children, ...rest },
  ref,
) {
  return (
    <Button
      ref={ref}
      variant={variant}
      size="icon"
      aria-label={label}
      title={title ?? label}
      className={cn('p-0', className)}
      {...rest}
    >
      <span aria-hidden="true" className="flex items-center justify-center">
        {children}
      </span>
    </Button>
  )
})
