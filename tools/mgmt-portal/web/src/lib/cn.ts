/**
 * Class-name joiner — the primitive layer's only styling helper.
 *
 * Deliberately dependency-free (no `clsx`/`tailwind-merge`, per the redesign's
 * "no new npm dependencies" constraint). It concatenates truthy class strings;
 * later classes win only through CSS specificity/order, so primitives keep
 * their base classes first and let callers append overrides.
 *
 * Usage: `cn('px-3', isActive && 'bg-primary', className)`
 */
export type ClassValue = string | number | false | null | undefined

export function cn(...classes: ClassValue[]): string {
  return classes.filter(Boolean).join(' ')
}
