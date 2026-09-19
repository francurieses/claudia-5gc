import type { HTMLAttributes, ReactNode, TdHTMLAttributes, ThHTMLAttributes } from 'react'
import { cn } from '../../lib/cn'

/**
 * Table family — one density, one hover treatment, one empty row so every page
 * looks the same after migration.
 *
 * ```tsx
 * <Table caption="Active PDU sessions">
 *   <TableHead>
 *     <TableRow><TableHeaderCell>SUPI</TableHeaderCell></TableRow>
 *   </TableHead>
 *   <TableBody>
 *     {rows.map(r => <TableRow key={r.id}><TableCell mono>{r.supi}</TableCell></TableRow>)}
 *     {rows.length === 0 && <TableEmptyRow colSpan={1}>No data</TableEmptyRow>}
 *   </TableBody>
 * </Table>
 * ```
 *
 * `Table` scrolls horizontally on narrow viewports instead of forcing a
 * page-level horizontal scrollbar (bounds the wide-table risk in the plan).
 */

export interface TableProps {
  children: ReactNode
  /** Accessible name for the table (rendered as a visually hidden `<caption>`). */
  caption?: string
  className?: string
}

export function Table({ children, caption, className }: TableProps) {
  return (
    <div className={cn('overflow-x-auto rounded-card border border-border bg-card', className)}>
      <table className="w-full border-collapse text-sm">
        {caption && <caption className="sr-only">{caption}</caption>}
        {children}
      </table>
    </div>
  )
}

export function TableHead({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <thead className={cn('border-b border-border text-xs uppercase tracking-wider text-muted-fg', className)}>
      {children}
    </thead>
  )
}

export function TableBody({ children, className }: { children: ReactNode; className?: string }) {
  return <tbody className={className}>{children}</tbody>
}

export function TableRow({ children, className, ...rest }: HTMLAttributes<HTMLTableRowElement>) {
  return (
    <tr className={cn('border-b border-border/60 last:border-0 hover:bg-muted/50', className)} {...rest}>
      {children}
    </tr>
  )
}

export function TableHeaderCell({ children, className, scope = 'col', ...rest }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th scope={scope} className={cn('px-4 py-3 text-left font-semibold', className)} {...rest}>
      {children}
    </th>
  )
}

export interface TableCellProps extends TdHTMLAttributes<HTMLTableCellElement> {
  /** Render in the mono face — identifiers, IPs, TEIDs, log values. */
  mono?: boolean
}

export function TableCell({ children, className, mono = false, ...rest }: TableCellProps) {
  return (
    <td className={cn('px-4 py-2.5 align-middle', mono && 'font-mono text-xs', className)} {...rest}>
      {children}
    </td>
  )
}

/** Full-width placeholder row for the empty state inside a `<TableBody>`. */
export function TableEmptyRow({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return (
    <tr>
      <td colSpan={colSpan} className="px-4 py-6 text-center text-sm text-muted-fg">
        {children}
      </td>
    </tr>
  )
}
