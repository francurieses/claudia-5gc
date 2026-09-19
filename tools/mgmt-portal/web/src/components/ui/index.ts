/**
 * Primitive layer barrel — `import { Button, Card, Table } from '../components/ui'`.
 *
 * Every export is documented in `web/STYLE_GUIDE.md`, which is the source of
 * truth for when/how to use each primitive.
 */

export { default as Button, IconButton } from './Button'
export type { ButtonProps, ButtonSize, ButtonVariant, IconButtonProps, IconButtonVariant } from './Button'

export { Input, Textarea } from './Input'
export type { InputProps, TextareaProps } from './Input'

export { default as Checkbox } from './Checkbox'
export type { CheckboxProps } from './Checkbox'

export { Select } from './Select'
export type { SelectOption, SelectProps } from './Select'

export { default as Field } from './Field'
export type { FieldControlProps, FieldProps } from './Field'

export { default as Card } from './Card'
export type { CardProps } from './Card'

export { default as Section } from './Section'
export type { SectionProps } from './Section'

export { default as PageHeader } from './PageHeader'
export type { PageHeaderProps } from './PageHeader'

export { default as Badge } from './Badge'
export type { BadgeProps, BadgeVariant } from './Badge'

export { Table, TableBody, TableCell, TableEmptyRow, TableHead, TableHeaderCell, TableRow } from './Table'
export type { TableCellProps, TableProps } from './Table'

export { default as Tabs } from './Tabs'
export type { TabItem, TabsProps } from './Tabs'

export { default as Disclosure } from './Disclosure'
export type { DisclosureProps } from './Disclosure'

export { default as SegmentedControl } from './SegmentedControl'
export type { SegmentedControlProps, SegmentedOption } from './SegmentedControl'

export { default as EmptyState } from './EmptyState'
export type { EmptyStateProps } from './EmptyState'

export { default as Loading, Skeleton, Spinner } from './Loading'
export type { LoadingProps, SpinnerProps } from './Loading'

export { default as ErrorState } from './ErrorState'
export type { ErrorStateProps } from './ErrorState'

export { default as DegradedState } from './DegradedState'
export type { DegradedStateProps } from './DegradedState'

export { ToastProvider, useToast } from './Toast'
export type { ToastOptions, ToastVariant } from './Toast'

export { default as Modal, Dialog } from './Modal'
export type { DialogProps, ModalProps } from './Modal'

export { default as ConfirmDialog } from './ConfirmDialog'
export type { ConfirmDialogProps } from './ConfirmDialog'

export { default as ChartWrapper, useChartTheme } from './ChartWrapper'
export type { ChartState, ChartTableFallback, ChartTheme, ChartWrapperProps } from './ChartWrapper'

export { default as RangeControl } from './RangeControl'
export type { RangeControlProps } from './RangeControl'

export { useFocusTrap } from './useFocusTrap'
export type { FocusTrapOptions } from './useFocusTrap'
