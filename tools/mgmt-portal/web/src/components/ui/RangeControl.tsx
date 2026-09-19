import { useState } from 'react'
import { CalendarRange, Check } from 'lucide-react'
import { cn } from '../../lib/cn'
import Button from './Button'
import Field from './Field'
import { Input } from './Input'
import { RANGE_PRESETS, toDateTimeLocal, validateCustomRange } from '../../lib/metricsRange'
import type { CustomRange, RangeId } from '../../lib/metricsRange'

/**
 * Time-range selector for the metrics charts: the PRD S17 presets
 * (15 m / 1 h / 6 h / 24 h, default 1 h) plus a custom `from`/`to` picker.
 *
 * Controlled: the parent owns the applied selection (`value` + `custom`) and the
 * effective window is resolved from it (`lib/metricsRange.resolveRangeWindow`).
 * Custom input validation is local — an invalid draft is never applied, and the
 * message is announced through `role="alert"` (the same contract as `Field`).
 *
 * Presets are *relative*: the parent recomputes `to = now` on every refetch, so
 * a live chart slides forward without the selection changing. A custom range is
 * absolute — the parent stops polling while one is selected.
 */
export interface RangeControlProps {
  value: RangeId
  custom: CustomRange | null
  onChange: (id: RangeId, custom?: CustomRange) => void
  className?: string
}

export default function RangeControl({ value, custom, onChange, className }: RangeControlProps) {
  const [draft, setDraft] = useState<CustomRange>(() => custom ?? defaultCustomRange())
  const [error, setError] = useState<string | null>(null)

  function select(id: RangeId) {
    setError(null)
    if (id === 'custom') {
      const next = custom ?? draft
      setDraft(next)
      onChange('custom', next)
      return
    }
    onChange(id)
  }

  function apply() {
    const problem = validateCustomRange(draft)
    setError(problem)
    if (!problem) onChange('custom', draft)
  }

  return (
    <div className={cn('flex flex-col gap-2', className)}>
      <div role="group" aria-label="Time range" className="flex flex-wrap items-center gap-1">
        {RANGE_PRESETS.map(preset => (
          <Button
            key={preset.id}
            size="sm"
            variant={value === preset.id ? 'primary' : 'secondary'}
            aria-pressed={value === preset.id}
            onClick={() => select(preset.id)}
          >
            {preset.label}
          </Button>
        ))}
        <Button
          size="sm"
          variant={value === 'custom' ? 'primary' : 'secondary'}
          aria-pressed={value === 'custom'}
          icon={<CalendarRange size={14} />}
          onClick={() => select('custom')}
        >
          Custom
        </Button>
      </div>

      {value === 'custom' && (
        <div className="flex flex-wrap items-end gap-2">
          <Field label="From" className="w-48">
            {({ id }) => (
              <Input
                id={id}
                type="datetime-local"
                value={draft.from}
                onChange={event => setDraft(current => ({ ...current, from: event.target.value }))}
              />
            )}
          </Field>
          <Field label="To" className="w-48">
            {({ id }) => (
              <Input
                id={id}
                type="datetime-local"
                value={draft.to}
                onChange={event => setDraft(current => ({ ...current, to: event.target.value }))}
              />
            )}
          </Field>
          <Button size="sm" icon={<Check size={14} />} onClick={apply}>
            Apply
          </Button>
          {error && (
            <p role="alert" className="pb-2 text-xs text-danger-fg">
              {error}
            </p>
          )}
        </div>
      )}
    </div>
  )
}

function defaultCustomRange(): CustomRange {
  const now = new Date()
  return { from: toDateTimeLocal(new Date(now.getTime() - 60 * 60_000)), to: toDateTimeLocal(now) }
}
