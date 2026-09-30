/**
 * useTabParam keeps the active tab in the `?tab=` query string so tabs are
 * deep-linkable and survive F5. Unknown values fall back to the default.
 */
import { useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'

export function useTabParam<T extends string>(valid: readonly T[], fallback: T): [T, (id: T) => void] {
  const [params, setParams] = useSearchParams()
  const raw = params.get('tab')
  const value = (valid as readonly string[]).includes(raw ?? '') ? (raw as T) : fallback

  const set = useCallback(
    (id: T) => {
      setParams(
        prev => {
          const next = new URLSearchParams(prev)
          next.set('tab', id)
          return next
        },
        { replace: true },
      )
    },
    [setParams],
  )

  return [value, set]
}
