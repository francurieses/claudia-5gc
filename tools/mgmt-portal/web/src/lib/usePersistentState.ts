/**
 * usePersistentState is useState backed by localStorage. Every storage access
 * is wrapped in try/catch (private mode / blocked cookies) and the value simply
 * stays in memory when storage is unavailable, like lib/theme.ts.
 */
import { useCallback, useState } from 'react'
import type { Dispatch, SetStateAction } from 'react'

export function usePersistentState<T>(key: string, initial: T): [T, Dispatch<SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = window.localStorage.getItem(key)
      return raw === null ? initial : (JSON.parse(raw) as T)
    } catch {
      return initial
    }
  })

  const set = useCallback<Dispatch<SetStateAction<T>>>(
    next => {
      setValue(prev => {
        const v = typeof next === 'function' ? (next as (p: T) => T)(prev) : next
        try {
          window.localStorage.setItem(key, JSON.stringify(v))
        } catch {
          /* storage unavailable — keep in-memory state */
        }
        return v
      })
    },
    [key],
  )

  return [value, set]
}
