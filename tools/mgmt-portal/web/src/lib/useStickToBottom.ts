/**
 * useStickToBottom keeps a scrollable log container pinned to its tail without
 * ever using the element-scroll API (which scrolls every ancestor, including the
 * document). It only follows new content while the user is near the bottom and
 * not paused.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import type { RefObject } from 'react'

const BOTTOM_THRESHOLD_PX = 24

export function useStickToBottom<T extends HTMLElement>(
  ref: RefObject<T>,
  dep: unknown,
  paused = false,
) {
  const [atBottom, setAtBottom] = useState(true)
  const stick = useRef(true)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const onScroll = () => {
      const near = el.scrollHeight - el.scrollTop - el.clientHeight <= BOTTOM_THRESHOLD_PX
      stick.current = near
      setAtBottom(near)
    }
    el.addEventListener('scroll', onScroll, { passive: true })
    return () => el.removeEventListener('scroll', onScroll)
  }, [ref])

  useEffect(() => {
    const el = ref.current
    if (el && stick.current && !paused) el.scrollTop = el.scrollHeight
  }, [ref, dep, paused])

  const jumpToLatest = useCallback(() => {
    const el = ref.current
    if (!el) return
    stick.current = true
    setAtBottom(true)
    el.scrollTop = el.scrollHeight
  }, [ref])

  return { atBottom, jumpToLatest }
}
