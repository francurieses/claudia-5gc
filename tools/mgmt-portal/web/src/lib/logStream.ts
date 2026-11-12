import { useSyncExternalStore } from 'react'

/**
 * Module-level log store. Buffers and WebSockets live outside React so that
 * navigating to another view (or switching container) never drops lines.
 * A buffer is emptied only by clearLogs() (the "Clear" button) or when the
 * backend reports that the container restarted.
 */

export type LogLine = { raw: string; level: string; msg: string; ts: string }
export type ConnState = 'connecting' | 'open' | 'closed'

/** Keep at most this many lines per container. */
const MAX_LINES = 2000
const RECONNECT_MS = 3_000
/** Marker the backend (internal/api/logs.go) emits when the Docker stream ends. */
const RESTART_MARKER = 'container restarted, reconnecting'

interface Entry {
  lines: LogLine[]
  persistTimer: ReturnType<typeof setTimeout> | null
  conn: ConnState
  ws: WebSocket | null
  timer: ReturnType<typeof setTimeout> | null
  listeners: Set<() => void>
}

const entries = new Map<string, Entry>()
let paused = false

const STORE_PREFIX = 'portal.logs.'
/** Lines persisted per container so a full page reload (F5) keeps them. */
const PERSIST_LINES = 1000
const PERSIST_MS = 1_000

function loadPersisted(container: string): LogLine[] {
  try {
    const v = JSON.parse(sessionStorage.getItem(STORE_PREFIX + container) ?? '[]')
    return Array.isArray(v) ? v : []
  } catch {
    return []
  }
}

function persist(container: string, e: Entry) {
  if (e.persistTimer) return
  e.persistTimer = setTimeout(() => {
    e.persistTimer = null
    try {
      sessionStorage.setItem(STORE_PREFIX + container, JSON.stringify(e.lines.slice(-PERSIST_LINES)))
    } catch {
      /* quota or storage blocked: in-memory buffer still works */
    }
  }, PERSIST_MS)
}

function entry(container: string): Entry {
  let e = entries.get(container)
  if (!e) {
    e = { lines: loadPersisted(container), persistTimer: null, conn: 'connecting', ws: null, timer: null, listeners: new Set() }
    entries.set(container, e)
  }
  return e
}

function emit(e: Entry) {
  e.listeners.forEach(l => l())
}

export function parseLogLine(raw: string): LogLine {
  try {
    const obj = JSON.parse(raw.trim())
    return {
      raw,
      level: (obj.level ?? '').toLowerCase(),
      msg: obj.msg ?? raw,
      ts: obj.time ?? '',
    }
  } catch {
    return { raw, level: 'info', msg: raw, ts: '' }
  }
}

function connect(container: string) {
  const e = entry(container)
  if (e.ws) return
  e.conn = 'connecting'
  emit(e)

  // First attach replays the recent history; later reconnects only follow new output.
  const tail = e.lines.length === 0 ? 200 : 0
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const ws = new WebSocket(`${protocol}//${window.location.host}/ws/logs/${container}?tail=${tail}`)
  e.ws = ws

  ws.onopen = () => {
    e.conn = 'open'
    emit(e)
  }
  ws.onmessage = ev => {
    if (paused) return
    const parsed = parseLogLine(ev.data as string)
    // Core/container restart: the old session's lines no longer apply.
    const next = parsed.msg.includes(RESTART_MARKER) ? [parsed] : [...e.lines, parsed]
    e.lines = next.length > MAX_LINES ? next.slice(-MAX_LINES) : next
    persist(container, e)
    emit(e)
  }
  ws.onclose = () => {
    e.ws = null
    e.conn = 'closed'
    emit(e)
    e.timer = setTimeout(() => {
      e.timer = null
      connect(container)
    }, RECONNECT_MS)
  }
}

/** Start streaming a container if not already (idempotent). */
export function ensureStream(container: string) {
  const e = entry(container)
  if (!e.ws && !e.timer) connect(container)
}

export function clearLogs(container: string) {
  const e = entry(container)
  e.lines = []
  persist(container, e)
  emit(e)
}

export function setLogsPaused(p: boolean) {
  paused = p
}

/** Subscribe to one container's buffer; returns the live lines and connection state. */
export function useLogStream(container: string): { lines: LogLine[]; conn: ConnState } {
  const e = entry(container)
  const subscribe = (cb: () => void) => {
    e.listeners.add(cb)
    return () => {
      e.listeners.delete(cb)
    }
  }
  const lines = useSyncExternalStore(subscribe, () => e.lines)
  const conn = useSyncExternalStore(subscribe, () => e.conn)
  return { lines, conn }
}
