/**
 * Shared display formatters — the "formatting helpers" consolidated out of the
 * page rollout (PORTAL-UI-19; formerly duplicated per page).
 *
 * React-free so they stay usable anywhere and reviewable in isolation, the same
 * pattern as `lib/navigation.ts` and `lib/metricsRange.ts`. Only formatting that
 * actually repeats across pages belongs here; a one-off stays on its page.
 */

const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB'] as const

/**
 * Human-readable byte size, binary units, one decimal above bytes.
 *
 * Used for PCAP capture-file sizes. `>= 1024` steps up a unit so a capture list
 * never shows a seven-digit raw count.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—'
  if (bytes < 1024) return `${Math.round(bytes)} B`

  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(1)} ${BYTE_UNITS[unit]}`
}

/**
 * Fixed-width, 0x-prefixed 32-bit hex — TEIDs (TS 29.281 §7), TMSIs
 * (TS 24.301 §9.9.3.12) and other 32-bit identifiers.
 *
 * Always 8 digits so columns of identifiers align under `tabular-nums`.
 */
export function formatHex32(value: number): string {
  return `0x${(value >>> 0).toString(16).toUpperCase().padStart(8, '0')}`
}

const BIT_UNITS = ['bps', 'kbps', 'Mbps', 'Gbps', 'Tbps'] as const

/**
 * Human-readable bit rate, SI units (1000), one decimal above the base unit.
 *
 * Used by the Dashboard's N3 throughput chart (TS 28.554 §5.3): the backend
 * reports GTP-U throughput in bits/s, which is unreadable as a raw count once
 * the lab actually forwards traffic. Mirrors {@link formatBytes} but with the
 * 1000-based SI ladder networking uses.
 */
export function formatBitsPerSec(bitsPerSecond: number): string {
  if (!Number.isFinite(bitsPerSecond) || bitsPerSecond < 0) return '—'
  if (bitsPerSecond < 1000) return `${Math.round(bitsPerSecond)} bps`

  let value = bitsPerSecond
  let unit = 0
  while (value >= 1000 && unit < BIT_UNITS.length - 1) {
    value /= 1000
    unit += 1
  }
  return `${value.toFixed(1)} ${BIT_UNITS[unit]}`
}
