import { Fragment, useEffect, useMemo, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { MapContainer, TileLayer, CircleMarker, Circle, Tooltip, useMap } from 'react-leaflet'
import type { LatLngBoundsExpression } from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { getLocationSummary } from '../lib/api'
import PageHeader from '../components/PageHeader'
import Badge from '../components/Badge'

const MADRID: [number, number] = [40.4168, -3.7038]

const GMM_STATES: Record<number, string> = {
  0: 'DEREGISTERED',
  1: 'REGISTERED',
  2: 'REGISTERED-INITIATED',
  3: 'DEREGISTERED-INITIATED',
}

function shortSupi(supi: string): string {
  const m = supi.match(/(\d{4})$/)
  return m ? '…' + m[1] : supi
}

// FitOnce fits the map to all located UEs the first time they appear, then leaves the
// view under user control (so markers can drift without the map snapping around).
function FitOnce({ points }: { points: [number, number][] }) {
  const map = useMap()
  const done = useRef(false)
  useEffect(() => {
    if (done.current || points.length === 0) return
    if (points.length === 1) {
      map.setView(points[0], 15)
    } else {
      const bounds: LatLngBoundsExpression = points
      map.fitBounds(bounds, { padding: [40, 40] })
    }
    done.current = true
  }, [points, map])
  return null
}

export default function Location() {
  const { data: locs = [], isLoading, error } = useQuery({
    queryKey: ['location-summary'],
    queryFn: getLocationSummary,
    refetchInterval: 3_000,
  })

  const located = useMemo(
    () => locs.filter(l => l.reachable && l.latitude != null && l.longitude != null),
    [locs],
  )
  const points = useMemo<[number, number][]>(
    () => located.map(l => [l.latitude as number, l.longitude as number]),
    [located],
  )

  const reachableCount = located.length
  const idleCount = locs.length - reachableCount

  return (
    <div className="p-6">
      <PageHeader
        title="UE Location"
        subtitle="Live Cell-ID positioning via LMF (Nlmf_Location DetermineLocation — TS 29.572 §5.2.2.2)"
        action={
          <div className="flex gap-2 text-xs">
            <Badge label={`${reachableCount} located`} variant="green" />
            <Badge label={`${idleCount} idle/unreachable`} variant="yellow" />
          </div>
        }
      />

      <div className="h-[460px] rounded-lg border border-gray-800 overflow-hidden mb-6">
        <MapContainer center={MADRID} zoom={12} className="h-full w-full" scrollWheelZoom>
          <TileLayer
            attribution='&copy; OpenStreetMap contributors'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />
          <FitOnce points={points} />
          {located.map(l => {
            const pos: [number, number] = [l.latitude as number, l.longitude as number]
            return (
              <Fragment key={l.supi}>
                {l.accuracy_m ? (
                  <Circle
                    center={pos}
                    radius={l.accuracy_m}
                    pathOptions={{ color: '#3b82f6', fillColor: '#3b82f6', fillOpacity: 0.12, weight: 1 }}
                  />
                ) : null}
                <CircleMarker
                  center={pos}
                  radius={7}
                  pathOptions={{ color: '#16a34a', fillColor: '#22c55e', fillOpacity: 0.9, weight: 2 }}
                >
                  <Tooltip>
                    <div className="text-xs">
                      <div className="font-mono font-semibold">{l.supi}</div>
                      <div>cell {l.nr_cell_id}</div>
                      <div>
                        {pos[0].toFixed(5)}, {pos[1].toFixed(5)} · ±{Math.round(l.accuracy_m ?? 0)} m
                      </div>
                    </div>
                  </Tooltip>
                </CircleMarker>
              </Fragment>
            )
          })}
        </MapContainer>
      </div>

      {error ? (
        <div className="text-sm text-red-400 mb-4">Failed to load locations: {(error as Error).message}</div>
      ) : null}
      <p className="text-xs text-gray-600 mb-3">
        Map tiles are served from OpenStreetMap and require outbound internet access. Coordinates are
        synthesized by the LMF from the serving NR cell (Cell-ID positioning carries no lat/lon on the wire).
      </p>

      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
              <th className="px-4 py-3 text-left">SUPI</th>
              <th className="px-4 py-3 text-left">Status</th>
              <th className="px-4 py-3 text-left">NR Cell</th>
              <th className="px-4 py-3 text-left">TAC / PLMN</th>
              <th className="px-4 py-3 text-left">Latitude</th>
              <th className="px-4 py-3 text-left">Longitude</th>
              <th className="px-4 py-3 text-left">Accuracy</th>
              <th className="px-4 py-3 text-left">Updated</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr><td colSpan={8} className="px-4 py-6 text-center text-gray-500">Loading…</td></tr>
            ) : locs.length === 0 ? (
              <tr><td colSpan={8} className="px-4 py-6 text-center text-gray-500">No registered UEs</td></tr>
            ) : (
              locs.map(l => (
                <tr key={l.supi} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-3 font-mono text-xs text-blue-300" title={l.supi}>
                    {shortSupi(l.supi)}
                  </td>
                  <td className="px-4 py-3">
                    {l.reachable ? (
                      <Badge label="LOCATED" variant="green" />
                    ) : (
                      <Badge label={l.cause || GMM_STATES[l.gmm_state] || 'UNREACHABLE'} variant="yellow" />
                    )}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-300">{l.nr_cell_id || '—'}</td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-400">
                    {l.reachable ? `${l.tac || '—'} / ${l.plmn || '—'}` : '—'}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-300">
                    {l.latitude != null ? l.latitude.toFixed(5) : '—'}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-300">
                    {l.longitude != null ? l.longitude.toFixed(5) : '—'}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-400">
                    {l.accuracy_m ? `±${Math.round(l.accuracy_m)} m` : '—'}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">
                    {new Date(l.timestamp).toLocaleTimeString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
