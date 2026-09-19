import { Fragment, useEffect, useMemo, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { MapContainer, TileLayer, CircleMarker, Circle, Tooltip, useMap } from 'react-leaflet'
import type { LatLngBoundsExpression } from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { CheckCircle2, RefreshCw, WifiOff } from 'lucide-react'
import { getLocationSummary } from '../lib/api'
import {
  Badge, Button, Card, ErrorState, Loading, PageHeader, Table, TableBody, TableCell,
  TableEmptyRow, TableHead, TableHeaderCell, TableRow, useChartTheme,
} from '../components/ui'

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
  // Leaflet renders to a canvas and needs concrete colour values, not classes:
  // resolve the token ramp at runtime so the marker/circle follow the theme
  // (see STYLE_GUIDE §12 "Leaflet dark tiles"). `useChartTheme` re-evaluates
  // when the `.dark` class flips.
  const chart = useChartTheme()

  const {
    data: locs = [],
    isLoading,
    error,
    refetch,
  } = useQuery({
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
    <div className="space-y-6 p-6">
      <PageHeader
        eyebrow="Test UEs"
        title="UE Location"
        subtitle="Live Cell-ID positioning via LMF (Nlmf_Location DetermineLocation — TS 29.572 §5.2.2.2)"
        action={
          <div className="flex flex-wrap items-center gap-2">
            <Badge
              label={`${reachableCount} located`}
              variant="success"
              icon={<CheckCircle2 size={12} />}
            />
            <Badge
              label={`${idleCount} idle/unreachable`}
              variant="warning"
              icon={<WifiOff size={12} />}
            />
          </div>
        }
      />

      <Card padded={false} className="h-[460px] overflow-hidden">
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
                    pathOptions={{
                      color: chart.series[0],
                      fillColor: chart.series[0],
                      fillOpacity: 0.12,
                      weight: 1,
                    }}
                  />
                ) : null}
                <CircleMarker
                  center={pos}
                  radius={7}
                  pathOptions={{
                    color: chart.series[2],
                    fillColor: chart.series[2],
                    fillOpacity: 0.9,
                    weight: 2,
                  }}
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
      </Card>

      <p className="text-xs text-muted-fg">
        Map tiles are served from OpenStreetMap and require outbound internet access. Coordinates are
        synthesized by the LMF from the serving NR cell (Cell-ID positioning carries no lat/lon on the wire).
      </p>

      {error ? (
        <ErrorState
          title="Failed to load UE locations"
          description={(error as Error).message}
          action={
            <Button variant="secondary" size="sm" icon={<RefreshCw size={14} />} onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : (
        <Table caption="UE location summary">
          <TableHead>
            <TableRow>
              <TableHeaderCell>SUPI</TableHeaderCell>
              <TableHeaderCell>Status</TableHeaderCell>
              <TableHeaderCell>NR Cell</TableHeaderCell>
              <TableHeaderCell>TAC / PLMN</TableHeaderCell>
              <TableHeaderCell>Latitude</TableHeaderCell>
              <TableHeaderCell>Longitude</TableHeaderCell>
              <TableHeaderCell>Accuracy</TableHeaderCell>
              <TableHeaderCell>Updated</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {isLoading ? (
              <TableEmptyRow colSpan={8}>
                <Loading rows={3} label="Loading UE locations…" />
              </TableEmptyRow>
            ) : locs.length === 0 ? (
              <TableEmptyRow colSpan={8}>No registered UEs</TableEmptyRow>
            ) : (
              locs.map(l => (
                <TableRow key={l.supi}>
                  <TableCell mono title={l.supi}>
                    <span aria-hidden="true">{shortSupi(l.supi)}</span>
                    <span className="sr-only">{l.supi}</span>
                  </TableCell>
                  <TableCell>
                    {l.reachable ? (
                      <Badge label="LOCATED" variant="success" icon={<CheckCircle2 size={12} />} />
                    ) : (
                      <Badge
                        label={l.cause || GMM_STATES[l.gmm_state] || 'UNREACHABLE'}
                        variant="warning"
                        icon={<WifiOff size={12} />}
                      />
                    )}
                  </TableCell>
                  <TableCell mono className="text-muted-fg">
                    {l.nr_cell_id || '—'}
                  </TableCell>
                  <TableCell mono className="text-muted-fg">
                    {l.reachable ? `${l.tac || '—'} / ${l.plmn || '—'}` : '—'}
                  </TableCell>
                  <TableCell mono>{l.latitude != null ? l.latitude.toFixed(5) : '—'}</TableCell>
                  <TableCell mono>{l.longitude != null ? l.longitude.toFixed(5) : '—'}</TableCell>
                  <TableCell className="text-xs text-muted-fg">
                    {l.accuracy_m ? `±${Math.round(l.accuracy_m)} m` : '—'}
                  </TableCell>
                  <TableCell className="text-xs text-muted-fg">
                    {new Date(l.timestamp).toLocaleTimeString()}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      )}
    </div>
  )
}
