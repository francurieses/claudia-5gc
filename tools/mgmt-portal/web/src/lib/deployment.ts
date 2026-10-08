import { useQuery } from '@tanstack/react-query'
import { getDeployment } from './api'
import type { Deployment, DeploymentMode, RanTool } from './api'

/** How often the deployment mode is re-probed; the backend caches for 5 s. */
const DEPLOYMENT_REFETCH_MS = 10_000

export interface DeploymentView {
  /** Deployment capabilities; undefined while the first probe is loading or if it failed. */
  caps: Deployment | undefined
  /** The probe failed — callers fail open and keep every tool visible. */
  failed: boolean
  isLoading: boolean
}

/** Current deployment mode (standalone core vs. RAN simulators), polled. */
export function useDeployment(): DeploymentView {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['deployment'],
    queryFn: getDeployment,
    refetchInterval: DEPLOYMENT_REFETCH_MS,
  })
  return { caps: data, failed: isError && !data, isLoading }
}

/**
 * Whether a RAN simulator page/feature should be offered. Standalone is the
 * default, so the tool stays hidden while loading; a failed probe fails open.
 */
export function isToolAvailable(view: DeploymentView, tool: RanTool): boolean {
  if (view.failed) return true
  return view.caps?.[tool].deployed ?? false
}

const MODE_LABELS: Record<DeploymentMode, string> = {
  standalone: 'Standalone core',
  ueransim: 'Core + UERANSIM',
  packetrusher: 'Core + PacketRusher',
  both: 'Core + UERANSIM + PacketRusher',
}

export function modeLabel(mode: DeploymentMode): string {
  return MODE_LABELS[mode]
}
