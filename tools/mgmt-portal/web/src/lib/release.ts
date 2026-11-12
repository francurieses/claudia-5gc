import { useQuery } from '@tanstack/react-query'
import { getRelease } from './api'
import type { ReleaseInfo } from './api'

/** The backend caches the profile for 30 s; the release only changes on a core redeploy. */
const RELEASE_REFETCH_MS = 60_000

/** Configured 3GPP release profile of the running core, polled slowly. */
export function useRelease() {
  return useQuery({ queryKey: ['release'], queryFn: getRelease, refetchInterval: RELEASE_REFETCH_MS })
}

export interface ReleaseLabel {
  text: string
  tooltip: string
}

/** Sidebar-footer label for a release answer (undefined = still loading/failed). */
export function releaseLabel(info: ReleaseInfo | undefined): ReleaseLabel {
  switch (info?.profile) {
    case 'rel19':
      return {
        text: 'Release 19 · configured',
        tooltip: 'Rel-19 profile; Rel-15/16/17 peers still supported (byte-identical messages)',
      }
    case 'rel17':
      return { text: 'Release 17 profile', tooltip: 'Rel-17 profile configured on every core NF' }
    case 'mixed':
      return {
        text: 'Mixed releases',
        tooltip: Object.entries(info.nfs)
          .map(([nf, p]) => `${nf.toUpperCase()}: ${p}`)
          .join('\n'),
      }
    default:
      return { text: 'Release: unknown', tooltip: 'No NF reported a release profile (containers stopped or logs unavailable)' }
  }
}
