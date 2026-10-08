import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { PackageX } from 'lucide-react'
import { EmptyState, Page, PageHeader } from './ui'
import { isToolAvailable, modeLabel, useDeployment } from '../lib/deployment'
import type { RanTool } from '../lib/api'

const TOOL_NAMES: Record<RanTool, string> = {
  ueransim: 'UERANSIM',
  packetrusher: 'PacketRusher',
}

/**
 * Renders `children` when the RAN simulator is part of the current deployment,
 * otherwise a "not deployed in this mode" notice with the command to add it.
 * Re-evaluates on every deployment poll, so a deep link comes alive as soon as
 * the simulator is started — no redirect, no reload.
 */
export default function RequiresTool({ tool, children }: { tool: RanTool; children: ReactNode }) {
  const view = useDeployment()
  if (isToolAvailable(view, tool)) return <>{children}</>

  const name = TOOL_NAMES[tool]
  return (
    <Page>
      <PageHeader eyebrow="Test Tools" title={name} />
      <EmptyState
        icon={<PackageX size={28} />}
        title={`${name} is not deployed in this mode`}
        description={`Current mode: ${view.caps ? modeLabel(view.caps.mode) : 'detecting…'}. Add it with: make up RAN=${tool}`}
        action={
          <Link to="/ran" className="text-sm text-primary-text underline">
            See the gNBs connected to the core
          </Link>
        }
      />
    </Page>
  )
}
