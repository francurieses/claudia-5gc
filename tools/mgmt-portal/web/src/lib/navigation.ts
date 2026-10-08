import type { LucideIcon } from 'lucide-react'
import type { Deployment } from './api'
import {
  Activity,
  AlertTriangle,
  Antenna,
  FileText,
  Gauge,
  Layers,
  LayoutDashboard,
  MapPin,
  Radio,
  RadioTower,
  Server,
  ShieldCheck,
  Users,
  Zap,
} from 'lucide-react'

/**
 * Navigation information architecture — grouped by domain/task instead of a
 * flat list of 13 entries.
 *
 * Routes are intentionally UNCHANGED from the pre-redesign IA: the regrouping is
 * presentational, so existing deep links keep working and no `<Navigate>`
 * redirects are required (PRD open question O1 — resolved as "keep the URLs").
 *
 * Kept free of React/DOM imports so the IA invariants (one group per route, no
 * duplicates, ≤2 clicks to any destination) stay mechanically checkable.
 */

export interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  /** Match the path exactly (used for the index route). */
  end?: boolean
  /** RAN simulator that must be deployed for this item to be offered. */
  requires?: 'ueransim' | 'packetrusher'
}

export interface NavGroup {
  id: string
  label: string
  items: NavItem[]
}

export const NAV_GROUPS: NavGroup[] = [
  {
    id: 'overview',
    label: 'Overview',
    items: [{ to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true }],
  },
  {
    id: 'data',
    label: 'Data & Config',
    items: [
      { to: '/subscribers', label: 'Subscribers', icon: Users },
      { to: '/slices', label: 'Network Slices', icon: Layers },
      { to: '/policies', label: 'Policies', icon: ShieldCheck },
    ],
  },
  {
    id: 'runtime',
    label: 'Runtime',
    items: [
      { to: '/services', label: 'Services', icon: Server },
      { to: '/ran', label: 'gNBs (RAN)', icon: RadioTower },
      { to: '/sessions', label: 'Sessions', icon: Activity },
      { to: '/qos', label: 'QoS / PDU Sessions', icon: Gauge },
    ],
  },
  {
    id: 'test-ues',
    label: 'Test Tools',
    items: [
      { to: '/ueransim', label: 'UERANSIM', icon: Antenna, requires: 'ueransim' },
      { to: '/packetrusher', label: 'PacketRusher', icon: Zap, requires: 'packetrusher' },
      { to: '/location', label: 'UE Location', icon: MapPin },
    ],
  },
  {
    id: 'operations',
    label: 'Operations',
    items: [
      { to: '/logs', label: 'Logs', icon: FileText },
      { to: '/pcap', label: 'PCAP', icon: Radio },
    ],
  },
  {
    id: 'safety',
    label: 'Safety',
    items: [{ to: '/pws', label: 'Public Warning', icon: AlertTriangle }],
  },
]

/**
 * The nav groups to render for the current deployment mode: items whose
 * `requires` simulator is not deployed are dropped, and groups left empty are
 * hidden. While the deployment probe is loading, gated items stay hidden
 * (standalone is the default); if it failed, everything is shown (fail-open).
 */
export function visibleNavGroups(
  groups: NavGroup[],
  caps: Pick<Deployment, 'ueransim' | 'packetrusher'> | undefined,
  failed: boolean,
): NavGroup[] {
  return groups
    .map(group => ({
      ...group,
      items: group.items.filter(item => {
        if (!item.requires || failed) return true
        return caps?.[item.requires].deployed ?? false
      }),
    }))
    .filter(group => group.items.length > 0)
}

/** The route table rendered by `App.tsx`, in navigation order. */
export const NAV_ROUTES: { path: string; label: string }[] = NAV_GROUPS.flatMap(group =>
  group.items.map(item => ({ path: item.to, label: item.label })),
)

export const ALL_GROUP_IDS: string[] = NAV_GROUPS.map(group => group.id)

/** The id of the nav group owning `pathname` (longest route prefix wins). */
export function groupForPath(pathname: string): string | undefined {
  let match: { id: string; length: number } | undefined

  for (const group of NAV_GROUPS) {
    for (const item of group.items) {
      const hit = item.end
        ? pathname === item.to
        : pathname === item.to || pathname.startsWith(`${item.to}/`)
      if (hit && (!match || item.to.length > match.length)) {
        match = { id: group.id, length: item.to.length }
      }
    }
  }

  return match?.id
}

/** localStorage keys for the persisted sidebar state. */
export const NAV_COLLAPSED_KEY = 'portal.nav.collapsed'
export const NAV_GROUPS_KEY = 'portal.nav.groups'
