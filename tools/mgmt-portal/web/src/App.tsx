import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { BrowserRouter, NavLink, Route, Routes, useLocation } from 'react-router-dom'
import { ChevronDown, Menu, X } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import Subscribers from './pages/Subscribers'
import Slices from './pages/Slices'
import Services from './pages/Services'
import Sessions from './pages/Sessions'
import Logs from './pages/Logs'
import PCAP from './pages/PCAP'
import UERANSim from './pages/UERANSim'
import PacketRusher from './pages/PacketRusher'
import Policies from './pages/Policies'
import QoS from './pages/QoS'
import Location from './pages/Location'
import PublicWarning from './pages/PublicWarning'
import ThemeToggle from './components/ThemeToggle'
import { IconButton, useFocusTrap } from './components/ui'
import { ALL_GROUP_IDS, NAV_GROUPS, groupForPath } from './lib/navigation'

/** Page components keyed by route path — mirrors `NAV_ROUTES`. */
const PAGES: Record<string, () => JSX.Element> = {
  '/': Dashboard,
  '/subscribers': Subscribers,
  '/slices': Slices,
  '/services': Services,
  '/sessions': Sessions,
  '/qos': QoS,
  '/policies': Policies,
  '/ueransim': UERANSim,
  '/location': Location,
  '/packetrusher': PacketRusher,
  '/pws': PublicWarning,
  '/logs': Logs,
  '/pcap': PCAP,
}

function AppShell() {
  const location = useLocation()
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(ALL_GROUP_IDS.map(id => [id, true])),
  )
  const [drawerOpen, setDrawerOpen] = useState(false)
  const menuButtonRef = useRef<HTMLButtonElement>(null)

  const activeGroup = useMemo(() => groupForPath(location.pathname), [location.pathname])

  // Keep the active group expanded so every destination stays within ≤2 clicks.
  useEffect(() => {
    if (!activeGroup) return
    setOpenGroups(prev => (prev[activeGroup] ? prev : { ...prev, [activeGroup]: true }))
  }, [activeGroup])

  // Navigate ⇒ the overlay drawer has done its job.
  useEffect(() => {
    setDrawerOpen(false)
  }, [location.pathname])

  const closeDrawer = useCallback(() => {
    setDrawerOpen(false)
    menuButtonRef.current?.focus()
  }, [])

  // Below `lg` the sidebar is an overlay drawer, so it owns the overlay
  // contract (focus trap, ESC, focus restore). On `lg`+ it is a static sidebar
  // and the trap stays disabled — `drawerOpen` can only be set from the
  // `lg:hidden` menu button.
  const drawerRef = useFocusTrap<HTMLElement>({ enabled: drawerOpen, onEscape: closeDrawer })

  return (
    <div className="flex h-screen overflow-hidden bg-bg text-fg">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-control focus:bg-primary focus:px-3 focus:py-2 focus:text-sm focus:text-primary-fg"
      >
        Skip to content
      </a>

      {drawerOpen && (
        // Decorative scrim: click-to-dismiss for pointers, `ESC` for keyboard
        // (the trap below). Not a focus stop — the `Modal` primitive does the
        // same with `aria-hidden`.
        <div
          aria-hidden="true"
          onClick={closeDrawer}
          className="fixed inset-0 z-30 bg-overlay/60 lg:hidden"
        />
      )}

      <aside
        ref={drawerRef}
        id="primary-navigation"
        className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-border bg-card transition-transform duration-200 lg:static lg:z-auto lg:translate-x-0 ${
          drawerOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex h-14 flex-shrink-0 items-center justify-between border-b border-border px-4 lg:hidden">
          <span className="text-sm font-semibold text-fg">Navigation</span>
          <IconButton label="Close navigation" variant="ghost" onClick={closeDrawer}>
            <X size={18} />
          </IconButton>
        </div>

        <nav aria-label="Primary" className="flex-1 overflow-y-auto p-2">
          {NAV_GROUPS.map(group => {
            const open = openGroups[group.id] ?? true
            const isActiveGroup = activeGroup === group.id
            const panelId = `nav-group-${group.id}`

            return (
              <div key={group.id} className="mb-1">
                <button
                  type="button"
                  onClick={() => setOpenGroups(prev => ({ ...prev, [group.id]: !open }))}
                  aria-expanded={open}
                  aria-controls={panelId}
                  className={`flex w-full items-center justify-between gap-2 rounded-control px-3 py-1.5 text-xs font-semibold uppercase tracking-wider transition-colors hover:text-fg ${
                    isActiveGroup ? 'text-fg' : 'text-muted-fg'
                  }`}
                >
                  <span className="truncate">{group.label}</span>
                  <ChevronDown
                    size={14}
                    aria-hidden="true"
                    className={`flex-shrink-0 transition-transform duration-200 ${open ? '' : '-rotate-90'}`}
                  />
                </button>

                {open && (
                  <div id={panelId} className="mt-0.5 space-y-0.5">
                    {group.items.map(({ to, label, icon: Icon, end }) => (
                      <NavLink
                        key={to}
                        to={to}
                        end={end}
                        className={({ isActive }) =>
                          `flex items-center gap-3 rounded-control px-3 py-2 text-sm transition-colors ${
                            isActive
                              ? 'bg-primary text-primary-fg'
                              : 'text-muted-fg hover:bg-muted hover:text-fg'
                          }`
                        }
                      >
                        <Icon size={16} aria-hidden="true" className="flex-shrink-0" />
                        <span className="truncate">{label}</span>
                      </NavLink>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </nav>

        <div className="flex-shrink-0 border-t border-border p-3">
          <p className="text-xs text-muted-fg">Rel-17 · dev</p>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <header className="flex h-14 flex-shrink-0 items-center gap-3 border-b border-border bg-card px-4">
          <IconButton
            ref={menuButtonRef}
            label="Open navigation"
            className="lg:hidden"
            aria-expanded={drawerOpen}
            aria-controls="primary-navigation"
            onClick={() => setDrawerOpen(true)}
          >
            <Menu size={18} />
          </IconButton>

          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-bold uppercase tracking-widest text-primary-text">
              ClaudIA 5GC
            </p>
            <p className="truncate text-xs text-muted-fg">Management Portal</p>
          </div>

          <ThemeToggle />
        </header>

        <main id="main-content" tabIndex={-1} className="flex-1 overflow-y-auto">
          <Routes>
            {Object.entries(PAGES).map(([path, Page]) => (
              <Route key={path} path={path} element={<Page />} />
            ))}
          </Routes>
        </main>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  )
}
