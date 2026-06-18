import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Users,
  Layers,
  Server,
  Activity,
  FileText,
  Radio,
  Antenna,
  Zap,
  ShieldCheck,
  Gauge,
} from 'lucide-react'
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

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/subscribers', label: 'Subscribers', icon: Users },
  { to: '/slices', label: 'Network Slices', icon: Layers },
  { to: '/policies', label: 'Policies', icon: ShieldCheck },
  { to: '/services', label: 'Services', icon: Server },
  { to: '/sessions', label: 'Sessions', icon: Activity },
  { to: '/qos', label: 'QoS / PDU Sessions', icon: Gauge },
  { to: '/ueransim', label: 'UERANSIM', icon: Antenna },
  { to: '/packetrusher', label: 'PacketRusher', icon: Zap },
  { to: '/logs', label: 'Logs', icon: FileText },
  { to: '/pcap', label: 'PCAP', icon: Radio },
]

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen overflow-hidden">
        {/* Sidebar */}
        <aside className="w-56 flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
          <div className="p-4 border-b border-gray-800">
            <h1 className="text-sm font-bold text-blue-400 uppercase tracking-widest">ClaudIA 5GC</h1>
            <p className="text-xs text-gray-400 mt-0.5">Management Portal</p>
          </div>
          <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
            {navItems.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                    isActive
                      ? 'bg-blue-600 text-white'
                      : 'text-gray-400 hover:bg-gray-800 hover:text-gray-100'
                  }`
                }
              >
                <Icon size={16} />
                {label}
              </NavLink>
            ))}
          </nav>
          <div className="p-3 border-t border-gray-800">
            <p className="text-xs text-gray-600">Rel-17 · dev</p>
          </div>
        </aside>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/subscribers" element={<Subscribers />} />
            <Route path="/slices" element={<Slices />} />
            <Route path="/services" element={<Services />} />
            <Route path="/sessions" element={<Sessions />} />
            <Route path="/qos" element={<QoS />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/ueransim" element={<UERANSim />} />
            <Route path="/packetrusher" element={<PacketRusher />} />
            <Route path="/logs" element={<Logs />} />
            <Route path="/pcap" element={<PCAP />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
