import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  FileText,
  AlertTriangle,
  Crosshair,
  GitFork,
  Network,
  ShieldCheck,
  Settings,
  Shield,
  Activity,
  Circle,
} from 'lucide-react'

const navItems = [
  { to: '/',              label: 'Overview',              icon: LayoutDashboard },
  { to: '/logs',          label: 'Security Logs',         icon: FileText },
  { to: '/alerts',        label: 'Alerts',                icon: AlertTriangle },
  { to: '/investigation', label: 'Attack Investigation',  icon: Crosshair },
  { to: '/kill-chain',    label: 'Kill Chains',           icon: GitFork },
  { to: '/graph',         label: 'Attack Graph',          icon: Network },
  { to: '/monitoring',    label: 'Monitoring',            icon: ShieldCheck },
  { to: '/settings',      label: 'Settings',              icon: Settings },
]

export default function Sidebar({ alertCount = 9 }) {
  return (
    <aside className="w-64 bg-[#0c1017] border-r border-[#1a2234] flex flex-col justify-between shrink-0 h-screen sticky top-0 select-none z-30">
      {/* Top: Brand Header */}
      <div>
        <div className="p-5 border-b border-[#1a2234]">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-blue-600 to-cyan-600 flex items-center justify-center shadow-lg shadow-blue-600/25 text-white">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm font-bold text-white tracking-wider leading-tight">
                THREAT INTELLIGENCE
              </div>
              <div className="text-[11px] text-cyan-400 font-medium tracking-wide">
                Kill-Chain Engine
              </div>
            </div>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-3 space-y-1">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30 shadow-sm font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#121826]'
                }`
              }
            >
              <div className="flex items-center gap-3">
                <Icon className="w-4 h-4" />
                <span>{label}</span>
              </div>
              {label === 'Alerts' && alertCount > 0 && (
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30">
                  {alertCount}
                </span>
              )}
            </NavLink>
          ))}
        </nav>
      </div>

      {/* Bottom: System Status Card */}
      <div className="p-4 border-t border-[#1a2234]">
        <div className="bg-[#121826] border border-[#1f293d] rounded-xl p-3.5 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span className="text-xs font-semibold text-slate-200">Engine Online</span>
            </div>
            <span className="text-[10px] text-slate-500">v2.4</span>
          </div>
          <div className="text-[11px] text-slate-400">
            Automated correlation active
          </div>
        </div>
      </div>
    </aside>
  )
}
