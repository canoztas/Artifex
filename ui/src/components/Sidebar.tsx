import { useState } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import {
  Briefcase,
  FileSearch,
  Clock,
  Search,
  Bot,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  LayoutDashboard,
  ClipboardList,
} from 'lucide-react'

interface NavItem {
  label: string
  path: string
  icon: React.ReactNode
}

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false)
  const location = useLocation()
  const { id } = useParams<{ id: string }>()

  const globalNav: NavItem[] = [
    { label: 'Cases', path: '/', icon: <Briefcase size={20} /> },
  ]

  const caseNav: NavItem[] = id
    ? [
        { label: 'Overview', path: `/cases/${id}`, icon: <LayoutDashboard size={20} /> },
        { label: 'Artifacts', path: `/cases/${id}/artifacts`, icon: <FileSearch size={20} /> },
        { label: 'Timeline', path: `/cases/${id}/timeline`, icon: <Clock size={20} /> },
        { label: 'Events', path: `/cases/${id}/events`, icon: <Search size={20} /> },
        { label: 'Agent', path: `/cases/${id}/agent`, icon: <Bot size={20} /> },
        { label: 'Actions', path: `/cases/${id}/actions`, icon: <ShieldCheck size={20} /> },
        { label: 'Audit', path: `/cases/${id}`, icon: <ClipboardList size={20} /> },
      ]
    : []

  function isActive(path: string) {
    return location.pathname === path
  }

  return (
    <aside
      className={`${
        collapsed ? 'w-16' : 'w-56'
      } bg-slate-800 border-r border-slate-700 flex flex-col shrink-0 transition-all duration-200`}
    >
      {/* Brand */}
      <div className="h-14 flex items-center px-4 border-b border-slate-700 gap-3">
        <div className="w-8 h-8 bg-forensic-600 rounded-lg flex items-center justify-center shrink-0">
          <Search size={18} className="text-white" />
        </div>
        {!collapsed && (
          <span className="text-sm font-semibold text-slate-200 whitespace-nowrap">
            Artifex
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
        {/* Global nav */}
        {globalNav.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
              isActive(item.path)
                ? 'bg-forensic-600/20 text-forensic-400'
                : 'text-slate-400 hover:bg-slate-700 hover:text-slate-200'
            }`}
            title={collapsed ? item.label : undefined}
          >
            {item.icon}
            {!collapsed && <span>{item.label}</span>}
          </Link>
        ))}

        {/* Case nav */}
        {caseNav.length > 0 && (
          <>
            <div className="pt-4 pb-2">
              {!collapsed && (
                <div className="px-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                  Case
                </div>
              )}
              {collapsed && <div className="border-t border-slate-700 mx-2" />}
            </div>
            {caseNav.map((item) => (
              <Link
                key={item.path + item.label}
                to={item.path}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  isActive(item.path)
                    ? 'bg-forensic-600/20 text-forensic-400'
                    : 'text-slate-400 hover:bg-slate-700 hover:text-slate-200'
                }`}
                title={collapsed ? item.label : undefined}
              >
                {item.icon}
                {!collapsed && <span>{item.label}</span>}
              </Link>
            ))}
          </>
        )}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="h-10 flex items-center justify-center border-t border-slate-700 text-slate-500 hover:text-slate-300 hover:bg-slate-700/50"
      >
        {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
      </button>
    </aside>
  )
}
