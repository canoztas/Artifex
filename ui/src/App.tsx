import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import CaseList from './pages/CaseList'
import CaseDetail from './pages/CaseDetail'
import ArtifactBrowser from './pages/ArtifactBrowser'
import Timeline from './pages/Timeline'
import EventSearch from './pages/EventSearch'
import AgentWorkspace from './pages/AgentWorkspace'
import ActionReview from './pages/ActionReview'

export default function App() {
  return (
    <div className="flex h-screen bg-slate-900 text-slate-100">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-14 bg-slate-800 border-b border-slate-700 flex items-center px-6 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-forensic-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-sm">P</span>
            </div>
            <h1 className="text-lg font-semibold text-slate-100 tracking-tight">
              Artifex <span className="text-forensic-400">DFIR</span>
            </h1>
          </div>
          <div className="ml-auto text-xs text-slate-500">
            Windows Digital Forensics &amp; Incident Response
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-6">
          <Routes>
            <Route path="/" element={<CaseList />} />
            <Route path="/cases/:id" element={<CaseDetail />} />
            <Route path="/cases/:id/artifacts" element={<ArtifactBrowser />} />
            <Route path="/cases/:id/timeline" element={<Timeline />} />
            <Route path="/cases/:id/events" element={<EventSearch />} />
            <Route path="/cases/:id/agent" element={<AgentWorkspace />} />
            <Route path="/cases/:id/actions" element={<ActionReview />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}
