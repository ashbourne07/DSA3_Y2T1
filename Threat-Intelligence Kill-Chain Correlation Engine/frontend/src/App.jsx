import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import axios from 'axios'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Logs from './pages/Logs'
import Alerts from './pages/Alerts'
import Investigation from './pages/Investigation'
import KillChain from './pages/KillChain'
import AttackGraph from './pages/AttackGraph'
import Monitoring from './pages/Monitoring'
import Settings from './pages/Settings'

const API = 'http://localhost:8000'

function App() {
  const [alertCount, setAlertCount] = useState(9)

  useEffect(() => {
    axios.get(`${API}/api/alerts/`)
      .then(({ data }) => {
        if (data.alerts) setAlertCount(data.alerts.length)
      })
      .catch(() => {})
  }, [])

  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-[#0a0d14] text-slate-100 font-sans antialiased">
        {/* Left: Professional SOC Sidebar */}
        <Sidebar alertCount={alertCount} />

        {/* Right: Main Application Work Area */}
        <main className="flex-1 flex flex-col min-w-0 overflow-y-auto">
          <Routes>
            <Route path="/"              element={<Dashboard />} />
            <Route path="/logs"          element={<Logs />} />
            <Route path="/alerts"        element={<Alerts />} />
            <Route path="/investigation" element={<Investigation />} />
            <Route path="/kill-chain"    element={<KillChain />} />
            <Route path="/graph"         element={<AttackGraph />} />
            <Route path="/monitoring"    element={<Monitoring />} />
            <Route path="/settings"      element={<Settings />} />
            <Route path="*"              element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

export default App
