import { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import {
  AlertTriangle,
  Search,
  Filter,
  ArrowRight,
  ShieldAlert,
  Clock,
  Laptop,
  CheckCircle2,
  X,
  ExternalLink,
} from 'lucide-react'
import Header from '../components/Header'

const API = 'http://localhost:8000'

const SEV_CONFIG = {
  CRITICAL: { badge: 'bg-red-500/15 text-red-400 border-red-500/30', dot: 'bg-red-500' },
  HIGH:     { badge: 'bg-orange-500/15 text-orange-400 border-orange-500/30', dot: 'bg-orange-500' },
  MEDIUM:   { badge: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30', dot: 'bg-yellow-500' },
  LOW:      { badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30', dot: 'bg-emerald-500' },
}

export default function Alerts() {
  const [alerts,        setAlerts]        = useState([])
  const [loading,       setLoading]       = useState(true)
  const [search,        setSearch]        = useState('')
  const [filterSev,     setFilterSev]     = useState('ALL')
  const [selectedAlert, setSelectedAlert] = useState(null)
  const navigate = useNavigate()

  const fetchAlerts = async () => {
    setLoading(true)
    try {
      const { data } = await axios.get(`${API}/api/alerts/priority`)
      setAlerts(data.alerts || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAlerts()
  }, [])

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchSev = filterSev === 'ALL' || a.severity === filterSev
      const q = search.toLowerCase()
      const matchSearch = !q ||
        a.alert_id.toLowerCase().includes(q) ||
        a.attack_type.toLowerCase().includes(q) ||
        a.source_ip.toLowerCase().includes(q) ||
        a.destination_ip.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q)
      return matchSev && matchSearch
    })
  }, [alerts, filterSev, search])

  // Mock relative time generator for display
  const getTimeAgo = (idx) => {
    const times = ['2 min ago', '8 min ago', '15 min ago', '22 min ago', '34 min ago', '48 min ago', '1h ago', '2h ago', '3h ago']
    return times[idx % times.length]
  }

  const getStatus = (severity) => {
    if (severity === 'CRITICAL') return 'Investigating'
    if (severity === 'HIGH') return 'Open'
    return 'Under Review'
  }

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-[#0a0d14] text-slate-200">
      <Header
        title="Security Alerts"
        subtitle="Prioritized threat detections across enterprise assets and network endpoints."
        onRefresh={fetchAlerts}
      />

      <div className="p-6 space-y-6 max-w-7xl mx-auto w-full">
        {/* Filter Bar */}
        <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3 w-full sm:w-auto flex-1">
            {/* Search */}
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search alerts by name, IP, or threat vector..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="w-full bg-[#0f1422] border border-[#222e47] rounded-xl pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            {/* Severity Tabs */}
            <div className="flex items-center gap-1 bg-[#0f1422] p-1 rounded-xl border border-[#222e47] text-xs">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
                <button
                  key={s}
                  onClick={() => setFilterSev(s)}
                  className={`px-3 py-1 rounded-lg font-medium transition-all ${
                    filterSev === s
                      ? 'bg-blue-600 text-white font-semibold shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          <span className="text-xs text-slate-400 font-medium shrink-0">
            {filtered.length} Alerts Discovered
          </span>
        </div>

        {/* ── PROFESSIONAL ALERTS TABLE ── */}
        <div className="bg-[#121826] border border-[#1f293d] rounded-2xl overflow-hidden shadow-xl">
          {loading ? (
            <div className="flex items-center justify-center h-64 text-slate-400 text-xs">
              Loading security alerts...
            </div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-16 text-slate-500 text-xs">
              No security alerts matched the specified criteria.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-[#151c2c] text-slate-400 border-b border-[#1f293d] text-[11px] font-semibold uppercase tracking-wider">
                  <tr>
                    <th className="py-3.5 px-4">Severity</th>
                    <th className="py-3.5 px-4">Alert</th>
                    <th className="py-3.5 px-4">Source</th>
                    <th className="py-3.5 px-4">Target</th>
                    <th className="py-3.5 px-4">Detected</th>
                    <th className="py-3.5 px-4">Status</th>
                    <th className="py-3.5 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1c2438]">
                  {filtered.map((alert, idx) => {
                    const sev = SEV_CONFIG[alert.severity] || SEV_CONFIG.LOW
                    const status = getStatus(alert.severity)

                    return (
                      <tr
                        key={alert.alert_id}
                        className="hover:bg-[#141b2b] transition-colors"
                      >
                        <td className="py-3 px-4">
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold border uppercase tracking-wider ${sev.badge}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
                            {alert.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <div className="font-bold text-white">
                            {alert.attack_type.replace(/_/g, ' ')}
                          </div>
                          <div className="text-[11px] text-slate-400 mt-0.5 max-w-xs truncate">
                            {alert.description}
                          </div>
                        </td>
                        <td className="py-3 px-4 text-sky-400 font-mono">
                          {alert.source_ip}
                        </td>
                        <td className="py-3 px-4 text-amber-400 font-mono">
                          {alert.destination_ip}
                        </td>
                        <td className="py-3 px-4 text-slate-400">
                          {getTimeAgo(idx)}
                        </td>
                        <td className="py-3 px-4">
                          <span className={`inline-block px-2.5 py-0.5 rounded text-[11px] font-medium ${
                            status === 'Investigating'
                              ? 'bg-red-950/40 text-red-300 border border-red-800/40'
                              : status === 'Open'
                              ? 'bg-orange-950/40 text-orange-300 border border-orange-800/40'
                              : 'bg-slate-800 text-slate-300'
                          }`}>
                            {status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => setSelectedAlert(alert)}
                              className="px-2.5 py-1 rounded bg-[#182136] hover:bg-[#202b46] border border-[#273556] text-slate-200 hover:text-white text-xs font-medium transition-all"
                            >
                              Quick View
                            </button>
                            <button
                              onClick={() => navigate(`/investigation?id=${alert.alert_id}`)}
                              className="px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition-all shadow-sm flex items-center gap-1"
                            >
                              <span>Investigate</span>
                              <ArrowRight className="w-3 h-3" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Quick View Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#121826] border border-[#222e47] rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4 relative">
            <button
              onClick={() => setSelectedAlert(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-2">
              <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase border ${
                SEV_CONFIG[selectedAlert.severity]?.badge || SEV_CONFIG.LOW.badge
              }`}>
                {selectedAlert.severity}
              </span>
              <span className="text-xs text-slate-400">ID: {selectedAlert.alert_id}</span>
            </div>

            <h3 className="text-lg font-bold text-white">
              {selectedAlert.attack_type.replace(/_/g, ' ')}
            </h3>

            <p className="text-xs text-slate-300 leading-relaxed">
              {selectedAlert.description}
            </p>

            <div className="grid grid-cols-2 gap-3 bg-[#0f1422] p-3.5 rounded-xl border border-[#1c2438] text-xs">
              <div>
                <span className="text-slate-400 text-[11px]">Adversary Source</span>
                <div className="font-mono text-sky-400 mt-0.5">{selectedAlert.source_ip}</div>
              </div>
              <div>
                <span className="text-slate-400 text-[11px]">Target Asset</span>
                <div className="font-mono text-amber-400 mt-0.5">{selectedAlert.destination_ip}</div>
              </div>
              <div>
                <span className="text-slate-400 text-[11px]">Kill Chain Stage</span>
                <div className="text-white mt-0.5">{selectedAlert.kill_chain_stage}</div>
              </div>
              <div>
                <span className="text-slate-400 text-[11px]">Status</span>
                <div className="text-red-400 mt-0.5">Active Investigation</div>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-4 py-2 rounded-xl bg-[#141b2b] hover:bg-[#1a2338] text-slate-300 text-xs font-medium"
              >
                Close
              </button>
              <button
                onClick={() => {
                  const id = selectedAlert.alert_id
                  setSelectedAlert(null)
                  navigate(`/investigation?id=${id}`)
                }}
                className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-md shadow-blue-600/30"
              >
                <span>Full Forensic Investigation</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
