import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import axios from 'axios'
import {
  Crosshair,
  ShieldAlert,
  Clock,
  Laptop,
  Server,
  Database,
  Terminal,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Flame,
  ArrowRight,
  Shield,
  FileText,
  Lock,
} from 'lucide-react'
import Header from '../components/Header'

const API = 'http://localhost:8000'

export default function Investigation() {
  const [searchParams] = useSearchParams()
  const initialAlertId = searchParams.get('id')

  const [alerts, setAlerts] = useState([])
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [loading, setLoading] = useState(true)
  const [investigationStatus, setInvestigationStatus] = useState('Investigating')

  const fetchAlerts = async () => {
    setLoading(true)
    try {
      const { data } = await axios.get(`${API}/api/alerts/`)
      const list = data.alerts || []
      setAlerts(list)
      if (list.length > 0) {
        if (initialAlertId) {
          const match = list.find(a => a.alert_id === initialAlertId)
          setSelectedAlert(match || list[0])
        } else {
          setSelectedAlert(list[0])
        }
      }
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAlerts()
  }, [initialAlertId])

  // Map alert to a clean 5-step incident progression timeline
  const timelineSteps = [
    { title: 'Initial Access', desc: 'Unusual authentication anomaly detected', status: 'Completed', time: '08:00:01 AM' },
    { title: 'Execution', desc: 'Suspicious payload launched in elevated environment', status: 'Completed', time: '08:05:00 AM' },
    { title: 'Credential Access', desc: 'Attempted privilege elevation & token harvesting', status: 'In Progress', time: '08:10:00 AM' },
    { title: 'Lateral Movement', desc: 'Outbound socket connection toward internal servers', status: 'Pending', time: '08:12:00 AM' },
    { title: 'Command & Control', desc: 'External telemetry beaconing or exfiltration', status: 'Pending', time: '08:15:00 AM' },
  ]

  const sevBadge = {
    CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
    HIGH:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
    MEDIUM:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    LOW:      'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  }

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-[#0a0d14] text-slate-200">
      <Header
        title="Attack Investigation"
        subtitle="Forensic incident analysis, blast radius evaluation, and automated response orchestration."
        onRefresh={fetchAlerts}
      />

      <div className="p-6 space-y-6 max-w-7xl mx-auto w-full">
        {loading ? (
          <div className="flex items-center justify-center h-64 text-slate-400 text-xs font-mono gap-2">
            <Activity className="w-4 h-4 animate-spin text-blue-500" />
            Loading threat investigation telemetry...
          </div>
        ) : alerts.length === 0 ? (
          <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-10 text-center space-y-3">
            <ShieldAlert className="w-10 h-10 text-slate-500 mx-auto" />
            <h2 className="text-base font-semibold text-slate-200">No Incidents to Investigate</h2>
            <p className="text-xs text-slate-400">Load sample data to begin forensic investigation.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 1 Col: Alert Incident Queue */}
            <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-4 shadow-xl flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between pb-3 border-b border-[#1f293d]">
                  <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                    Incident Queue ({alerts.length})
                  </span>
                  <span className="text-[11px] text-slate-500">Live Detections</span>
                </div>

                <div className="space-y-2 mt-3 max-h-[580px] overflow-y-auto pr-1">
                  {alerts.map(a => {
                    const isSelected = selectedAlert?.alert_id === a.alert_id
                    return (
                      <div
                        key={a.alert_id}
                        onClick={() => setSelectedAlert(a)}
                        className={`cursor-pointer p-3 rounded-xl border transition-all ${
                          isSelected
                            ? 'bg-blue-600/15 border-blue-500/50 shadow-md shadow-blue-500/10'
                            : 'bg-[#0f1422] border-[#1c2438] hover:border-slate-600'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1.5">
                          <span className="text-xs font-bold text-white">{a.alert_id}</span>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${sevBadge[a.severity] || sevBadge.LOW}`}>
                            {a.severity}
                          </span>
                        </div>
                        <div className="text-xs text-slate-200 font-medium truncate">{a.attack_type}</div>
                        <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between">
                          <span>{a.source_ip} ➔ {a.destination_ip}</span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>

            {/* Right 2 Cols: Main Threat Investigation Dossier */}
            {selectedAlert && (
              <div className="lg:col-span-2 space-y-6">
                {/* Threat Dossier Header Card */}
                <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1f293d]">
                    <div>
                      <span className="text-[11px] text-slate-400 font-semibold tracking-wider uppercase">
                        Active Threat Dossier · {selectedAlert.alert_id}
                      </span>
                      <h2 className="text-xl font-bold text-white mt-1">
                        {selectedAlert.attack_type.replace(/_/g, ' ')}
                      </h2>
                    </div>

                    <div className="flex items-center gap-3">
                      <span className={`text-xs font-bold px-3 py-1 rounded-lg border uppercase tracking-wider ${sevBadge[selectedAlert.severity] || sevBadge.LOW}`}>
                        {selectedAlert.severity}
                      </span>
                      <select
                        value={investigationStatus}
                        onChange={e => setInvestigationStatus(e.target.value)}
                        className="bg-[#0f1422] border border-[#25324d] text-slate-200 text-xs px-3 py-1.5 rounded-lg focus:outline-none focus:border-blue-500"
                      >
                        <option value="Investigating">Investigating</option>
                        <option value="Open">Open</option>
                        <option value="Contained">Contained</option>
                        <option value="Resolved">Resolved</option>
                      </select>
                    </div>
                  </div>

                  {/* Incident Telemetry Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-1">
                    <div className="bg-[#0f1422] p-3.5 rounded-xl border border-[#1c2438]">
                      <span className="text-[11px] text-slate-400">Adversary Source</span>
                      <div className="text-sm font-bold text-sky-400 mt-1">{selectedAlert.source_ip}</div>
                      <span className="text-[10px] text-slate-500">Origin Host</span>
                    </div>

                    <div className="bg-[#0f1422] p-3.5 rounded-xl border border-[#1c2438]">
                      <span className="text-[11px] text-slate-400">Target Asset</span>
                      <div className="text-sm font-bold text-amber-400 mt-1">{selectedAlert.destination_ip}</div>
                      <span className="text-[10px] text-slate-500">Impacted Asset</span>
                    </div>

                    <div className="bg-[#0f1422] p-3.5 rounded-xl border border-[#1c2438]">
                      <span className="text-[11px] text-slate-400">First Detected</span>
                      <div className="text-sm font-bold text-white mt-1">08:00:01 AM</div>
                      <span className="text-[10px] text-slate-500">Initial Trigger</span>
                    </div>

                    <div className="bg-[#0f1422] p-3.5 rounded-xl border border-[#1c2438]">
                      <span className="text-[11px] text-slate-400">Current Phase</span>
                      <div className="text-sm font-bold text-purple-400 mt-1">{selectedAlert.kill_chain_stage}</div>
                      <span className="text-[10px] text-slate-500">Attack Stage</span>
                    </div>
                  </div>

                  {/* Threat Description */}
                  <div className="bg-[#0f1422] p-4 rounded-xl border border-[#1c2438] text-xs text-slate-300 leading-relaxed">
                    <span className="font-semibold text-slate-200 block mb-1">Incident Summary:</span>
                    {selectedAlert.description}
                  </div>
                </div>

                {/* Attack Timeline Card */}
                <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-6 shadow-xl space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                      Attack Timeline
                    </h3>
                    <span className="text-xs text-slate-400">Chronological Event Flow</span>
                  </div>

                  <div className="space-y-4 pt-2">
                    {timelineSteps.map((step, idx) => {
                      const isDone = step.status === 'Completed'
                      const isCurrent = step.status === 'In Progress'

                      return (
                        <div key={step.title} className="flex items-start gap-4 relative">
                          {/* Step Icon */}
                          <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 border z-10 ${
                            isDone
                              ? 'bg-emerald-950/80 border-emerald-500 text-emerald-400'
                              : isCurrent
                              ? 'bg-blue-950 border-blue-500 text-blue-400 shadow-md shadow-blue-500/30'
                              : 'bg-slate-900 border-slate-700 text-slate-600'
                          }`}>
                            {isDone ? <CheckCircle2 className="w-4 h-4" /> : <span className="text-xs font-bold">{idx + 1}</span>}
                          </div>

                          {/* Line Connector */}
                          {idx < timelineSteps.length - 1 && (
                            <div className={`absolute left-4 top-8 w-0.5 h-10 ${
                              isDone ? 'bg-emerald-500/40' : 'bg-slate-800'
                            }`} />
                          )}

                          {/* Content */}
                          <div className="flex-1 bg-[#0f1422] border border-[#1c2438] p-3.5 rounded-xl">
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-bold text-white">{step.title}</span>
                              <span className="text-[11px] text-slate-500">{step.time}</span>
                            </div>
                            <p className="text-xs text-slate-400 mt-1">{step.desc}</p>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>

                {/* Recommended Response Actions */}
                <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-6 shadow-xl space-y-3">
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                    Recommended Response Actions
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
                    <button className="p-3 rounded-xl bg-red-950/30 hover:bg-red-900/40 border border-red-700/50 text-red-300 text-xs font-semibold transition-all text-left">
                      🛡️ Isolate Host ({selectedAlert.source_ip})
                    </button>
                    <button className="p-3 rounded-xl bg-[#141b2b] hover:bg-[#1c263c] border border-[#232f48] text-slate-200 text-xs font-semibold transition-all text-left">
                      🔑 Revoke Active Credentials
                    </button>
                    <button className="p-3 rounded-xl bg-[#141b2b] hover:bg-[#1c263c] border border-[#232f48] text-slate-200 text-xs font-semibold transition-all text-left">
                      📋 Export Forensic Packet Log
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
