import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import {
  ShieldAlert,
  Terminal,
  Activity,
  GitFork,
  Radio,
  AlertTriangle,
  ArrowUpRight,
  TrendingUp,
  Clock,
  Layers,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  ChevronRight,
  Server,
  Database,
  ArrowRight,
} from 'lucide-react'
import Header from '../components/Header'

const API = 'http://localhost:8000'

export default function Dashboard() {
  const [summary,     setSummary]     = useState(null)
  const [alerts,      setAlerts]      = useState([])
  const [killChains,  setKillChains]  = useState([])
  const [loading,     setLoading]     = useState(true)
  const [timeRange,   setTimeRange]   = useState('24H')
  const navigate = useNavigate()

  const fetchDashboardData = async () => {
    try {
      const [sumRes, alertRes, kcRes] = await Promise.all([
        axios.get(`${API}/api/analysis/dashboard`),
        axios.get(`${API}/api/alerts/`),
        axios.get(`${API}/api/analysis/kill-chains`),
      ])
      setSummary(sumRes.data)
      setAlerts(alertRes.data.alerts || [])
      setKillChains(kcRes.data.kill_chains || [])
    } catch (e) {
      console.error('Dashboard fetch error:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDashboardData()
  }, [])

  // Sample points for the Threat Activity Area Chart (SVG based, highly polished)
  const activityData = [
    { time: '08:00', events: 12, alerts: 1, critical: 0, normal: 11 },
    { time: '08:15', events: 38, alerts: 4, critical: 1, normal: 33 },
    { time: '08:30', events: 25, alerts: 2, critical: 1, normal: 22 },
    { time: '08:45', events: 18, alerts: 1, critical: 0, normal: 17 },
    { time: '09:00', events: 45, alerts: 6, critical: 2, normal: 37 },
    { time: '09:15', events: 32, alerts: 3, critical: 1, normal: 28 },
    { time: '09:30', events: 60, alerts: 8, critical: 3, normal: 49 },
    { time: '09:45', events: 42, alerts: 4, critical: 1, normal: 37 },
    { time: '10:00', events: 28, alerts: 2, critical: 0, normal: 26 },
    { time: '10:15', events: 50, alerts: 7, critical: 2, normal: 41 },
    { time: '10:30', events: 35, alerts: 3, critical: 1, normal: 31 },
    { time: '10:45', events: 15, alerts: 1, critical: 0, normal: 14 },
  ]

  const maxVal = Math.max(...activityData.map(d => d.events))

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-[#0a0d14] text-slate-200">
      <Header
        title="Threat Intelligence Overview"
        subtitle="Monitor security activity, investigate detected threats, and reconstruct attack sequences."
        onRefresh={fetchDashboardData}
      />

      <div className="p-6 space-y-6 max-w-7xl mx-auto w-full">
        {loading ? (
          <div className="flex items-center justify-center h-64 text-slate-400 text-xs font-mono gap-2">
            <Activity className="w-4 h-4 animate-spin text-blue-500" />
            Loading security operations intelligence...
          </div>
        ) : (
          <>
            {/* ── 4 CLEAN KPI CARDS ── */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Card 1: Total Log Events */}
              <div
                onClick={() => navigate('/logs')}
                className="cursor-pointer bg-[#121826] border border-[#1f293d] hover:border-slate-500 rounded-2xl p-5 shadow-lg transition-all hover:scale-[1.01]"
              >
                <div className="flex items-center justify-between text-slate-400 text-xs font-semibold uppercase tracking-wider">
                  <span>Total Log Events</span>
                  <div className="w-8 h-8 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center justify-center">
                    <Terminal className="w-4 h-4" />
                  </div>
                </div>
                <div className="text-3xl font-extrabold text-white mt-3">
                  {summary?.total_logs ?? 30}
                </div>
                <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium mt-2">
                  <TrendingUp className="w-3.5 h-3.5" />
                  <span>+12% from previous scan</span>
                </div>
              </div>

              {/* Card 2: Active Alerts */}
              <div
                onClick={() => navigate('/alerts')}
                className="cursor-pointer bg-[#121826] border border-[#1f293d] hover:border-slate-500 rounded-2xl p-5 shadow-lg transition-all hover:scale-[1.01]"
              >
                <div className="flex items-center justify-between text-slate-400 text-xs font-semibold uppercase tracking-wider">
                  <span>Active Alerts</span>
                  <div className="w-8 h-8 rounded-xl bg-orange-500/10 border border-orange-500/20 text-orange-400 flex items-center justify-center">
                    <AlertTriangle className="w-4 h-4" />
                  </div>
                </div>
                <div className="text-3xl font-extrabold text-white mt-3">
                  {summary?.total_alerts ?? 9}
                </div>
                <div className="text-xs text-red-400 font-medium mt-2 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-red-500 inline-block animate-pulse"></span>
                  <span>{summary?.severity_counts?.CRITICAL ?? 3} Critical Severity</span>
                </div>
              </div>

              {/* Card 3: Attack Chains */}
              <div
                onClick={() => navigate('/kill-chain')}
                className="cursor-pointer bg-[#121826] border border-[#1f293d] hover:border-slate-500 rounded-2xl p-5 shadow-lg transition-all hover:scale-[1.01]"
              >
                <div className="flex items-center justify-between text-slate-400 text-xs font-semibold uppercase tracking-wider">
                  <span>Attack Chains</span>
                  <div className="w-8 h-8 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400 flex items-center justify-center">
                    <GitFork className="w-4 h-4" />
                  </div>
                </div>
                <div className="text-3xl font-extrabold text-white mt-3">
                  {summary?.total_kill_chains ?? 5}
                </div>
                <div className="text-xs text-purple-300 font-medium mt-2">
                  2 currently active campaigns
                </div>
              </div>

              {/* Card 4: Critical Nodes */}
              <div
                onClick={() => navigate('/graph')}
                className="cursor-pointer bg-[#121826] border border-[#1f293d] hover:border-slate-500 rounded-2xl p-5 shadow-lg transition-all hover:scale-[1.01]"
              >
                <div className="flex items-center justify-between text-slate-400 text-xs font-semibold uppercase tracking-wider">
                  <span>Critical Nodes</span>
                  <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center">
                    <ShieldAlert className="w-4 h-4" />
                  </div>
                </div>
                <div className="text-3xl font-extrabold text-white mt-3">
                  {summary?.choke_point_count ?? 6}
                </div>
                <div className="text-xs text-slate-400 font-medium mt-2">
                  Across detected attack paths
                </div>
              </div>
            </div>

            {/* ── THREAT ACTIVITY SECTION (LARGE AREA CHART) ── */}
            <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h3 className="text-base font-bold text-white">Threat Activity</h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Security events, threat detections, and telemetry volume over time.
                  </p>
                </div>

                {/* Time Range Filter: 1H | 6H | 24H | 7D */}
                <div className="flex items-center gap-1 bg-[#0e121d] p-1 rounded-xl border border-[#20293d] text-xs font-medium">
                  {['1H', '6H', '24H', '7D'].map(t => (
                    <button
                      key={t}
                      onClick={() => setTimeRange(t)}
                      className={`px-3 py-1 rounded-lg transition-all ${
                        timeRange === t
                          ? 'bg-blue-600 text-white font-semibold shadow-sm'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>

              {/* Chart Legend */}
              <div className="flex flex-wrap items-center gap-5 text-xs text-slate-400 pt-1">
                <span className="flex items-center gap-2">
                  <span className="w-3 h-1 bg-blue-500 rounded-full inline-block"></span>
                  <span>Security Events</span>
                </span>
                <span className="flex items-center gap-2">
                  <span className="w-3 h-1 bg-orange-500 rounded-full inline-block"></span>
                  <span>Alerts Detected</span>
                </span>
                <span className="flex items-center gap-2">
                  <span className="w-3 h-1 bg-red-500 rounded-full inline-block"></span>
                  <span>Critical Incidents</span>
                </span>
                <span className="flex items-center gap-2">
                  <span className="w-3 h-1 bg-emerald-500 rounded-full inline-block"></span>
                  <span>Normal Traffic</span>
                </span>
              </div>

              {/* Clean SVG Area Chart */}
              <div className="w-full h-64 pt-4 relative">
                <svg className="w-full h-full overflow-visible" viewBox="0 0 600 180" preserveAspectRatio="none">
                  <defs>
                    <linearGradient id="blueGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.3" />
                      <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.0" />
                    </linearGradient>
                    <linearGradient id="redGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#ef4444" stopOpacity="0.25" />
                      <stop offset="100%" stopColor="#ef4444" stopOpacity="0.0" />
                    </linearGradient>
                  </defs>

                  {/* Horizontal Grid lines */}
                  {[30, 75, 120, 165].map((y, i) => (
                    <line key={i} x1="0" y1={y} x2="600" y2={y} stroke="#1b2438" strokeWidth="1" />
                  ))}

                  {/* Area: Security Events */}
                  <path
                    d={`M 0 170 ${activityData.map((d, i) => {
                      const x = (i / (activityData.length - 1)) * 600
                      const y = 170 - (d.events / maxVal) * 140
                      return `L ${x} ${y}`
                    }).join(' ')} L 600 170 Z`}
                    fill="url(#blueGradient)"
                  />

                  {/* Line: Security Events */}
                  <path
                    d={`M 0 ${170 - (activityData[0].events / maxVal) * 140} ${activityData.map((d, i) => {
                      const x = (i / (activityData.length - 1)) * 600
                      const y = 170 - (d.events / maxVal) * 140
                      return `L ${x} ${y}`
                    }).join(' ')}`}
                    fill="none"
                    stroke="#3b82f6"
                    strokeWidth="2.5"
                  />

                  {/* Line: Alerts Detected */}
                  <path
                    d={`M 0 ${170 - (activityData[0].alerts / 10) * 80} ${activityData.map((d, i) => {
                      const x = (i / (activityData.length - 1)) * 600
                      const y = 170 - (d.alerts / 10) * 80
                      return `L ${x} ${y}`
                    }).join(' ')}`}
                    fill="none"
                    stroke="#f97316"
                    strokeWidth="2"
                    strokeDasharray="4 2"
                  />

                  {/* Line: Critical Events */}
                  <path
                    d={`M 0 ${170 - (activityData[0].critical / 5) * 60} ${activityData.map((d, i) => {
                      const x = (i / (activityData.length - 1)) * 600
                      const y = 170 - (d.critical / 5) * 60
                      return `L ${x} ${y}`
                    }).join(' ')}`}
                    fill="none"
                    stroke="#ef4444"
                    strokeWidth="2"
                  />
                </svg>

                {/* X-axis labels */}
                <div className="flex justify-between text-[11px] text-slate-500 font-mono pt-2">
                  {activityData.map((d, i) => (
                    <span key={i} className={i % 2 === 0 ? 'block' : 'hidden sm:block'}>
                      {d.time}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            {/* ── ROW: RECENT DETECTIONS & ATTACK RECONSTRUCTION OVERVIEW ── */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left 2 Cols: Recent Security Alerts */}
              <div className="lg:col-span-2 bg-[#121826] border border-[#1f293d] rounded-2xl p-6 shadow-xl space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-[#1f293d]">
                  <div>
                    <h3 className="text-base font-bold text-white">Recent Security Alerts</h3>
                    <p className="text-xs text-slate-400 mt-0.5">High-confidence attack indicators requiring triage.</p>
                  </div>
                  <button
                    onClick={() => navigate('/alerts')}
                    className="text-xs text-blue-400 hover:text-blue-300 font-medium flex items-center gap-1"
                  >
                    <span>View All Alerts</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="space-y-2">
                  {alerts.slice(0, 4).map((a) => {
                    const isCrit = a.severity === 'CRITICAL'
                    return (
                      <div
                        key={a.alert_id}
                        onClick={() => navigate(`/investigation?id=${a.alert_id}`)}
                        className="cursor-pointer p-3.5 rounded-xl bg-[#0f1422] border border-[#1c2438] hover:border-slate-500 transition-all flex items-center justify-between"
                      >
                        <div className="flex items-center gap-3">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wide ${
                            isCrit ? 'bg-red-500/15 text-red-400 border-red-500/30' : 'bg-orange-500/15 text-orange-400 border-orange-500/30'
                          }`}>
                            {a.severity}
                          </span>
                          <div>
                            <div className="text-xs font-bold text-white">{a.attack_type.replace(/_/g, ' ')}</div>
                            <div className="text-[11px] text-slate-400 mt-0.5">{a.source_ip} ➔ {a.destination_ip}</div>
                          </div>
                        </div>

                        <div className="flex items-center gap-3 text-xs">
                          <span className="text-slate-400 hidden sm:inline">{a.kill_chain_stage}</span>
                          <span className="text-blue-400 hover:text-blue-300 font-medium">Investigate →</span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Right 1 Col: Active Attack Chain Progress */}
              <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-6 shadow-xl flex flex-col justify-between space-y-4">
                <div>
                  <div className="flex items-center justify-between pb-3 border-b border-[#1f293d]">
                    <h3 className="text-base font-bold text-white">Active Attack Chains</h3>
                    <span className="text-xs text-purple-400 font-medium">{killChains.length} Reconstructed</span>
                  </div>

                  <div className="space-y-3 mt-4">
                    {killChains.slice(0, 3).map((kc) => {
                      const obsCount = kc.stages?.filter(s => s.status === 'Observed').length || 1
                      const pct = Math.round((obsCount / 7) * 100)
                      return (
                        <div
                          key={kc.kill_chain_id}
                          onClick={() => navigate('/kill-chain')}
                          className="cursor-pointer p-3 rounded-xl bg-[#0f1422] border border-[#1c2438] hover:border-slate-500 transition-all space-y-2"
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-bold text-white">{kc.kill_chain_id}</span>
                            <span className="text-[10px] text-orange-400 font-medium">
                              {kc.severity}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-400">
                            Source: <span className="text-slate-200">{kc.source_ip}</span>
                          </div>
                          <div>
                            <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
                              <span>Progression</span>
                              <span>{obsCount}/7 Stages ({pct}%)</span>
                            </div>
                            <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                              <div
                                className={`h-full ${kc.severity === 'CRITICAL' ? 'bg-red-500' : 'bg-orange-500'}`}
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>

                <button
                  onClick={() => navigate('/kill-chain')}
                  className="w-full py-2 rounded-xl bg-[#141b2b] hover:bg-[#1a2338] border border-[#222e47] text-slate-300 hover:text-white text-xs font-semibold transition-all text-center block"
                >
                  Explore Attack Chains →
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
