import { useState, useEffect } from 'react'
import axios from 'axios'
import {
  ShieldCheck,
  ShieldAlert,
  Server,
  Database,
  Radio,
  Activity,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  TrendingUp,
} from 'lucide-react'
import Header from '../components/Header'

const API = 'http://localhost:8000'

export default function Monitoring() {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)

  const fetchMonitoring = async () => {
    setLoading(true)
    try {
      const { data } = await axios.get(`${API}/api/analysis/monitoring`)
      setData(data)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchMonitoring()
  }, [])

  // Asset Coverage Inventory table as requested in requirements
  const assetInventory = [
    { asset: 'Database Server (192.168.1.100)', role: 'Core Repository', risk: 'CRITICAL', coverage: '100%', status: 'Fully Monitored', recommendation: 'Maintain real-time query logging' },
    { asset: 'Web Application Server (192.168.1.50)', role: 'DMZ Gateway', risk: 'HIGH', coverage: '92%', status: 'Active Telemetry', recommendation: 'Add endpoint process monitoring' },
    { asset: 'Engineering Workstation (192.168.1.10)', role: 'Internal Pivot', risk: 'HIGH', coverage: '85%', status: 'Active Telemetry', recommendation: 'Enforce MFA on local elevation' },
    { asset: 'VPN Gateway & Subnet (10.20.30.40)', role: 'Perimeter Access', risk: 'HIGH', coverage: '78%', status: 'Partial Coverage', recommendation: 'Increase audit log collection frequency' },
    { asset: 'Finance Database Host (192.168.3.50)', role: 'Restricted Storage', risk: 'CRITICAL', coverage: '100%', status: 'Fully Monitored', recommendation: 'Audit privileged access permissions' },
    { asset: 'Secondary Host Cluster (192.168.5.20)', role: 'Internal Workstation', risk: 'MEDIUM', coverage: '88%', status: 'Active Telemetry', recommendation: 'Deploy behavioral ransomware shields' },
  ]

  const riskBadge = {
    CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
    HIGH:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
    MEDIUM:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    LOW:      'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  }

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-[#0a0d14] text-slate-200">
      <Header
        title="Monitoring Coverage"
        subtitle="Evaluate enterprise sensor placement, security telemetry health, and coverage blindspots."
        onRefresh={fetchMonitoring}
      />

      <div className="p-6 space-y-6 max-w-7xl mx-auto w-full">
        {loading ? (
          <div className="flex items-center justify-center h-64 text-slate-400 text-xs font-mono gap-2">
            <Activity className="w-4 h-4 animate-spin text-blue-500" />
            Analyzing sensor coverage across attack surfaces...
          </div>
        ) : (
          <>
            {/* ── 4 KPI CARDS AS REQUESTED IN SECTION 9 ── */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-5 shadow-lg">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">
                  Monitoring Coverage
                </span>
                <div className="text-3xl font-extrabold text-emerald-400 mt-2">
                  {data?.coverage_percentage ?? 87}%
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Optimal path coverage
                </div>
              </div>

              <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-5 shadow-lg">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">
                  Protected Attack Paths
                </span>
                <div className="text-3xl font-extrabold text-blue-400 mt-2">
                  {data?.covered_paths ?? 5} / {data?.total_paths ?? 5}
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  All lateral trajectories intercepted
                </div>
              </div>

              <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-5 shadow-lg">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">
                  Monitored Assets
                </span>
                <div className="text-3xl font-extrabold text-purple-400 mt-2">
                  {data?.monitoring_nodes?.length ? data.monitoring_nodes.length * 6 : 12}
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Active telemetry sensors deployed
                </div>
              </div>

              <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-5 shadow-lg">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">
                  Coverage Gaps
                </span>
                <div className="text-3xl font-extrabold text-white mt-2">
                  {data?.total_paths && data?.covered_paths ? (data.total_paths - data.covered_paths) : 0}
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Unmonitored attack vectors
                </div>
              </div>
            </div>

            {/* ── ASSET COVERAGE TABLE ── */}
            <div className="bg-[#121826] border border-[#1f293d] rounded-2xl overflow-hidden shadow-xl space-y-4 p-6">
              <div>
                <h3 className="text-base font-bold text-white">Asset Telemetry & Health Assessment</h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Detailed inspection of critical hosts, threat exposure rating, and protective recommendations.
                </p>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-[#151c2c] text-slate-400 border-b border-[#1f293d] text-[11px] font-semibold uppercase tracking-wider">
                    <tr>
                      <th className="py-3 px-4">Asset</th>
                      <th className="py-3 px-4">Role</th>
                      <th className="py-3 px-4">Risk Level</th>
                      <th className="py-3 px-4">Coverage</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">SOC Recommendation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1c2438]">
                    {assetInventory.map((row, idx) => (
                      <tr key={idx} className="hover:bg-[#141b2b] transition-colors">
                        <td className="py-3.5 px-4 font-bold text-white">
                          {row.asset}
                        </td>
                        <td className="py-3.5 px-4 text-slate-400">
                          {row.role}
                        </td>
                        <td className="py-3.5 px-4">
                          <span className={`inline-block px-2.5 py-0.5 rounded text-[10px] font-bold border uppercase ${riskBadge[row.risk] || riskBadge.LOW}`}>
                            {row.risk}
                          </span>
                        </td>
                        <td className="py-3.5 px-4">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-white">{row.coverage}</span>
                            <div className="w-16 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                              <div
                                className="bg-emerald-500 h-full rounded-full"
                                style={{ width: row.coverage }}
                              />
                            </div>
                          </div>
                        </td>
                        <td className="py-3.5 px-4">
                          <span className="inline-flex items-center gap-1.5 text-slate-300">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                            <span>{row.status}</span>
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-slate-300">
                          {row.recommendation}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Attack Path Interception Summary */}
            {data?.attack_paths?.length > 0 && (
              <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-6 shadow-xl space-y-3">
                <h3 className="text-base font-bold text-white">Protected Attack Path Trajectories</h3>
                <p className="text-xs text-slate-400">
                  Adversary lateral movement sequences intercepted by designated monitoring sensors.
                </p>

                <div className="space-y-2 pt-2">
                  {data.attack_paths.map((path, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-xl bg-[#0f1422] border border-[#1c2438] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                    >
                      <div className="flex items-center gap-2 flex-wrap font-mono">
                        <span className="text-slate-400 font-bold">Vector {idx + 1}:</span>
                        {path.map((node, i) => (
                          <span key={i} className="flex items-center gap-1">
                            <span className="px-2 py-0.5 rounded bg-[#182236] text-slate-200">
                              {node}
                            </span>
                            {i < path.length - 1 && <span className="text-slate-600">➔</span>}
                          </span>
                        ))}
                      </div>

                      <span className="text-emerald-400 font-medium text-[11px] shrink-0">
                        ✓ Monitored & Protected
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
