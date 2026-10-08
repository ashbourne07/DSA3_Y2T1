import { useState, useEffect } from 'react'
import axios from 'axios'
import {
  GitFork,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Server,
  Database,
  Terminal,
  Activity,
  ArrowRight,
  Shield,
  Layers,
  Flame,
  Info,
  ChevronRight,
  Lock,
} from 'lucide-react'
import Header from '../components/Header'

const API = 'http://localhost:8000'

// 7 Standard Lockheed Martin / MITRE Cyber Kill Chain Stages
const STANDARD_STAGES = [
  'Reconnaissance',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Credential Access',
  'Exfiltration',
]

const STAGE_META = {
  'Reconnaissance': {
    tactic: 'TA0043',
    desc: 'Adversary scans IP ranges and discovers network topology and open ports.',
    icon: '📡',
  },
  'Initial Access': {
    tactic: 'TA0001',
    desc: 'Adversary gains entry via unauthorized authentication or credential brute-forcing.',
    icon: '🚪',
  },
  'Execution': {
    tactic: 'TA0002',
    desc: 'Adversary runs malicious binaries or scripts in user context.',
    icon: '⚡',
  },
  'Persistence': {
    tactic: 'TA0003',
    desc: 'Adversary maintains access across reboots and network resets.',
    icon: '⚓',
  },
  'Privilege Escalation': {
    tactic: 'TA0004',
    desc: 'Adversary leverages exploits to elevate privileges to administrator / root.',
    icon: '👑',
  },
  'Credential Access': {
    tactic: 'TA0006',
    desc: 'Adversary dumps credentials and accesses sensitive database repositories.',
    icon: '🔑',
  },
  'Exfiltration': {
    tactic: 'TA0010',
    desc: 'Adversary transfers stolen data to an external unauthorized command & control server.',
    icon: '📤',
  },
}

export default function KillChain() {
  const [killChains,  setKillChains]  = useState([])
  const [alerts,      setAlerts]      = useState([])
  const [loading,     setLoading]     = useState(true)
  const [selectedIdx, setSelectedIdx] = useState(0)
  const [activeStage, setActiveStage] = useState('Initial Access')

  const fetchKillChains = async () => {
    setLoading(true)
    try {
      const [kcRes, alertRes] = await Promise.all([
        axios.get(`${API}/api/analysis/kill-chains`),
        axios.get(`${API}/api/alerts/`),
      ])
      const list = kcRes.data.kill_chains || []
      setKillChains(list)
      setAlerts(alertRes.data.alerts || [])
      if (list.length > 0) {
        const firstObserved = list[0].stages?.find(s => s.status === 'Observed')
        if (firstObserved) setActiveStage(firstObserved.stage)
      }
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchKillChains()
  }, [])

  const currentChain = killChains[selectedIdx] || null

  // Collect related events for the active stage
  const selectedStageData = currentChain?.stages?.find(s => s.stage === activeStage)
  const isObserved = selectedStageData?.status === 'Observed'
  const stageAlerts = alerts.filter(a => selectedStageData?.alert_ids?.includes(a.alert_id))

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-[#0a0d14] text-slate-200">
      <Header
        title="Attack Kill Chains"
        subtitle="Reconstruct adversary attack paths from initial compromise to objective completion."
        onRefresh={fetchKillChains}
      />

      <div className="p-6 space-y-6 max-w-7xl mx-auto w-full">
        {loading ? (
          <div className="flex items-center justify-center h-64 text-slate-400 text-xs font-mono gap-2">
            <Activity className="w-4 h-4 animate-spin text-blue-500" />
            Reconstructing attack kill chain sequences...
          </div>
        ) : killChains.length === 0 ? (
          <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-10 text-center space-y-3">
            <ShieldAlert className="w-10 h-10 text-slate-500 mx-auto" />
            <h2 className="text-base font-semibold text-slate-200">No Attack Chains Detected</h2>
            <p className="text-xs text-slate-400">Load sample data to reconstruct active cyber kill chains.</p>
          </div>
        ) : (
          <>
            {/* ── INCIDENT CARDS SELECTOR ── */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {killChains.map((kc, idx) => {
                const isSelected = selectedIdx === idx
                const observedCount = kc.stages?.filter(s => s.status === 'Observed').length || 1
                const isCritical = kc.severity === 'CRITICAL'

                return (
                  <div
                    key={kc.kill_chain_id}
                    onClick={() => {
                      setSelectedIdx(idx)
                      const obs = kc.stages?.find(s => s.status === 'Observed')
                      if (obs) setActiveStage(obs.stage)
                    }}
                    className={`cursor-pointer p-4 rounded-2xl border transition-all ${
                      isSelected
                        ? 'bg-[#151d2f] border-blue-500/60 shadow-lg shadow-blue-500/10'
                        : 'bg-[#121826] border-[#1f293d] hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-bold text-white font-mono">{kc.kill_chain_id}</span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${
                        isCritical
                          ? 'bg-red-500/15 text-red-400 border-red-500/30'
                          : 'bg-orange-500/15 text-orange-400 border-orange-500/30'
                      }`}>
                        {kc.severity}
                      </span>
                    </div>

                    <div className="text-sm font-bold text-white">
                      {kc.attack_types?.join(' & ') || 'Lockheed Martin Incident'}
                    </div>

                    <div className="text-xs text-slate-400 mt-1 flex items-center justify-between">
                      <span>Source: <strong className="text-slate-300 font-mono">{kc.source_ip}</strong></span>
                      <span className="text-emerald-400 font-medium">Active investigation</span>
                    </div>

                    <div className="mt-3 pt-2 border-t border-[#1c2438] flex items-center justify-between text-[11px] text-slate-400">
                      <span>{observedCount} stages detected</span>
                      <span className="text-blue-400 font-medium">View Chain →</span>
                    </div>
                  </div>
                )
              })}
            </div>

            {/* ── TIMELINE ATTACK PROGRESSION DIAGRAM ── */}
            {currentChain && (
              <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-6 shadow-xl space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#1f293d]">
                  <div>
                    <span className="text-[11px] text-slate-400 font-semibold tracking-wider uppercase">
                      Incident Chain Reconstructed · {currentChain.kill_chain_id}
                    </span>
                    <h3 className="text-lg font-bold text-white mt-0.5">
                      Attack Progression Flow
                    </h3>
                  </div>
                  <div className="flex items-center gap-4 text-xs font-medium">
                    <span className="flex items-center gap-1.5 text-emerald-400">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block shadow-sm shadow-emerald-500/50" />
                      Observed Stage
                    </span>
                    <span className="flex items-center gap-1.5 text-slate-500">
                      <span className="w-2.5 h-2.5 rounded-full bg-slate-700 inline-block" />
                      Bypassed / Dormant
                    </span>
                  </div>
                </div>

                {/* Horizontal Attack Pipeline */}
                <div className="overflow-x-auto pb-4 pt-2">
                  <div className="min-w-[900px] flex items-center justify-between relative px-2">
                    {STANDARD_STAGES.map((stageName, i) => {
                      const stageObj = currentChain.stages?.find(s => s.stage === stageName)
                      const observed = stageObj ? stageObj.status === 'Observed' : (stageName === 'Initial Access' || stageName === 'Execution' || stageName === 'Credential Access')
                      const isSelected = activeStage === stageName
                      const meta = STAGE_META[stageName]

                      return (
                        <div key={stageName} className="flex items-center">
                          {/* Stage Node */}
                          <div
                            onClick={() => setActiveStage(stageName)}
                            className={`cursor-pointer flex flex-col items-center transition-all ${
                              isSelected ? 'scale-105 z-10' : 'hover:scale-102'
                            }`}
                          >
                            <div
                              className={`w-14 h-14 rounded-2xl border flex flex-col items-center justify-center transition-all ${
                                observed
                                  ? 'bg-blue-600/15 border-blue-500 text-white shadow-lg shadow-blue-500/20'
                                  : 'bg-[#0f1422] border-slate-800 text-slate-600'
                              } ${isSelected ? 'ring-2 ring-blue-400 ring-offset-2 ring-offset-[#121826]' : ''}`}
                            >
                              <span className="text-base">{meta?.icon || '🛡️'}</span>
                              <span className="text-[10px] font-bold mt-0.5 font-mono">
                                0{i + 1}
                              </span>
                            </div>

                            <span className={`text-xs font-semibold mt-2 text-center max-w-[85px] leading-tight ${
                              observed ? 'text-white' : 'text-slate-500'
                            }`}>
                              {stageName}
                            </span>

                            <span className={`mt-1 px-1.5 py-0.2 rounded text-[10px] font-semibold ${
                              observed
                                ? 'bg-emerald-500/20 text-emerald-400'
                                : 'bg-slate-900 text-slate-600'
                            }`}>
                              {observed ? 'Observed' : 'Not Observed'}
                            </span>
                          </div>

                          {/* Connecting Arrow */}
                          {i < STANDARD_STAGES.length - 1 && (
                            <div className="w-8 sm:w-12 h-0.5 mx-1 bg-slate-800 relative flex items-center justify-center">
                              <div className={`w-full h-0.5 ${
                                observed ? 'bg-blue-500/60' : 'bg-slate-800'
                              }`} />
                              <ChevronRight className={`w-3.5 h-3.5 absolute right-0 ${
                                observed ? 'text-blue-400' : 'text-slate-700'
                              }`} />
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                </div>

                {/* ── CLICKABLE STAGE FORENSIC DETAILS ── */}
                <div className="bg-[#0f1422] border border-[#1c2438] rounded-xl p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-[#1c2438]">
                    <div className="flex items-center gap-3">
                      <span className="text-2xl">{STAGE_META[activeStage]?.icon || '🛡️'}</span>
                      <div>
                        <div className="flex items-center gap-2">
                          <h4 className="text-base font-bold text-white">{activeStage}</h4>
                          <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                            {STAGE_META[activeStage]?.tactic}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5">
                          {STAGE_META[activeStage]?.desc}
                        </p>
                      </div>
                    </div>

                    <span className={`text-xs font-semibold px-3 py-1 rounded-lg border uppercase self-start sm:self-center ${
                      isObserved
                        ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}>
                      {isObserved ? 'Observed in Logs' : 'No Activity Detected'}
                    </span>
                  </div>

                  {/* Related Events Table */}
                  <div className="space-y-3">
                    <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
                      Related Security Events ({stageAlerts.length})
                    </span>

                    {stageAlerts.length === 0 ? (
                      <p className="text-xs text-slate-500 italic">
                        No security alerts triggered for this stage in {currentChain.kill_chain_id}. The adversary may have bypassed this step or utilized unmonitored vectors.
                      </p>
                    ) : (
                      <div className="space-y-2">
                        {stageAlerts.map(a => (
                          <div
                            key={a.alert_id}
                            className="bg-[#141b2b] border border-[#202b42] rounded-xl p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                          >
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-white">{a.attack_type.replace(/_/g, ' ')}</span>
                                <span className="text-slate-400">({a.alert_id})</span>
                              </div>
                              <div className="text-slate-300">{a.description}</div>
                              <div className="text-[11px] text-slate-400">
                                Source: <span className="text-sky-400 font-mono">{a.source_ip}</span> ➔ Target: <span className="text-amber-400 font-mono">{a.destination_ip}</span>
                              </div>
                            </div>

                            <span className="text-xs font-bold text-red-400 self-start sm:self-center">
                              {a.severity}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
