import { useState } from 'react'
import {
  Settings as SettingsIcon,
  Shield,
  Database,
  Sliders,
  Bell,
  CheckCircle2,
  HardDrive,
  RefreshCw,
} from 'lucide-react'
import Header from '../components/Header'

export default function Settings() {
  const [autoIsolate, setAutoIsolate] = useState(false)
  const [alertThreshold, setAlertThreshold] = useState('HIGH')
  const [correlationWindow, setCorrelationWindow] = useState('15m')
  const [saved, setSaved] = useState(false)

  const handleSave = () => {
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-[#0a0d14] text-slate-200">
      <Header
        title="Settings & System Configuration"
        subtitle="Configure threat detection thresholds, automated containment policies, and telemetry connectors."
      />

      <div className="p-6 max-w-4xl mx-auto w-full space-y-6">
        {saved && (
          <div className="p-3 bg-emerald-950/40 border border-emerald-600/50 rounded-xl text-xs text-emerald-300 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>Configuration changes saved successfully.</span>
          </div>
        )}

        {/* Threat Correlation Engine Settings */}
        <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-6 shadow-xl space-y-5">
          <div className="flex items-center gap-2.5 pb-4 border-b border-[#1f293d]">
            <Sliders className="w-5 h-5 text-blue-400" />
            <h2 className="text-base font-bold text-white">Detection & Correlation Policies</h2>
          </div>

          <div className="space-y-4 text-xs">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 bg-[#0f1422] rounded-xl border border-[#1c2438]">
              <div>
                <div className="font-semibold text-white">Event Correlation Window</div>
                <div className="text-slate-400 mt-0.5">Maximum time delta to group related logs into a continuous attack chain.</div>
              </div>
              <select
                value={correlationWindow}
                onChange={e => setCorrelationWindow(e.target.value)}
                className="bg-[#141b2b] border border-[#283550] text-slate-200 px-3 py-1.5 rounded-lg text-xs"
              >
                <option value="5m">5 Minutes</option>
                <option value="15m">15 Minutes (Default)</option>
                <option value="1h">1 Hour</option>
                <option value="24h">24 Hours</option>
              </select>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 bg-[#0f1422] rounded-xl border border-[#1c2438]">
              <div>
                <div className="font-semibold text-white">Minimum Notification Threshold</div>
                <div className="text-slate-400 mt-0.5">Filter alerts dispatched to notification webhooks by severity.</div>
              </div>
              <select
                value={alertThreshold}
                onChange={e => setAlertThreshold(e.target.value)}
                className="bg-[#141b2b] border border-[#283550] text-slate-200 px-3 py-1.5 rounded-lg text-xs"
              >
                <option value="LOW">LOW & Above</option>
                <option value="MEDIUM">MEDIUM & Above</option>
                <option value="HIGH">HIGH & Above</option>
                <option value="CRITICAL">CRITICAL Only</option>
              </select>
            </div>

            <div className="flex items-center justify-between p-3.5 bg-[#0f1422] rounded-xl border border-[#1c2438]">
              <div>
                <div className="font-semibold text-white">Automated Asset Isolation</div>
                <div className="text-slate-400 mt-0.5">Automatically trigger containment on hosts generating Critical severity attacks.</div>
              </div>
              <input
                type="checkbox"
                checked={autoIsolate}
                onChange={e => setAutoIsolate(e.target.checked)}
                className="w-4 h-4 accent-blue-600 rounded cursor-pointer"
              />
            </div>
          </div>
        </div>

        {/* Threat Intelligence Feeds */}
        <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2.5 pb-4 border-b border-[#1f293d]">
            <Shield className="w-5 h-5 text-emerald-400" />
            <h2 className="text-base font-bold text-white">Threat Intelligence Feeds</h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3.5 bg-[#0f1422] rounded-xl border border-[#1c2438] flex items-center justify-between">
              <div>
                <div className="font-semibold text-white">MITRE ATT&CK Matrix</div>
                <div className="text-slate-400 mt-0.5">Enterprise v14.1 Tactics & Techniques</div>
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                Connected
              </span>
            </div>

            <div className="p-3.5 bg-[#0f1422] rounded-xl border border-[#1c2438] flex items-center justify-between">
              <div>
                <div className="font-semibold text-white">Internal Attack Signatures</div>
                <div className="text-slate-400 mt-0.5">Predefined Detection Rules</div>
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                5 Active Rules
              </span>
            </div>
          </div>
        </div>

        {/* System & Infrastructure Status */}
        <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2.5 pb-4 border-b border-[#1f293d]">
            <Database className="w-5 h-5 text-purple-400" />
            <h2 className="text-base font-bold text-white">Database & API Health</h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="p-3.5 bg-[#0f1422] rounded-xl border border-[#1c2438]">
              <span className="text-slate-400">Backend API Gateway</span>
              <div className="text-sm font-bold text-emerald-400 mt-1">200 OK</div>
              <span className="text-[10px] text-slate-500">http://localhost:8000</span>
            </div>

            <div className="p-3.5 bg-[#0f1422] rounded-xl border border-[#1c2438]">
              <span className="text-slate-400">MongoDB Storage</span>
              <div className="text-sm font-bold text-emerald-400 mt-1">Connected</div>
              <span className="text-[10px] text-slate-500">localhost:27017</span>
            </div>

            <div className="p-3.5 bg-[#0f1422] rounded-xl border border-[#1c2438]">
              <span className="text-slate-400">Correlation Engine</span>
              <div className="text-sm font-bold text-sky-400 mt-1">Operational</div>
              <span className="text-[10px] text-slate-500">v2.4 Production</span>
            </div>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            onClick={handleSave}
            className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition-all shadow-md shadow-blue-600/30"
          >
            Save Policy Settings
          </button>
        </div>
      </div>
    </div>
  )
}
