import { useState } from 'react'
import {
  RotateCw,
  Database,
  Bell,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react'
import axios from 'axios'

const API = 'http://localhost:8000'

export default function Header({ title, subtitle, onRefresh }) {
  const [loadingSample, setLoadingSample] = useState(false)
  const [toast, setToast] = useState(null)

  const handleLoadSample = async () => {
    setLoadingSample(true)
    setToast(null)
    try {
      const { data } = await axios.post(`${API}/api/logs/import-sample`)
      setToast({
        type: 'success',
        msg: `Sample logs ingested: ${data.total_logs} events, ${data.summary?.alerts_generated || 9} alerts, ${data.summary?.correlations || 5} attack chains updated.`
      })
      if (onRefresh) onRefresh()
    } catch (e) {
      setToast({
        type: 'error',
        msg: `Failed to load data: ${e.response?.data?.detail || e.message}`
      })
    } finally {
      setLoadingSample(false)
      setTimeout(() => setToast(null), 5000)
    }
  }

  return (
    <header className="bg-[#0c1017]/90 backdrop-blur-md border-b border-[#1a2234] px-6 py-4 sticky top-0 z-20">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        {/* Title & Subtitle */}
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">{title}</h1>
          {subtitle && (
            <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>
          )}
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => onRefresh && onRefresh()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#141b2b] hover:bg-[#1a2338] border border-[#222e47] text-slate-300 hover:text-white text-xs font-medium transition-all shadow-sm"
          >
            <RotateCw className="w-3.5 h-3.5 text-slate-400" />
            <span>Refresh Data</span>
          </button>

          <button
            onClick={handleLoadSample}
            disabled={loadingSample}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold transition-all shadow-md shadow-blue-600/20"
          >
            <Database className="w-3.5 h-3.5" />
            <span>{loadingSample ? 'Ingesting Data...' : 'Load Sample Data'}</span>
          </button>
        </div>
      </div>

      {/* Toast Banner */}
      {toast && (
        <div className={`mt-3 p-2.5 rounded-lg text-xs flex items-center justify-between transition-all ${
          toast.type === 'success'
            ? 'bg-emerald-950/50 border border-emerald-700/60 text-emerald-300'
            : 'bg-red-950/50 border border-red-700/60 text-red-300'
        }`}>
          <div className="flex items-center gap-2">
            {toast.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            )}
            <span>{toast.msg}</span>
          </div>
          <button onClick={() => setToast(null)} className="text-slate-400 hover:text-white text-sm px-1">✕</button>
        </div>
      )}
    </header>
  )
}
