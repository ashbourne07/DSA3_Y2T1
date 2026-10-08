import { useState, useEffect, useMemo } from 'react'
import axios from 'axios'
import {
  FileText,
  Search,
  Filter,
  Upload,
  Download,
  Terminal,
  Activity,
  CheckCircle2,
  X,
  ExternalLink,
} from 'lucide-react'
import Header from '../components/Header'

const API = 'http://localhost:8000'

const SEV_BADGE = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  LOW:      'bg-slate-700/30 text-slate-400 border-slate-700',
}

export default function Logs() {
  const [logs,        setLogs]        = useState([])
  const [loading,     setLoading]     = useState(true)
  const [search,      setSearch]      = useState('')
  const [filterSev,   setFilterSev]   = useState('ALL')
  const [filterEvent, setFilterEvent] = useState('ALL')
  const [selectedLog, setSelectedLog] = useState(null)
  const [uploading,   setUploading]   = useState(false)
  const [file,        setFile]        = useState(null)
  const [uploadMsg,   setUploadMsg]   = useState('')

  const fetchLogs = async () => {
    setLoading(true)
    try {
      const { data } = await axios.get(`${API}/api/logs/?limit=100`)
      setLogs(data.logs || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchLogs()
  }, [])

  const uploadCSV = async (e) => {
    const selectedFile = e.target.files[0]
    if (!selectedFile) return
    setUploading(true)
    setUploadMsg('')
    const form = new FormData()
    form.append('file', selectedFile)
    try {
      const { data } = await axios.post(`${API}/api/logs/import`, form)
      setUploadMsg(`✓ Successfully ingested ${data.total_logs} log records.`)
      fetchLogs()
    } catch (err) {
      setUploadMsg(`✕ Error ingesting file: ${err.response?.data?.detail?.message || err.message}`)
    } finally {
      setUploading(false)
      setTimeout(() => setUploadMsg(''), 5000)
    }
  }

  // Unique event types
  const eventTypes = useMemo(() => {
    const s = new Set(logs.map(l => l.event_type))
    return ['ALL', ...Array.from(s).sort()]
  }, [logs])

  const filteredLogs = useMemo(() => {
    return logs.filter(l => {
      const matchSev = filterSev === 'ALL' || l.severity === filterSev
      const matchEvt = filterEvent === 'ALL' || l.event_type === filterEvent
      const q = search.toLowerCase()
      const matchSearch = !q ||
        l.log_id.toLowerCase().includes(q) ||
        l.source_ip.toLowerCase().includes(q) ||
        l.destination_ip.toLowerCase().includes(q) ||
        l.event_type.toLowerCase().includes(q) ||
        l.description.toLowerCase().includes(q)
      return matchSev && matchEvt && matchSearch
    })
  }, [logs, filterSev, filterEvent, search])

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-[#0a0d14] text-slate-200">
      <Header
        title="Security Logs"
        subtitle="Real-time enterprise event stream ingestion and audit log repository."
        onRefresh={fetchLogs}
      />

      <div className="p-6 space-y-6 max-w-7xl mx-auto w-full">
        {/* Top Actions: Import CSV + Filter Bar */}
        <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3 w-full md:w-auto flex-1">
            {/* Search */}
            <div className="relative flex-1 max-w-xs">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search by IP, event or host..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="w-full bg-[#0f1422] border border-[#222e47] rounded-xl pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            {/* Severity Filter */}
            <select
              value={filterSev}
              onChange={e => setFilterSev(e.target.value)}
              className="bg-[#0f1422] border border-[#222e47] text-slate-200 text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-blue-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            {/* Event Type Filter */}
            <select
              value={filterEvent}
              onChange={e => setFilterEvent(e.target.value)}
              className="bg-[#0f1422] border border-[#222e47] text-slate-200 text-xs px-3 py-2 rounded-xl focus:outline-none focus:border-blue-500 max-w-[180px]"
            >
              {eventTypes.map(evt => (
                <option key={evt} value={evt}>{evt === 'ALL' ? 'All Event Types' : evt}</option>
              ))}
            </select>
          </div>

          {/* Import CSV Button */}
          <div className="flex items-center gap-3 shrink-0">
            <label className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#182136] hover:bg-[#202c48] border border-[#283758] text-slate-200 hover:text-white text-xs font-semibold cursor-pointer transition-all">
              <Upload className="w-3.5 h-3.5 text-blue-400" />
              <span>{uploading ? 'Importing...' : 'Import Logs (CSV)'}</span>
              <input
                type="file"
                accept=".csv"
                onChange={uploadCSV}
                className="hidden"
                disabled={uploading}
              />
            </label>
          </div>
        </div>

        {uploadMsg && (
          <div className="p-3 bg-emerald-950/40 border border-emerald-600/50 rounded-xl text-xs text-emerald-300">
            {uploadMsg}
          </div>
        )}

        {/* ── SECURITY LOGS TABLE ── */}
        <div className="bg-[#121826] border border-[#1f293d] rounded-2xl overflow-hidden shadow-xl">
          {loading ? (
            <div className="flex items-center justify-center h-64 text-slate-400 text-xs">
              Loading security logs...
            </div>
          ) : filteredLogs.length === 0 ? (
            <div className="text-center py-16 text-slate-500 text-xs">
              No security logs match the active filter criteria.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-[#151c2c] text-slate-400 border-b border-[#1f293d] text-[11px] font-semibold uppercase tracking-wider">
                  <tr>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Source</th>
                    <th className="py-3 px-4">Event</th>
                    <th className="py-3 px-4">Destination</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1c2438]">
                  {filteredLogs.map(log => {
                    const sev = SEV_BADGE[log.severity] || SEV_BADGE.LOW
                    return (
                      <tr
                        key={log.log_id}
                        onClick={() => setSelectedLog(log)}
                        className="hover:bg-[#141b2b] cursor-pointer transition-colors"
                      >
                        <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                          {log.timestamp}
                        </td>
                        <td className="py-3 px-4 text-sky-400 font-mono">
                          {log.source_ip}
                        </td>
                        <td className="py-3 px-4">
                          <span className="font-semibold text-white">
                            {log.event_type}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-amber-400 font-mono">
                          {log.destination_ip}
                        </td>
                        <td className="py-3 px-4">
                          <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${sev}`}>
                            {log.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span className="inline-flex items-center gap-1.5 text-slate-400 text-[11px]">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block" />
                            Processed
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <span className="text-blue-400 hover:text-blue-300 font-medium">
                            View →
                          </span>
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

      {/* Log Details Modal */}
      {selectedLog && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#121826] border border-[#222e47] rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4 relative">
            <button
              onClick={() => setSelectedLog(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            <div>
              <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">
                Event Telemetry Record · {selectedLog.log_id}
              </span>
              <h3 className="text-base font-bold text-white mt-1">
                {selectedLog.event_type}
              </h3>
            </div>

            <div className="bg-[#0f1422] p-4 rounded-xl border border-[#1c2438] space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Timestamp:</span>
                <span className="text-slate-200 font-mono">{selectedLog.timestamp}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Source Host:</span>
                <span className="text-sky-400 font-mono">{selectedLog.source_ip}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Destination Host:</span>
                <span className="text-amber-400 font-mono">{selectedLog.destination_ip}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Severity Rating:</span>
                <span className="font-bold text-red-400">{selectedLog.severity}</span>
              </div>
            </div>

            <div>
              <span className="text-xs font-semibold text-slate-300">Payload Description:</span>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed bg-[#0f1422] p-3 rounded-lg border border-[#1c2438]">
                {selectedLog.description}
              </p>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedLog(null)}
                className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-md"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
