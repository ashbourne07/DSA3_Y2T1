const severityStyle = {
  CRITICAL: 'bg-red-900/40 border-red-600 text-red-300',
  HIGH:     'bg-orange-900/40 border-orange-500 text-orange-300',
  MEDIUM:   'bg-yellow-900/40 border-yellow-500 text-yellow-300',
  LOW:      'bg-slate-800 border-slate-600 text-slate-300',
}

const badge = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH:     'bg-orange-500 text-white',
  MEDIUM:   'bg-yellow-500 text-black',
  LOW:      'bg-slate-600 text-white',
}

export default function AlertCard({ alert }) {
  const sev = alert.severity || 'LOW'
  return (
    <div className={`border rounded-lg p-4 mb-3 ${severityStyle[sev] || severityStyle.LOW}`}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className={`text-xs font-bold px-2 py-0.5 rounded ${badge[sev]}`}>
            {sev}
          </span>
          <span className="font-semibold text-sm">{alert.alert_id}</span>
          <span className="text-xs text-slate-400">{alert.attack_type?.replace(/_/g, ' ')}</span>
        </div>
        <span className="text-xs text-slate-500">{alert.kill_chain_stage}</span>
      </div>
      <p className="text-xs text-slate-300 mb-2">{alert.description}</p>
      <div className="flex gap-4 text-xs text-slate-500">
        <span>From: <span className="text-slate-300">{alert.source_ip}</span></span>
        <span>To: <span className="text-slate-300">{alert.destination_ip}</span></span>
        <span>Logs: <span className="text-slate-300">{alert.related_log_ids?.join(', ')}</span></span>
      </div>
    </div>
  )
}
