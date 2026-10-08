import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import axios from 'axios'
import {
  Network,
  Search,
  Filter,
  Shield,
  ShieldAlert,
  Server,
  Database,
  Terminal,
  Activity,
  ArrowRight,
  Maximize2,
  Lock,
  Layers,
  Info,
  CheckCircle2,
  Sliders,
  ExternalLink,
} from 'lucide-react'
import Header from '../components/Header'

const API = 'http://localhost:8000'

export default function AttackGraph() {
  const [graphData,    setGraphData]    = useState(null)
  const [loading,      setLoading]      = useState(true)
  const [search,       setSearch]       = useState('')
  const [connectionFilter, setConnectionFilter] = useState('all') // 'all' | 'attack' | 'normal'
  const [selectedNode, setSelectedNode] = useState(null)
  const [highlighted,  setHighlighted]  = useState(null)
  const [isolatedNode, setIsolatedNode] = useState(null)

  // Fast route query state
  const [routeSource,  setRouteSource]  = useState('')
  const [routeTarget,  setRouteTarget]  = useState('')
  const [activeRoute,  setActiveRoute]  = useState(null)

  const graphRef = useRef(null)
  const containerRef = useRef(null)
  const [dimensions, setDimensions] = useState({ width: 900, height: 600 })

  useEffect(() => {
    const updateSize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth || 900,
          height: 600
        })
      }
    }
    updateSize()
    window.addEventListener('resize', updateSize)
    return () => window.removeEventListener('resize', updateSize)
  }, [])

  const fetchGraph = async () => {
    setLoading(true)
    try {
      const { data } = await axios.get(`${API}/api/graph/`)
      const g = data.graph || { nodes: [], links: [] }
      setGraphData(g)

      if (g.nodes.length > 0) {
        const attacker = g.nodes.find(n => n.node_type === 'external' || n.id.startsWith('192.168.1.10'))?.id || g.nodes[0].id
        const db = g.nodes.find(n => n.node_type === 'database')?.id || g.nodes[g.nodes.length - 1].id
        setRouteSource(attacker)
        setRouteTarget(db)
      }
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchGraph()
  }, [])

  // Filtered Graph Data
  const displayedData = useMemo(() => {
    if (!graphData) return { nodes: [], links: [] }
    let links = graphData.links || []

    if (connectionFilter === 'attack') {
      links = links.filter(l => l.edge_type === 'attack')
    } else if (connectionFilter === 'normal') {
      links = links.filter(l => l.edge_type !== 'attack')
    }

    if (isolatedNode) {
      links = links.filter(l => {
        const s = typeof l.source === 'object' ? l.source.id : l.source
        const t = typeof l.target === 'object' ? l.target.id : l.target
        return s !== isolatedNode && t !== isolatedNode
      })
    }

    return {
      nodes: graphData.nodes.map(n => ({ ...n })),
      links: links.map(l => ({ ...l }))
    }
  }, [graphData, connectionFilter, isolatedNode])

  // Route highlight set
  const routeSet = useMemo(() => {
    return new Set(activeRoute || [])
  }, [activeRoute])

  const computeFastestExposureRoute = async () => {
    if (!routeSource || !routeTarget) return
    try {
      const { data } = await axios.get(`${API}/api/graph/path?start=${routeSource}&end=${routeTarget}`)
      setActiveRoute(data.shortest_path || [])
    } catch (e) {
      console.error(e)
    }
  }

  // Node Color Logic
  const getNodeColor = useCallback((node) => {
    if (node.id === isolatedNode) return '#475569'
    if (routeSet.has(node.id)) return '#22c55e' // Bright exposure path
    if (node.node_type === 'database')  return '#ef4444' // Red
    if (node.node_type === 'server')    return '#f97316' // Orange
    if (node.node_type === 'external')  return '#eab308' // Yellow Attacker
    return '#3b82f6' // Host Blue
  }, [routeSet, isolatedNode])

  // Custom Node Drawing
  const drawNode = useCallback((node, ctx, globalScale) => {
    const isSelected = selectedNode?.id === node.id
    const isRoute = routeSet.has(node.id)
    const isIsolated = node.id === isolatedNode

    let radius = node.node_type === 'database' ? 10 : node.node_type === 'server' ? 8 : 7
    if (isSelected || isRoute) radius += 2

    const color = getNodeColor(node)

    // Glow for selected or route nodes
    if (isSelected || isRoute) {
      ctx.beginPath()
      ctx.arc(node.x, node.y, radius + 4, 0, 2 * Math.PI)
      ctx.fillStyle = isRoute ? 'rgba(34, 197, 94, 0.25)' : 'rgba(59, 130, 246, 0.3)'
      ctx.fill()
    }

    // Node body
    ctx.beginPath()
    ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI)
    ctx.fillStyle = color
    ctx.fill()
    ctx.strokeStyle = isSelected ? '#ffffff' : 'rgba(255, 255, 255, 0.25)'
    ctx.lineWidth = isSelected ? 2 : 1
    ctx.stroke()

    // Node text label
    const fontSize = Math.max(9 / globalScale, 3.5)
    ctx.font = `${isSelected ? 'bold ' : ''}${fontSize}px sans-serif`
    ctx.fillStyle = isIsolated ? '#64748b' : '#f1f5f9'
    ctx.textAlign = 'center'
    const label = isIsolated ? `[CONTAINED] ${node.id}` : node.id
    ctx.fillText(label, node.x, node.y + radius + fontSize + 2)
  }, [selectedNode, routeSet, isolatedNode, getNodeColor])

  const getLinkColor = useCallback((link) => {
    const s = typeof link.source === 'object' ? link.source.id : link.source
    const t = typeof link.target === 'object' ? link.target.id : link.target
    if (routeSet.has(s) && routeSet.has(t)) return '#22c55e'
    if (link.edge_type === 'attack') return '#ef444499'
    return '#3b82f633'
  }, [routeSet])

  const getLinkWidth = useCallback((link) => {
    const s = typeof link.source === 'object' ? link.source.id : link.source
    const t = typeof link.target === 'object' ? link.target.id : link.target
    if (routeSet.has(s) && routeSet.has(t)) return 3
    return link.edge_type === 'attack' ? 2 : 1
  }, [routeSet])

  const handleSearch = (e) => {
    const q = e.target.value
    setSearch(q)
    if (!q) {
      setSelectedNode(null)
      return
    }
    const match = graphData?.nodes?.find(n => n.id.toLowerCase().includes(q.toLowerCase()))
    if (match && graphRef.current) {
      setSelectedNode(match)
      graphRef.current.centerAt(match.x, match.y, 800)
      graphRef.current.zoom(2.5, 800)
    }
  }

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-[#0a0d14] text-slate-200">
      <Header
        title="Attack Graph"
        subtitle="Visualize relationships between hosts, users, events and attack stages."
        onRefresh={fetchGraph}
      />

      <div className="p-6 space-y-6 max-w-7xl mx-auto w-full">
        {/* ── TOP CONTROLS & LEGEND ── */}
        <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3 w-full md:w-auto flex-1">
            {/* Search */}
            <div className="relative flex-1 max-w-xs">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Find host (e.g. 192.168.1.100)..."
                value={search}
                onChange={handleSearch}
                className="w-full bg-[#0f1422] border border-[#222e47] rounded-xl pl-9 pr-4 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>

            {/* Connection filter */}
            <div className="flex items-center gap-1 bg-[#0f1422] p-1 rounded-xl border border-[#222e47] text-xs">
              {['all', 'attack', 'normal'].map(f => (
                <button
                  key={f}
                  onClick={() => setConnectionFilter(f)}
                  className={`px-3 py-1 rounded-lg capitalize transition-all ${
                    connectionFilter === f
                      ? 'bg-blue-600 text-white font-semibold shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {f === 'all' ? 'All Activity' : f === 'attack' ? 'Attack Traffic' : 'Normal Connections'}
                </button>
              ))}
            </div>
          </div>

          {/* Clean Legend */}
          <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400 font-medium">
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-yellow-500 inline-block" /> Attacker</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" /> Host</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-orange-500 inline-block" /> Server</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" /> Database</span>
          </div>
        </div>

        {/* ── FASTEST EXPOSURE ROUTE CALCULATOR ── */}
        <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-semibold text-white">Identify Infiltration Route:</span>
            <span className="text-slate-400">From Attacker:</span>
            <select
              value={routeSource}
              onChange={e => setRouteSource(e.target.value)}
              className="bg-[#0f1422] border border-[#222e47] text-slate-200 px-2.5 py-1 rounded-lg font-mono text-xs"
            >
              {graphData?.nodes?.map(n => <option key={n.id} value={n.id}>{n.id}</option>)}
            </select>
            <span className="text-slate-400">To Asset:</span>
            <select
              value={routeTarget}
              onChange={e => setRouteTarget(e.target.value)}
              className="bg-[#0f1422] border border-[#222e47] text-slate-200 px-2.5 py-1 rounded-lg font-mono text-xs"
            >
              {graphData?.nodes?.map(n => <option key={n.id} value={n.id}>{n.id}</option>)}
            </select>
            <button
              onClick={computeFastestExposureRoute}
              className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold transition-all shadow-sm"
            >
              Trace Route
            </button>
          </div>

          {activeRoute && activeRoute.length > 0 && (
            <div className="text-emerald-400 font-mono text-[11px] flex items-center gap-1 flex-wrap">
              <span>Path: {activeRoute.join(' ➔ ')}</span>
              <button onClick={() => setActiveRoute(null)} className="text-slate-400 hover:text-white ml-2">✕ Clear</button>
            </div>
          )}
        </div>

        {/* ── GRAPH CANVAS & ASSET INVESTIGATION DRAWER ── */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Main Interactive Canvas */}
          <div
            ref={containerRef}
            className="lg:col-span-3 bg-[#0c1017] border border-[#1f293d] rounded-2xl overflow-hidden relative shadow-2xl"
            style={{ height: '580px' }}
          >
            {loading ? (
              <div className="flex items-center justify-center h-full text-slate-400 text-xs">
                Rendering network topology...
              </div>
            ) : (
              <ForceGraph2D
                ref={graphRef}
                graphData={displayedData}
                width={dimensions.width}
                height={dimensions.height}
                backgroundColor="#0c1017"
                nodeCanvasObject={drawNode}
                nodeCanvasObjectMode={() => 'replace'}
                linkColor={getLinkColor}
                linkWidth={getLinkWidth}
                linkDirectionalArrowLength={6}
                linkDirectionalArrowRelPos={1}
                linkDirectionalArrowColor={getLinkColor}
                linkCurvature={0.06}
                cooldownTicks={100}
                onNodeClick={(node) => setSelectedNode(node)}
              />
            )}

            <div className="absolute bottom-3 left-3 bg-[#121826]/90 backdrop-blur-md px-3 py-1.5 rounded-lg border border-[#1f293d] text-[11px] text-slate-400 pointer-events-none">
              Drag nodes to adjust layout · Scroll to zoom · Click host for details
            </div>
          </div>

          {/* Right Asset Detail Drawer */}
          <div className="bg-[#121826] border border-[#1f293d] rounded-2xl p-5 shadow-xl flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-[#1f293d]">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  Asset Details
                </h3>
                {selectedNode && (
                  <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30 uppercase">
                    {selectedNode.node_type || 'Host'}
                  </span>
                )}
              </div>

              {selectedNode ? (
                <div className="space-y-4 mt-3 text-xs">
                  <div>
                    <span className="text-slate-400 text-[11px]">Asset Identifier (IP):</span>
                    <div className="text-sm font-bold text-white font-mono mt-0.5">
                      {selectedNode.id}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="bg-[#0f1422] p-2.5 rounded-xl border border-[#1c2438]">
                      <span className="text-slate-400 text-[11px]">Outbound Sockets:</span>
                      <div className="text-sm font-bold text-sky-400 mt-0.5">
                        {graphData?.links?.filter(l => (l.source?.id || l.source) === selectedNode.id).length || 0}
                      </div>
                    </div>
                    <div className="bg-[#0f1422] p-2.5 rounded-xl border border-[#1c2438]">
                      <span className="text-slate-400 text-[11px]">Inbound Sockets:</span>
                      <div className="text-sm font-bold text-amber-400 mt-0.5">
                        {graphData?.links?.filter(l => (l.target?.id || l.target) === selectedNode.id).length || 0}
                      </div>
                    </div>
                  </div>

                  {/* Connected Traffic */}
                  <div>
                    <span className="text-slate-400 text-[11px] font-semibold uppercase tracking-wider block mb-1.5">
                      Active Connections:
                    </span>
                    <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                      {graphData?.links
                        ?.filter(l => (l.source?.id || l.source) === selectedNode.id)
                        .map((l, i) => (
                          <div key={i} className="p-2 rounded-lg bg-[#0f1422] border border-[#1c2438] text-[11px] flex items-center justify-between">
                            <span className="text-slate-300 font-mono">➔ {l.target?.id || l.target}</span>
                            <span className={`font-semibold ${l.edge_type === 'attack' ? 'text-red-400' : 'text-slate-400'}`}>
                              {l.event_type}
                            </span>
                          </div>
                        ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-16 text-slate-500 text-xs">
                  Click any host in the attack graph to inspect telemetry and connections.
                </div>
              )}
            </div>

            {selectedNode && (
              <div className="pt-3 border-t border-[#1f293d] space-y-2">
                <button
                  onClick={() => setIsolatedNode(isolatedNode === selectedNode.id ? null : selectedNode.id)}
                  className={`w-full py-2 rounded-xl text-xs font-semibold transition-all ${
                    isolatedNode === selectedNode.id
                      ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                      : 'bg-red-600/20 hover:bg-red-600/30 border border-red-500/40 text-red-300'
                  }`}
                >
                  {isolatedNode === selectedNode.id ? '✓ Restore Network Connection' : '🛡️ Isolate Host from Network'}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
