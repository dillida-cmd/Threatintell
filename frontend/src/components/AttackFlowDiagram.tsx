import { useCallback, useMemo, useEffect, useState } from 'react'
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  Position,
  BackgroundVariant,
} from 'reactflow'
import 'reactflow/dist/style.css'

// Custom animated styles
const customStyles = `
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.8; transform: scale(1.05); }
  }

  @keyframes glow {
    0%, 100% { box-shadow: 0 0 5px currentColor, 0 0 10px currentColor; }
    50% { box-shadow: 0 0 15px currentColor, 0 0 25px currentColor; }
  }

  @keyframes flowParticle {
    0% { stroke-dashoffset: 24; }
    100% { stroke-dashoffset: 0; }
  }

  .node-pulse {
    animation: pulse 2s ease-in-out infinite;
  }

  .node-glow {
    animation: glow 2s ease-in-out infinite;
  }

  .malicious-node {
    animation: pulse 1s ease-in-out infinite;
    box-shadow: 0 0 20px rgba(239, 68, 68, 0.6);
  }

  .c2-node {
    animation: glow 1.5s ease-in-out infinite;
  }

  .react-flow__edge-path {
    stroke-width: 2;
  }

  .animated-edge {
    stroke-dasharray: 8;
    animation: flowParticle 1s linear infinite;
  }

  .react-flow__node {
    transition: transform 0.2s ease, box-shadow 0.2s ease;
  }

  .react-flow__node:hover {
    transform: scale(1.05);
    z-index: 100;
  }
`

// Inject styles
const StyleInjector = () => {
  useEffect(() => {
    const styleEl = document.createElement('style')
    styleEl.textContent = customStyles
    document.head.appendChild(styleEl)
    return () => { document.head.removeChild(styleEl) }
  }, [])
  return null
}

// Icon components as SVG for better rendering
const ProcessIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
  </svg>
)

const NetworkIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
  </svg>
)

const FileIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
  </svg>
)

const AlertIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
  </svg>
)

const ServerIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
  </svg>
)

const CpuIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
  </svg>
)

const ShieldIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
)

// Custom node component for processes
function ProcessNode({ data }: { data: any }) {
  const isSuspicious = data.suspicious
  const baseClass = isSuspicious
    ? 'bg-gradient-to-br from-red-900/80 to-red-800/60 border-red-500 malicious-node'
    : 'bg-gradient-to-br from-blue-900/80 to-blue-800/60 border-blue-500 node-pulse'
  const textColor = isSuspicious ? 'text-red-300' : 'text-blue-300'

  return (
    <div className={`px-4 py-3 rounded-xl border-2 ${baseClass} min-w-[150px] backdrop-blur-sm`}>
      <div className="flex items-center gap-2">
        <div className={textColor}><ProcessIcon /></div>
        <span className={`font-bold text-sm ${textColor}`}>{data.label}</span>
      </div>
      {data.pid && (
        <div className="text-xs text-gray-400 mt-1 font-mono">PID: {data.pid}</div>
      )}
      {data.technique && (
        <div className="text-xs text-orange-400 mt-1 font-semibold">{data.technique}</div>
      )}
    </div>
  )
}

// Custom node for network connections
function NetworkNode({ data }: { data: any }) {
  const isC2 = data.isC2 || data.suspicious
  const baseClass = isC2
    ? 'bg-gradient-to-br from-red-900/90 to-red-700/70 border-red-400 c2-node'
    : 'bg-gradient-to-br from-purple-900/80 to-purple-800/60 border-purple-500 node-pulse'
  const textColor = isC2 ? 'text-red-300' : 'text-purple-300'

  return (
    <div className={`px-4 py-3 rounded-xl border-2 ${baseClass} min-w-[150px] backdrop-blur-sm`}>
      <div className="flex items-center gap-2">
        <div className={textColor}><NetworkIcon /></div>
        <span className={`font-bold text-sm ${textColor}`}>
          {data.ip || data.domain || data.label}
        </span>
      </div>
      {data.port && (
        <div className="text-xs text-gray-400 mt-1 font-mono">:{data.port}</div>
      )}
      {data.protocol && (
        <div className="text-xs text-gray-500 mt-1">{data.protocol}</div>
      )}
      {isC2 && (
        <div className="text-xs text-red-300 mt-2 flex items-center gap-1 font-bold">
          <AlertIcon /> C2 SERVER
        </div>
      )}
    </div>
  )
}

// Custom node for file operations
function FileNode({ data }: { data: any }) {
  const colors: Record<string, { bg: string; border: string; text: string }> = {
    created: { bg: 'from-green-900/80 to-green-800/60', border: 'border-green-500', text: 'text-green-300' },
    modified: { bg: 'from-yellow-900/80 to-yellow-800/60', border: 'border-yellow-500', text: 'text-yellow-300' },
    deleted: { bg: 'from-red-900/80 to-red-800/60', border: 'border-red-500', text: 'text-red-300' },
    dropped: { bg: 'from-orange-900/80 to-orange-800/60', border: 'border-orange-500', text: 'text-orange-300' },
  }
  const color = colors[data.operation] || colors.created

  return (
    <div className={`px-4 py-3 rounded-xl border-2 bg-gradient-to-br ${color.bg} ${color.border} min-w-[140px] backdrop-blur-sm node-pulse`}>
      <div className="flex items-center gap-2">
        <div className={color.text}><FileIcon /></div>
        <span className={`font-bold text-sm ${color.text} truncate max-w-[100px]`} title={data.label}>
          {data.label}
        </span>
      </div>
      <div className="text-xs text-gray-400 mt-1 capitalize font-semibold">{data.operation}</div>
    </div>
  )
}

// Custom node for IOCs/Techniques
function IOCNode({ data }: { data: any }) {
  const isMalicious = data.malicious
  const baseClass = isMalicious
    ? 'bg-gradient-to-br from-red-900/90 to-orange-900/70 border-red-400 malicious-node'
    : 'bg-gradient-to-br from-orange-900/80 to-orange-800/60 border-orange-500'
  const textColor = isMalicious ? 'text-red-300' : 'text-orange-300'

  return (
    <div className={`px-4 py-3 rounded-xl border-2 ${baseClass} min-w-[130px] backdrop-blur-sm`}>
      <div className="flex items-center gap-2">
        <div className={textColor}><ShieldIcon /></div>
        <span className={`font-bold text-xs ${textColor}`}>{data.type}</span>
      </div>
      <div className="text-xs text-gray-300 mt-1 truncate max-w-[110px]" title={data.value}>
        {data.value}
      </div>
      {isMalicious && (
        <div className="text-xs text-red-300 mt-1 font-bold flex items-center gap-1">
          <AlertIcon /> MALICIOUS
        </div>
      )}
    </div>
  )
}

// Entry point node
function EntryNode({ data }: { data: any }) {
  return (
    <div className="px-5 py-4 rounded-2xl border-2 bg-gradient-to-br from-indigo-900/90 to-purple-900/80 border-indigo-400 min-w-[180px] backdrop-blur-sm node-glow shadow-lg shadow-indigo-500/30">
      <div className="flex items-center gap-2">
        <div className="text-indigo-300"><CpuIcon /></div>
        <span className="font-bold text-sm text-indigo-200">{data.label}</span>
      </div>
      {data.hash && (
        <div className="text-xs text-gray-400 mt-2 font-mono bg-black/30 px-2 py-1 rounded truncate max-w-[160px]" title={data.hash}>
          {data.hash.substring(0, 20)}...
        </div>
      )}
      {data.type && (
        <div className="text-xs text-indigo-300 mt-1 font-semibold uppercase">{data.type}</div>
      )}
    </div>
  )
}

// URL redirect node
function URLNode({ data }: { data: any }) {
  const isSuspicious = data.suspicious
  const statusColor = data.status >= 400 ? 'text-red-300' : data.status >= 300 ? 'text-yellow-300' : 'text-green-300'
  const baseClass = isSuspicious
    ? 'bg-gradient-to-br from-red-900/80 to-orange-900/60 border-orange-500 malicious-node'
    : 'bg-gradient-to-br from-cyan-900/80 to-teal-900/60 border-cyan-500 node-pulse'

  return (
    <div className={`px-4 py-3 rounded-xl border-2 ${baseClass} min-w-[200px] max-w-[280px] backdrop-blur-sm`}>
      <div className="flex items-center gap-2 mb-1">
        <div className="text-cyan-300"><ServerIcon /></div>
        {data.status && (
          <span className={`font-bold text-sm ${statusColor} bg-black/30 px-2 py-0.5 rounded`}>
            HTTP {data.status}
          </span>
        )}
      </div>
      <div className="text-xs text-gray-300 truncate font-mono bg-black/20 px-2 py-1 rounded" title={data.url}>
        {data.url}
      </div>
      {isSuspicious && (
        <div className="text-xs text-orange-300 mt-2 flex items-center gap-1 font-bold">
          <AlertIcon /> SUSPICIOUS
        </div>
      )}
    </div>
  )
}

const nodeTypes = {
  process: ProcessNode,
  network: NetworkNode,
  file: FileNode,
  ioc: IOCNode,
  entry: EntryNode,
  url: URLNode,
}

interface AttackFlowProps {
  analysis: any
}

export default function AttackFlowDiagram({ analysis }: AttackFlowProps) {
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  // Build nodes and edges from analysis data
  const { initialNodes, initialEdges } = useMemo(() => {
    const nodes: Node[] = []
    const edges: Edge[] = []
    let nodeId = 0
    let yOffset = 0
    const xSpacing = 280
    const ySpacing = 140

    const getNextId = () => `node-${nodeId++}`

    // Entry point (the analyzed file/URL)
    const entryId = getNextId()
    const entryLabel = analysis.filename || analysis.url || 'Sample'
    const displayLabel = entryLabel.length > 25 ? entryLabel.substring(0, 25) + '...' : entryLabel

    nodes.push({
      id: entryId,
      type: 'entry',
      position: { x: 400, y: 0 },
      data: {
        label: displayLabel,
        hash: analysis.fileAnalysis?.hashes?.sha256 || analysis.sha256,
        type: analysis.fileAnalysis?.fileType || analysis.type || analysis.mode,
      },
      sourcePosition: Position.Bottom,
      targetPosition: Position.Top,
    })
    yOffset += ySpacing

    // URL redirect chain (for URL analysis) - show this prominently
    const redirectChain = analysis.redirectChain || []
    if (redirectChain.length > 0 || analysis.finalUrl) {
      let urlX = 100
      let prevUrlId = entryId

      // Add each redirect as a node
      redirectChain.forEach((redirect: any, idx: number) => {
        const urlId = getNextId()
        const urlStr = redirect.redirectTo || redirect.url || ''
        const displayUrl = urlStr.length > 40 ? urlStr.substring(0, 40) + '...' : urlStr

        nodes.push({
          id: urlId,
          type: 'url',
          position: { x: urlX, y: yOffset },
          data: {
            url: displayUrl,
            fullUrl: urlStr,
            status: redirect.statusCode,
            suspicious: redirect.suspicious,
          },
          sourcePosition: Position.Right,
          targetPosition: Position.Left,
        })

        edges.push({
          id: `edge-url-${urlId}`,
          source: prevUrlId,
          target: urlId,
          animated: true,
          className: 'animated-edge',
          style: { stroke: 'url(#gradient-cyan)', strokeWidth: 3 },
          markerEnd: { type: MarkerType.ArrowClosed, color: '#06b6d4', width: 20, height: 20 },
          label: redirect.statusCode ? `${redirect.statusCode}` : 'redirect',
          labelStyle: { fill: '#9ca3af', fontSize: 11, fontWeight: 600 },
          labelBgStyle: { fill: 'rgba(0,0,0,0.6)', fillOpacity: 0.8 },
          labelBgPadding: [4, 8] as [number, number],
          labelBgBorderRadius: 4,
        })

        prevUrlId = urlId
        urlX += 300
      })

      // Final URL if different
      if (analysis.finalUrl) {
        const finalId = getNextId()
        const finalUrl = analysis.finalUrl
        const displayFinal = finalUrl.length > 40 ? finalUrl.substring(0, 40) + '...' : finalUrl

        nodes.push({
          id: finalId,
          type: 'url',
          position: { x: urlX, y: yOffset },
          data: {
            url: displayFinal,
            fullUrl: finalUrl,
            status: 200,
            suspicious: false,
          },
          sourcePosition: Position.Bottom,
          targetPosition: Position.Left,
        })

        if (prevUrlId !== entryId) {
          edges.push({
            id: `edge-final-${finalId}`,
            source: prevUrlId,
            target: finalId,
            animated: true,
            className: 'animated-edge',
            style: { stroke: '#22c55e', strokeWidth: 3 },
            markerEnd: { type: MarkerType.ArrowClosed, color: '#22c55e', width: 20, height: 20 },
            label: 'final',
            labelStyle: { fill: '#22c55e', fontSize: 11, fontWeight: 600 },
            labelBgStyle: { fill: 'rgba(0,0,0,0.6)' },
            labelBgPadding: [4, 8] as [number, number],
            labelBgBorderRadius: 4,
          })
        }
      }
      yOffset += ySpacing
    }

    // Process tree
    const processTree = analysis.processTree || analysis.process_tree || []
    const processNodes: Record<string, string> = {}

    if (processTree.length > 0) {
      let processX = 100
      processTree.forEach((proc: any, idx: number) => {
        const procId = getNextId()
        processNodes[proc.pid || idx] = procId
        const procName = proc.name || proc.command?.split(' ')[0] || 'Process'

        nodes.push({
          id: procId,
          type: 'process',
          position: { x: processX, y: yOffset },
          data: {
            label: procName.length > 20 ? procName.substring(0, 20) + '...' : procName,
            pid: proc.pid,
            suspicious: proc.suspicious,
            technique: proc.technique,
          },
          sourcePosition: Position.Bottom,
          targetPosition: Position.Top,
        })

        // Connect to entry or parent
        if (idx === 0) {
          edges.push({
            id: `edge-entry-${procId}`,
            source: entryId,
            target: procId,
            animated: true,
            className: 'animated-edge',
            style: { stroke: 'url(#gradient-blue)', strokeWidth: 3 },
            markerEnd: { type: MarkerType.ArrowClosed, color: '#6366f1', width: 20, height: 20 },
            label: 'executes',
            labelStyle: { fill: '#a5b4fc', fontSize: 11, fontWeight: 600 },
            labelBgStyle: { fill: 'rgba(0,0,0,0.6)' },
            labelBgPadding: [4, 8] as [number, number],
            labelBgBorderRadius: 4,
          })
        }

        // Process children
        if (proc.children) {
          proc.children.forEach((child: any, childIdx: number) => {
            const childId = getNextId()
            processNodes[child.pid || `${idx}-${childIdx}`] = childId
            const childName = child.name || child.command?.split(' ')[0] || 'Child'

            nodes.push({
              id: childId,
              type: 'process',
              position: { x: processX + 60 + childIdx * 200, y: yOffset + ySpacing },
              data: {
                label: childName.length > 20 ? childName.substring(0, 20) + '...' : childName,
                pid: child.pid,
                suspicious: child.suspicious,
              },
              sourcePosition: Position.Bottom,
              targetPosition: Position.Top,
            })

            edges.push({
              id: `edge-${procId}-${childId}`,
              source: procId,
              target: childId,
              animated: true,
              className: 'animated-edge',
              style: { stroke: '#3b82f6', strokeWidth: 2 },
              markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6', width: 16, height: 16 },
            })
          })
        }

        processX += xSpacing
      })
      yOffset += ySpacing * 2
    }

    // Network connections
    const network = analysis.networkConnections || analysis.network_connections || []
    const extractedIocs = analysis.extractedIocs || analysis.extracted_iocs || {}
    const c2Ips = extractedIocs.ips || []

    if (network.length > 0) {
      let netX = 50
      network.slice(0, 6).forEach((conn: any) => {
        const netId = getNextId()
        const ip = conn.remoteIp || conn.ip || conn.destination
        const isC2 = c2Ips.includes(ip) || conn.suspicious

        nodes.push({
          id: netId,
          type: 'network',
          position: { x: netX, y: yOffset },
          data: {
            ip: ip,
            port: conn.remotePort || conn.port,
            protocol: conn.protocol || 'TCP',
            isC2: isC2,
            suspicious: conn.suspicious,
          },
          sourcePosition: Position.Bottom,
          targetPosition: Position.Top,
        })

        const sourceNode = Object.values(processNodes)[0] || entryId
        edges.push({
          id: `edge-net-${netId}`,
          source: sourceNode,
          target: netId,
          animated: true,
          className: isC2 ? 'animated-edge' : '',
          style: { stroke: isC2 ? '#ef4444' : '#a855f7', strokeWidth: isC2 ? 4 : 2 },
          markerEnd: { type: MarkerType.ArrowClosed, color: isC2 ? '#ef4444' : '#a855f7', width: isC2 ? 24 : 18, height: isC2 ? 24 : 18 },
          label: isC2 ? 'C2' : 'connect',
          labelStyle: { fill: isC2 ? '#fca5a5' : '#c4b5fd', fontSize: 11, fontWeight: 700 },
          labelBgStyle: { fill: isC2 ? 'rgba(127,29,29,0.8)' : 'rgba(0,0,0,0.6)' },
          labelBgPadding: [4, 8] as [number, number],
          labelBgBorderRadius: 4,
        })

        netX += xSpacing
      })
      yOffset += ySpacing
    }

    // File operations
    const files = analysis.filesystemChanges || analysis.filesystem_changes || {}
    const allFiles = [
      ...(files.created || []).map((f: string) => ({ path: f, operation: 'created' })),
      ...(files.modified || []).map((f: string) => ({ path: f, operation: 'modified' })),
      ...(files.deleted || []).map((f: string) => ({ path: f, operation: 'deleted' })),
    ].slice(0, 5)

    if (allFiles.length > 0) {
      let fileX = 100
      allFiles.forEach((file: any) => {
        const fileId = getNextId()
        const fileName = file.path.split('/').pop() || file.path.split('\\').pop() || file.path
        const displayName = fileName.length > 15 ? fileName.substring(0, 15) + '...' : fileName

        nodes.push({
          id: fileId,
          type: 'file',
          position: { x: fileX, y: yOffset },
          data: {
            label: displayName,
            fullPath: file.path,
            operation: file.operation,
          },
          sourcePosition: Position.Bottom,
          targetPosition: Position.Top,
        })

        const sourceNode = Object.values(processNodes)[0] || entryId
        const opColors: Record<string, string> = {
          created: '#22c55e',
          modified: '#eab308',
          deleted: '#ef4444',
        }

        edges.push({
          id: `edge-file-${fileId}`,
          source: sourceNode,
          target: fileId,
          style: { stroke: opColors[file.operation] || '#22c55e', strokeWidth: 2 },
          markerEnd: { type: MarkerType.ArrowClosed, color: opColors[file.operation] || '#22c55e', width: 16, height: 16 },
          label: file.operation,
          labelStyle: { fill: '#9ca3af', fontSize: 10, fontWeight: 600 },
          labelBgStyle: { fill: 'rgba(0,0,0,0.6)' },
          labelBgPadding: [3, 6] as [number, number],
          labelBgBorderRadius: 3,
        })

        fileX += 180
      })
      yOffset += ySpacing
    }

    // Threat map behaviors as IOC nodes
    const threatMap = analysis.threatMap || analysis.threat_map || {}
    let iocX = 650
    let iocY = 80

    Object.entries(threatMap).forEach(([category, behaviors]: [string, any]) => {
      if (behaviors && behaviors.length > 0) {
        behaviors.slice(0, 3).forEach((behavior: any) => {
          const iocId = getNextId()
          nodes.push({
            id: iocId,
            type: 'ioc',
            position: { x: iocX, y: iocY },
            data: {
              type: behavior.technique || category,
              value: behavior.behavior || behavior.api || '',
              malicious: behavior.severity === 'high' || behavior.severity === 'critical',
            },
            sourcePosition: Position.Left,
            targetPosition: Position.Right,
          })

          edges.push({
            id: `edge-ioc-${iocId}`,
            source: entryId,
            target: iocId,
            style: { stroke: '#f97316', strokeWidth: 2, strokeDasharray: '8,4' },
            markerEnd: { type: MarkerType.ArrowClosed, color: '#f97316', width: 14, height: 14 },
          })

          iocY += 90
        })
      }
    })

    return { initialNodes: nodes, initialEdges: edges }
  }, [analysis])

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)

  const nodeColor = useCallback((node: Node) => {
    switch (node.type) {
      case 'entry': return '#6366f1'
      case 'process': return '#3b82f6'
      case 'network': return '#a855f7'
      case 'file': return '#22c55e'
      case 'url': return '#06b6d4'
      case 'ioc': return '#f97316'
      default: return '#6b7280'
    }
  }, [])

  if (!mounted) return null

  if (initialNodes.length <= 1) {
    return (
      <div className="card bg-gradient-to-br from-dark-600 to-dark-700">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <NetworkIcon />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-purple-400">
            Attack Flow Diagram
          </span>
        </h3>
        <div className="text-gray-400 text-center py-12 bg-dark-600/50 rounded-xl border border-dark-300">
          <div className="text-4xl mb-4">🔍</div>
          No behavioral data available to visualize.
          <br />
          <span className="text-sm text-gray-500">
            Run a dynamic analysis (sandbox) to see the attack flow.
          </span>
        </div>
      </div>
    )
  }

  return (
    <div className="card bg-gradient-to-br from-dark-600 to-dark-700 p-0 overflow-hidden">
      <StyleInjector />

      <div className="p-4 border-b border-dark-300">
        <h3 className="text-lg font-semibold flex items-center gap-2">
          <div className="text-indigo-400"><NetworkIcon /></div>
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-purple-400">
            Attack Flow Diagram
          </span>
          <span className="text-xs text-gray-500 font-normal ml-2 bg-dark-500 px-2 py-1 rounded">
            Interactive - drag & zoom
          </span>
        </h3>

        {/* Legend */}
        <div className="flex flex-wrap gap-3 mt-3 text-xs">
          {[
            { color: 'bg-indigo-500', label: 'Entry Point' },
            { color: 'bg-blue-500', label: 'Process' },
            { color: 'bg-purple-500', label: 'Network' },
            { color: 'bg-red-500', label: 'C2/Malicious' },
            { color: 'bg-green-500', label: 'File' },
            { color: 'bg-cyan-500', label: 'URL' },
            { color: 'bg-orange-500', label: 'IOC' },
          ].map(item => (
            <div key={item.label} className="flex items-center gap-1.5 bg-dark-500/50 px-2 py-1 rounded">
              <div className={`w-2.5 h-2.5 rounded-full ${item.color} shadow-lg`}></div>
              <span className="text-gray-400">{item.label}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="h-[550px] bg-gradient-to-br from-slate-900 via-dark-600 to-slate-900">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.2}
          maxZoom={2}
          defaultViewport={{ x: 0, y: 0, zoom: 0.7 }}
        >
          {/* Gradient definitions for edges */}
          <svg>
            <defs>
              <linearGradient id="gradient-blue" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#6366f1" />
                <stop offset="100%" stopColor="#8b5cf6" />
              </linearGradient>
              <linearGradient id="gradient-cyan" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#06b6d4" />
                <stop offset="100%" stopColor="#22d3ee" />
              </linearGradient>
              <linearGradient id="gradient-red" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#ef4444" />
                <stop offset="100%" stopColor="#f87171" />
              </linearGradient>
            </defs>
          </svg>
          <Background color="#1e293b" gap={24} variant={BackgroundVariant.Dots} />
          <Controls
            className="bg-dark-500/90 border border-dark-300 rounded-lg backdrop-blur-sm"
            showInteractive={false}
          />
          <MiniMap
            nodeColor={nodeColor}
            maskColor="rgba(0,0,0,0.85)"
            className="bg-dark-500/90 border border-dark-300 rounded-lg backdrop-blur-sm"
            pannable
            zoomable
          />
        </ReactFlow>
      </div>
    </div>
  )
}
