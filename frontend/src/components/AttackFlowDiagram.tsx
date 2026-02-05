import { useCallback, useMemo } from 'react'
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
} from 'reactflow'
import 'reactflow/dist/style.css'
import { Terminal, Globe, FileText, AlertTriangle, Server, Shield, Cpu, HardDrive } from 'lucide-react'

// Custom node component for processes
function ProcessNode({ data }: { data: any }) {
  const bgColor = data.suspicious ? 'bg-red-500/20 border-red-500' : 'bg-blue-500/20 border-blue-500'
  const textColor = data.suspicious ? 'text-red-400' : 'text-blue-400'

  return (
    <div className={`px-4 py-3 rounded-lg border-2 ${bgColor} min-w-[140px]`}>
      <div className="flex items-center gap-2">
        <Terminal className={`h-4 w-4 ${textColor}`} />
        <span className={`font-semibold text-sm ${textColor}`}>{data.label}</span>
      </div>
      {data.pid && (
        <div className="text-xs text-gray-400 mt-1">PID: {data.pid}</div>
      )}
      {data.technique && (
        <div className="text-xs text-orange-400 mt-1">{data.technique}</div>
      )}
    </div>
  )
}

// Custom node for network connections
function NetworkNode({ data }: { data: any }) {
  const isC2 = data.isC2 || data.suspicious
  const bgColor = isC2 ? 'bg-red-500/20 border-red-500' : 'bg-purple-500/20 border-purple-500'
  const textColor = isC2 ? 'text-red-400' : 'text-purple-400'

  return (
    <div className={`px-4 py-3 rounded-lg border-2 ${bgColor} min-w-[140px]`}>
      <div className="flex items-center gap-2">
        <Globe className={`h-4 w-4 ${textColor}`} />
        <span className={`font-semibold text-sm ${textColor}`}>
          {data.ip || data.domain || data.label}
        </span>
      </div>
      {data.port && (
        <div className="text-xs text-gray-400 mt-1">Port: {data.port}</div>
      )}
      {data.protocol && (
        <div className="text-xs text-gray-500 mt-1">{data.protocol}</div>
      )}
      {isC2 && (
        <div className="text-xs text-red-400 mt-1 flex items-center gap-1">
          <AlertTriangle className="h-3 w-3" /> C2 Server
        </div>
      )}
    </div>
  )
}

// Custom node for file operations
function FileNode({ data }: { data: any }) {
  const colors: Record<string, string> = {
    created: 'bg-green-500/20 border-green-500 text-green-400',
    modified: 'bg-yellow-500/20 border-yellow-500 text-yellow-400',
    deleted: 'bg-red-500/20 border-red-500 text-red-400',
    dropped: 'bg-orange-500/20 border-orange-500 text-orange-400',
  }
  const colorClass = colors[data.operation] || colors.created

  return (
    <div className={`px-4 py-3 rounded-lg border-2 ${colorClass} min-w-[140px]`}>
      <div className="flex items-center gap-2">
        <FileText className="h-4 w-4" />
        <span className="font-semibold text-sm truncate max-w-[120px]" title={data.label}>
          {data.label}
        </span>
      </div>
      <div className="text-xs text-gray-400 mt-1 capitalize">{data.operation}</div>
    </div>
  )
}

// Custom node for IOCs
function IOCNode({ data }: { data: any }) {
  const isMalicious = data.malicious
  const bgColor = isMalicious ? 'bg-red-500/20 border-red-500' : 'bg-gray-500/20 border-gray-500'
  const textColor = isMalicious ? 'text-red-400' : 'text-gray-400'

  return (
    <div className={`px-4 py-3 rounded-lg border-2 ${bgColor} min-w-[120px]`}>
      <div className="flex items-center gap-2">
        <Shield className={`h-4 w-4 ${textColor}`} />
        <span className={`font-semibold text-sm ${textColor}`}>{data.type}</span>
      </div>
      <div className="text-xs text-gray-300 mt-1 truncate max-w-[100px]" title={data.value}>
        {data.value}
      </div>
      {isMalicious && (
        <div className="text-xs text-red-400 mt-1">Malicious</div>
      )}
    </div>
  )
}

// Entry point node
function EntryNode({ data }: { data: any }) {
  return (
    <div className="px-4 py-3 rounded-lg border-2 bg-primary-500/20 border-primary-500 min-w-[160px]">
      <div className="flex items-center gap-2">
        <Cpu className="h-4 w-4 text-primary-400" />
        <span className="font-semibold text-sm text-primary-400">{data.label}</span>
      </div>
      {data.hash && (
        <div className="text-xs text-gray-400 mt-1 font-mono truncate max-w-[140px]" title={data.hash}>
          {data.hash.substring(0, 16)}...
        </div>
      )}
      {data.type && (
        <div className="text-xs text-gray-500 mt-1">{data.type}</div>
      )}
    </div>
  )
}

// URL redirect node
function URLNode({ data }: { data: any }) {
  const isSuspicious = data.suspicious
  const bgColor = isSuspicious ? 'bg-orange-500/20 border-orange-500' : 'bg-cyan-500/20 border-cyan-500'
  const textColor = isSuspicious ? 'text-orange-400' : 'text-cyan-400'

  return (
    <div className={`px-4 py-3 rounded-lg border-2 ${bgColor} min-w-[180px] max-w-[250px]`}>
      <div className="flex items-center gap-2">
        <Server className={`h-4 w-4 ${textColor}`} />
        <span className={`font-semibold text-sm ${textColor}`}>
          {data.status ? `HTTP ${data.status}` : 'URL'}
        </span>
      </div>
      <div className="text-xs text-gray-300 mt-1 truncate" title={data.url}>
        {data.url}
      </div>
    </div>
  )
}

// Registry node
function RegistryNode({ data }: { data: any }) {
  return (
    <div className="px-4 py-3 rounded-lg border-2 bg-yellow-500/20 border-yellow-500 min-w-[140px]">
      <div className="flex items-center gap-2">
        <HardDrive className="h-4 w-4 text-yellow-400" />
        <span className="font-semibold text-sm text-yellow-400">Registry</span>
      </div>
      <div className="text-xs text-gray-300 mt-1 truncate max-w-[120px]" title={data.key}>
        {data.key}
      </div>
      <div className="text-xs text-gray-500 mt-1 capitalize">{data.operation}</div>
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
  registry: RegistryNode,
}

interface AttackFlowProps {
  analysis: any
}

export default function AttackFlowDiagram({ analysis }: AttackFlowProps) {
  // Build nodes and edges from analysis data
  const { initialNodes, initialEdges } = useMemo(() => {
    const nodes: Node[] = []
    const edges: Edge[] = []
    let nodeId = 0
    let yOffset = 0
    const xSpacing = 250
    const ySpacing = 120

    const getNextId = () => `node-${nodeId++}`

    // Entry point (the analyzed file/URL)
    const entryId = getNextId()
    nodes.push({
      id: entryId,
      type: 'entry',
      position: { x: 400, y: 0 },
      data: {
        label: analysis.filename || analysis.url || 'Sample',
        hash: analysis.fileAnalysis?.hashes?.sha256 || analysis.sha256,
        type: analysis.fileAnalysis?.fileType || analysis.type,
      },
      sourcePosition: Position.Bottom,
      targetPosition: Position.Top,
    })
    yOffset += ySpacing

    // Process tree
    const processTree = analysis.processTree || analysis.process_tree || []
    const processNodes: Record<string, string> = {}

    if (processTree.length > 0) {
      let processX = 100
      processTree.forEach((proc: any, idx: number) => {
        const procId = getNextId()
        processNodes[proc.pid || idx] = procId

        nodes.push({
          id: procId,
          type: 'process',
          position: { x: processX, y: yOffset },
          data: {
            label: proc.name || proc.command?.split(' ')[0] || 'Process',
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
            style: { stroke: '#6366f1' },
            markerEnd: { type: MarkerType.ArrowClosed, color: '#6366f1' },
            label: 'executes',
            labelStyle: { fill: '#9ca3af', fontSize: 10 },
          })
        }

        // Process children
        if (proc.children) {
          proc.children.forEach((child: any, childIdx: number) => {
            const childId = getNextId()
            processNodes[child.pid || `${idx}-${childIdx}`] = childId

            nodes.push({
              id: childId,
              type: 'process',
              position: { x: processX + 50 + childIdx * 180, y: yOffset + ySpacing },
              data: {
                label: child.name || child.command?.split(' ')[0] || 'Child',
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
              style: { stroke: '#3b82f6' },
              markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' },
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
      network.slice(0, 8).forEach((conn: any, idx: number) => {
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

        // Connect to a process or entry
        const sourceNode = Object.values(processNodes)[0] || entryId
        edges.push({
          id: `edge-net-${netId}`,
          source: sourceNode,
          target: netId,
          animated: isC2,
          style: { stroke: isC2 ? '#ef4444' : '#a855f7' },
          markerEnd: { type: MarkerType.ArrowClosed, color: isC2 ? '#ef4444' : '#a855f7' },
          label: isC2 ? 'C2' : 'connects',
          labelStyle: { fill: '#9ca3af', fontSize: 10 },
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
    ].slice(0, 6)

    if (allFiles.length > 0) {
      let fileX = 100
      allFiles.forEach((file: any) => {
        const fileId = getNextId()
        const fileName = file.path.split('/').pop() || file.path.split('\\').pop() || file.path

        nodes.push({
          id: fileId,
          type: 'file',
          position: { x: fileX, y: yOffset },
          data: {
            label: fileName,
            operation: file.operation,
          },
          sourcePosition: Position.Bottom,
          targetPosition: Position.Top,
        })

        // Connect to process or entry
        const sourceNode = Object.values(processNodes)[0] || entryId
        edges.push({
          id: `edge-file-${fileId}`,
          source: sourceNode,
          target: fileId,
          style: { stroke: '#22c55e' },
          markerEnd: { type: MarkerType.ArrowClosed, color: '#22c55e' },
          label: file.operation,
          labelStyle: { fill: '#9ca3af', fontSize: 10 },
        })

        fileX += 200
      })
      yOffset += ySpacing
    }

    // URL redirect chain (for URL analysis)
    const redirectChain = analysis.redirectChain || []
    if (redirectChain.length > 0) {
      let urlX = 100
      let prevUrlId = entryId

      redirectChain.forEach((redirect: any, idx: number) => {
        const urlId = getNextId()

        nodes.push({
          id: urlId,
          type: 'url',
          position: { x: urlX, y: yOffset },
          data: {
            url: redirect.redirectTo || redirect.url,
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
          style: { stroke: '#06b6d4' },
          markerEnd: { type: MarkerType.ArrowClosed, color: '#06b6d4' },
          label: `${redirect.statusCode || 'redirect'}`,
          labelStyle: { fill: '#9ca3af', fontSize: 10 },
        })

        prevUrlId = urlId
        urlX += 280
      })
      yOffset += ySpacing
    }

    // Threat map behaviors as IOC nodes
    const threatMap = analysis.threatMap || analysis.threat_map || {}
    let iocX = 600
    let iocY = 100

    Object.entries(threatMap).forEach(([category, behaviors]: [string, any]) => {
      if (behaviors && behaviors.length > 0) {
        behaviors.slice(0, 2).forEach((behavior: any) => {
          const iocId = getNextId()
          nodes.push({
            id: iocId,
            type: 'ioc',
            position: { x: iocX, y: iocY },
            data: {
              type: behavior.technique || category,
              value: behavior.behavior || behavior.api,
              malicious: behavior.severity === 'high' || behavior.severity === 'critical',
            },
            sourcePosition: Position.Left,
            targetPosition: Position.Right,
          })

          // Connect to entry
          edges.push({
            id: `edge-ioc-${iocId}`,
            source: entryId,
            target: iocId,
            style: { stroke: '#f97316', strokeDasharray: '5,5' },
            markerEnd: { type: MarkerType.ArrowClosed, color: '#f97316' },
          })

          iocY += 80
        })
      }
    })

    return { initialNodes: nodes, initialEdges: edges }
  }, [analysis])

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)

  // Custom minimap node color
  const nodeColor = useCallback((node: Node) => {
    switch (node.type) {
      case 'entry': return '#6366f1'
      case 'process': return '#3b82f6'
      case 'network': return '#a855f7'
      case 'file': return '#22c55e'
      case 'url': return '#06b6d4'
      case 'ioc': return '#f97316'
      case 'registry': return '#eab308'
      default: return '#6b7280'
    }
  }, [])

  if (initialNodes.length <= 1) {
    return (
      <div className="card">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Globe className="h-5 w-5 text-primary-500" />
          Attack Flow Diagram
        </h3>
        <div className="text-gray-400 text-center py-8">
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
    <div className="card">
      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <Globe className="h-5 w-5 text-primary-500" />
        Attack Flow Diagram
        <span className="text-xs text-gray-500 font-normal ml-2">Interactive - drag to explore</span>
      </h3>

      {/* Legend */}
      <div className="flex flex-wrap gap-4 mb-4 text-xs">
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-primary-500"></div>
          <span className="text-gray-400">Entry Point</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-blue-500"></div>
          <span className="text-gray-400">Process</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-purple-500"></div>
          <span className="text-gray-400">Network</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-red-500"></div>
          <span className="text-gray-400">C2/Malicious</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-green-500"></div>
          <span className="text-gray-400">File</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-orange-500"></div>
          <span className="text-gray-400">IOC/Technique</span>
        </div>
      </div>

      <div className="h-[500px] bg-dark-600 rounded-lg border border-dark-300">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.3}
          maxZoom={2}
          defaultViewport={{ x: 0, y: 0, zoom: 0.8 }}
        >
          <Background color="#374151" gap={20} />
          <Controls className="bg-dark-500 border-dark-300 rounded-lg" />
          <MiniMap
            nodeColor={nodeColor}
            maskColor="rgba(0,0,0,0.8)"
            className="bg-dark-500 border-dark-300 rounded-lg"
          />
        </ReactFlow>
      </div>
    </div>
  )
}
