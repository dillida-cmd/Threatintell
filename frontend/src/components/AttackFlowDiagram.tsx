import { useMemo } from 'react'
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
  Handle,
} from 'reactflow'
import 'reactflow/dist/style.css'

// Custom styles for animation
const StyleInjector = () => {
  return (
    <style>{`
      @keyframes pulse {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.85; transform: scale(1.02); }
      }
      @keyframes flowLine {
        0% { stroke-dashoffset: 24; }
        100% { stroke-dashoffset: 0; }
      }
      .attack-flow-node {
        transition: all 0.3s ease;
      }
      .attack-flow-node:hover {
        transform: scale(1.05);
        z-index: 100;
      }
      .react-flow__edge-path {
        stroke-dasharray: 8 4;
        animation: flowLine 1s linear infinite;
      }
    `}</style>
  )
}

interface FlowNode {
  id: string
  type: string
  label: string
  description?: string
  data?: any
  step?: number
  severity?: string
  isCenter?: boolean  // For radial layout - marks the center node
}

interface FlowEdge {
  source: string
  target: string
  label?: string
  type?: string
  style?: string  // 'dotted' for dotted lines
}

interface AttackFlow {
  nodes: FlowNode[]
  edges: FlowEdge[]
  summary?: any
  timeline?: any[]
  layoutType?: string  // 'radial' for VirusTotal-style graph
  centerNode?: string  // ID of center node for radial layout
}

interface AttackFlowDiagramProps {
  analysis?: any
  attackFlow?: AttackFlow
}

// Severity colors
const severityColors: Record<string, { bg: string; border: string; text: string; glow: string }> = {
  critical: { bg: '#450a0a', border: '#dc2626', text: '#fecaca', glow: 'rgba(220, 38, 38, 0.4)' },
  high: { bg: '#431407', border: '#ea580c', text: '#fed7aa', glow: 'rgba(234, 88, 12, 0.4)' },
  warning: { bg: '#422006', border: '#ca8a04', text: '#fef08a', glow: 'rgba(202, 138, 4, 0.3)' },
  medium: { bg: '#422006', border: '#ca8a04', text: '#fef08a', glow: 'rgba(202, 138, 4, 0.3)' },
  low: { bg: '#052e16', border: '#16a34a', text: '#bbf7d0', glow: 'rgba(22, 163, 74, 0.3)' },
  info: { bg: '#172554', border: '#2563eb', text: '#bfdbfe', glow: 'rgba(37, 99, 235, 0.3)' },
}

// Node type icons
const nodeIcons: Record<string, string> = {
  entry: '👆',
  dns: '🔍',
  http: '🌐',
  redirect: '↪️',
  page: '📄',
  render: '🖼️',
  assessment: '📊',
  file: '📁',
  analysis: '🔬',
  execution: '▶️',
  process: '⚙️',
  network: '📡',
  c2: '💀',
  threat: '⚠️',
  ioc: '🎯',
  evasion: '🛡️',
  dll: '📦',
  memory: '🧠',
  shellcode: '💉',
  registry: '🔑',
}

// Custom node component
function FlowNodeComponent({ data }: { data: any }) {
  const colors = severityColors[data.severity] || severityColors.info
  const icon = nodeIcons[data.nodeType] || '📌'
  const isCritical = data.severity === 'critical' || data.severity === 'high'

  // Radial layout - center node (file) is larger, others are circular badges
  if (data.isCenter) {
    // Center node - large prominent display with handles on all sides
    return (
      <div
        className="attack-flow-node"
        style={{
          background: `radial-gradient(circle, ${colors.bg} 0%, #0f172a 100%)`,
          border: `3px solid ${colors.border}`,
          borderRadius: '50%',
          width: '120px',
          height: '120px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: `0 0 30px ${colors.glow}, 0 0 60px ${colors.glow}55`,
          animation: 'pulse 2s ease-in-out infinite',
          position: 'relative',
        }}
      >
        {/* Handles for edges - invisible but functional */}
        <Handle type="source" position={Position.Top} style={{ opacity: 0 }} />
        <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
        <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
        <Handle type="source" position={Position.Left} style={{ opacity: 0 }} />
        <span style={{ fontSize: '28px', marginBottom: '4px' }}>{icon}</span>
        <span style={{
          color: colors.text,
          fontWeight: 700,
          fontSize: '11px',
          textAlign: 'center',
          maxWidth: '100px',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}>
          {data.label}
        </span>
        <span style={{ color: '#6b7280', fontSize: '9px', marginTop: '2px' }}>
          {data.description}
        </span>
      </div>
    )
  }

  // Radial layout - peripheral nodes (IPs, DLLs, APIs) as labeled nodes
  if (data.nodeType === 'ip' || data.nodeType === 'dll' || data.nodeType === 'api' || data.nodeType === 'domain') {
    return (
      <div
        className="attack-flow-node"
        style={{
          background: `linear-gradient(135deg, ${colors.bg} 0%, #0f172a 100%)`,
          border: `2px solid ${colors.border}`,
          borderRadius: '12px',
          padding: '12px 16px',
          minWidth: '180px',
          maxWidth: '280px',
          boxShadow: `0 4px 15px ${colors.glow}`,
          animation: isCritical ? 'pulse 2s ease-in-out infinite' : undefined,
          position: 'relative',
        }}
      >
        {/* Handles for edges - invisible but functional */}
        <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
        <Handle type="target" position={Position.Right} style={{ opacity: 0 }} />
        <Handle type="target" position={Position.Bottom} style={{ opacity: 0 }} />
        <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />

        {/* Header with icon and type */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
          <span style={{ fontSize: '20px' }}>{icon}</span>
          <span style={{
            color: colors.text,
            fontWeight: 700,
            fontSize: '13px',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
          }}>
            {data.nodeType === 'ip' ? 'C2 Server' :
             data.nodeType === 'dll' ? 'DLL' :
             data.nodeType === 'api' ? 'API Call' : 'Domain'}
          </span>
        </div>

        {/* Main value - IP:port, DLL name, API name */}
        <div style={{
          color: '#fff',
          fontSize: '12px',
          fontFamily: 'monospace',
          fontWeight: 600,
          marginBottom: '4px',
          wordBreak: 'break-all',
        }}>
          {data.nodeType === 'ip' ? `${data.ip || ''}:${data.port || ''}` :
           data.nodeType === 'api' ? data.api || data.label :
           data.dll || data.label}
        </div>

        {/* Secondary info - path for DLLs, source DLL for APIs */}
        {data.nodeType === 'dll' && data.path && (
          <div style={{
            color: '#6ee7b7',
            fontSize: '10px',
            fontFamily: 'monospace',
            wordBreak: 'break-all',
            lineHeight: 1.3,
          }}>
            {data.path}
          </div>
        )}
        {data.nodeType === 'api' && data.dll && (
          <div style={{
            color: '#fbbf24',
            fontSize: '10px',
            fontFamily: 'monospace',
          }}>
            from {data.dll}
          </div>
        )}
      </div>
    )
  }

  // Original rectangular style for sequential flows
  return (
    <div
      className="attack-flow-node"
      style={{
        background: `linear-gradient(135deg, ${colors.bg} 0%, ${colors.bg}dd 100%)`,
        border: `2px solid ${colors.border}`,
        borderRadius: '12px',
        padding: '14px 18px',
        minWidth: '180px',
        maxWidth: '240px',
        boxShadow: `0 4px 20px ${colors.glow}, inset 0 1px 0 rgba(255,255,255,0.1)`,
        position: 'relative',
        animation: isCritical ? 'pulse 2s ease-in-out infinite' : undefined,
      }}
    >
      {/* Handles for edges */}
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />

      {/* Step number badge */}
      {data.step && (
        <div style={{
          position: 'absolute',
          top: '-12px',
          left: '-12px',
          background: `linear-gradient(135deg, ${colors.border} 0%, ${colors.border}cc 100%)`,
          color: '#fff',
          borderRadius: '50%',
          width: '26px',
          height: '26px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '12px',
          fontWeight: 700,
          boxShadow: `0 2px 8px ${colors.glow}`,
          border: '2px solid rgba(255,255,255,0.2)',
        }}>
          {data.step}
        </div>
      )}

      {/* Icon and label */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
        <span style={{ fontSize: '20px', filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.3))' }}>{icon}</span>
        <span style={{
          color: colors.text,
          fontWeight: 600,
          fontSize: '14px',
          lineHeight: 1.2,
        }}>
          {data.label}
        </span>
      </div>

      {/* Description */}
      <div style={{
        color: '#9ca3af',
        fontSize: '11px',
        marginTop: '4px',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      }}>
        {data.description}
      </div>
    </div>
  )
}

const nodeTypes = {
  flowNode: FlowNodeComponent,
}

// Generate flow from analysis when no AI flow is available
function generateFallbackFlow(analysis: any): AttackFlow | null {
  if (!analysis) return null

  const nodes: FlowNode[] = []
  const edges: FlowEdge[] = []
  let step = 1

  // Entry point
  nodes.push({
    id: 'entry',
    type: 'entry',
    label: 'User Action',
    description: analysis.url ? 'Click URL' : 'Open File',
    data: {},
    step: step++,
    severity: 'info'
  })

  let prevId = 'entry'

  // URL analysis
  if (analysis.url) {
    // DNS
    nodes.push({
      id: 'dns',
      type: 'dns',
      label: 'DNS Lookup',
      description: new URL(analysis.url).hostname,
      data: {},
      step: step++,
      severity: 'info'
    })
    edges.push({ source: prevId, target: 'dns', label: 'Resolve', type: 'request' })
    prevId = 'dns'

    // HTTP Request
    nodes.push({
      id: 'http',
      type: 'http',
      label: 'HTTP Request',
      description: 'GET request sent',
      data: {},
      step: step++,
      severity: 'info'
    })
    edges.push({ source: prevId, target: 'http', label: 'Connect', type: 'request' })
    prevId = 'http'

    // Redirects
    const redirectChain = analysis.redirectChain || []
    redirectChain.forEach((redirect: any, i: number) => {
      const url = typeof redirect === 'string' ? redirect : redirect.url
      const nodeId = `redirect_${i}`
      nodes.push({
        id: nodeId,
        type: 'redirect',
        label: `Redirect ${i + 1}`,
        description: new URL(url).hostname,
        data: { url },
        step: step++,
        severity: 'warning'
      })
      edges.push({ source: prevId, target: nodeId, label: '302', type: 'redirect' })
      prevId = nodeId
    })

    // Final page
    if (analysis.finalUrl || redirectChain.length > 0) {
      nodes.push({
        id: 'final',
        type: 'page',
        label: 'Page Loaded',
        description: analysis.finalUrl ? new URL(analysis.finalUrl).hostname : 'Response received',
        data: {},
        step: step++,
        severity: 'info'
      })
      edges.push({ source: prevId, target: 'final', label: '200 OK', type: 'response' })
      prevId = 'final'
    }

    // Screenshot
    if (analysis.screenshots?.length > 0) {
      nodes.push({
        id: 'screenshot',
        type: 'render',
        label: 'Page Captured',
        description: `${analysis.screenshots.length} screenshot(s)`,
        data: {},
        step: step++,
        severity: 'info'
      })
      edges.push({ source: prevId, target: 'screenshot', label: 'Render', type: 'action' })
      prevId = 'screenshot'
    }
  }

  // Risk assessment
  const riskScore = analysis.riskScore || 0
  nodes.push({
    id: 'risk',
    type: 'assessment',
    label: `Risk: ${riskScore}/100`,
    description: analysis.riskLevel || (riskScore >= 70 ? 'Critical' : riskScore >= 50 ? 'High' : riskScore >= 30 ? 'Medium' : 'Low'),
    data: {},
    step: step++,
    severity: riskScore >= 70 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 30 ? 'medium' : 'low'
  })
  edges.push({ source: prevId, target: 'risk', label: 'Analyze', type: 'assessment' })

  return {
    nodes,
    edges,
    summary: {
      totalSteps: nodes.length,
      redirects: (analysis.redirectChain || []).length,
    },
    timeline: nodes.map(n => ({ step: n.step, label: n.label, type: n.type }))
  }
}

export default function AttackFlowDiagram({ analysis, attackFlow }: AttackFlowDiagramProps) {
  // Use provided attackFlow or generate fallback
  const flowData = useMemo(() => {
    if (attackFlow && attackFlow.nodes && attackFlow.nodes.length > 0) {
      return attackFlow
    }
    return generateFallbackFlow(analysis)
  }, [analysis, attackFlow])

  // Convert to ReactFlow format
  const { initialNodes, initialEdges } = useMemo(() => {
    if (!flowData?.nodes) {
      return { initialNodes: [], initialEdges: [] }
    }

    const isRadialLayout = flowData.layoutType === 'radial'
    const centerX = 450
    const centerY = 280
    const radius = 250

    // Position nodes
    const reactFlowNodes: Node[] = flowData.nodes.map((node, index) => {
      let x: number, y: number

      if (isRadialLayout) {
        // Radial layout - center node in middle, others around it
        if (node.isCenter) {
          x = centerX
          y = centerY
        } else {
          // Position non-center nodes in a circle
          const nonCenterNodes = flowData.nodes.filter(n => !n.isCenter)
          const nodeIndex = nonCenterNodes.findIndex(n => n.id === node.id)
          const totalNonCenter = nonCenterNodes.length
          const angle = (nodeIndex / totalNonCenter) * 2 * Math.PI - Math.PI / 2
          x = centerX + radius * Math.cos(angle)
          y = centerY + radius * Math.sin(angle)
        }
      } else {
        // Original horizontal layout
        const horizontalGap = 300
        const verticalGap = 100
        const row = Math.floor(index / 4)
        const col = index % 4
        const isEvenRow = row % 2 === 0
        x = isEvenRow ? col * horizontalGap : (3 - col) * horizontalGap
        y = row * verticalGap * 1.5
      }

      return {
        id: node.id,
        type: 'flowNode',
        position: { x, y },
        data: {
          label: node.label,
          description: node.description,
          severity: node.severity,
          nodeType: node.type,
          step: node.step,
          isCenter: node.isCenter,
          ...node.data
        },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
      }
    })

    const reactFlowEdges: Edge[] = flowData.edges.map((edge, index) => {
      // Color based on relationship type
      const edgeColor = edge.type === 'network' || edge.type === 'c2' ? '#dc2626' :
                        edge.type === 'api' ? '#f59e0b' :
                        edge.type === 'library' ? '#3b82f6' :
                        edge.type === 'dns' ? '#8b5cf6' : '#6b7280'

      return {
        id: `e_${index}`,
        source: edge.source,
        target: edge.target,
        label: edge.label,
        type: isRadialLayout ? 'straight' : 'smoothstep',  // Straight lines for radial layout
        animated: edge.type === 'network' || edge.type === 'c2',
        style: { stroke: edgeColor, strokeWidth: 2, strokeDasharray: '5 5' },  // Always dotted
        labelStyle: { fill: '#d1d5db', fontSize: 10, fontWeight: 500 },
        labelBgStyle: { fill: '#1f2937', fillOpacity: 0.9 },
        markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor },
      }
    })

    return { initialNodes: reactFlowNodes, initialEdges: reactFlowEdges }
  }, [flowData])

  // Create a key that changes when flowData changes to force re-render
  const flowKey = useMemo(() => {
    return flowData?.nodes?.map(n => n.id).join('-') || 'empty'
  }, [flowData])

  const [nodes, , onNodesChange] = useNodesState(initialNodes)
  const [edges, , onEdgesChange] = useEdgesState(initialEdges)

  if (!flowData || flowData.nodes.length === 0) {
    return (
      <div className="card">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <span>🔄</span> Attack Flow Diagram
        </h3>
        <div className="text-gray-400 text-center py-8">
          No flow data available
        </div>
      </div>
    )
  }

  return (
    <div className="card">
      <StyleInjector />

      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold flex items-center gap-2">
          <span>🔄</span> Attack Flow Diagram
        </h3>
        <div className="flex gap-2 text-xs">
          {flowData.summary?.totalSteps && (
            <span className="badge badge-info">{flowData.summary.totalSteps} Steps</span>
          )}
          {flowData.summary?.redirects > 0 && (
            <span className="badge badge-warning">{flowData.summary.redirects} Redirects</span>
          )}
          {flowData.summary?.networkConnections > 0 && (
            <span className="badge badge-danger">{flowData.summary.networkConnections} C2</span>
          )}
        </div>
      </div>

      {/* Timeline */}
      {flowData.timeline && flowData.timeline.length > 0 && (
        <div className="mb-4 p-3 bg-dark-500 rounded-lg overflow-x-auto">
          <div className="text-xs text-gray-400 mb-2">Sequence:</div>
          <div className="flex items-center gap-1 min-w-max">
            {flowData.timeline.map((item, i) => (
              <div key={i} className="flex items-center">
                <div className="flex items-center gap-1 px-2 py-1 bg-dark-400 rounded text-xs">
                  <span className="w-5 h-5 rounded-full bg-primary-600 text-white flex items-center justify-center text-[10px] font-bold">
                    {item.step}
                  </span>
                  <span className="text-gray-300 whitespace-nowrap">{item.label}</span>
                </div>
                {i < (flowData.timeline?.length ?? 0) - 1 && (
                  <span className="text-primary-500 mx-1">→</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Flow Diagram */}
      <div style={{ height: '550px', background: '#0c1222', borderRadius: '8px', border: '1px solid #1e293b' }}>
        <ReactFlow
          key={flowKey}
          nodes={initialNodes}
          edges={initialEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.3 }}
          minZoom={0.3}
          maxZoom={2}
          attributionPosition="bottom-left"
        >
          <Background color="#1e293b" gap={24} />
          <Controls style={{ background: '#1f2937', borderRadius: '8px', border: '1px solid #374151' }} />
          <MiniMap
            nodeColor={(node) => severityColors[node.data?.severity]?.border || '#2563eb'}
            maskColor="#0c122290"
            style={{ background: '#1f2937', borderRadius: '8px', border: '1px solid #374151' }}
          />
        </ReactFlow>
      </div>

      {/* Legend */}
      <div className="mt-4 flex flex-wrap gap-4 text-xs">
        {Object.entries(severityColors).slice(0, 4).map(([key, colors]) => (
          <div key={key} className="flex items-center gap-2">
            <div className="w-3 h-3 rounded" style={{ background: colors.border }}></div>
            <span className="text-gray-400 capitalize">{key}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
