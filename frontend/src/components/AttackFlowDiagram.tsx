import { useMemo, useState, useCallback } from 'react'
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
import dagre from 'dagre'

// Layout type
type LayoutType = 'sequential' | 'radial' | 'hierarchical' | 'force'

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
      @keyframes slideIn {
        0% { transform: translateX(100%); opacity: 0; }
        100% { transform: translateX(0); opacity: 1; }
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
      .node-detail-panel {
        animation: slideIn 0.3s ease-out;
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
  isCenter?: boolean
}

interface FlowEdge {
  source: string
  target: string
  label?: string
  type?: string
  style?: string
}

interface AttackFlow {
  nodes: FlowNode[]
  edges: FlowEdge[]
  summary?: any
  timeline?: any[]
  layoutType?: string
  centerNode?: string
  expandableNodes?: string[]
  nodeDetails?: Record<string, any>
  correlationEdges?: FlowEdge[]
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
  cluster: '📂',
  ip: '📡',
  domain: '🔍',
  api: '⚙️',
}

// ===== LAYOUT FUNCTIONS =====

function calculateSequentialLayout(nodes: FlowNode[]): Record<string, { x: number; y: number }> {
  const positions: Record<string, { x: number; y: number }> = {}
  const horizontalGap = 300
  const verticalGap = 100
  nodes.forEach((node, index) => {
    const row = Math.floor(index / 4)
    const col = index % 4
    const isEvenRow = row % 2 === 0
    positions[node.id] = {
      x: isEvenRow ? col * horizontalGap : (3 - col) * horizontalGap,
      y: row * verticalGap * 1.5,
    }
  })
  return positions
}

function calculateRadialLayout(
  nodes: FlowNode[],
  centerNodeId?: string
): Record<string, { x: number; y: number }> {
  const positions: Record<string, { x: number; y: number }> = {}
  const centerX = 450
  const centerY = 280
  const radius = 250

  nodes.forEach((node) => {
    if (node.isCenter || node.id === centerNodeId) {
      positions[node.id] = { x: centerX, y: centerY }
    } else {
      const nonCenterNodes = nodes.filter((n) => !n.isCenter && n.id !== centerNodeId)
      const nodeIndex = nonCenterNodes.findIndex((n) => n.id === node.id)
      const totalNonCenter = nonCenterNodes.length
      const angle = (nodeIndex / totalNonCenter) * 2 * Math.PI - Math.PI / 2
      positions[node.id] = {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
      }
    }
  })
  return positions
}

function calculateHierarchicalLayout(
  nodes: FlowNode[],
  edges: FlowEdge[]
): Record<string, { x: number; y: number }> {
  const g = new dagre.graphlib.Graph()
  g.setGraph({ rankdir: 'TB', nodesep: 80, ranksep: 120 })
  g.setDefaultEdgeLabel(() => ({}))

  nodes.forEach((node) => {
    g.setNode(node.id, { width: 220, height: 80 })
  })
  edges.forEach((edge) => {
    g.setEdge(edge.source, edge.target)
  })

  dagre.layout(g)

  const positions: Record<string, { x: number; y: number }> = {}
  nodes.forEach((node) => {
    const dagreNode = g.node(node.id)
    if (dagreNode) {
      positions[node.id] = {
        x: dagreNode.x - 110,
        y: dagreNode.y - 40,
      }
    }
  })
  return positions
}

function calculateForceLayout(
  nodes: FlowNode[],
  edges: FlowEdge[]
): Record<string, { x: number; y: number }> {
  // Fruchterman-Reingold force-directed layout
  const positions: Record<string, { x: number; y: number }> = {}
  const width = 900
  const height = 560
  const iterations = 100
  const area = width * height
  const k = Math.sqrt(area / Math.max(nodes.length, 1))

  // Initialize positions in a circle
  nodes.forEach((node, i) => {
    const angle = (i / nodes.length) * 2 * Math.PI
    positions[node.id] = {
      x: width / 2 + (width / 3) * Math.cos(angle),
      y: height / 2 + (height / 3) * Math.sin(angle),
    }
  })

  // Pin center node
  const centerNode = nodes.find((n) => n.isCenter)
  if (centerNode) {
    positions[centerNode.id] = { x: width / 2, y: height / 2 }
  }

  // Build adjacency for quick lookup
  const edgeSet = new Set(edges.map((e) => `${e.source}-${e.target}`))
  const hasEdge = (a: string, b: string) => edgeSet.has(`${a}-${b}`) || edgeSet.has(`${b}-${a}`)

  for (let iter = 0; iter < iterations; iter++) {
    const temp = (1 - iter / iterations) * 10 // cooling
    const displacements: Record<string, { dx: number; dy: number }> = {}
    nodes.forEach((n) => (displacements[n.id] = { dx: 0, dy: 0 }))

    // Repulsive forces
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i].id
        const b = nodes[j].id
        let dx = positions[a].x - positions[b].x
        let dy = positions[a].y - positions[b].y
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1)
        const force = (k * k) / dist
        const fx = (dx / dist) * force
        const fy = (dy / dist) * force
        displacements[a].dx += fx
        displacements[a].dy += fy
        displacements[b].dx -= fx
        displacements[b].dy -= fy
      }
    }

    // Attractive forces (edges)
    edges.forEach((edge) => {
      const a = edge.source
      const b = edge.target
      if (!positions[a] || !positions[b]) return
      let dx = positions[a].x - positions[b].x
      let dy = positions[a].y - positions[b].y
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1)
      const force = (dist * dist) / k
      const fx = (dx / dist) * force
      const fy = (dy / dist) * force
      displacements[a].dx -= fx
      displacements[a].dy -= fy
      displacements[b].dx += fx
      displacements[b].dy += fy
    })

    // Apply displacements with cooling
    nodes.forEach((node) => {
      if (node.isCenter || node.id === centerNode?.id) return // pin center
      const d = displacements[node.id]
      const dist = Math.max(Math.sqrt(d.dx * d.dx + d.dy * d.dy), 1)
      const cappedDist = Math.min(dist, temp * 10)
      positions[node.id].x += (d.dx / dist) * cappedDist
      positions[node.id].y += (d.dy / dist) * cappedDist
      // Keep within bounds
      positions[node.id].x = Math.max(50, Math.min(width - 50, positions[node.id].x))
      positions[node.id].y = Math.max(50, Math.min(height - 50, positions[node.id].y))
    })
  }

  return positions
}

// ===== NODE DETAIL PANEL =====

function NodeDetailPanel({
  node,
  flowData,
  onClose,
}: {
  node: Node
  flowData: AttackFlow
  onClose: () => void
}) {
  const data = node.data
  const colors = severityColors[data.severity] || severityColors.info
  const icon = nodeIcons[data.nodeType] || '📌'

  // Get details from nodeDetails if available
  const details = flowData.nodeDetails?.[node.id] || data

  // Find connected edges
  const connectedEdges = flowData.edges.filter(
    (e) => e.source === node.id || e.target === node.id
  )
  const correlationEdges = (flowData.correlationEdges || []).filter(
    (e) => e.source === node.id || e.target === node.id
  )

  // Find connected node labels
  const getNodeLabel = (nodeId: string) => {
    const n = flowData.nodes.find((n) => n.id === nodeId)
    return n?.label || nodeId
  }

  return (
    <div
      className="node-detail-panel"
      style={{
        position: 'absolute',
        top: 0,
        right: 0,
        width: '320px',
        height: '100%',
        background: 'linear-gradient(180deg, #1a1f2e 0%, #0f1420 100%)',
        borderLeft: `2px solid ${colors.border}`,
        padding: '16px',
        overflowY: 'auto',
        zIndex: 1000,
      }}
    >
      {/* Close button */}
      <button
        onClick={onClose}
        style={{
          position: 'absolute',
          top: '12px',
          right: '12px',
          background: 'none',
          border: '1px solid #374151',
          borderRadius: '4px',
          color: '#9ca3af',
          cursor: 'pointer',
          padding: '4px 8px',
          fontSize: '12px',
        }}
      >
        ✕
      </button>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
        <span style={{ fontSize: '28px' }}>{icon}</span>
        <div>
          <div style={{ color: '#fff', fontWeight: 700, fontSize: '15px' }}>{data.label}</div>
          <div style={{ color: '#9ca3af', fontSize: '11px', textTransform: 'uppercase' }}>
            {data.nodeType}
          </div>
        </div>
      </div>

      {/* Severity badge */}
      <div
        style={{
          display: 'inline-block',
          padding: '3px 10px',
          borderRadius: '12px',
          background: colors.bg,
          border: `1px solid ${colors.border}`,
          color: colors.text,
          fontSize: '11px',
          fontWeight: 600,
          marginBottom: '16px',
          textTransform: 'uppercase',
        }}
      >
        {data.severity || 'info'}
      </div>

      {/* Description */}
      {data.description && (
        <div style={{ color: '#d1d5db', fontSize: '12px', marginBottom: '16px' }}>
          {data.description}
        </div>
      )}

      {/* Type-specific detail sections */}
      <div
        style={{
          background: '#111827',
          borderRadius: '8px',
          padding: '12px',
          marginBottom: '12px',
          border: '1px solid #1e293b',
        }}
      >
        <div
          style={{
            color: '#6b7280',
            fontSize: '10px',
            textTransform: 'uppercase',
            marginBottom: '8px',
            fontWeight: 600,
          }}
        >
          Details
        </div>

        {/* IP details */}
        {data.nodeType === 'ip' && (
          <div style={{ fontSize: '12px', color: '#d1d5db' }}>
            {details.ip && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>IP:</span>{' '}
                <span style={{ fontFamily: 'monospace' }}>{details.ip}</span>
              </div>
            )}
            {details.port && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Port:</span> {details.port}
              </div>
            )}
            {details.country && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Country:</span> {details.country}
              </div>
            )}
            {details.isp && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>ISP:</span> {details.isp}
              </div>
            )}
            {details.asn && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>ASN:</span> {details.asn}
              </div>
            )}
          </div>
        )}

        {/* Domain details */}
        {data.nodeType === 'domain' && (
          <div style={{ fontSize: '12px', color: '#d1d5db' }}>
            {details.domain && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Domain:</span>{' '}
                <span style={{ fontFamily: 'monospace' }}>{details.domain}</span>
              </div>
            )}
            {details.registrar && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Registrar:</span> {details.registrar}
              </div>
            )}
            {details.dns && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>DNS:</span> {details.dns}
              </div>
            )}
          </div>
        )}

        {/* DLL details */}
        {data.nodeType === 'dll' && (
          <div style={{ fontSize: '12px', color: '#d1d5db' }}>
            {details.dll && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>DLL:</span>{' '}
                <span style={{ fontFamily: 'monospace' }}>{details.dll}</span>
              </div>
            )}
            {details.path && (
              <div style={{ marginBottom: '4px', wordBreak: 'break-all' }}>
                <span style={{ color: '#6b7280' }}>Path:</span>{' '}
                <span style={{ fontFamily: 'monospace', color: '#6ee7b7' }}>{details.path}</span>
              </div>
            )}
            {details.mitre && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>MITRE:</span>{' '}
                <span style={{ color: '#f59e0b' }}>
                  {details.mitre.id} - {details.mitre.name}
                </span>
              </div>
            )}
          </div>
        )}

        {/* API details */}
        {data.nodeType === 'api' && (
          <div style={{ fontSize: '12px', color: '#d1d5db' }}>
            {(details.api || data.api) && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Function:</span>{' '}
                <span style={{ fontFamily: 'monospace' }}>{details.api || data.api}</span>
              </div>
            )}
            {(details.dll || data.dll) && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Source DLL:</span>{' '}
                <span style={{ fontFamily: 'monospace', color: '#fbbf24' }}>
                  {details.dll || data.dll}
                </span>
              </div>
            )}
            {details.mitre && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>MITRE:</span>{' '}
                <span style={{ color: '#f59e0b' }}>
                  {details.mitre.id} - {details.mitre.name}
                </span>
              </div>
            )}
          </div>
        )}

        {/* DNS details */}
        {data.nodeType === 'dns' && (
          <div style={{ fontSize: '12px', color: '#d1d5db' }}>
            {details.domain && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Domain:</span>{' '}
                <span style={{ fontFamily: 'monospace' }}>{details.domain}</span>
              </div>
            )}
            {details.ips && details.ips.length > 0 && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Resolves to:</span>{' '}
                <span style={{ fontFamily: 'monospace' }}>{details.ips.join(', ')}</span>
              </div>
            )}
          </div>
        )}

        {/* HTTP details */}
        {data.nodeType === 'http' && (
          <div style={{ fontSize: '12px', color: '#d1d5db' }}>
            {details.method && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Method:</span> {details.method}
              </div>
            )}
            {details.url && (
              <div style={{ marginBottom: '4px', wordBreak: 'break-all' }}>
                <span style={{ color: '#6b7280' }}>URL:</span>{' '}
                <span style={{ fontFamily: 'monospace', fontSize: '11px' }}>{details.url}</span>
              </div>
            )}
          </div>
        )}

        {/* Redirect details */}
        {data.nodeType === 'redirect' && (
          <div style={{ fontSize: '12px', color: '#d1d5db' }}>
            {details.statusCode && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Status:</span> {details.statusCode}
              </div>
            )}
            {details.url && (
              <div style={{ marginBottom: '4px', wordBreak: 'break-all' }}>
                <span style={{ color: '#6b7280' }}>Target:</span>{' '}
                <span style={{ fontFamily: 'monospace', fontSize: '11px' }}>{details.url}</span>
              </div>
            )}
            {details.crossDomain && (
              <div style={{ color: '#f59e0b', marginBottom: '4px' }}>Cross-domain redirect</div>
            )}
          </div>
        )}

        {/* Assessment details */}
        {data.nodeType === 'assessment' && (
          <div style={{ fontSize: '12px', color: '#d1d5db' }}>
            {details.score !== undefined && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Score:</span> {details.score}/100
              </div>
            )}
            {details.level && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Level:</span>{' '}
                <span style={{ textTransform: 'uppercase' }}>{details.level}</span>
              </div>
            )}
          </div>
        )}

        {/* File details */}
        {data.nodeType === 'file' && (
          <div style={{ fontSize: '12px', color: '#d1d5db' }}>
            {details.filename && (
              <div style={{ marginBottom: '4px', wordBreak: 'break-all' }}>
                <span style={{ color: '#6b7280' }}>File:</span>{' '}
                <span style={{ fontFamily: 'monospace' }}>{details.filename}</span>
              </div>
            )}
            {details.hash && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Hash:</span>{' '}
                <span style={{ fontFamily: 'monospace' }}>{details.hash}</span>
              </div>
            )}
            {details.fileType && (
              <div style={{ marginBottom: '4px' }}>
                <span style={{ color: '#6b7280' }}>Type:</span> {details.fileType}
              </div>
            )}
          </div>
        )}

        {/* Generic fallback for any data keys */}
        {!['ip', 'domain', 'dll', 'api', 'dns', 'http', 'redirect', 'assessment', 'file'].includes(
          data.nodeType
        ) && (
          <div style={{ fontSize: '12px', color: '#d1d5db' }}>
            {Object.entries(details)
              .filter(
                ([k]) =>
                  !['label', 'description', 'severity', 'nodeType', 'step', 'isCenter'].includes(k)
              )
              .slice(0, 6)
              .map(([key, value]) => (
                <div key={key} style={{ marginBottom: '4px' }}>
                  <span style={{ color: '#6b7280' }}>{key}:</span>{' '}
                  {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                </div>
              ))}
          </div>
        )}
      </div>

      {/* Connected entities */}
      {(connectedEdges.length > 0 || correlationEdges.length > 0) && (
        <div
          style={{
            background: '#111827',
            borderRadius: '8px',
            padding: '12px',
            border: '1px solid #1e293b',
          }}
        >
          <div
            style={{
              color: '#6b7280',
              fontSize: '10px',
              textTransform: 'uppercase',
              marginBottom: '8px',
              fontWeight: 600,
            }}
          >
            Connected Entities ({connectedEdges.length + correlationEdges.length})
          </div>
          {connectedEdges.map((edge, i) => {
            const otherId = edge.source === node.id ? edge.target : edge.source
            const direction = edge.source === node.id ? '→' : '←'
            return (
              <div
                key={`e-${i}`}
                style={{
                  fontSize: '11px',
                  color: '#d1d5db',
                  padding: '4px 0',
                  borderBottom: '1px solid #1e293b',
                }}
              >
                <span style={{ color: '#6b7280' }}>{direction}</span> {getNodeLabel(otherId)}
                {edge.label && (
                  <span style={{ color: '#6b7280', marginLeft: '4px' }}>({edge.label})</span>
                )}
              </div>
            )
          })}
          {correlationEdges.map((edge, i) => {
            const otherId = edge.source === node.id ? edge.target : edge.source
            return (
              <div
                key={`c-${i}`}
                style={{
                  fontSize: '11px',
                  color: '#a855f7',
                  padding: '4px 0',
                  borderBottom: '1px solid #1e293b',
                }}
              >
                <span style={{ color: '#7c3aed' }}>⟷</span> {getNodeLabel(otherId)}
                {edge.label && (
                  <span style={{ color: '#7c3aed', marginLeft: '4px' }}>({edge.label})</span>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ===== CUSTOM NODE COMPONENT =====

function FlowNodeComponent({ data }: { data: any }) {
  const colors = severityColors[data.severity] || severityColors.info
  const icon = nodeIcons[data.nodeType] || '📌'
  const isCritical = data.severity === 'critical' || data.severity === 'high'
  const isExpandable = data.isExpandable
  const isSelected = data.isSelected

  // Cluster node - shows grouped nodes
  if (data.nodeType === 'cluster') {
    return (
      <div
        className="attack-flow-node"
        style={{
          background: 'linear-gradient(135deg, #1e293b 0%, #0f172a 100%)',
          border: `2px dashed ${colors.border}`,
          borderRadius: '16px',
          padding: '14px 18px',
          minWidth: '160px',
          maxWidth: '220px',
          boxShadow: `0 4px 15px rgba(37, 99, 235, 0.2)`,
          position: 'relative',
          cursor: 'pointer',
        }}
      >
        <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
        <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
        <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
        <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
          <span style={{ fontSize: '20px' }}>{icon}</span>
          <span style={{ color: '#e2e8f0', fontWeight: 600, fontSize: '13px' }}>{data.label}</span>
        </div>

        {/* Count badge */}
        <div
          style={{
            position: 'absolute',
            top: '-10px',
            right: '-10px',
            background: '#2563eb',
            color: '#fff',
            borderRadius: '50%',
            width: '24px',
            height: '24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '11px',
            fontWeight: 700,
            border: '2px solid #0f172a',
          }}
        >
          {data.count || '?'}
        </div>

        <div style={{ color: '#6b7280', fontSize: '10px' }}>Click to expand</div>
      </div>
    )
  }

  // Radial layout - center node
  if (data.isCenter) {
    return (
      <div
        className="attack-flow-node"
        style={{
          background: `radial-gradient(circle, ${colors.bg} 0%, #0f172a 100%)`,
          border: `3px solid ${isSelected ? '#3b82f6' : colors.border}`,
          borderRadius: '50%',
          width: '120px',
          height: '120px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: isSelected
            ? '0 0 20px rgba(59, 130, 246, 0.6), 0 0 40px rgba(59, 130, 246, 0.3)'
            : `0 0 30px ${colors.glow}, 0 0 60px ${colors.glow}55`,
          animation: 'pulse 2s ease-in-out infinite',
          position: 'relative',
        }}
      >
        <Handle type="source" position={Position.Top} style={{ opacity: 0 }} />
        <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
        <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
        <Handle type="source" position={Position.Left} style={{ opacity: 0 }} />

        {isExpandable && (
          <div
            style={{
              position: 'absolute',
              top: '-6px',
              right: '-6px',
              background: '#2563eb',
              color: '#fff',
              borderRadius: '50%',
              width: '20px',
              height: '20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '14px',
              fontWeight: 700,
              border: '2px solid #0f172a',
            }}
          >
            +
          </div>
        )}

        <span style={{ fontSize: '28px', marginBottom: '4px' }}>{icon}</span>
        <span
          style={{
            color: colors.text,
            fontWeight: 700,
            fontSize: '11px',
            textAlign: 'center',
            maxWidth: '100px',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {data.label}
        </span>
        <span style={{ color: '#6b7280', fontSize: '9px', marginTop: '2px' }}>
          {data.description}
        </span>
      </div>
    )
  }

  // Radial layout - peripheral nodes (IPs, DLLs, APIs, domains)
  if (
    data.nodeType === 'ip' ||
    data.nodeType === 'dll' ||
    data.nodeType === 'api' ||
    data.nodeType === 'domain'
  ) {
    return (
      <div
        className="attack-flow-node"
        style={{
          background: `linear-gradient(135deg, ${colors.bg} 0%, #0f172a 100%)`,
          border: `2px solid ${isSelected ? '#3b82f6' : colors.border}`,
          borderRadius: '12px',
          padding: '12px 16px',
          minWidth: '180px',
          maxWidth: '280px',
          boxShadow: isSelected
            ? '0 0 15px rgba(59, 130, 246, 0.5)'
            : `0 4px 15px ${colors.glow}`,
          animation: isCritical ? 'pulse 2s ease-in-out infinite' : undefined,
          position: 'relative',
        }}
      >
        <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
        <Handle type="target" position={Position.Right} style={{ opacity: 0 }} />
        <Handle type="target" position={Position.Bottom} style={{ opacity: 0 }} />
        <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />

        {isExpandable && (
          <div
            style={{
              position: 'absolute',
              top: '-6px',
              right: '-6px',
              background: '#2563eb',
              color: '#fff',
              borderRadius: '50%',
              width: '18px',
              height: '18px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '12px',
              fontWeight: 700,
              border: '2px solid #0f172a',
            }}
          >
            +
          </div>
        )}

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
          <span style={{ fontSize: '20px' }}>{icon}</span>
          <span
            style={{
              color: colors.text,
              fontWeight: 700,
              fontSize: '13px',
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
            }}
          >
            {data.nodeType === 'ip'
              ? 'C2 Server'
              : data.nodeType === 'dll'
                ? 'DLL'
                : data.nodeType === 'api'
                  ? 'API Call'
                  : 'Domain'}
          </span>
        </div>

        <div
          style={{
            color: '#fff',
            fontSize: '12px',
            fontFamily: 'monospace',
            fontWeight: 600,
            marginBottom: '4px',
            wordBreak: 'break-all',
          }}
        >
          {data.nodeType === 'ip'
            ? `${data.ip || ''}:${data.port || ''}`
            : data.nodeType === 'api'
              ? data.api || data.label
              : data.dll || data.label}
        </div>

        {data.nodeType === 'dll' && data.path && (
          <div
            style={{
              color: '#6ee7b7',
              fontSize: '10px',
              fontFamily: 'monospace',
              wordBreak: 'break-all',
              lineHeight: 1.3,
            }}
          >
            {data.path}
          </div>
        )}
        {data.nodeType === 'api' && data.dll && (
          <div style={{ color: '#fbbf24', fontSize: '10px', fontFamily: 'monospace' }}>
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
        border: `2px solid ${isSelected ? '#3b82f6' : colors.border}`,
        borderRadius: '12px',
        padding: '14px 18px',
        minWidth: '180px',
        maxWidth: '240px',
        boxShadow: isSelected
          ? '0 0 15px rgba(59, 130, 246, 0.5)'
          : `0 4px 20px ${colors.glow}, inset 0 1px 0 rgba(255,255,255,0.1)`,
        position: 'relative',
        animation: isCritical ? 'pulse 2s ease-in-out infinite' : undefined,
      }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />

      {isExpandable && (
        <div
          style={{
            position: 'absolute',
            top: '-6px',
            right: '-6px',
            background: '#2563eb',
            color: '#fff',
            borderRadius: '50%',
            width: '18px',
            height: '18px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '12px',
            fontWeight: 700,
            border: '2px solid #0f172a',
          }}
        >
          +
        </div>
      )}

      {/* Step number badge */}
      {data.step && (
        <div
          style={{
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
          }}
        >
          {data.step}
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
        <span style={{ fontSize: '20px', filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.3))' }}>
          {icon}
        </span>
        <span style={{ color: colors.text, fontWeight: 600, fontSize: '14px', lineHeight: 1.2 }}>
          {data.label}
        </span>
      </div>

      <div
        style={{
          color: '#9ca3af',
          fontSize: '11px',
          marginTop: '4px',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {data.description}
      </div>
    </div>
  )
}

const nodeTypes = {
  flowNode: FlowNodeComponent,
}

// ===== CLUSTERING =====

function clusterNodes(flowData: AttackFlow): AttackFlow {
  if (!flowData.nodes || flowData.nodes.length < 30) return flowData

  // Group non-center nodes by type
  const centerNode = flowData.nodes.find((n) => n.isCenter)
  const grouped: Record<string, FlowNode[]> = {}
  const keepNodes: FlowNode[] = []

  flowData.nodes.forEach((node) => {
    if (node.isCenter) {
      keepNodes.push(node)
      return
    }
    const type = node.type
    if (!grouped[type]) grouped[type] = []
    grouped[type].push(node)
  })

  const newNodes: FlowNode[] = [...keepNodes]
  const newEdges: FlowEdge[] = []
  const clusterMap: Record<string, string[]> = {} // clusterId -> original node IDs

  Object.entries(grouped).forEach(([type, typeNodes]) => {
    if (typeNodes.length <= 3) {
      // Keep small groups as-is
      newNodes.push(...typeNodes)
      // Keep their edges
      typeNodes.forEach((n) => {
        flowData.edges
          .filter((e) => e.source === n.id || e.target === n.id)
          .forEach((e) => {
            if (!newEdges.find((ne) => ne.source === e.source && ne.target === e.target)) {
              newEdges.push(e)
            }
          })
      })
    } else {
      // Cluster them
      const clusterId = `cluster_${type}`
      const icon = nodeIcons[type] || '📂'
      newNodes.push({
        id: clusterId,
        type: 'cluster',
        label: `${type.toUpperCase()} (${typeNodes.length})`,
        description: `${typeNodes.length} ${type} nodes`,
        data: { count: typeNodes.length, clusterType: type, childIds: typeNodes.map((n) => n.id) },
        severity: typeNodes[0].severity || 'info',
      })
      clusterMap[clusterId] = typeNodes.map((n) => n.id)

      // Create edge from center to cluster
      if (centerNode) {
        newEdges.push({
          source: centerNode.id,
          target: clusterId,
          label: `${typeNodes.length} ${type}s`,
          type: 'cluster',
        })
      }
    }
  })

  // Copy edges that connect kept nodes
  flowData.edges.forEach((e) => {
    const sourceKept = newNodes.find((n) => n.id === e.source)
    const targetKept = newNodes.find((n) => n.id === e.target)
    if (sourceKept && targetKept) {
      if (!newEdges.find((ne) => ne.source === e.source && ne.target === e.target)) {
        newEdges.push(e)
      }
    }
  })

  return {
    ...flowData,
    nodes: newNodes,
    edges: newEdges,
  }
}

// ===== GENERATE FALLBACK FLOW =====

function generateFallbackFlow(analysis: any): AttackFlow | null {
  if (!analysis) return null

  const nodes: FlowNode[] = []
  const edges: FlowEdge[] = []
  let step = 1

  nodes.push({
    id: 'entry',
    type: 'entry',
    label: 'User Action',
    description: analysis.url ? 'Click URL' : 'Open File',
    data: {},
    step: step++,
    severity: 'info',
  })

  let prevId = 'entry'

  if (analysis.url) {
    nodes.push({
      id: 'dns',
      type: 'dns',
      label: 'DNS Lookup',
      description: new URL(analysis.url).hostname,
      data: {},
      step: step++,
      severity: 'info',
    })
    edges.push({ source: prevId, target: 'dns', label: 'Resolve', type: 'request' })
    prevId = 'dns'

    nodes.push({
      id: 'http',
      type: 'http',
      label: 'HTTP Request',
      description: 'GET request sent',
      data: {},
      step: step++,
      severity: 'info',
    })
    edges.push({ source: prevId, target: 'http', label: 'Connect', type: 'request' })
    prevId = 'http'

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
        severity: 'warning',
      })
      edges.push({ source: prevId, target: nodeId, label: '302', type: 'redirect' })
      prevId = nodeId
    })

    if (analysis.finalUrl || redirectChain.length > 0) {
      nodes.push({
        id: 'final',
        type: 'page',
        label: 'Page Loaded',
        description: analysis.finalUrl
          ? new URL(analysis.finalUrl).hostname
          : 'Response received',
        data: {},
        step: step++,
        severity: 'info',
      })
      edges.push({ source: prevId, target: 'final', label: '200 OK', type: 'response' })
      prevId = 'final'
    }

    if (analysis.screenshots?.length > 0) {
      nodes.push({
        id: 'screenshot',
        type: 'render',
        label: 'Page Captured',
        description: `${analysis.screenshots.length} screenshot(s)`,
        data: {},
        step: step++,
        severity: 'info',
      })
      edges.push({ source: prevId, target: 'screenshot', label: 'Render', type: 'action' })
      prevId = 'screenshot'
    }
  }

  const riskScore = analysis.riskScore || 0
  nodes.push({
    id: 'risk',
    type: 'assessment',
    label: `Risk: ${riskScore}/100`,
    description:
      analysis.riskLevel ||
      (riskScore >= 70 ? 'Critical' : riskScore >= 50 ? 'High' : riskScore >= 30 ? 'Medium' : 'Low'),
    data: {},
    step: step++,
    severity:
      riskScore >= 70 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 30 ? 'medium' : 'low',
  })
  edges.push({ source: prevId, target: 'risk', label: 'Analyze', type: 'assessment' })

  return {
    nodes,
    edges,
    summary: {
      totalSteps: nodes.length,
      redirects: (analysis.redirectChain || []).length,
    },
    timeline: nodes.map((n) => ({ step: n.step, label: n.label, type: n.type })),
  }
}

// ===== MAIN COMPONENT =====

export default function AttackFlowDiagram({ analysis, attackFlow }: AttackFlowDiagramProps) {
  const [activeLayout, setActiveLayout] = useState<LayoutType>('sequential')
  const [selectedNode, setSelectedNode] = useState<string | null>(null)

  // Use provided attackFlow or generate fallback
  const flowData = useMemo(() => {
    if (attackFlow && attackFlow.nodes && attackFlow.nodes.length > 0) {
      // Apply clustering for large graphs
      const clustered = clusterNodes(attackFlow)
      return clustered
    }
    return generateFallbackFlow(analysis)
  }, [analysis, attackFlow])

  // Auto-detect initial layout from flowData
  useMemo(() => {
    if (flowData?.layoutType === 'radial') {
      setActiveLayout('radial')
    }
  }, [flowData?.layoutType])

  // Handle node click
  const onNodeClick = useCallback(
    (_: any, node: Node) => {
      const expandableNodes = flowData?.expandableNodes || []
      // Always allow selecting a node to view details
      if (expandableNodes.length === 0 || expandableNodes.includes(node.id)) {
        setSelectedNode((prev) => (prev === node.id ? null : node.id))
      }
    },
    [flowData?.expandableNodes]
  )

  // Convert to ReactFlow format
  const { initialNodes, initialEdges } = useMemo(() => {
    if (!flowData?.nodes) {
      return { initialNodes: [], initialEdges: [] }
    }

    // All edges including correlation
    const allFlowEdges = [
      ...flowData.edges,
      ...(flowData.correlationEdges || []),
    ]

    // Calculate positions based on active layout
    let positions: Record<string, { x: number; y: number }>

    switch (activeLayout) {
      case 'radial':
        positions = calculateRadialLayout(flowData.nodes, flowData.centerNode)
        break
      case 'hierarchical':
        positions = calculateHierarchicalLayout(flowData.nodes, allFlowEdges)
        break
      case 'force':
        positions = calculateForceLayout(flowData.nodes, allFlowEdges)
        break
      case 'sequential':
      default:
        positions = calculateSequentialLayout(flowData.nodes)
        break
    }

    const isRadialLayout = activeLayout === 'radial'

    // Position nodes
    const reactFlowNodes: Node[] = flowData.nodes.map((node) => {
      const pos = positions[node.id] || { x: 0, y: 0 }

      return {
        id: node.id,
        type: 'flowNode',
        position: pos,
        data: {
          label: node.label,
          description: node.description,
          severity: node.severity,
          nodeType: node.type,
          step: node.step,
          isCenter: node.isCenter,
          isExpandable:
            (flowData.expandableNodes || []).includes(node.id) ||
            node.type === 'cluster',
          isSelected: selectedNode === node.id,
          ...node.data,
        },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
      }
    })

    // Build edges
    const reactFlowEdges: Edge[] = flowData.edges.map((edge, index) => {
      const edgeColor =
        edge.type === 'network' || edge.type === 'c2'
          ? '#dc2626'
          : edge.type === 'api'
            ? '#f59e0b'
            : edge.type === 'library'
              ? '#3b82f6'
              : edge.type === 'dns'
                ? '#8b5cf6'
                : edge.type === 'cluster'
                  ? '#6366f1'
                  : '#6b7280'

      return {
        id: `e_${index}`,
        source: edge.source,
        target: edge.target,
        label: edge.label,
        type: isRadialLayout ? 'straight' : 'smoothstep',
        animated: edge.type === 'network' || edge.type === 'c2',
        style: { stroke: edgeColor, strokeWidth: 2, strokeDasharray: '5 5' },
        labelStyle: { fill: '#d1d5db', fontSize: 10, fontWeight: 500 },
        labelBgStyle: { fill: '#1f2937', fillOpacity: 0.9 },
        markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor },
      }
    })

    // Add correlation edges with distinct style
    const correlationEdges = flowData.correlationEdges || []
    correlationEdges.forEach((edge, index) => {
      reactFlowEdges.push({
        id: `corr_${index}`,
        source: edge.source,
        target: edge.target,
        label: edge.label || 'related',
        type: 'straight',
        animated: true,
        style: {
          stroke: '#a855f7',
          strokeWidth: 2,
          strokeDasharray: '3 6',
          opacity: 0.7,
        },
        labelStyle: { fill: '#c084fc', fontSize: 9, fontWeight: 500 },
        labelBgStyle: { fill: '#1f2937', fillOpacity: 0.9 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#a855f7' },
      })
    })

    return { initialNodes: reactFlowNodes, initialEdges: reactFlowEdges }
  }, [flowData, activeLayout, selectedNode])

  // Create a key that changes when flowData or layout changes to force re-render
  const flowKey = useMemo(() => {
    const nodeIds = flowData?.nodes?.map((n) => n.id).join('-') || 'empty'
    return `${nodeIds}-${activeLayout}`
  }, [flowData, activeLayout])

  const [nodes, , onNodesChange] = useNodesState(initialNodes)
  const [edges, , onEdgesChange] = useEdgesState(initialEdges)

  // Find selected ReactFlow node for detail panel
  const selectedReactFlowNode = useMemo(() => {
    if (!selectedNode) return null
    return initialNodes.find((n) => n.id === selectedNode) || null
  }, [selectedNode, initialNodes])

  if (!flowData || flowData.nodes.length === 0) {
    return (
      <div className="card">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <span>🔄</span> Attack Flow Diagram
        </h3>
        <div className="text-gray-400 text-center py-8">No flow data available</div>
      </div>
    )
  }

  const layoutButtons: { key: LayoutType; label: string; icon: string }[] = [
    { key: 'sequential', label: 'Sequential', icon: '⬌' },
    { key: 'radial', label: 'Radial', icon: '◎' },
    { key: 'hierarchical', label: 'Hierarchy', icon: '⊞' },
    { key: 'force', label: 'Force', icon: '⊛' },
  ]

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
          {flowData.summary?.totalNodes && (
            <span className="badge badge-info">{flowData.summary.totalNodes} Nodes</span>
          )}
          {flowData.summary?.redirects > 0 && (
            <span className="badge badge-warning">{flowData.summary.redirects} Redirects</span>
          )}
          {flowData.summary?.networkConnections > 0 && (
            <span className="badge badge-danger">{flowData.summary.networkConnections} C2</span>
          )}
          {(flowData.correlationEdges?.length || 0) > 0 && (
            <span
              style={{
                background: '#7c3aed22',
                border: '1px solid #7c3aed',
                color: '#c084fc',
                padding: '2px 8px',
                borderRadius: '12px',
                fontSize: '11px',
              }}
            >
              {flowData.correlationEdges!.length} Correlations
            </span>
          )}
        </div>
      </div>

      {/* Layout Switcher Toolbar */}
      <div
        style={{
          display: 'flex',
          gap: '4px',
          marginBottom: '12px',
          padding: '4px',
          background: '#111827',
          borderRadius: '8px',
          border: '1px solid #1e293b',
          width: 'fit-content',
        }}
      >
        {layoutButtons.map((btn) => (
          <button
            key={btn.key}
            onClick={() => setActiveLayout(btn.key)}
            style={{
              padding: '6px 14px',
              borderRadius: '6px',
              border: 'none',
              background: activeLayout === btn.key ? '#2563eb' : 'transparent',
              color: activeLayout === btn.key ? '#fff' : '#9ca3af',
              fontSize: '12px',
              fontWeight: activeLayout === btn.key ? 600 : 400,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              transition: 'all 0.2s ease',
            }}
          >
            <span style={{ fontSize: '14px' }}>{btn.icon}</span>
            {btn.label}
          </button>
        ))}
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

      {/* Flow Diagram + Detail Panel */}
      <div style={{ position: 'relative' }}>
        <div
          style={{
            height: '550px',
            background: '#0c1222',
            borderRadius: '8px',
            border: '1px solid #1e293b',
            width: selectedReactFlowNode ? 'calc(100% - 320px)' : '100%',
            transition: 'width 0.3s ease',
          }}
        >
          <ReactFlow
            key={flowKey}
            nodes={initialNodes}
            edges={initialEdges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.3 }}
            minZoom={0.3}
            maxZoom={2}
            attributionPosition="bottom-left"
          >
            <Background color="#1e293b" gap={24} />
            <Controls
              style={{
                background: '#1f2937',
                borderRadius: '8px',
                border: '1px solid #374151',
              }}
            />
            <MiniMap
              nodeColor={(node) => severityColors[node.data?.severity]?.border || '#2563eb'}
              maskColor="#0c122290"
              style={{
                background: '#1f2937',
                borderRadius: '8px',
                border: '1px solid #374151',
              }}
            />
          </ReactFlow>
        </div>

        {/* Detail Panel */}
        {selectedReactFlowNode && flowData && (
          <NodeDetailPanel
            node={selectedReactFlowNode}
            flowData={flowData}
            onClose={() => setSelectedNode(null)}
          />
        )}
      </div>

      {/* Legend */}
      <div className="mt-4 flex flex-wrap gap-4 text-xs">
        {Object.entries(severityColors)
          .slice(0, 4)
          .map(([key, colors]) => (
            <div key={key} className="flex items-center gap-2">
              <div className="w-3 h-3 rounded" style={{ background: colors.border }}></div>
              <span className="text-gray-400 capitalize">{key}</span>
            </div>
          ))}
        <div className="flex items-center gap-2">
          <div
            className="w-3 h-3 rounded"
            style={{ background: '#a855f7' }}
          ></div>
          <span className="text-gray-400">Correlation</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded" style={{ background: '#dc2626' }}></div>
          <span className="text-gray-400">Network/C2</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded" style={{ background: '#3b82f6' }}></div>
          <span className="text-gray-400">Library</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded" style={{ background: '#f59e0b' }}></div>
          <span className="text-gray-400">API</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded" style={{ background: '#8b5cf6' }}></div>
          <span className="text-gray-400">DNS</span>
        </div>
      </div>
    </div>
  )
}
