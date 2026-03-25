import { useEffect, useRef, useState, useMemo } from 'react'
import Globe from 'react-globe.gl'

interface Location {
  latitude: number
  longitude: number
  city?: string
  country?: string
  ip?: string
}

interface ThreatGlobeProps {
  sourceLocation: Location
  targetLocation: Location
  riskScore: number
}

export default function ThreatGlobe({ sourceLocation, targetLocation, riskScore }: ThreatGlobeProps) {
  const globeRef = useRef<any>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(600)

  // Responsive width
  useEffect(() => {
    if (!containerRef.current) return
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        setWidth(entry.contentRect.width)
      }
    })
    observer.observe(containerRef.current)
    return () => observer.disconnect()
  }, [])

  // Auto-position camera to show both points
  useEffect(() => {
    if (!globeRef.current) return
    const timer = setTimeout(() => {
      const midLat = (sourceLocation.latitude + targetLocation.latitude) / 2
      const midLng = (sourceLocation.longitude + targetLocation.longitude) / 2
      globeRef.current.pointOfView({ lat: midLat, lng: midLng, altitude: 2.2 }, 1000)
    }, 500)
    return () => clearTimeout(timer)
  }, [sourceLocation, targetLocation])

  // Arc color based on risk
  const arcColor = useMemo(() => {
    if (riskScore >= 70) return ['#ef4444', '#dc2626'] // red
    if (riskScore >= 40) return ['#f97316', '#ea580c'] // orange
    return ['#22c55e', '#16a34a'] // green
  }, [riskScore])

  const arcsData = useMemo(() => [{
    startLat: sourceLocation.latitude,
    startLng: sourceLocation.longitude,
    endLat: targetLocation.latitude,
    endLng: targetLocation.longitude,
  }], [sourceLocation, targetLocation])

  const pointsData = useMemo(() => [
    {
      lat: sourceLocation.latitude,
      lng: sourceLocation.longitude,
      label: sourceLocation.city || 'You',
      color: '#3b82f6', // blue
      size: 0.6,
    },
    {
      lat: targetLocation.latitude,
      lng: targetLocation.longitude,
      label: targetLocation.city || targetLocation.ip || 'Target',
      color: riskScore >= 50 ? '#ef4444' : '#22c55e',
      size: 0.6,
    },
  ], [sourceLocation, targetLocation, riskScore])

  const labelsData = useMemo(() => [
    {
      lat: sourceLocation.latitude,
      lng: sourceLocation.longitude,
      text: sourceLocation.city || 'Your Location',
      color: '#93c5fd',
      size: 0.7,
    },
    {
      lat: targetLocation.latitude,
      lng: targetLocation.longitude,
      text: targetLocation.city || targetLocation.ip || 'Target',
      color: riskScore >= 50 ? '#fca5a5' : '#86efac',
      size: 0.7,
    },
  ], [sourceLocation, targetLocation, riskScore])

  const height = Math.min(width * 0.75, 500)

  return (
    <div ref={containerRef} className="w-full relative">
      <Globe
        ref={globeRef}
        width={width}
        height={height}
        globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
        backgroundColor="rgba(0,0,0,0)"
        atmosphereColor="#ef4444"
        atmosphereAltitude={0.15}
        arcsData={arcsData}
        arcColor={() => arcColor}
        arcDashLength={0.5}
        arcDashGap={0.2}
        arcDashAnimateTime={1500}
        arcStroke={0.8}
        pointsData={pointsData}
        pointLat="lat"
        pointLng="lng"
        pointColor="color"
        pointRadius="size"
        pointAltitude={0.01}
        labelsData={labelsData}
        labelLat="lat"
        labelLng="lng"
        labelText="text"
        labelColor="color"
        labelSize="size"
        labelDotRadius={0.3}
        labelAltitude={0.02}
        labelResolution={2}
      />
      {/* Legend */}
      <div className="absolute bottom-3 left-3 bg-dark-700/80 backdrop-blur-sm border border-dark-300 rounded-lg px-3 py-2 text-xs space-y-1">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" />
          <span className="text-gray-300">Your Location</span>
        </div>
        <div className="flex items-center gap-2">
          <span className={`w-2.5 h-2.5 rounded-full inline-block ${riskScore >= 50 ? 'bg-red-500' : 'bg-green-500'}`} />
          <span className="text-gray-300">Target IP</span>
        </div>
      </div>
    </div>
  )
}
