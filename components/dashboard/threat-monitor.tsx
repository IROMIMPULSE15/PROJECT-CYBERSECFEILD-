"use client"

import { useEffect, useState } from "react"
import { Shield, Eye, Zap } from "lucide-react"

interface Threat {
  id: string
  type: string
  source: string
  severity: "low" | "medium" | "high" | "critical"
  status: "detected" | "blocked" | "mitigated"
  timestamp: Date
}

export function ThreatMonitor() {
  const [threats, setThreats] = useState<Threat[]>([
    {
      id: "1",
      type: "DDoS Attack",
      source: "185.220.101.42",
      severity: "critical",
      status: "blocked",
      timestamp: new Date(Date.now() - 2 * 60 * 1000),
    },
    {
      id: "2",
      type: "SQL Injection",
      source: "203.0.113.15",
      severity: "high",
      status: "mitigated",
      timestamp: new Date(Date.now() - 5 * 60 * 1000),
    },
    {
      id: "3",
      type: "Brute Force",
      source: "198.51.100.8",
      severity: "medium",
      status: "detected",
      timestamp: new Date(Date.now() - 8 * 60 * 1000),
    },
  ])

  useEffect(() => {
    const interval = setInterval(() => {
      if (Math.random() > 0.7) {
        const threatTypes = ["DDoS Attack", "SQL Injection", "XSS Attack", "Brute Force", "Malware", "Phishing"]
        const severities: ("low" | "medium" | "high" | "critical")[] = ["low", "medium", "high", "critical"]
        const statuses: ("detected" | "blocked" | "mitigated")[] = ["detected", "blocked", "mitigated"]

        const newThreat: Threat = {
          id: Date.now().toString(),
          type: threatTypes[Math.floor(Math.random() * threatTypes.length)],
          source: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          severity: severities[Math.floor(Math.random() * severities.length)],
          status: statuses[Math.floor(Math.random() * statuses.length)],
          timestamp: new Date(),
        }

        setThreats((prev) => [newThreat, ...prev.slice(0, 9)])
      }
    }, 3000)

    return () => clearInterval(interval)
  }, [])

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "text-red-400 border-red-500"
      case "high":
        return "text-orange-400 border-orange-500"
      case "medium":
        return "text-yellow-400 border-yellow-500"
      default:
        return "text-green-400 border-green-500"
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "blocked":
        return <Shield className="w-4 h-4 text-red-400" />
      case "mitigated":
        return <Zap className="w-4 h-4 text-green-400" />
      default:
        return <Eye className="w-4 h-4 text-yellow-400" />
    }
  }

  const formatTime = (date: Date) => {
    const now = new Date()
    const diff = Math.floor((now.getTime() - date.getTime()) / 1000)

    if (diff < 60) return `${diff}s ago`
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    return `${Math.floor(diff / 3600)}h ago`
  }

  return (
    <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold text-green-400 font-mono">THREAT MONITOR</h2>
        <div className="flex items-center space-x-2">
          <div className="w-2 h-2 bg-red-400 rounded-full animate-pulse"></div>
          <span className="text-red-400 text-sm font-mono">LIVE</span>
        </div>
      </div>

      <div className="space-y-3 max-h-96 overflow-y-auto">
        {threats.map((threat) => (
          <div key={threat.id} className="bg-gray-900/50 rounded-lg p-4 border-l-4 border-l-red-500">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center space-x-3">
                {getStatusIcon(threat.status)}
                <span className="text-green-400 font-mono font-bold">{threat.type}</span>
                <span className={`text-xs px-2 py-1 rounded border ${getSeverityColor(threat.severity)}`}>
                  {threat.severity.toUpperCase()}
                </span>
              </div>
              <span className="text-green-300 text-sm">{formatTime(threat.timestamp)}</span>
            </div>
            <div className="text-sm text-green-200 mb-1">Source: {threat.source}</div>
            <div className="text-xs text-green-300 uppercase">Status: {threat.status}</div>
          </div>
        ))}
      </div>

      <div className="mt-4 pt-4 border-t border-green-500/30">
        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <div className="text-lg font-bold text-red-400 font-mono">
              {threats.filter((t) => t.status === "blocked").length}
            </div>
            <div className="text-xs text-green-300">BLOCKED</div>
          </div>
          <div>
            <div className="text-lg font-bold text-green-400 font-mono">
              {threats.filter((t) => t.status === "mitigated").length}
            </div>
            <div className="text-xs text-green-300">MITIGATED</div>
          </div>
          <div>
            <div className="text-lg font-bold text-yellow-400 font-mono">
              {threats.filter((t) => t.status === "detected").length}
            </div>
            <div className="text-xs text-green-300">DETECTED</div>
          </div>
        </div>
      </div>
    </div>
  )
}
