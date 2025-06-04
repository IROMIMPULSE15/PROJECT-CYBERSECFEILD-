"use client"

import { useEffect, useState } from "react"
import { AlertTriangle, Eye, Brain, Radar, Shield } from "lucide-react"

export function ThreatDetection() {
  const [threats, setThreats] = useState([
    { id: 1, type: "DDoS Attack", severity: "HIGH", source: "185.220.101.42", status: "BLOCKED" },
    { id: 2, type: "SQL Injection", severity: "CRITICAL", source: "203.0.113.15", status: "MITIGATED" },
    { id: 3, type: "Brute Force", severity: "MEDIUM", source: "198.51.100.8", status: "MONITORING" },
    { id: 4, type: "Data Exfiltration", severity: "HIGH", source: "192.0.2.146", status: "BLOCKED" },
  ])

  const [scanProgress, setScanProgress] = useState(0)

  useEffect(() => {
    const interval = setInterval(() => {
      setScanProgress((prev) => (prev + 1) % 101)

      if (Math.random() > 0.8) {
        const newThreat = {
          id: Date.now(),
          type: ["DDoS Attack", "Malware", "Phishing", "Bot Traffic", "XSS Attack"][Math.floor(Math.random() * 5)],
          severity: ["LOW", "MEDIUM", "HIGH", "CRITICAL"][Math.floor(Math.random() * 4)],
          source: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          status: ["BLOCKED", "MITIGATED", "MONITORING"][Math.floor(Math.random() * 3)],
        }

        setThreats((prev) => [newThreat, ...prev.slice(0, 3)])
      }
    }, 3000)

    return () => clearInterval(interval)
  }, [])

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "text-red-400 border-red-500"
      case "HIGH":
        return "text-orange-400 border-orange-500"
      case "MEDIUM":
        return "text-yellow-400 border-yellow-500"
      default:
        return "text-green-400 border-green-500"
    }
  }

  return (
    <section className="relative py-20 z-10">
      <div className="container mx-auto px-6">
        <div className="text-center mb-16">
          <h2 className="text-4xl font-bold text-green-400 mb-4 font-mono">REAL-TIME THREAT DETECTION</h2>
          <p className="text-green-200 text-lg max-w-3xl mx-auto">
            Advanced AI algorithms continuously monitor network traffic patterns, detecting and neutralizing threats
            before they can compromise your infrastructure.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Threat Scanner */}
          <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
            <div className="flex items-center mb-6">
              <Radar className="w-6 h-6 text-green-400 mr-3 animate-spin" />
              <h3 className="text-xl font-bold text-green-400 font-mono">NEURAL SCANNER</h3>
            </div>

            <div className="mb-4">
              <div className="flex justify-between text-sm text-green-300 mb-2">
                <span>Deep Packet Inspection</span>
                <span>{scanProgress}%</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-green-600 to-green-400 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              {[
                { label: "Packets Analyzed", value: "2.4M", icon: Eye },
                { label: "Patterns Detected", value: "847", icon: Brain },
                { label: "Anomalies Found", value: "23", icon: AlertTriangle },
                { label: "Threats Blocked", value: "156", icon: Shield },
              ].map((metric, index) => (
                <div key={index} className="bg-gray-900/50 rounded p-3 text-center">
                  <metric.icon className="w-5 h-5 text-green-400 mx-auto mb-2" />
                  <div className="text-lg font-bold text-green-400 font-mono">{metric.value}</div>
                  <div className="text-xs text-green-300">{metric.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Live Threats */}
          <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
            <div className="flex items-center mb-6">
              <AlertTriangle className="w-6 h-6 text-red-400 mr-3 animate-pulse" />
              <h3 className="text-xl font-bold text-green-400 font-mono">LIVE THREATS</h3>
            </div>

            <div className="space-y-3 max-h-80 overflow-y-auto">
              {threats.map((threat) => (
                <div key={threat.id} className="bg-gray-900/50 rounded p-3 border-l-4 border-red-500">
                  <div className="flex justify-between items-start mb-2">
                    <div className="text-green-400 font-mono font-bold">{threat.type}</div>
                    <div className={`text-xs px-2 py-1 rounded border ${getSeverityColor(threat.severity)}`}>
                      {threat.severity}
                    </div>
                  </div>
                  <div className="text-sm text-green-300">Source: {threat.source}</div>
                  <div className="text-xs text-green-200 mt-1">Status: {threat.status}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
