"use client"

import { useEffect, useState } from "react"
import { Activity, Server, Users, Zap } from "lucide-react"

export function RealTimeDashboard() {
  const [metrics, setMetrics] = useState({
    requests: 0,
    blocked: 0,
    latency: 0,
    uptime: 99.99,
  })

  const [networkData, setNetworkData] = useState<number[]>(Array(20).fill(0))

  useEffect(() => {
    const interval = setInterval(() => {
      setMetrics((prev) => ({
        requests: prev.requests + Math.floor(Math.random() * 1000) + 500,
        blocked: prev.blocked + Math.floor(Math.random() * 50) + 10,
        latency: Math.floor(Math.random() * 20) + 5,
        uptime: 99.99 - Math.random() * 0.01,
      }))

      setNetworkData((prev) => {
        const newData = [...prev.slice(1), Math.floor(Math.random() * 100)]
        return newData
      })
    }, 1000)

    return () => clearInterval(interval)
  }, [])

  return (
    <section className="relative py-20 z-10">
      <div className="container mx-auto px-6">
        <div className="text-center mb-16">
          <h2 className="text-4xl font-bold text-green-400 mb-4 font-mono">COMMAND & CONTROL CENTER</h2>
          <p className="text-green-200 text-lg max-w-3xl mx-auto">
            Monitor your entire infrastructure in real-time with our advanced analytics dashboard. Track threats,
            performance metrics, and system health at a glance.
          </p>
        </div>

        {/* Main Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-12">
          {[
            { icon: Activity, label: "Requests/sec", value: metrics.requests.toLocaleString(), color: "text-blue-400" },
            { icon: Zap, label: "Threats Blocked", value: metrics.blocked.toLocaleString(), color: "text-red-400" },
            { icon: Server, label: "Avg Latency", value: `${metrics.latency}ms`, color: "text-yellow-400" },
            { icon: Users, label: "Uptime", value: `${metrics.uptime.toFixed(3)}%`, color: "text-green-400" },
          ].map((metric, index) => (
            <div
              key={index}
              className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm hover:border-green-400/50 transition-all duration-300"
            >
              <div className="flex items-center justify-between mb-4">
                <metric.icon className={`w-8 h-8 ${metric.color}`} />
                <div className="text-right">
                  <div className={`text-2xl font-bold font-mono ${metric.color}`}>{metric.value}</div>
                  <div className="text-green-300 text-sm">{metric.label}</div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Network Activity Graph */}
        <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm mb-8">
          <h3 className="text-xl font-bold text-green-400 mb-6 font-mono">NETWORK ACTIVITY</h3>
          <div className="h-64 flex items-end space-x-2">
            {networkData.map((value, index) => (
              <div
                key={index}
                className="bg-gradient-to-t from-green-600 to-green-400 rounded-t transition-all duration-300 flex-1"
                style={{ height: `${value}%` }}
              />
            ))}
          </div>
          <div className="flex justify-between text-green-300 text-sm mt-4">
            <span>-20s</span>
            <span>-10s</span>
            <span>Now</span>
          </div>
        </div>

        {/* Global Threat Map */}
        <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
          <h3 className="text-xl font-bold text-green-400 mb-6 font-mono">GLOBAL THREAT MAP</h3>
          <div className="relative h-64 bg-gray-900 rounded-lg overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-green-900/20 to-blue-900/20" />
            {/* Simulated threat indicators */}
            {Array.from({ length: 15 }).map((_, index) => (
              <div
                key={index}
                className="absolute w-3 h-3 bg-red-500 rounded-full animate-pulse"
                style={{
                  left: `${Math.random() * 90 + 5}%`,
                  top: `${Math.random() * 80 + 10}%`,
                  animationDelay: `${Math.random() * 2}s`,
                }}
              />
            ))}
            <div className="absolute bottom-4 left-4 text-green-300 text-sm">
              <div>Active Threats: 15</div>
              <div>Blocked Attacks: 1,247</div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
