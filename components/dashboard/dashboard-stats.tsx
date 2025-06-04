"use client"

import { useEffect, useState } from "react"
import { Shield, Zap, Globe, AlertTriangle, TrendingUp, TrendingDown } from "lucide-react"

export function DashboardStats() {
  const [stats, setStats] = useState({
    threatsBlocked: 1247,
    requestsPerSecond: 2847,
    uptime: 99.99,
    activeConnections: 15847,
    bandwidthUsed: 2.4,
    responseTime: 12,
  })

  const [trends, setTrends] = useState({
    threatsBlocked: 12,
    requestsPerSecond: -5,
    uptime: 0.01,
    activeConnections: 8,
  })

  useEffect(() => {
    const interval = setInterval(() => {
      setStats((prev) => ({
        threatsBlocked: prev.threatsBlocked + Math.floor(Math.random() * 10) + 1,
        requestsPerSecond: Math.max(1000, prev.requestsPerSecond + Math.floor(Math.random() * 200) - 100),
        uptime: Math.min(99.99, prev.uptime + Math.random() * 0.001),
        activeConnections: Math.max(10000, prev.activeConnections + Math.floor(Math.random() * 100) - 50),
        bandwidthUsed: Math.max(1, prev.bandwidthUsed + (Math.random() - 0.5) * 0.2),
        responseTime: Math.max(5, prev.responseTime + (Math.random() - 0.5) * 3),
      }))
    }, 2000)

    return () => clearInterval(interval)
  }, [])

  const statCards = [
    {
      icon: Shield,
      label: "Threats Blocked",
      value: stats.threatsBlocked.toLocaleString(),
      trend: trends.threatsBlocked,
      color: "text-red-400",
      bgColor: "bg-red-900/20 border-red-500/30",
    },
    {
      icon: Zap,
      label: "Requests/sec",
      value: stats.requestsPerSecond.toLocaleString(),
      trend: trends.requestsPerSecond,
      color: "text-blue-400",
      bgColor: "bg-blue-900/20 border-blue-500/30",
    },
    {
      icon: Globe,
      label: "Uptime",
      value: `${stats.uptime.toFixed(3)}%`,
      trend: trends.uptime,
      color: "text-green-400",
      bgColor: "bg-green-900/20 border-green-500/30",
    },
    {
      icon: AlertTriangle,
      label: "Active Connections",
      value: stats.activeConnections.toLocaleString(),
      trend: trends.activeConnections,
      color: "text-yellow-400",
      bgColor: "bg-yellow-900/20 border-yellow-500/30",
    },
  ]

  return (
    <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
      <h2 className="text-xl font-bold text-green-400 mb-6 font-mono">SYSTEM METRICS</h2>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        {statCards.map((stat, index) => (
          <div key={index} className={`${stat.bgColor} rounded-lg p-4 border`}>
            <div className="flex items-center justify-between mb-2">
              <stat.icon className={`w-6 h-6 ${stat.color}`} />
              <div className="flex items-center space-x-1">
                {stat.trend > 0 ? (
                  <TrendingUp className="w-4 h-4 text-green-400" />
                ) : (
                  <TrendingDown className="w-4 h-4 text-red-400" />
                )}
                <span className={`text-xs font-mono ${stat.trend > 0 ? "text-green-400" : "text-red-400"}`}>
                  {stat.trend > 0 ? "+" : ""}
                  {stat.trend}%
                </span>
              </div>
            </div>
            <div className={`text-2xl font-bold font-mono ${stat.color} mb-1`}>{stat.value}</div>
            <div className="text-green-300 text-sm">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Additional Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-gray-900/50 rounded-lg p-4">
          <div className="text-green-400 font-mono text-sm mb-2">BANDWIDTH USAGE</div>
          <div className="text-2xl font-bold text-blue-400 font-mono mb-2">{stats.bandwidthUsed.toFixed(1)} GB/s</div>
          <div className="w-full bg-gray-800 rounded-full h-2">
            <div
              className="bg-blue-400 h-2 rounded-full transition-all duration-300"
              style={{ width: `${Math.min(100, (stats.bandwidthUsed / 5) * 100)}%` }}
            />
          </div>
        </div>

        <div className="bg-gray-900/50 rounded-lg p-4">
          <div className="text-green-400 font-mono text-sm mb-2">RESPONSE TIME</div>
          <div className="text-2xl font-bold text-yellow-400 font-mono mb-2">{Math.round(stats.responseTime)}ms</div>
          <div className="w-full bg-gray-800 rounded-full h-2">
            <div
              className="bg-yellow-400 h-2 rounded-full transition-all duration-300"
              style={{ width: `${Math.min(100, (stats.responseTime / 50) * 100)}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  )
}
