"use client"

import { useEffect, useState } from "react"
import { Cpu, HardDrive, Wifi, Battery } from "lucide-react"

export function SystemHealth() {
  const [health, setHealth] = useState({
    cpu: 45,
    memory: 62,
    network: 78,
    storage: 34,
  })

  useEffect(() => {
    const interval = setInterval(() => {
      setHealth((prev) => ({
        cpu: Math.max(0, Math.min(100, prev.cpu + (Math.random() - 0.5) * 10)),
        memory: Math.max(0, Math.min(100, prev.memory + (Math.random() - 0.5) * 8)),
        network: Math.max(0, Math.min(100, prev.network + (Math.random() - 0.5) * 12)),
        storage: Math.max(0, Math.min(100, prev.storage + (Math.random() - 0.5) * 5)),
      }))
    }, 2000)

    return () => clearInterval(interval)
  }, [])

  const getHealthColor = (value: number) => {
    if (value < 30) return "text-green-400"
    if (value < 70) return "text-yellow-400"
    return "text-red-400"
  }

  const getHealthBg = (value: number) => {
    if (value < 30) return "bg-green-400"
    if (value < 70) return "bg-yellow-400"
    return "bg-red-400"
  }

  const healthMetrics = [
    { icon: Cpu, label: "CPU Usage", value: health.cpu, unit: "%" },
    { icon: HardDrive, label: "Memory", value: health.memory, unit: "%" },
    { icon: Wifi, label: "Network", value: health.network, unit: "%" },
    { icon: Battery, label: "Storage", value: health.storage, unit: "%" },
  ]

  return (
    <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
      <h2 className="text-xl font-bold text-green-400 mb-6 font-mono">SYSTEM HEALTH</h2>

      <div className="space-y-4">
        {healthMetrics.map((metric, index) => (
          <div key={index} className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <metric.icon className="w-4 h-4 text-green-400" />
                <span className="text-green-300 text-sm font-mono">{metric.label}</span>
              </div>
              <span className={`text-sm font-mono ${getHealthColor(metric.value)}`}>
                {Math.round(metric.value)}
                {metric.unit}
              </span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-2">
              <div
                className={`h-2 rounded-full transition-all duration-300 ${getHealthBg(metric.value)}`}
                style={{ width: `${metric.value}%` }}
              />
            </div>
          </div>
        ))}
      </div>

      <div className="mt-6 pt-4 border-t border-green-500/30">
        <div className="text-center">
          <div className="text-2xl font-bold text-green-400 font-mono mb-1">OPTIMAL</div>
          <div className="text-green-300 text-sm">System Status</div>
        </div>
      </div>
    </div>
  )
}
