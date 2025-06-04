"use client"

import { useEffect, useState } from "react"
import { Shield, Lock, Eye, Zap, CheckCircle, AlertCircle } from "lucide-react"

export function SecurityOverview() {
  const [securityStatus, setSecurityStatus] = useState({
    firewall: "active",
    ddosProtection: "active",
    intrusion: "active",
    encryption: "active",
    monitoring: "active",
    backup: "warning",
  })

  const [scanProgress, setScanProgress] = useState(0)

  useEffect(() => {
    const interval = setInterval(() => {
      setScanProgress((prev) => (prev + 1) % 101)

      // Randomly update security status
      if (Math.random() > 0.9) {
        const statuses = ["active", "warning", "error"]
        const keys = Object.keys(securityStatus)
        const randomKey = keys[Math.floor(Math.random() * keys.length)]

        setSecurityStatus((prev) => ({
          ...prev,
          [randomKey]: statuses[Math.floor(Math.random() * statuses.length)],
        }))
      }
    }, 1000)

    return () => clearInterval(interval)
  }, [securityStatus])

  const getStatusColor = (status: string) => {
    switch (status) {
      case "active":
        return "text-green-400"
      case "warning":
        return "text-yellow-400"
      case "error":
        return "text-red-400"
      default:
        return "text-gray-400"
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "active":
        return <CheckCircle className="w-4 h-4" />
      case "warning":
        return <AlertCircle className="w-4 h-4" />
      case "error":
        return <AlertCircle className="w-4 h-4" />
      default:
        return <AlertCircle className="w-4 h-4" />
    }
  }

  const securityModules = [
    { icon: Shield, name: "Firewall", key: "firewall" },
    { icon: Zap, name: "DDoS Protection", key: "ddosProtection" },
    { icon: Eye, name: "Intrusion Detection", key: "intrusion" },
    { icon: Lock, name: "Encryption", key: "encryption" },
    { icon: Eye, name: "Monitoring", key: "monitoring" },
    { icon: Shield, name: "Backup Systems", key: "backup" },
  ]

  return (
    <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
      <h2 className="text-xl font-bold text-green-400 mb-6 font-mono">SECURITY OVERVIEW</h2>

      {/* Security Scan */}
      <div className="mb-6">
        <div className="flex justify-between text-sm text-green-300 mb-2">
          <span>Security Scan Progress</span>
          <span>{scanProgress}%</span>
        </div>
        <div className="w-full bg-gray-800 rounded-full h-2">
          <div
            className="bg-gradient-to-r from-green-600 to-green-400 h-2 rounded-full transition-all duration-300"
            style={{ width: `${scanProgress}%` }}
          />
        </div>
      </div>

      {/* Security Modules */}
      <div className="space-y-3">
        {securityModules.map((module, index) => (
          <div key={index} className="flex items-center justify-between p-3 bg-gray-900/50 rounded-lg">
            <div className="flex items-center space-x-3">
              <module.icon className="w-5 h-5 text-green-400" />
              <span className="text-green-300 font-mono">{module.name}</span>
            </div>
            <div
              className={`flex items-center space-x-2 ${getStatusColor(securityStatus[module.key as keyof typeof securityStatus])}`}
            >
              {getStatusIcon(securityStatus[module.key as keyof typeof securityStatus])}
              <span className="text-sm font-mono uppercase">
                {securityStatus[module.key as keyof typeof securityStatus]}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Overall Security Score */}
      <div className="mt-6 pt-4 border-t border-green-500/30">
        <div className="text-center">
          <div className="text-3xl font-bold text-green-400 font-mono mb-2">98.7%</div>
          <div className="text-green-300 text-sm">SECURITY SCORE</div>
          <div className="text-xs text-green-400 mt-1">EXCELLENT</div>
        </div>
      </div>
    </div>
  )
}
