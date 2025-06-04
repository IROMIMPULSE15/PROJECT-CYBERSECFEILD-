"use client"

import { useEffect, useState } from "react"
import { Activity, User, Shield, AlertTriangle, Clock } from "lucide-react"

interface ActivityItem {
  id: string
  type: "security" | "user" | "system" | "alert"
  message: string
  timestamp: Date
  severity: "info" | "warning" | "error" | "success"
}

export function ActivityFeed() {
  const [activities, setActivities] = useState<ActivityItem[]>([
    {
      id: "1",
      type: "security",
      message: "DDoS attack blocked from 185.220.101.42",
      timestamp: new Date(Date.now() - 2 * 60 * 1000),
      severity: "success",
    },
    {
      id: "2",
      type: "user",
      message: "Admin user logged in from secure terminal",
      timestamp: new Date(Date.now() - 5 * 60 * 1000),
      severity: "info",
    },
    {
      id: "3",
      type: "system",
      message: "Firewall rules updated successfully",
      timestamp: new Date(Date.now() - 8 * 60 * 1000),
      severity: "success",
    },
    {
      id: "4",
      type: "alert",
      message: "Unusual traffic pattern detected",
      timestamp: new Date(Date.now() - 12 * 60 * 1000),
      severity: "warning",
    },
  ])

  useEffect(() => {
    const interval = setInterval(() => {
      if (Math.random() > 0.6) {
        const messages = [
          "Threat signature database updated",
          "SSL certificate renewed automatically",
          "Backup completed successfully",
          "New security policy applied",
          "Intrusion attempt blocked",
          "System health check passed",
          "API rate limit enforced",
          "Malicious IP address blacklisted",
        ]

        const types: ("security" | "user" | "system" | "alert")[] = ["security", "user", "system", "alert"]
        const severities: ("info" | "warning" | "error" | "success")[] = ["info", "warning", "error", "success"]

        const newActivity: ActivityItem = {
          id: Date.now().toString(),
          type: types[Math.floor(Math.random() * types.length)],
          message: messages[Math.floor(Math.random() * messages.length)],
          timestamp: new Date(),
          severity: severities[Math.floor(Math.random() * severities.length)],
        }

        setActivities((prev) => [newActivity, ...prev.slice(0, 19)])
      }
    }, 4000)

    return () => clearInterval(interval)
  }, [])

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "security":
        return <Shield className="w-4 h-4" />
      case "user":
        return <User className="w-4 h-4" />
      case "system":
        return <Activity className="w-4 h-4" />
      case "alert":
        return <AlertTriangle className="w-4 h-4" />
      default:
        return <Activity className="w-4 h-4" />
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "success":
        return "text-green-400"
      case "warning":
        return "text-yellow-400"
      case "error":
        return "text-red-400"
      default:
        return "text-blue-400"
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
        <h2 className="text-xl font-bold text-green-400 font-mono">ACTIVITY FEED</h2>
        <div className="flex items-center space-x-2">
          <Clock className="w-4 h-4 text-green-400" />
          <span className="text-green-400 text-sm font-mono">REAL-TIME</span>
        </div>
      </div>

      <div className="space-y-3 max-h-96 overflow-y-auto">
        {activities.map((activity) => (
          <div
            key={activity.id}
            className="flex items-start space-x-3 p-3 bg-gray-900/50 rounded-lg hover:bg-gray-900/70 transition-colors"
          >
            <div className={`${getSeverityColor(activity.severity)} mt-1`}>{getTypeIcon(activity.type)}</div>
            <div className="flex-1 min-w-0">
              <div className="text-green-300 text-sm">{activity.message}</div>
              <div className="text-green-500 text-xs mt-1">{formatTime(activity.timestamp)}</div>
            </div>
            <div className={`text-xs px-2 py-1 rounded ${getSeverityColor(activity.severity)} border border-current`}>
              {activity.severity.toUpperCase()}
            </div>
          </div>
        ))}
      </div>

      <div className="mt-4 pt-4 border-t border-green-500/30 text-center">
        <button className="text-green-400 hover:text-green-300 text-sm font-mono transition-colors">
          VIEW ALL ACTIVITIES →
        </button>
      </div>
    </div>
  )
}
