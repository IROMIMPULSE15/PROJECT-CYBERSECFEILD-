"use client"

import { useState, useEffect } from "react"
import { User, AlertTriangle, CheckCircle, XCircle, Eye, Brain, Fingerprint } from "lucide-react"

interface UserSession {
  id: string
  ip: string
  location: string
  device: string
  browser: string
  loginTime: Date
  riskScore: number
  status: "verified" | "suspicious" | "blocked"
  activities: string[]
}

export function UserVerification() {
  const [activeSessions, setActiveSessions] = useState<UserSession[]>([
    {
      id: "1",
      ip: "192.168.1.100",
      location: "Washington, DC, USA",
      device: "Windows 11 Desktop",
      browser: "Chrome 120.0",
      loginTime: new Date(Date.now() - 30 * 60 * 1000),
      riskScore: 15,
      status: "verified",
      activities: ["Dashboard access", "Security scan initiated", "Report downloaded"],
    },
    {
      id: "2",
      ip: "203.0.113.42",
      location: "Unknown Location",
      device: "Android Mobile",
      browser: "Chrome Mobile",
      loginTime: new Date(Date.now() - 5 * 60 * 1000),
      riskScore: 85,
      status: "suspicious",
      activities: ["Multiple login attempts", "Unusual access patterns", "Data extraction attempts"],
    },
  ])

  const [realTimeAnalysis, setRealTimeAnalysis] = useState({
    totalSessions: 2,
    verifiedUsers: 1,
    suspiciousActivity: 1,
    blockedAttempts: 3,
    anomaliesDetected: 5,
  })

  useEffect(() => {
    const interval = setInterval(() => {
      // Simulate real-time user behavior analysis
      if (Math.random() > 0.7) {
        const newSession: UserSession = {
          id: Date.now().toString(),
          ip: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          location: ["New York, NY", "Los Angeles, CA", "Unknown Location", "London, UK", "Tokyo, JP"][
            Math.floor(Math.random() * 5)
          ],
          device: ["Windows Desktop", "MacOS Laptop", "iPhone", "Android Mobile", "Linux Server"][
            Math.floor(Math.random() * 5)
          ],
          browser: ["Chrome", "Firefox", "Safari", "Edge", "Unknown"][Math.floor(Math.random() * 5)],
          loginTime: new Date(),
          riskScore: Math.floor(Math.random() * 100),
          status: Math.random() > 0.7 ? "suspicious" : Math.random() > 0.3 ? "verified" : "blocked",
          activities: ["Login attempt", "Page navigation", "Data access"],
        }

        setActiveSessions((prev) => [newSession, ...prev.slice(0, 4)])

        setRealTimeAnalysis((prev) => ({
          totalSessions: prev.totalSessions + 1,
          verifiedUsers: prev.verifiedUsers + (newSession.status === "verified" ? 1 : 0),
          suspiciousActivity: prev.suspiciousActivity + (newSession.status === "suspicious" ? 1 : 0),
          blockedAttempts: prev.blockedAttempts + (newSession.status === "blocked" ? 1 : 0),
          anomaliesDetected: prev.anomaliesDetected + Math.floor(Math.random() * 3),
        }))
      }
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  const getStatusColor = (status: string) => {
    switch (status) {
      case "verified":
        return "text-green-400"
      case "suspicious":
        return "text-yellow-400"
      case "blocked":
        return "text-red-400"
      default:
        return "text-gray-400"
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "verified":
        return <CheckCircle className="w-4 h-4" />
      case "suspicious":
        return <AlertTriangle className="w-4 h-4" />
      case "blocked":
        return <XCircle className="w-4 h-4" />
      default:
        return <AlertTriangle className="w-4 h-4" />
    }
  }

  const getRiskColor = (score: number) => {
    if (score < 30) return "text-green-400"
    if (score < 70) return "text-yellow-400"
    return "text-red-400"
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
        <div className="flex items-center">
          <User className="w-6 h-6 text-green-400 mr-3" />
          <h2 className="text-xl font-bold text-green-400 font-mono">USER VERIFICATION</h2>
        </div>
        <div className="flex items-center space-x-2">
          <Brain className="w-4 h-4 text-blue-400" />
          <span className="text-blue-400 text-sm font-mono">AI ANALYSIS</span>
        </div>
      </div>

      {/* Real-time Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-blue-400 font-mono">{realTimeAnalysis.totalSessions}</div>
          <div className="text-xs text-green-300">TOTAL SESSIONS</div>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-green-400 font-mono">{realTimeAnalysis.verifiedUsers}</div>
          <div className="text-xs text-green-300">VERIFIED</div>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-yellow-400 font-mono">{realTimeAnalysis.suspiciousActivity}</div>
          <div className="text-xs text-green-300">SUSPICIOUS</div>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-red-400 font-mono">{realTimeAnalysis.blockedAttempts}</div>
          <div className="text-xs text-green-300">BLOCKED</div>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-orange-400 font-mono">{realTimeAnalysis.anomaliesDetected}</div>
          <div className="text-xs text-green-300">ANOMALIES</div>
        </div>
      </div>

      {/* Active Sessions */}
      <div className="mb-6">
        <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">ACTIVE USER SESSIONS</h3>
        <div className="space-y-3 max-h-80 overflow-y-auto">
          {activeSessions.map((session) => (
            <div key={session.id} className="bg-gray-900/50 rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center space-x-3">
                  {getStatusIcon(session.status)}
                  <div>
                    <div className="text-green-400 font-mono font-bold">{session.ip}</div>
                    <div className="text-green-300 text-sm">{session.location}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className={`text-lg font-bold font-mono ${getRiskColor(session.riskScore)}`}>
                    {session.riskScore}%
                  </div>
                  <div className="text-green-300 text-xs">RISK SCORE</div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
                <div>
                  <div className="text-green-400 text-xs font-mono">DEVICE</div>
                  <div className="text-green-300 text-sm">{session.device}</div>
                </div>
                <div>
                  <div className="text-green-400 text-xs font-mono">BROWSER</div>
                  <div className="text-green-300 text-sm">{session.browser}</div>
                </div>
                <div>
                  <div className="text-green-400 text-xs font-mono">LOGIN TIME</div>
                  <div className="text-green-300 text-sm">{formatTime(session.loginTime)}</div>
                </div>
              </div>

              <div className="mb-3">
                <div className="text-green-400 text-xs font-mono mb-1">RECENT ACTIVITIES</div>
                <div className="space-y-1">
                  {session.activities.map((activity, index) => (
                    <div key={index} className="flex items-center text-sm text-green-200">
                      <div className="w-1 h-1 bg-green-400 rounded-full mr-2" />
                      {activity}
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div className={`flex items-center space-x-2 ${getStatusColor(session.status)}`}>
                  <span className="text-xs px-2 py-1 rounded border border-current font-mono">
                    {session.status.toUpperCase()}
                  </span>
                </div>
                <div className="flex space-x-2">
                  {session.status === "suspicious" && (
                    <>
                      <button className="bg-red-600 hover:bg-red-500 text-white text-xs px-3 py-1 rounded font-mono">
                        BLOCK
                      </button>
                      <button className="bg-yellow-600 hover:bg-yellow-500 text-black text-xs px-3 py-1 rounded font-mono">
                        INVESTIGATE
                      </button>
                    </>
                  )}
                  <button className="border border-green-500 text-green-400 hover:bg-green-500/10 text-xs px-3 py-1 rounded font-mono">
                    DETAILS
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* AI Analysis Features */}
      <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4">
        <h4 className="text-lg font-bold text-blue-400 mb-3 font-mono flex items-center">
          <Fingerprint className="w-5 h-5 mr-2" />
          AI BEHAVIORAL ANALYSIS
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <div className="text-blue-400 text-sm font-mono mb-2">DETECTION METHODS</div>
            <div className="space-y-1">
              {[
                "Device fingerprinting",
                "Behavioral biometrics",
                "Geolocation analysis",
                "Session pattern recognition",
              ].map((method, index) => (
                <div key={index} className="flex items-center text-sm text-blue-300">
                  <CheckCircle className="w-3 h-3 mr-2" />
                  {method}
                </div>
              ))}
            </div>
          </div>
          <div>
            <div className="text-blue-400 text-sm font-mono mb-2">RISK FACTORS</div>
            <div className="space-y-1">
              {[
                "Unusual login times",
                "Multiple failed attempts",
                "Suspicious IP ranges",
                "Abnormal user behavior",
              ].map((factor, index) => (
                <div key={index} className="flex items-center text-sm text-blue-300">
                  <Eye className="w-3 h-3 mr-2" />
                  {factor}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
