"use client"

import { useEffect, useState } from "react"
import { Shield, Activity, AlertTriangle, Globe, Zap, Eye, Lock, Bot } from "lucide-react"

interface SecurityMetrics {
  requests_per_second: number
  blocked_requests: number
  threat_score: number
  active_threats: Array<{
    type: string
    count: number
    trend: string
  }>
  geographic_attacks: Array<{
    country: string
    count: number
  }>
  protection_status: {
    waf: { status: string; blocked_today: number }
    ddos_protection: { status: string; attacks_mitigated: number }
    bot_management: { status: string; bots_detected: number }
    ssl_protection: { status: string; certificates: number; grade: string }
  }
}

export function RealTimeSecurityMonitor() {
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date())

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const response = await fetch("/api/security/real-time-monitor")
        const data = await response.json()
        setMetrics(data)
        setLastUpdate(new Date())
      } catch (error) {
        console.error("Failed to fetch security metrics:", error)
      } finally {
        setIsLoading(false)
      }
    }

    // Initial fetch
    fetchMetrics()

    // Set up real-time updates
    const interval = setInterval(fetchMetrics, 5000) // Update every 5 seconds

    return () => clearInterval(interval)
  }, [])

  if (isLoading) {
    return (
      <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-green-400"></div>
        </div>
      </div>
    )
  }

  if (!metrics) {
    return (
      <div className="bg-black/70 border border-red-500/30 rounded-lg p-6 backdrop-blur-sm">
        <div className="text-red-400 text-center">Failed to load security metrics</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Real-time Metrics */}
      <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
        <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">REAL-TIME METRICS</h3>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gray-900/50 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-blue-400 font-mono">{metrics.requests_per_second?.toFixed(0) || '0'}</div>
            <div className="text-blue-300 text-sm">Requests/sec</div>
          </div>
          <div className="bg-gray-900/50 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-red-400 font-mono">{metrics.blocked_requests?.toLocaleString() || '0'}</div>
            <div className="text-red-300 text-sm">Blocked Today</div>
          </div>
          <div className="bg-gray-900/50 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-yellow-400 font-mono">{metrics.threat_score?.toFixed(0) || '0'}%</div>
            <div className="text-yellow-300 text-sm">Threat Level</div>
          </div>
          <div className="bg-gray-900/50 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-green-400 font-mono">{metrics.active_threats?.length || '0'}</div>
            <div className="text-green-300 text-sm">Active Threats</div>
          </div>
        </div>
      </div>

      {/* Protection Status */}
      <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
        <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">PROTECTION STATUS</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* WAF Protection */}
          <div className="bg-gray-900/50 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center">
                <Shield className="w-5 h-5 text-red-400 mr-2" />
                <span className="text-red-400 font-mono text-sm">WAF</span>
              </div>
              <div className="w-2 h-2 bg-green-400 rounded-full"></div>
            </div>
            <div className="text-green-400 text-xs">
              {metrics.protection_status?.waf?.blocked_today?.toLocaleString() || '0'} blocked today
            </div>
          </div>

          {/* DDoS Protection */}
          <div className="bg-gray-900/50 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center">
                <Zap className="w-5 h-5 text-yellow-400 mr-2" />
                <span className="text-yellow-400 font-mono text-sm">DDoS</span>
              </div>
              <div className="w-2 h-2 bg-green-400 rounded-full"></div>
            </div>
            <div className="text-green-400 text-xs">
              {metrics.protection_status?.ddos_protection?.attacks_mitigated || '0'} mitigated
            </div>
          </div>

          {/* Bot Management */}
          <div className="bg-gray-900/50 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center">
                <Bot className="w-5 h-5 text-purple-400 mr-2" />
                <span className="text-purple-400 font-mono text-sm">BOT</span>
              </div>
              <div className="w-2 h-2 bg-green-400 rounded-full"></div>
            </div>
            <div className="text-green-400 text-xs">
              {metrics.protection_status?.bot_management?.bots_detected?.toLocaleString() || '0'} detected
            </div>
          </div>

          {/* SSL Protection */}
          <div className="bg-gray-900/50 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center">
                <Lock className="w-5 h-5 text-green-400 mr-2" />
                <span className="text-green-400 font-mono text-sm">SSL</span>
              </div>
              <div className="w-2 h-2 bg-green-400 rounded-full"></div>
            </div>
            <div className="text-green-400 text-xs">
              Grade {metrics.protection_status?.ssl_protection?.grade || 'N/A'} •{" "}
              {metrics.protection_status?.ssl_protection?.certificates || '0'} certs
            </div>
          </div>
        </div>
      </div>

      {/* Active Threats */}
      <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
        <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">ACTIVE THREATS</h3>
        <div className="space-y-3">
          {metrics.active_threats?.map((threat, index) => (
            <div key={index} className="bg-gray-900/50 rounded-lg p-3 flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <AlertTriangle className="w-5 h-5 text-yellow-400" />
                <span className="text-yellow-300 font-mono">{threat.type}</span>
              </div>
              <div className="flex items-center space-x-4">
                <span className="text-yellow-400 font-mono">{threat.count} incidents</span>
                <span className={`text-xs font-mono ${threat.trend === "up" ? "text-red-400" : "text-green-400"}`}>
                  {threat.trend === "up" ? "↑" : "↓"}
                </span>
              </div>
            </div>
          ))}
          {(!metrics.active_threats || metrics.active_threats.length === 0) && (
            <div className="text-green-400 text-center py-4">No active threats detected</div>
          )}
        </div>
      </div>

      {/* Geographic Attacks */}
      <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
        <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">GEOGRAPHIC ATTACKS</h3>
        <div className="space-y-3">
          {metrics.geographic_attacks?.map((attack, index) => (
            <div key={index} className="bg-gray-900/50 rounded-lg p-3 flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Globe className="w-5 h-5 text-blue-400" />
                <span className="text-blue-300 font-mono">{attack.country}</span>
              </div>
              <span className="text-blue-400 font-mono">{attack.count} attacks</span>
            </div>
          ))}
          {(!metrics.geographic_attacks || metrics.geographic_attacks.length === 0) && (
            <div className="text-green-400 text-center py-4">No geographic attacks detected</div>
          )}
        </div>
      </div>

      {/* Last Update */}
      <div className="text-center text-green-400/60 text-sm">
        Last updated: {lastUpdate.toLocaleTimeString()}
      </div>
    </div>
  )
}
