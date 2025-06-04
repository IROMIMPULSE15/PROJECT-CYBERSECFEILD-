"use client"

import { useEffect, useState } from "react"
import { TrendingUp, Shield, Clock, Users } from "lucide-react"

export function TrustMetrics() {
  const [metrics, setMetrics] = useState({
    uptime: 99.99,
    responseTime: 12,
    threatsBlocked: 2847293,
    protectedSites: 15847,
  })

  useEffect(() => {
    const interval = setInterval(() => {
      setMetrics((prev) => ({
        uptime: Math.min(99.999, prev.uptime + Math.random() * 0.001),
        responseTime: Math.max(8, prev.responseTime + (Math.random() - 0.5) * 2),
        threatsBlocked: prev.threatsBlocked + Math.floor(Math.random() * 100) + 50,
        protectedSites: prev.protectedSites + Math.floor(Math.random() * 5),
      }))
    }, 2000)

    return () => clearInterval(interval)
  }, [])

  return (
    <section className="relative py-20 z-10">
      <div className="container mx-auto px-6">
        <div className="text-center mb-16">
          <h2 className="text-4xl font-bold text-green-400 mb-4 font-mono">TRUSTED BY GOVERNMENTS WORLDWIDE</h2>
          <p className="text-green-200 text-lg max-w-3xl mx-auto">
            Our platform protects critical infrastructure for governments, financial institutions, and public services
            across the globe with proven reliability and performance.
          </p>
        </div>

        {/* Live Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-16">
          <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm text-center">
            <Clock className="w-12 h-12 text-green-400 mx-auto mb-4" />
            <div className="text-3xl font-bold text-green-400 font-mono mb-2">{metrics.uptime.toFixed(3)}%</div>
            <div className="text-green-300">System Uptime</div>
          </div>

          <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm text-center">
            <TrendingUp className="w-12 h-12 text-blue-400 mx-auto mb-4" />
            <div className="text-3xl font-bold text-blue-400 font-mono mb-2">{Math.round(metrics.responseTime)}ms</div>
            <div className="text-blue-300">Avg Response Time</div>
          </div>

          <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm text-center">
            <Shield className="w-12 h-12 text-red-400 mx-auto mb-4" />
            <div className="text-3xl font-bold text-red-400 font-mono mb-2">
              {metrics.threatsBlocked.toLocaleString()}
            </div>
            <div className="text-red-300">Threats Blocked</div>
          </div>

          <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm text-center">
            <Users className="w-12 h-12 text-yellow-400 mx-auto mb-4" />
            <div className="text-3xl font-bold text-yellow-400 font-mono mb-2">
              {metrics.protectedSites.toLocaleString()}
            </div>
            <div className="text-yellow-300">Protected Sites</div>
          </div>
        </div>

        {/* Call to Action */}
        <div className="text-center">
          <div className="bg-gradient-to-r from-green-900/50 to-blue-900/50 border border-green-500/30 rounded-lg p-8 backdrop-blur-sm">
            <h3 className="text-2xl font-bold text-green-400 mb-4 font-mono">SECURE YOUR INFRASTRUCTURE TODAY</h3>
            <p className="text-green-200 mb-6 max-w-2xl mx-auto">
              Join thousands of government agencies and critical infrastructure providers who trust our platform to
              defend against sophisticated cyber threats.
            </p>
            <div className="space-x-4">
              <button className="bg-green-600 hover:bg-green-500 text-black font-bold py-4 px-8 rounded-lg transition-all duration-300 transform hover:scale-105 shadow-lg shadow-green-500/25">
                REQUEST DEMO
              </button>
              <button className="border border-green-500 text-green-400 hover:bg-green-500/10 font-bold py-4 px-8 rounded-lg transition-all duration-300">
                CONTACT SECURITY TEAM
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
