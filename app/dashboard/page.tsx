"use client"

import { useState } from "react"
import { DashboardStats } from "@/components/dashboard/dashboard-stats"
import { ThreatMonitor } from "@/components/dashboard/threat-monitor"
import { SecurityOverview } from "@/components/dashboard/security-overview"
import { ActivityFeed } from "@/components/dashboard/activity-feed"
import { SystemHealth } from "@/components/dashboard/system-health"
import { RealTimeSecurityMonitor } from "@/components/dashboard/real-time-security-monitor"
import { AdvancedSecurityScanner } from "@/components/dashboard/advanced-security-scanner"
import { ToolSpecificScanner } from "@/components/dashboard/tool-specific-scanner"
import { ProtectionDeployment } from "@/components/dashboard/protection-deployment"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

export default function DashboardPage() {
  const [scanResult, setScanResult] = useState<any>(null)
  const [deploymentResult, setDeploymentResult] = useState<any>(null)

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-green-400 mb-2 font-mono">CYBER DEFENSE COMMAND CENTER</h1>
          <p className="text-green-300">Advanced Security Monitoring & Protection Platform</p>
        </div>

        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="grid w-full grid-cols-6 bg-black/50 border border-green-500/30">
            <TabsTrigger
              value="overview"
              className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400"
            >
              Overview
            </TabsTrigger>
            <TabsTrigger
              value="monitoring"
              className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400"
            >
              Real-Time Monitor
            </TabsTrigger>
            <TabsTrigger
              value="scanner"
              className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400"
            >
              Advanced Scanner
            </TabsTrigger>
            <TabsTrigger
              value="tools"
              className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400"
            >
              Security Tools
            </TabsTrigger>
            <TabsTrigger
              value="protection"
              className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400"
            >
              Protection
            </TabsTrigger>
            <TabsTrigger
              value="analytics"
              className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400"
            >
              Analytics
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <DashboardStats />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <ThreatMonitor />
              <SecurityOverview />
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <ActivityFeed />
              <SystemHealth />
            </div>
          </TabsContent>

          <TabsContent value="monitoring" className="space-y-6">
            <RealTimeSecurityMonitor />
          </TabsContent>

          <TabsContent value="scanner" className="space-y-6">
            <AdvancedSecurityScanner onScanComplete={setScanResult} />
          </TabsContent>

          <TabsContent value="tools" className="space-y-6">
            <ToolSpecificScanner />
          </TabsContent>

          <TabsContent value="protection" className="space-y-6">
            {scanResult && <ProtectionDeployment scanResult={scanResult} onDeploymentComplete={setDeploymentResult} />}
            {!scanResult && (
              <div className="bg-black/70 border border-yellow-500/30 rounded-lg p-6 backdrop-blur-sm text-center">
                <div className="text-yellow-400 mb-2">No scan results available</div>
                <div className="text-yellow-300 text-sm">
                  Please run a security scan first to deploy protection measures
                </div>
              </div>
            )}
          </TabsContent>

          <TabsContent value="analytics" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
                <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">THREAT ANALYTICS</h3>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-green-300">SQL Injection Attempts</span>
                    <span className="text-red-400 font-mono">1,247</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-green-300">XSS Attempts</span>
                    <span className="text-orange-400 font-mono">892</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-green-300">DDoS Attacks</span>
                    <span className="text-yellow-400 font-mono">156</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-green-300">Bot Traffic</span>
                    <span className="text-blue-400 font-mono">3,421</span>
                  </div>
                </div>
              </div>

              <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
                <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">PERFORMANCE METRICS</h3>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-green-300">Response Time</span>
                    <span className="text-green-400 font-mono">45ms</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-green-300">Uptime</span>
                    <span className="text-green-400 font-mono">99.99%</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-green-300">Bandwidth Usage</span>
                    <span className="text-blue-400 font-mono">2.3 TB</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-green-300">Cache Hit Rate</span>
                    <span className="text-green-400 font-mono">94.2%</span>
                  </div>
                </div>
              </div>
            </div>

            {deploymentResult && (
              <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
                <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">DEPLOYMENT STATUS</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-gray-900/50 rounded-lg p-4 text-center">
                    <div className="text-green-400 font-mono text-lg">ACTIVE</div>
                    <div className="text-green-300 text-sm">Protection Status</div>
                  </div>
                  <div className="bg-gray-900/50 rounded-lg p-4 text-center">
                    <div className="text-blue-400 font-mono text-lg">{deploymentResult.id}</div>
                    <div className="text-blue-300 text-sm">Deployment ID</div>
                  </div>
                  <div className="bg-gray-900/50 rounded-lg p-4 text-center">
                    <div className="text-yellow-400 font-mono text-lg">24/7</div>
                    <div className="text-yellow-300 text-sm">Monitoring</div>
                  </div>
                </div>
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
