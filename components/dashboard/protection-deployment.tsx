"use client"

import { useState } from "react"
import { Shield, CheckCircle, Settings, Globe, Key, Code, Download, AlertTriangle } from "lucide-react"

interface DeploymentStatus {
  id: string
  url: string
  status: "deploying" | "active" | "error"
  services: {
    cdn: { status: string; endpoint: string }
    waf: { status: string; rules: number }
    ddos: { status: string; capacity: string }
    ssl: { status: string; grade: string }
  }
  apiKey: string
  protectionScript: string
  dnsConfig: string[]
  monitoring: {
    endpoint: string
    alerts: boolean
    reporting: string
  }
}

interface ProtectionDeploymentProps {
  scanResult: any
  onDeploymentComplete: (deployment: DeploymentStatus) => void
}

export function ProtectionDeployment({ scanResult, onDeploymentComplete }: ProtectionDeploymentProps) {
  const [deployment, setDeployment] = useState<DeploymentStatus | null>(null)
  const [deploying, setDeploying] = useState(false)
  const [deploymentStep, setDeploymentStep] = useState("")

  const deploymentSteps = [
    "Configuring CDN endpoints...",
    "Setting up WAF rules...",
    "Enabling DDoS protection...",
    "Generating SSL certificates...",
    "Configuring DNS routing...",
    "Activating monitoring systems...",
    "Finalizing protection deployment...",
  ]

  const deployProtection = async () => {
    setDeploying(true)

    try {
      // Step through deployment process
      for (let i = 0; i < deploymentSteps.length; i++) {
        setDeploymentStep(deploymentSteps[i])
        await new Promise((resolve) => setTimeout(resolve, 2000))
      }

      // Call deployment API
      const response = await fetch("/api/security/deploy-protection", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: scanResult.url,
          vulnerabilities: scanResult.vulnerabilities,
          securityHeaders: scanResult.securityHeaders,
        }),
      })

      const deploymentData = await response.json()

      const newDeployment: DeploymentStatus = {
        id: deploymentData.deployment.id,
        url: scanResult.url,
        status: "active",
        services: deploymentData.deployment.services,
        apiKey: deploymentData.apiKey,
        protectionScript: `<script src="https://cdn.cyberdefense.gov/protection.js" data-api-key="${deploymentData.apiKey}" data-site="${deploymentData.deployment.id}"></script>`,
        dnsConfig: [
          `CNAME protection.${new URL(scanResult.url).hostname} shield.cyberdefense.gov`,
          `TXT ${new URL(scanResult.url).hostname} "cyberdefense-verification=${deploymentData.deployment.id}"`,
        ],
        monitoring: deploymentData.deployment.monitoring,
      }

      setDeployment(newDeployment)
      onDeploymentComplete(newDeployment)
    } catch (error) {
      console.error("Deployment failed:", error)
      setDeployment({
        ...deployment!,
        status: "error",
      })
    } finally {
      setDeploying(false)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <Shield className="w-6 h-6 text-green-400 mr-3" />
          <h2 className="text-xl font-bold text-green-400 font-mono">PROTECTION DEPLOYMENT</h2>
        </div>
        {!deployment && (
          <button
            onClick={deployProtection}
            disabled={deploying}
            className="bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm flex items-center space-x-2"
          >
            <Shield className="w-4 h-4" />
            <span>{deploying ? "DEPLOYING..." : "DEPLOY PROTECTION"}</span>
          </button>
        )}
      </div>

      {/* Deployment Progress */}
      {deploying && (
        <div className="mb-6">
          <div className="text-blue-400 text-sm font-mono mb-2">{deploymentStep}</div>
          <div className="w-full bg-gray-800 rounded-full h-2">
            <div className="bg-gradient-to-r from-blue-600 to-blue-400 h-2 rounded-full animate-pulse w-full" />
          </div>
        </div>
      )}

      {/* Deployment Status */}
      {deployment && (
        <div className="space-y-6">
          {/* Status Overview */}
          <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center space-x-3">
                <CheckCircle className="w-6 h-6 text-green-400" />
                <div>
                  <div className="text-green-400 font-mono font-bold">PROTECTION ACTIVE</div>
                  <div className="text-green-300 text-sm">{deployment.url}</div>
                </div>
              </div>
              <div className="text-green-400 font-mono text-sm">ID: {deployment.id}</div>
            </div>

            {/* Service Status */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              <div className="bg-gray-900/50 rounded p-3 text-center">
                <Globe className="w-5 h-5 text-blue-400 mx-auto mb-2" />
                <div className="text-blue-400 font-mono text-sm">CDN</div>
                <div className="text-green-400 text-xs">ACTIVE</div>
              </div>
              <div className="bg-gray-900/50 rounded p-3 text-center">
                <Shield className="w-5 h-5 text-red-400 mx-auto mb-2" />
                <div className="text-red-400 font-mono text-sm">WAF</div>
                <div className="text-green-400 text-xs">{deployment.services.waf.rules} RULES</div>
              </div>
              <div className="bg-gray-900/50 rounded p-3 text-center">
                <AlertTriangle className="w-5 h-5 text-yellow-400 mx-auto mb-2" />
                <div className="text-yellow-400 font-mono text-sm">DDoS</div>
                <div className="text-green-400 text-xs">{deployment.services.ddos.capacity}</div>
              </div>
              <div className="bg-gray-900/50 rounded p-3 text-center">
                <CheckCircle className="w-5 h-5 text-green-400 mx-auto mb-2" />
                <div className="text-green-400 font-mono text-sm">SSL</div>
                <div className="text-green-400 text-xs">GRADE {deployment.services.ssl.grade}</div>
              </div>
            </div>
          </div>

          {/* Integration Instructions */}
          <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4">
            <h4 className="text-lg font-bold text-blue-400 mb-4 font-mono flex items-center">
              <Code className="w-5 h-5 mr-2" />
              INTEGRATION STEPS
            </h4>

            <div className="space-y-4">
              {/* Step 1: Script Integration */}
              <div>
                <div className="text-blue-400 text-sm font-mono mb-2">1. Add Protection Script to Your Website:</div>
                <div className="bg-gray-900/50 p-3 rounded relative">
                  <code className="text-green-400 text-sm font-mono break-all">{deployment.protectionScript}</code>
                  <button
                    onClick={() => copyToClipboard(deployment.protectionScript)}
                    className="absolute top-2 right-2 text-blue-400 hover:text-blue-300"
                  >
                    <Download className="w-4 h-4" />
                  </button>
                </div>
                <div className="text-blue-300 text-xs mt-1">
                  Add this script before the closing &lt;/head&gt; tag on all pages
                </div>
              </div>

              {/* Step 2: DNS Configuration */}
              <div>
                <div className="text-blue-400 text-sm font-mono mb-2">2. Configure DNS Records:</div>
                <div className="space-y-2">
                  {deployment.dnsConfig.map((record, index) => (
                    <div key={index} className="bg-gray-900/50 p-3 rounded relative">
                      <code className="text-green-400 text-sm font-mono">{record}</code>
                      <button
                        onClick={() => copyToClipboard(record)}
                        className="absolute top-2 right-2 text-blue-400 hover:text-blue-300"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Step 3: API Key */}
              <div>
                <div className="text-blue-400 text-sm font-mono mb-2">3. Your API Key (Keep Secure):</div>
                <div className="bg-gray-900/50 p-3 rounded relative">
                  <div className="flex items-center justify-between">
                    <code className="text-green-400 text-sm font-mono">{deployment.apiKey}</code>
                    <div className="flex items-center space-x-2">
                      <Key className="w-4 h-4 text-yellow-400" />
                      <button
                        onClick={() => copyToClipboard(deployment.apiKey)}
                        className="text-blue-400 hover:text-blue-300"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Monitoring Dashboard */}
          <div className="bg-gray-900/50 rounded-lg p-4">
            <h4 className="text-lg font-bold text-green-400 mb-4 font-mono flex items-center">
              <Settings className="w-5 h-5 mr-2" />
              MONITORING & MANAGEMENT
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <div className="text-green-400 text-sm font-mono mb-2">Real-time Dashboard:</div>
                <div className="text-blue-400 text-sm underline cursor-pointer">{deployment.monitoring.endpoint}</div>
              </div>
              <div>
                <div className="text-green-400 text-sm font-mono mb-2">Alert System:</div>
                <div className="text-green-400 text-sm">{deployment.monitoring.alerts ? "ENABLED" : "DISABLED"}</div>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-4">
            <button className="bg-green-600 hover:bg-green-500 text-black font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm">
              VIEW DASHBOARD
            </button>
            <button className="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm">
              DOWNLOAD CONFIG
            </button>
            <button className="border border-green-500 text-green-400 hover:bg-green-500/10 font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm">
              TEST PROTECTION
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
