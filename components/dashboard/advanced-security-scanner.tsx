"use client"

import { useState, useEffect } from "react"
import {
  Shield,
  Search,
  Settings,
  Download,
  Play,
  Pause,
  RotateCcw,
  CheckCircle,
  Zap,
  Eye,
  Lock,
  Globe,
  Database,
  Code,
  Wifi,
  Server,
  Bug,
  Key,
} from "lucide-react"
import { useToast } from "@/hooks/use-toast"

interface SecurityTool {
  id: string
  name: string
  description: string
  category: "network" | "web" | "ssl" | "discovery" | "vulnerability" | "analysis"
  icon: any
  enabled: boolean
  status: "idle" | "running" | "completed" | "error"
  findings: number
  duration: number
  severity: "info" | "low" | "medium" | "high" | "critical"
  customOptions: Record<string, any>
}

interface ScanResult {
  scanId: string
  url: string
  timestamp: Date
  results: any[]
  report: any
  summary: any
  status: "running" | "completed" | "error"
  progress: number
}

export function AdvancedSecurityScanner() {
  const [url, setUrl] = useState("")
  const [scanDepth, setScanDepth] = useState<"basic" | "intermediate" | "advanced" | "comprehensive">("intermediate")
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [selectedTools, setSelectedTools] = useState<string[]>([])
  const [scanProgress, setScanProgress] = useState(0)
  const [currentTool, setCurrentTool] = useState("")
  const { toast } = useToast()

  const [securityTools, setSecurityTools] = useState<SecurityTool[]>([
    {
      id: "nmap",
      name: "Nmap",
      description: "Network discovery and security auditing",
      category: "network",
      icon: Wifi,
      enabled: true,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "nikto",
      name: "Nikto",
      description: "Web server scanner for vulnerabilities",
      category: "web",
      icon: Globe,
      enabled: true,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "sqlmap",
      name: "SQLMap",
      description: "Automatic SQL injection detection and exploitation",
      category: "vulnerability",
      icon: Database,
      enabled: true,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "dirb",
      name: "DIRB",
      description: "Web content scanner for hidden directories",
      category: "discovery",
      icon: Search,
      enabled: true,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "wpscan",
      name: "WPScan",
      description: "WordPress security scanner",
      category: "web",
      icon: Code,
      enabled: false,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "sslyze",
      name: "SSLyze",
      description: "SSL/TLS configuration analyzer",
      category: "ssl",
      icon: Lock,
      enabled: true,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "whatweb",
      name: "WhatWeb",
      description: "Web technology fingerprinting",
      category: "discovery",
      icon: Eye,
      enabled: true,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "nuclei",
      name: "Nuclei",
      description: "Fast vulnerability scanner with templates",
      category: "vulnerability",
      icon: Zap,
      enabled: true,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "subfinder",
      name: "Subfinder",
      description: "Subdomain discovery tool",
      category: "discovery",
      icon: Search,
      enabled: true,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "httpx",
      name: "HTTPX",
      description: "Fast HTTP toolkit for probing services",
      category: "discovery",
      icon: Globe,
      enabled: true,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "amass",
      name: "AMASS",
      description: "In-depth attack surface mapping",
      category: "discovery",
      icon: Search,
      enabled: false,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "gobuster",
      name: "Gobuster",
      description: "Directory/file & DNS busting tool",
      category: "discovery",
      icon: Search,
      enabled: true,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "masscan",
      name: "Masscan",
      description: "High-speed port scanner",
      category: "network",
      icon: Server,
      enabled: false,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "zap",
      name: "OWASP ZAP",
      description: "Web application security scanner",
      category: "web",
      icon: Bug,
      enabled: true,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
    {
      id: "testssl",
      name: "testssl.sh",
      description: "SSL/TLS implementation testing",
      category: "ssl",
      icon: Key,
      enabled: true,
      status: "idle",
      findings: 0,
      duration: 0,
      severity: "info",
      customOptions: {},
    },
  ])

  useEffect(() => {
    // Auto-select enabled tools
    setSelectedTools(securityTools.filter((tool) => tool.enabled).map((tool) => tool.id))
  }, [securityTools])

  const startAdvancedScan = async () => {
    if (!url || selectedTools.length === 0) {
      toast({
        title: "Invalid Configuration",
        description: "Please enter a URL and select at least one security tool",
        variant: "destructive",
      })
      return
    }

    setScanning(true)
    setScanProgress(0)
    setScanResult(null)

    try {
      // Update tool statuses
      setSecurityTools((prev) =>
        prev.map((tool) => (selectedTools.includes(tool.id) ? { ...tool, status: "running" as const } : tool)),
      )

      // Start the advanced scan
      const response = await fetch("/api/security/advanced-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url,
          tools: selectedTools,
          depth: scanDepth,
          customOptions: getCustomOptions(),
        }),
      })

      if (!response.ok) {
        throw new Error("Scan failed")
      }

      // Simulate progress updates
      const progressInterval = setInterval(() => {
        setScanProgress((prev) => {
          if (prev >= 95) {
            clearInterval(progressInterval)
            return 95
          }
          return prev + Math.random() * 10
        })
      }, 2000)

      // Update current tool being executed
      const toolInterval = setInterval(() => {
        const runningTools = selectedTools.filter((_, index) => index < (scanProgress / 100) * selectedTools.length)
        if (runningTools.length > 0) {
          const currentToolId = runningTools[runningTools.length - 1]
          const tool = securityTools.find((t) => t.id === currentToolId)
          setCurrentTool(tool?.name || "")
        }
      }, 1000)

      const result = await response.json()

      clearInterval(progressInterval)
      clearInterval(toolInterval)

      setScanProgress(100)
      setScanResult({
        ...result,
        status: "completed",
        progress: 100,
      })

      // Update tool statuses with results
      setSecurityTools((prev) =>
        prev.map((tool) => {
          const toolResult = result.results.find((r: any) => r.tool === tool.id)
          if (toolResult) {
            return {
              ...tool,
              status: toolResult.status === "success" ? "completed" : "error",
              findings: toolResult.findings.length,
              duration: toolResult.duration,
              severity: toolResult.severity,
            }
          }
          return tool
        }),
      )

      toast({
        title: "Scan Completed",
        description: `Advanced security scan completed with ${result.summary.total_findings} findings`,
      })
    } catch (error) {
      toast({
        title: "Scan Failed",
        description: "Advanced security scan failed. Please try again.",
        variant: "destructive",
      })

      setSecurityTools((prev) =>
        prev.map((tool) => (selectedTools.includes(tool.id) ? { ...tool, status: "error" as const } : tool)),
      )
    } finally {
      setScanning(false)
      setCurrentTool("")
    }
  }

  const toggleTool = (toolId: string) => {
    setSecurityTools((prev) => prev.map((tool) => (tool.id === toolId ? { ...tool, enabled: !tool.enabled } : tool)))
  }

  const toggleToolSelection = (toolId: string) => {
    setSelectedTools((prev) => (prev.includes(toolId) ? prev.filter((id) => id !== toolId) : [...prev, toolId]))
  }

  const getCustomOptions = () => {
    const options: Record<string, any> = {}
    securityTools.forEach((tool) => {
      if (selectedTools.includes(tool.id) && Object.keys(tool.customOptions).length > 0) {
        options[tool.id] = tool.customOptions
      }
    })
    return options
  }

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case "network":
        return Server
      case "web":
        return Globe
      case "ssl":
        return Lock
      case "discovery":
        return Search
      case "vulnerability":
        return Bug
      case "analysis":
        return Eye
      default:
        return Shield
    }
  }

  const getCategoryColor = (category: string) => {
    switch (category) {
      case "network":
        return "text-blue-400 border-blue-500"
      case "web":
        return "text-green-400 border-green-500"
      case "ssl":
        return "text-purple-400 border-purple-500"
      case "discovery":
        return "text-yellow-400 border-yellow-500"
      case "vulnerability":
        return "text-red-400 border-red-500"
      case "analysis":
        return "text-cyan-400 border-cyan-500"
      default:
        return "text-gray-400 border-gray-500"
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "running":
        return "text-yellow-400"
      case "completed":
        return "text-green-400"
      case "error":
        return "text-red-400"
      default:
        return "text-gray-400"
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "text-red-400"
      case "high":
        return "text-orange-400"
      case "medium":
        return "text-yellow-400"
      case "low":
        return "text-blue-400"
      default:
        return "text-green-400"
    }
  }

  const resetScan = () => {
    setScanResult(null)
    setScanProgress(0)
    setCurrentTool("")
    setSecurityTools((prev) =>
      prev.map((tool) => ({
        ...tool,
        status: "idle",
        findings: 0,
        duration: 0,
        severity: "info",
      })),
    )
  }

  return (
    <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <Shield className="w-6 h-6 text-green-400 mr-3" />
          <h2 className="text-2xl font-bold text-green-400 font-mono">ADVANCED SECURITY SCANNER</h2>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
          <span className="text-green-400 text-sm font-mono">15 TOOLS AVAILABLE</span>
        </div>
      </div>

      {/* Scan Configuration */}
      <div className="mb-6 space-y-4">
        <div className="flex space-x-4">
          <div className="flex-1">
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter target URL (e.g., https://example.com)"
              className="w-full bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 text-green-400 placeholder-green-600 focus:border-green-400 focus:outline-none transition-colors font-mono"
              disabled={scanning}
            />
          </div>
          <select
            value={scanDepth}
            onChange={(e) => setScanDepth(e.target.value as any)}
            className="bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 text-green-400 focus:border-green-400 focus:outline-none transition-colors font-mono"
            disabled={scanning}
          >
            <option value="basic">Basic Scan</option>
            <option value="intermediate">Intermediate Scan</option>
            <option value="advanced">Advanced Scan</option>
            <option value="comprehensive">Comprehensive Scan</option>
          </select>
        </div>

        <div className="flex justify-between items-center">
          <div className="text-green-400 text-sm font-mono">
            Selected Tools: {selectedTools.length} / {securityTools.length}
          </div>
          <div className="flex space-x-2">
            <button
              onClick={resetScan}
              disabled={scanning}
              className="bg-gray-600 hover:bg-gray-500 disabled:bg-gray-800 text-white font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm flex items-center space-x-2"
            >
              <RotateCcw className="w-4 h-4" />
              <span>RESET</span>
            </button>
            <button
              onClick={startAdvancedScan}
              disabled={scanning || !url || selectedTools.length === 0}
              className="bg-green-600 hover:bg-green-500 disabled:bg-green-800 text-black font-bold py-2 px-4 rounded-lg transition-all duration-300 transform hover:scale-105 disabled:scale-100 font-mono text-sm flex items-center space-x-2"
            >
              {scanning ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              <span>{scanning ? "SCANNING..." : "START SCAN"}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Scan Progress */}
      {scanning && (
        <div className="mb-6">
          <div className="flex justify-between text-sm text-green-300 mb-2">
            <span>Running: {currentTool || "Initializing..."}</span>
            <span>{Math.round(scanProgress)}%</span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-3">
            <div
              className="bg-gradient-to-r from-green-600 to-green-400 h-3 rounded-full transition-all duration-300"
              style={{ width: `${scanProgress}%` }}
            />
          </div>
        </div>
      )}

      {/* Security Tools Grid */}
      <div className="mb-6">
        <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">SECURITY TOOLS</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {securityTools.map((tool) => {
            const CategoryIcon = getCategoryIcon(tool.category)
            const ToolIcon = tool.icon

            return (
              <div
                key={tool.id}
                className={`bg-gray-900/50 rounded-lg p-4 border-l-4 ${
                  selectedTools.includes(tool.id) ? "border-l-green-500" : "border-l-gray-600"
                } hover:bg-gray-800/50 transition-colors cursor-pointer`}
                onClick={() => !scanning && toggleToolSelection(tool.id)}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-3">
                    <ToolIcon
                      className={`w-5 h-5 ${selectedTools.includes(tool.id) ? "text-green-400" : "text-gray-400"}`}
                    />
                    <div>
                      <div
                        className={`font-mono font-bold ${selectedTools.includes(tool.id) ? "text-green-400" : "text-gray-400"}`}
                      >
                        {tool.name}
                      </div>
                      <div className="text-green-300 text-xs">{tool.description}</div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={`text-xs px-2 py-1 rounded border ${getCategoryColor(tool.category)}`}>
                      {tool.category.toUpperCase()}
                    </span>
                    {selectedTools.includes(tool.id) && <CheckCircle className="w-4 h-4 text-green-400" />}
                  </div>
                </div>

                <div className="flex items-center justify-between text-xs">
                  <div className={`flex items-center space-x-1 ${getStatusColor(tool.status)}`}>
                    <div
                      className={`w-2 h-2 rounded-full ${
                        tool.status === "running"
                          ? "bg-yellow-400 animate-pulse"
                          : tool.status === "completed"
                            ? "bg-green-400"
                            : tool.status === "error"
                              ? "bg-red-400"
                              : "bg-gray-400"
                      }`}
                    ></div>
                    <span>{tool.status.toUpperCase()}</span>
                  </div>
                  {tool.findings > 0 && (
                    <div className={`${getSeverityColor(tool.severity)}`}>{tool.findings} findings</div>
                  )}
                  {tool.duration > 0 && <div className="text-green-300">{(tool.duration / 1000).toFixed(1)}s</div>}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Scan Results */}
      {scanResult && (
        <div className="space-y-6">
          {/* Executive Summary */}
          <div className="bg-gray-900/50 rounded-lg p-6">
            <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">EXECUTIVE SUMMARY</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-400 font-mono">{scanResult.summary.tools_executed}</div>
                <div className="text-green-300 text-sm">Tools Executed</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-400 font-mono">{scanResult.summary.total_findings}</div>
                <div className="text-green-300 text-sm">Total Findings</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-400 font-mono">{scanResult.summary.successful_scans}</div>
                <div className="text-green-300 text-sm">Successful Scans</div>
              </div>
              <div className="text-center">
                <div
                  className={`text-2xl font-bold font-mono ${getSeverityColor(scanResult.summary.highest_severity)}`}
                >
                  {scanResult.summary.highest_severity.toUpperCase()}
                </div>
                <div className="text-green-300 text-sm">Highest Severity</div>
              </div>
            </div>
          </div>

          {/* Detailed Results */}
          <div className="bg-gray-900/50 rounded-lg p-6">
            <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">DETAILED FINDINGS</h3>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {scanResult.results.map((result: any, index: number) => (
                <div key={index} className="bg-gray-800/50 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <div className="text-green-400 font-mono font-bold">{result.tool.toUpperCase()}</div>
                      <span className={`text-xs px-2 py-1 rounded border ${getSeverityColor(result.severity)}`}>
                        {result.severity.toUpperCase()}
                      </span>
                    </div>
                    <div className="text-green-300 text-sm">
                      {result.findings.length} findings in {(result.duration / 1000).toFixed(1)}s
                    </div>
                  </div>

                  {result.findings.slice(0, 3).map((finding: any, findingIndex: number) => (
                    <div key={findingIndex} className="text-green-200 text-sm mb-1">
                      • {finding.description || finding.type || JSON.stringify(finding)}
                    </div>
                  ))}

                  {result.findings.length > 3 && (
                    <div className="text-green-400 text-sm">+{result.findings.length - 3} more findings...</div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-4">
            <button className="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm flex items-center space-x-2">
              <Download className="w-4 h-4" />
              <span>DOWNLOAD REPORT</span>
            </button>
            <button className="bg-green-600 hover:bg-green-500 text-black font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm flex items-center space-x-2">
              <Shield className="w-4 h-4" />
              <span>DEPLOY PROTECTION</span>
            </button>
            <button className="border border-green-500 text-green-400 hover:bg-green-500/10 font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm flex items-center space-x-2">
              <Settings className="w-4 h-4" />
              <span>CONFIGURE MONITORING</span>
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
