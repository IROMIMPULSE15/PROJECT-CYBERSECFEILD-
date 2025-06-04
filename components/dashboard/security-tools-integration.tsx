"use client"

import { useState } from "react"
import {
  PenToolIcon as Tool,
  CheckCircle,
  AlertTriangle,
  Settings,
  Terminal,
  RefreshCw,
  Shield,
  Lock,
} from "lucide-react"

interface SecurityTool {
  id: string
  name: string
  category: "firewall" | "scanner" | "monitoring" | "encryption" | "authentication" | "analysis"
  status: "active" | "inactive" | "updating"
  version: string
  lastUpdated: Date
  description: string
  capabilities: string[]
  integrationStatus: {
    connected: boolean
    apiStatus: "healthy" | "degraded" | "error"
    dataSync: "real-time" | "hourly" | "daily" | "manual"
  }
}

export function SecurityToolsIntegration() {
  const [securityTools, setSecurityTools] = useState<SecurityTool[]>([
    {
      id: "tool-001",
      name: "ModSecurity WAF",
      category: "firewall",
      status: "active",
      version: "3.0.8",
      lastUpdated: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
      description: "Advanced Web Application Firewall with OWASP Core Rule Set integration",
      capabilities: [
        "SQL Injection Prevention",
        "XSS Attack Blocking",
        "Request Rate Limiting",
        "IP Reputation Checking",
        "Virtual Patching",
      ],
      integrationStatus: {
        connected: true,
        apiStatus: "healthy",
        dataSync: "real-time",
      },
    },
    {
      id: "tool-002",
      name: "Nessus Professional",
      category: "scanner",
      status: "active",
      version: "10.5.1",
      lastUpdated: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      description: "Comprehensive vulnerability scanner with CVE database integration",
      capabilities: [
        "Network Vulnerability Scanning",
        "Web Application Testing",
        "Configuration Auditing",
        "Malware Detection",
        "Compliance Checking",
      ],
      integrationStatus: {
        connected: true,
        apiStatus: "healthy",
        dataSync: "daily",
      },
    },
    {
      id: "tool-003",
      name: "Suricata IDS/IPS",
      category: "monitoring",
      status: "active",
      version: "6.0.12",
      lastUpdated: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000),
      description: "High-performance Network IDS, IPS and Network Security Monitoring engine",
      capabilities: [
        "Deep Packet Inspection",
        "Protocol Analysis",
        "Automatic Threat Blocking",
        "TLS/SSL Inspection",
        "File Extraction and Analysis",
      ],
      integrationStatus: {
        connected: true,
        apiStatus: "healthy",
        dataSync: "real-time",
      },
    },
    {
      id: "tool-004",
      name: "OWASP ZAP",
      category: "scanner",
      status: "inactive",
      version: "2.14.0",
      lastUpdated: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
      description: "Open-source web application security scanner",
      capabilities: ["Automated Scanning", "Spider Crawling", "Passive Scanning", "Active Scanning", "API Scanning"],
      integrationStatus: {
        connected: false,
        apiStatus: "error",
        dataSync: "manual",
      },
    },
    {
      id: "tool-005",
      name: "Splunk SIEM",
      category: "analysis",
      status: "active",
      version: "9.1.2",
      lastUpdated: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
      description: "Security Information and Event Management platform",
      capabilities: [
        "Log Aggregation",
        "Security Analytics",
        "Threat Intelligence",
        "Incident Response",
        "Compliance Reporting",
      ],
      integrationStatus: {
        connected: true,
        apiStatus: "degraded",
        dataSync: "hourly",
      },
    },
    {
      id: "tool-006",
      name: "Hashicorp Vault",
      category: "encryption",
      status: "updating",
      version: "1.15.2",
      lastUpdated: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
      description: "Secrets management and data protection platform",
      capabilities: [
        "Secret Management",
        "Encryption as a Service",
        "Key Rotation",
        "Dynamic Secrets",
        "PKI Management",
      ],
      integrationStatus: {
        connected: true,
        apiStatus: "degraded",
        dataSync: "hourly",
      },
    },
    {
      id: "tool-007",
      name: "CrowdStrike Falcon",
      category: "monitoring",
      status: "active",
      version: "7.2.0",
      lastUpdated: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      description: "Endpoint Detection and Response (EDR) platform",
      capabilities: [
        "Next-Gen Antivirus",
        "Threat Hunting",
        "Behavioral Monitoring",
        "Exploit Prevention",
        "Incident Response",
      ],
      integrationStatus: {
        connected: true,
        apiStatus: "healthy",
        dataSync: "real-time",
      },
    },
    {
      id: "tool-008",
      name: "Okta Identity Cloud",
      category: "authentication",
      status: "active",
      version: "2023.10.1",
      lastUpdated: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000),
      description: "Identity and access management platform",
      capabilities: [
        "Single Sign-On",
        "Multi-Factor Authentication",
        "Adaptive Authentication",
        "User Lifecycle Management",
        "API Access Management",
      ],
      integrationStatus: {
        connected: true,
        apiStatus: "healthy",
        dataSync: "real-time",
      },
    },
  ])

  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState("")

  const filteredTools = securityTools.filter((tool) => {
    const matchesCategory = selectedCategory ? tool.category === selectedCategory : true
    const matchesSearch = searchQuery
      ? tool.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        tool.description.toLowerCase().includes(searchQuery.toLowerCase())
      : true
    return matchesCategory && matchesSearch
  })

  const getToolCategoryIcon = (category: string) => {
    switch (category) {
      case "firewall":
        return <Shield className="w-4 h-4" />
      case "scanner":
        return <AlertTriangle className="w-4 h-4" />
      case "monitoring":
        return <Terminal className="w-4 h-4" />
      case "encryption":
        return <Lock className="w-4 h-4" />
      case "authentication":
        return <CheckCircle className="w-4 h-4" />
      case "analysis":
        return <Settings className="w-4 h-4" />
      default:
        return <Tool className="w-4 h-4" />
    }
  }

  const getToolCategoryColor = (category: string) => {
    switch (category) {
      case "firewall":
        return "text-red-400 border-red-500"
      case "scanner":
        return "text-yellow-400 border-yellow-500"
      case "monitoring":
        return "text-blue-400 border-blue-500"
      case "encryption":
        return "text-purple-400 border-purple-500"
      case "authentication":
        return "text-green-400 border-green-500"
      case "analysis":
        return "text-orange-400 border-orange-500"
      default:
        return "text-gray-400 border-gray-500"
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "active":
        return "text-green-400"
      case "inactive":
        return "text-red-400"
      case "updating":
        return "text-yellow-400"
      default:
        return "text-gray-400"
    }
  }

  const getApiStatusColor = (status: string) => {
    switch (status) {
      case "healthy":
        return "text-green-400"
      case "degraded":
        return "text-yellow-400"
      case "error":
        return "text-red-400"
      default:
        return "text-gray-400"
    }
  }

  const formatDate = (date: Date) => {
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    })
  }

  const categories = [
    { id: "firewall", name: "Firewall", icon: Shield },
    { id: "scanner", name: "Scanner", icon: AlertTriangle },
    { id: "monitoring", name: "Monitoring", icon: Terminal },
    { id: "encryption", name: "Encryption", icon: Lock },
    { id: "authentication", name: "Authentication", icon: CheckCircle },
    { id: "analysis", name: "Analysis", icon: Settings },
  ]

  return (
    <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <Tool className="w-6 h-6 text-green-400 mr-3" />
          <h2 className="text-xl font-bold text-green-400 font-mono">SECURITY TOOLS INTEGRATION</h2>
        </div>
        <button className="bg-green-600 hover:bg-green-500 text-black font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm flex items-center space-x-2">
          <RefreshCw className="w-4 h-4" />
          <span>UPDATE ALL</span>
        </button>
      </div>

      {/* Search and Filter */}
      <div className="flex flex-col md:flex-row gap-4 mb-6">
        <div className="flex-1">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search security tools..."
            className="w-full bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-2 text-green-400 placeholder-green-600 focus:border-green-400 focus:outline-none transition-colors font-mono"
          />
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => setSelectedCategory(null)}
            className={`px-3 py-1 rounded-lg text-xs font-mono ${
              selectedCategory === null
                ? "bg-green-600 text-black"
                : "border border-green-500/30 text-green-400 hover:bg-green-500/10"
            }`}
          >
            ALL
          </button>
          {categories.map((category) => (
            <button
              key={category.id}
              onClick={() => setSelectedCategory(category.id)}
              className={`px-3 py-1 rounded-lg text-xs font-mono flex items-center space-x-1 ${
                selectedCategory === category.id
                  ? "bg-green-600 text-black"
                  : "border border-green-500/30 text-green-400 hover:bg-green-500/10"
              }`}
            >
              <category.icon className="w-3 h-3" />
              <span>{category.name}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Tools Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredTools.map((tool) => (
          <div key={tool.id} className="bg-gray-900/50 rounded-lg p-4 border-l-4 border-l-green-500">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-3">
                {getToolCategoryIcon(tool.category)}
                <div>
                  <div className="text-green-400 font-mono font-bold">{tool.name}</div>
                  <div className="text-green-300 text-xs">v{tool.version}</div>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <span className={`text-xs px-2 py-1 rounded border ${getToolCategoryColor(tool.category)}`}>
                  {tool.category.toUpperCase()}
                </span>
                <div className={`flex items-center space-x-1 ${getStatusColor(tool.status)}`}>
                  <div
                    className={`w-2 h-2 rounded-full ${
                      tool.status === "active"
                        ? "bg-green-400 animate-pulse"
                        : tool.status === "updating"
                          ? "bg-yellow-400"
                          : "bg-red-400"
                    }`}
                  ></div>
                  <span className="text-xs">{tool.status.toUpperCase()}</span>
                </div>
              </div>
            </div>

            <div className="mb-3">
              <div className="text-green-300 text-sm">{tool.description}</div>
            </div>

            <div className="mb-3">
              <div className="text-green-400 text-xs font-mono mb-1">CAPABILITIES:</div>
              <div className="flex flex-wrap gap-2">
                {tool.capabilities.slice(0, 3).map((capability, index) => (
                  <span key={index} className="bg-gray-800/50 text-green-300 px-2 py-1 rounded text-xs">
                    {capability}
                  </span>
                ))}
                {tool.capabilities.length > 3 && (
                  <span className="bg-gray-800/50 text-green-300 px-2 py-1 rounded text-xs">
                    +{tool.capabilities.length - 3} more
                  </span>
                )}
              </div>
            </div>

            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center space-x-4">
                <div>
                  <span className="text-green-300">API:</span>{" "}
                  <span className={getApiStatusColor(tool.integrationStatus.apiStatus)}>
                    {tool.integrationStatus.apiStatus.toUpperCase()}
                  </span>
                </div>
                <div>
                  <span className="text-green-300">Sync:</span>{" "}
                  <span className="text-blue-400">{tool.integrationStatus.dataSync.toUpperCase()}</span>
                </div>
              </div>
              <div className="text-green-300">Updated: {formatDate(tool.lastUpdated)}</div>
            </div>
          </div>
        ))}
      </div>

      {filteredTools.length === 0 && (
        <div className="bg-gray-900/50 rounded-lg p-8 text-center">
          <Tool className="w-12 h-12 text-green-400/50 mx-auto mb-4" />
          <p className="text-green-300">No security tools match your filters</p>
        </div>
      )}
    </div>
  )
}
