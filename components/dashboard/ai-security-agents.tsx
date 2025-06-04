"use client"

import { useState, useEffect } from "react"
import { Brain, Zap, AlertTriangle, CheckCircle, Eye, Shield, Bot, Cpu } from "lucide-react"

interface AIAgent {
  id: string
  name: string
  type: "detection" | "prevention" | "analysis" | "response"
  status: "active" | "learning" | "idle"
  model: string
  capabilities: string[]
  lastAction: {
    timestamp: Date
    description: string
    result: string
  }
  performance: {
    accuracy: number
    latency: number
    falsePositives: number
  }
}

interface AIInsight {
  id: string
  timestamp: Date
  agentId: string
  severity: "info" | "warning" | "critical"
  title: string
  description: string
  recommendation: string
}

export function AISecurityAgents() {
  const [agents, setAgents] = useState<AIAgent[]>([])
  const [insights, setInsights] = useState<AIInsight[]>([])
  const [selectedAgent, setSelectedAgent] = useState<AIAgent | null>(null)
  const [agentMetrics, setAgentMetrics] = useState({
    threatsDetected: 247,
    attacksPrevented: 189,
    averageResponseTime: 0.8,
    learningProgress: 94,
  })

  useEffect(() => {
    // Load AI security agents
    const mockAgents: AIAgent[] = [
      {
        id: "agent-001",
        name: "SENTINEL",
        type: "detection",
        status: "active",
        model: "GPT-4o",
        capabilities: [
          "Traffic pattern analysis",
          "Anomaly detection",
          "User behavior profiling",
          "Zero-day threat identification",
        ],
        lastAction: {
          timestamp: new Date(Date.now() - 5 * 60 * 1000),
          description: "Analyzed login patterns across 1,247 sessions",
          result: "Identified 3 suspicious access attempts from unusual geolocations",
        },
        performance: {
          accuracy: 98.7,
          latency: 0.3,
          falsePositives: 0.5,
        },
      },
      {
        id: "agent-002",
        name: "GUARDIAN",
        type: "prevention",
        status: "active",
        model: "Claude 3 Opus",
        capabilities: [
          "Real-time threat neutralization",
          "Adaptive firewall rule generation",
          "Attack surface reduction",
          "Deception technology deployment",
        ],
        lastAction: {
          timestamp: new Date(Date.now() - 12 * 60 * 1000),
          description: "Detected SQL injection attempt on authentication endpoint",
          result: "Generated WAF rule and blocked source IP range",
        },
        performance: {
          accuracy: 99.2,
          latency: 0.2,
          falsePositives: 0.3,
        },
      },
      {
        id: "agent-003",
        name: "ANALYST",
        type: "analysis",
        status: "learning",
        model: "Gemini 1.5 Pro",
        capabilities: [
          "Threat intelligence correlation",
          "Attack chain reconstruction",
          "Vulnerability prioritization",
          "Security posture assessment",
        ],
        lastAction: {
          timestamp: new Date(Date.now() - 45 * 60 * 1000),
          description: "Analyzed 24 security incidents from the past week",
          result: "Identified pattern suggesting targeted campaign against admin interfaces",
        },
        performance: {
          accuracy: 96.5,
          latency: 1.2,
          falsePositives: 1.8,
        },
      },
      {
        id: "agent-004",
        name: "RESPONDER",
        type: "response",
        status: "active",
        model: "Custom LLM Ensemble",
        capabilities: [
          "Incident response automation",
          "System recovery orchestration",
          "Evidence preservation",
          "Post-incident analysis",
        ],
        lastAction: {
          timestamp: new Date(Date.now() - 3 * 60 * 60 * 1000),
          description: "Coordinated response to DDoS attack on primary API endpoint",
          result: "Mitigated attack within 47 seconds with zero downtime",
        },
        performance: {
          accuracy: 97.8,
          latency: 0.5,
          falsePositives: 0.7,
        },
      },
    ]

    setAgents(mockAgents)
    setSelectedAgent(mockAgents[0])

    // Load AI insights
    const mockInsights: AIInsight[] = [
      {
        id: "insight-001",
        timestamp: new Date(Date.now() - 35 * 60 * 1000),
        agentId: "agent-001",
        severity: "critical",
        title: "Credential Stuffing Attack Detected",
        description:
          "Pattern analysis indicates a coordinated credential stuffing attack using credentials from the recent DataVault breach. 247 login attempts from 13 different IP ranges detected.",
        recommendation:
          "Implement CAPTCHA for all login attempts, force password reset for potentially affected accounts, and deploy additional rate limiting.",
      },
      {
        id: "insight-002",
        timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
        agentId: "agent-003",
        severity: "warning",
        title: "Outdated Dependencies Vulnerability",
        description:
          "Security analysis of your application dependencies revealed 3 packages with known vulnerabilities (CVE-2023-45127, CVE-2024-21567).",
        recommendation:
          "Update react-server-components to version 1.4.2 or higher and sanitize-html to version 2.10.0.",
      },
      {
        id: "insight-003",
        timestamp: new Date(Date.now() - 8 * 60 * 60 * 1000),
        agentId: "agent-002",
        severity: "info",
        title: "Security Headers Optimization",
        description:
          "Your website is missing recommended security headers: Content-Security-Policy, X-Content-Type-Options, and X-Frame-Options.",
        recommendation:
          "Implement the missing security headers to improve your security posture and prevent common web vulnerabilities.",
      },
      {
        id: "insight-004",
        timestamp: new Date(Date.now() - 15 * 60 * 1000),
        agentId: "agent-004",
        severity: "critical",
        title: "Potential Data Exfiltration Attempt",
        description:
          "Unusual data transfer patterns detected from your database server to external IP 185.173.35.42. Approximately 2.7GB of data transferred over the last 48 hours.",
        recommendation:
          "Immediately block the suspicious IP, audit database access logs, and initiate incident response procedures.",
      },
    ]

    setInsights(mockInsights)

    // Simulate real-time updates
    const interval = setInterval(() => {
      // Update agent statuses and actions
      setAgents((prevAgents) => {
        return prevAgents.map((agent) => {
          if (Math.random() > 0.7) {
            const actions = [
              "Analyzed user login patterns",
              "Scanned for SQL injection vulnerabilities",
              "Monitored API request patterns",
              "Evaluated authentication attempts",
              "Inspected file upload contents",
            ]

            const results = [
              "No anomalies detected",
              "Blocked suspicious IP address",
              "Updated security rules",
              "Generated threat intelligence report",
              "Identified potential vulnerability",
            ]

            return {
              ...agent,
              status: Math.random() > 0.8 ? "learning" : "active",
              lastAction: {
                timestamp: new Date(),
                description: actions[Math.floor(Math.random() * actions.length)],
                result: results[Math.floor(Math.random() * results.length)],
              },
            }
          }
          return agent
        })
      })

      // Update metrics
      setAgentMetrics((prev) => ({
        ...prev,
        threatsDetected: prev.threatsDetected + Math.floor(Math.random() * 3),
        attacksPrevented: prev.attacksPrevented + Math.floor(Math.random() * 2),
        averageResponseTime: Number.parseFloat((prev.averageResponseTime + (Math.random() * 0.2 - 0.1)).toFixed(1)),
        learningProgress: Math.min(100, prev.learningProgress + Math.random() * 0.5),
      }))
    }, 10000)

    return () => clearInterval(interval)
  }, [])

  const getAgentTypeColor = (type: string) => {
    switch (type) {
      case "detection":
        return "text-blue-400 border-blue-500"
      case "prevention":
        return "text-green-400 border-green-500"
      case "analysis":
        return "text-yellow-400 border-yellow-500"
      case "response":
        return "text-red-400 border-red-500"
      default:
        return "text-gray-400 border-gray-500"
    }
  }

  const getAgentTypeIcon = (type: string) => {
    switch (type) {
      case "detection":
        return <Eye className="w-4 h-4" />
      case "prevention":
        return <Shield className="w-4 h-4" />
      case "analysis":
        return <Brain className="w-4 h-4" />
      case "response":
        return <Zap className="w-4 h-4" />
      default:
        return <Bot className="w-4 h-4" />
    }
  }

  const getAgentStatusColor = (status: string) => {
    switch (status) {
      case "active":
        return "text-green-400"
      case "learning":
        return "text-blue-400"
      case "idle":
        return "text-yellow-400"
      default:
        return "text-gray-400"
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "text-red-400 border-red-500"
      case "warning":
        return "text-yellow-400 border-yellow-500"
      case "info":
        return "text-blue-400 border-blue-500"
      default:
        return "text-gray-400 border-gray-500"
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "critical":
        return <AlertTriangle className="w-4 h-4" />
      case "warning":
        return <AlertTriangle className="w-4 h-4" />
      case "info":
        return <CheckCircle className="w-4 h-4" />
      default:
        return <CheckCircle className="w-4 h-4" />
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
        <div className="flex items-center">
          <Brain className="w-6 h-6 text-green-400 mr-3" />
          <h2 className="text-xl font-bold text-green-400 font-mono">AI SECURITY AGENTS</h2>
        </div>
        <div className="flex items-center space-x-2">
          <Cpu className="w-4 h-4 text-blue-400" />
          <span className="text-blue-400 text-sm font-mono">NEURAL NETWORK ACTIVE</span>
        </div>
      </div>

      {/* Agent Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-red-400 font-mono">{agentMetrics.threatsDetected}</div>
          <div className="text-xs text-green-300">THREATS DETECTED</div>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-green-400 font-mono">{agentMetrics.attacksPrevented}</div>
          <div className="text-xs text-green-300">ATTACKS PREVENTED</div>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-blue-400 font-mono">{agentMetrics.averageResponseTime}s</div>
          <div className="text-xs text-green-300">AVG RESPONSE TIME</div>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-yellow-400 font-mono">{agentMetrics.learningProgress}%</div>
          <div className="text-xs text-green-300">LEARNING PROGRESS</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* AI Agents List */}
        <div className="lg:col-span-1">
          <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">ACTIVE AGENTS</h3>
          <div className="space-y-3 max-h-[400px] overflow-y-auto">
            {agents.map((agent) => (
              <div
                key={agent.id}
                onClick={() => setSelectedAgent(agent)}
                className={`bg-gray-900/50 rounded-lg p-3 cursor-pointer hover:bg-gray-800/50 transition-colors ${selectedAgent?.id === agent.id ? "border border-green-500" : ""}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <Bot className={`w-4 h-4 ${getAgentTypeColor(agent.type)}`} />
                    <span className="text-green-400 font-mono font-bold">{agent.name}</span>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded border ${getAgentTypeColor(agent.type)}`}>
                    {agent.type.toUpperCase()}
                  </span>
                </div>
                <div className="text-green-300 text-sm mb-1">Model: {agent.model}</div>
                <div className="flex items-center justify-between text-xs">
                  <div className={`flex items-center space-x-1 ${getAgentStatusColor(agent.status)}`}>
                    <div
                      className={`w-2 h-2 rounded-full ${agent.status === "active" ? "bg-green-400 animate-pulse" : agent.status === "learning" ? "bg-blue-400" : "bg-yellow-400"}`}
                    ></div>
                    <span>{agent.status.toUpperCase()}</span>
                  </div>
                  <span className="text-green-200">{formatTime(agent.lastAction.timestamp)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Selected Agent Details */}
        <div className="lg:col-span-2">
          <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">AGENT DETAILS</h3>
          {selectedAgent ? (
            <div className="bg-gray-900/50 rounded-lg p-4">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  {getAgentTypeIcon(selectedAgent.type)}
                  <div>
                    <div className="text-green-400 font-mono font-bold">{selectedAgent.name}</div>
                    <div className="text-green-300 text-sm">{selectedAgent.model} AI Model</div>
                  </div>
                </div>
                <div className={`flex items-center space-x-2 ${getAgentStatusColor(selectedAgent.status)}`}>
                  <div
                    className={`w-2 h-2 rounded-full ${selectedAgent.status === "active" ? "bg-green-400 animate-pulse" : selectedAgent.status === "learning" ? "bg-blue-400" : "bg-yellow-400"}`}
                  ></div>
                  <span className="text-sm font-mono">{selectedAgent.status.toUpperCase()}</span>
                </div>
              </div>

              <div className="mb-4">
                <div className="text-green-400 text-xs font-mono mb-2">CAPABILITIES</div>
                <div className="space-y-1">
                  {selectedAgent.capabilities.map((capability, index) => (
                    <div key={index} className="flex items-center text-sm text-green-300">
                      <div className="w-2 h-2 bg-green-400 rounded-full mr-2" />
                      {capability}
                    </div>
                  ))}
                </div>
              </div>

              <div className="mb-4">
                <div className="text-green-400 text-xs font-mono mb-2">LAST ACTION</div>
                <div className="bg-blue-900/20 border border-blue-500/30 p-3 rounded">
                  <div className="text-blue-300 text-sm mb-1">{selectedAgent.lastAction.description}</div>
                  <div className="text-blue-400 text-sm">Result: {selectedAgent.lastAction.result}</div>
                  <div className="text-blue-300 text-xs mt-1">{formatTime(selectedAgent.lastAction.timestamp)}</div>
                </div>
              </div>

              <div>
                <div className="text-green-400 text-xs font-mono mb-2">PERFORMANCE METRICS</div>
                <div className="grid grid-cols-3 gap-3">
                  <div className="bg-gray-900/50 rounded p-2 text-center">
                    <div className="text-green-400 font-mono font-bold">{selectedAgent.performance.accuracy}%</div>
                    <div className="text-xs text-green-300">ACCURACY</div>
                  </div>
                  <div className="bg-gray-900/50 rounded p-2 text-center">
                    <div className="text-blue-400 font-mono font-bold">{selectedAgent.performance.latency}s</div>
                    <div className="text-xs text-green-300">LATENCY</div>
                  </div>
                  <div className="bg-gray-900/50 rounded p-2 text-center">
                    <div className="text-yellow-400 font-mono font-bold">
                      {selectedAgent.performance.falsePositives}%
                    </div>
                    <div className="text-xs text-green-300">FALSE POSITIVES</div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-gray-900/50 rounded-lg p-8 text-center">
              <Bot className="w-12 h-12 text-green-400/50 mx-auto mb-4" />
              <p className="text-green-300">Select an AI agent to view details</p>
            </div>
          )}
        </div>
      </div>

      {/* AI Insights */}
      <div className="mt-6">
        <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">AI SECURITY INSIGHTS</h3>
        <div className="space-y-3">
          {insights.map((insight) => (
            <div key={insight.id} className="bg-gray-900/50 rounded-lg p-4 border-l-4 border-l-blue-500">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center space-x-3">
                  {getSeverityIcon(insight.severity)}
                  <div className="text-green-400 font-mono font-bold">{insight.title}</div>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`text-xs px-2 py-1 rounded border ${getSeverityColor(insight.severity)}`}>
                    {insight.severity.toUpperCase()}
                  </span>
                  <span className="text-green-300 text-xs">{formatTime(insight.timestamp)}</span>
                </div>
              </div>

              <div className="mb-3">
                <div className="text-green-300 text-sm">{insight.description}</div>
              </div>

              <div>
                <div className="text-green-400 text-xs font-mono mb-1">RECOMMENDATION:</div>
                <div className="text-yellow-300 text-sm">{insight.recommendation}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
