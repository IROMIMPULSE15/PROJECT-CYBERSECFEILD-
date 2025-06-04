"use client"

import { useState, useEffect } from "react"
import { Brain, AlertTriangle, Eye, Target } from "lucide-react"

interface ThreatAnalysis {
  id: string
  timestamp: Date
  threatType: string
  severity: "low" | "medium" | "high" | "critical"
  confidence: number
  description: string
  indicators: string[]
  mitigationSteps: string[]
  aiModel: string
  analysisTime: number
  relatedThreats: string[]
  geolocation: {
    country: string
    region: string
    coordinates: [number, number]
  }
  attackVector: string
  potentialImpact: string
}

export function AIThreatAnalyzer() {
  const [analyses, setAnalyses] = useState<ThreatAnalysis[]>([])
  const [selectedAnalysis, setSelectedAnalysis] = useState<ThreatAnalysis | null>(null)
  const [realTimeStats, setRealTimeStats] = useState({
    threatsAnalyzed: 0,
    averageConfidence: 0,
    criticalThreats: 0,
    responseTime: 0
  })

  useEffect(() => {
    // Load initial threat analyses
    const mockAnalyses: ThreatAnalysis[] = [
      {
        id: "analysis-001",
        timestamp: new Date(Date.now() - 15 * 60 * 1000),
        threatType: "Advanced Persistent Threat (APT)",
        severity: "critical",
        confidence: 94.7,
        description: "Sophisticated multi-stage attack detected with characteristics matching known APT groups. The attack shows signs of lateral movement and data exfiltration attempts.",
        indicators: [
          "Unusual outbound network traffic to known C&C servers",
          "PowerShell execution with encoded commands",
          "Registry modifications for persistence",
          "Credential dumping attempts detected"
        ],
        mitigationSteps: [
          "Isolate affected systems immediately",
          "Reset all administrative credentials",
          "Deploy additional monitoring on network segments",
          "Conduct forensic analysis of compromised systems"
        ],
        aiModel: "GPT-4o + Custom Threat Intelligence",
        analysisTime: 0.8,
        relatedThreats: ["Lazarus Group", "APT29", "Carbanak"],
        geolocation: {
          country: "Unknown (TOR)",
          region: "Eastern Europe",
          coordinates: [50.4501, 30.5234]
        },
        attackVector: "Spear-phishing email with malicious attachment",
        potentialImpact: "Data exfiltration, system compromise, financial loss"
      },
      {
        id: "analysis-002",
        timestamp: new Date(Date.now() - 45 * 60 * 1000),
        threatType: "SQL Injection Attack",
        severity: "high",
        confidence: 98.2,
        description: "Automated SQL injection attack targeting user authentication endpoints. Attack patterns suggest use of SQLMap or similar tools.",
        indicators: [
          "Multiple UNION SELECT statements in request parameters",
          "Time-based blind injection techniques",
          "Error-based injection attempts",
          "Database enumeration queries"
        ],
        mitigationSteps: [
          "Block source IP immediately",
          "Review and patch vulnerable endpoints",
          "Implement parameterized queries",
          "Enable WAF rules for SQL injection"
        ],
        aiModel: "Claude 3 Opus + Security Pattern Recognition",
        analysisTime: 0.3,
        relatedThreats: ["SQLMap", "Havij", "Automated scanners"],
        geolocation: {
          country: "Russia",
          region: "Moscow",
          coordinates: [55.7558, 37.6176]
        },
        attackVector: "Direct web application attack",
        potentialImpact: "Database compromise, data theft, authentication bypass"
      },
      {
        id: "analysis-003",
        timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
        threatType: "Distributed Denial of Service (DDoS)",
        severity: "high",
        confidence: 96.8,
        description: "Large-scale DDoS attack utilizing compromised IoT devices. Traffic patterns indicate Mirai botnet variant with enhanced evasion techniques.",
        indicators: [
          "Traffic spike from 15,000+ unique IPs",
          "IoT device user agents detected",
          "Randomized request patterns",
          "Geographic distribution across 45 countries"
        ],
        mitigationSteps: [
          "Activate DDoS mitigation services",
          "Implement rate limiting",
          "Block IoT device signatures",
          "Coordinate with ISPs for upstream filtering"
        ],
        aiModel: "Gemini 1.5 Pro + Traffic Analysis Engine",
        analysisTime: 1.2,
        relatedThreats: ["Mirai", "Gafgyt", "IoT botnets"],
        geolocation: {
          country: "Multiple",
          region: "Global",
          coordinates: [0, 0]
        },
        attackVector: "Volumetric network flood",
        potentialImpact: "Service disruption, infrastructure overload, revenue loss"
      }
    ]

    setAnalyses(mockAnalyses)
    setSelectedAnalysis(mockAnalyses[0])

    // Update real-time stats
    setRealTimeStats({
      threatsAnalyzed: 1247,
      averageConfidence: 94.2,
      criticalThreats: 23,
      responseTime: 0.7
    })

    // Simulate real-time threat analysis
    const interval = setInterval(() => {
      if (Math.random() > 0.8) {
        const threatTypes = [
          "Malware Detection",
          "Phishing Attempt",
          "Brute Force Attack",
          "Cross-Site Scripting",
          "Command Injection",
          "File Upload Vulnerability"
        ]

        const severities: ("low" | "medium" | "high" | "critical")[] = ["low", "medium", "high", "critical"]
        const models = [
          "GPT-4o + Threat Intelligence",
          "Claude 3 Opus + Pattern Recognition",
          "Gemini 1.5 Pro + Behavioral Analysis",
          "Custom LLM Ensemble"
        ]

        const newAnalysis: ThreatAnalysis = {
          id: `analysis-${Date.now()}`,
          timestamp: new Date(),
          threatType: threatTypes[Math.floor(Math.random() * threatTypes.length)],
          severity: severities[Math.floor(Math.random() * severities.length)],
          confidence: Math.random() * 20 + 80,
          description: "Real-time threat detected and analyzed by AI security agents",
          indicators: ["Suspicious network activity", "Anomalous user behavior", "Malicious payload detected"],
          mitigationSteps: ["Block source", "Update security rules", "Monitor for similar patterns"],
          aiModel: models[Math.floor(Math.random() * models.length)],
          analysisTime: Math.random() * 2 + 0.1,
          relatedThreats: ["Unknown threat actor"],
          geolocation: {
            country: ["USA", "China", "Russia", "Unknown"][Math.floor(Math.random() * 4)],
            region: "Unknown",
            coordinates: [Math.random() * 180 - 90, Math.random() * 360 - 180]
          },
          attackVector: "Network-based attack",
          potentialImpact: "System compromise"
        }

        setAnalyses(prev => [newAnalysis, ...prev.slice(0, 9)])
        setRealTimeStats(prev => ({
          ...prev,
          threatsAnalyzed: prev.threatsAnalyzed + 1,
          criticalThreats: prev.criticalThreats + (newAnalysis.severity === "critical" ? 1 : 0)
        }))
      }
    }, 8000)

    return () => clearInterval(interval)
  }, [])

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "text-red-400 border-red-500"
      case "high": return "text-orange-400 border-orange-500"
      case "medium": return "text-yellow-400 border-yellow-500"
      case "low": return "text-green-400 border-green-500"
      default: return "text-gray-400 border-gray-500"
    }
  }

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 90) return "text-green-400"
    if (confidence >= 70) return "text-yellow-400"
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
          <Brain className="w-6 h-6 text-green-400 mr-3" />
          <h2 className="text-xl font-bold text-green-400 font-mono">AI THREAT ANALYZER</h2>
        </div>
        <div className="flex items-center space-x-2">
          <Eye className="w-4 h-4 text-blue-400" />
          <span className="text-blue-400 text-sm font-mono">NEURAL ANALYSIS ACTIVE</span>
        </div>
      </div>

      {/* Real-time Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-blue-400 font-mono">{realTimeStats.threatsAnalyzed}</div>
          <div className="text-xs text-green-300">THREATS ANALYZED</div>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-green-400 font-mono">{realTimeStats.averageConfidence.toFixed(1)}%</div>
          <div className="text-xs text-green-300">AVG CONFIDENCE</div>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-red-400 font-mono">{realTimeStats.criticalThreats}</div>
          <div className="text-xs text-green-300">CRITICAL THREATS</div>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-yellow-400 font-mono">{realTimeStats.responseTime}s</div>
          <div className="text-xs text-green-300">RESPONSE TIME</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Analysis List */}
        <div className="lg:col-span-1">
          <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">RECENT ANALYSES</h3>
          <div className="space-y-3 max-h-[500px] overflow-y-auto">
            {analyses.map((analysis) => (
              <div
                key={analysis.id}
                onClick={() => setSelectedAnalysis(analysis)}
                className={`bg-gray-900/50 rounded-lg p-3 cursor-pointer hover:bg-gray-800/50 transition-colors ${selectedAnalysis?.id === analysis.id ? "border border-green-500" : ""}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <Target className="w-4 h-4 text-red-400" />
                    <span className={`text-xs px-2 py-1 rounded border ${getSeverityColor(analysis.severity)}`}>
                      {analysis.severity.toUpperCase()}
                    </span>
                  </div>
                  <span className={`text-xs font-mono ${getConfidenceColor(analysis.confidence)}`}>
                    {analysis.confidence.toFixed(1)}%
                  </span>
                </div>
                <div className="text-green-400 font-bold text-sm mb-1">{analysis.threatType}</div>
                <div className="text-green-300 text-xs">{formatTime(analysis.timestamp)}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Detailed Analysis */}
        <div className="lg:col-span-2">
          <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">THREAT ANALYSIS DETAILS</h3>
          {selectedAnalysis ? (
            <div className="bg-gray-900/50 rounded-lg p-4">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <AlertTriangle className={`w-5 h-5 ${getSeverityColor(selectedAnalysis.severity)
