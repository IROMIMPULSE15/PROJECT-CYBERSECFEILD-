"use client"

import { useState } from "react"
import { Globe, Search, AlertTriangle, CheckCircle, XCircle } from "lucide-react"

interface ScanResult {
  category: string
  status: "safe" | "warning" | "danger"
  score: number
  details: string[]
  recommendations: string[]
}

interface WebsiteData {
  url: string
  title: string
  ip: string
  server: string
  ssl: boolean
  loadTime: number
  size: string
  technologies: string[]
}

export function WebsiteAnalyzer() {
  const [url, setUrl] = useState("")
  const [scanning, setScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [websiteData, setWebsiteData] = useState<WebsiteData | null>(null)
  const [scanResults, setScanResults] = useState<ScanResult[]>([])
  const [overallScore, setOverallScore] = useState(0)
  const [currentScanStep, setCurrentScanStep] = useState("")

  const scanSteps = [
    "Analyzing DNS configuration...",
    "Checking SSL/TLS certificates...",
    "Scanning for vulnerabilities...",
    "Testing security headers...",
    "Analyzing user behavior patterns...",
    "Checking for malware signatures...",
    "Validating authentication systems...",
    "Testing DDoS protection...",
    "Analyzing traffic patterns...",
    "Generating security report...",
  ]

  const performScan = async () => {
    if (!url) return

    setScanning(true)
    setScanProgress(0)
    setScanResults([])
    setWebsiteData(null)

    // Simulate comprehensive scanning process
    for (let i = 0; i < scanSteps.length; i++) {
      setCurrentScanStep(scanSteps[i])
      setScanProgress((i + 1) * 10)
      await new Promise((resolve) => setTimeout(resolve, 1500))
    }

    // Generate mock website data
    const mockWebsiteData: WebsiteData = {
      url: url,
      title: `${url.replace(/https?:\/\//, "").split(".")[0]} - Official Website`,
      ip: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      server: ["Apache/2.4.41", "Nginx/1.18.0", "Cloudflare", "AWS CloudFront"][Math.floor(Math.random() * 4)],
      ssl: Math.random() > 0.2,
      loadTime: Math.random() * 3 + 0.5,
      size: `${(Math.random() * 5 + 1).toFixed(1)}MB`,
      technologies: ["React", "Node.js", "MongoDB", "Redis", "Docker", "Kubernetes"].slice(
        0,
        Math.floor(Math.random() * 4) + 2,
      ),
    }

    // Generate comprehensive scan results
    const mockResults: ScanResult[] = [
      {
        category: "SSL/TLS Security",
        status: mockWebsiteData.ssl ? "safe" : "danger",
        score: mockWebsiteData.ssl ? 95 : 20,
        details: mockWebsiteData.ssl
          ? ["Valid SSL certificate", "TLS 1.3 supported", "Strong cipher suites", "HSTS enabled"]
          : ["No SSL certificate", "Insecure connection", "Data transmission vulnerable"],
        recommendations: mockWebsiteData.ssl
          ? ["Consider certificate pinning", "Enable OCSP stapling"]
          : ["Install SSL certificate immediately", "Redirect HTTP to HTTPS", "Enable HSTS"],
      },
      {
        category: "Vulnerability Assessment",
        status: Math.random() > 0.7 ? "danger" : Math.random() > 0.4 ? "warning" : "safe",
        score: Math.floor(Math.random() * 40) + 60,
        details: [
          "SQL injection tests: Passed",
          "XSS vulnerability scan: 2 potential issues found",
          "CSRF protection: Active",
          "Directory traversal: Secure",
        ],
        recommendations: [
          "Update outdated JavaScript libraries",
          "Implement Content Security Policy",
          "Add input validation for user forms",
        ],
      },
      {
        category: "User Authentication",
        status: Math.random() > 0.6 ? "safe" : "warning",
        score: Math.floor(Math.random() * 30) + 70,
        details: [
          "Password policy: Strong requirements",
          "Two-factor authentication: Available",
          "Session management: Secure",
          "Login attempt monitoring: Active",
        ],
        recommendations: [
          "Implement biometric authentication",
          "Add device fingerprinting",
          "Enable account lockout policies",
        ],
      },
      {
        category: "Malware Detection",
        status: Math.random() > 0.9 ? "danger" : "safe",
        score: Math.floor(Math.random() * 20) + 80,
        details: [
          "Malware signatures: None detected",
          "Suspicious scripts: Clean",
          "Phishing indicators: None found",
          "Blacklist status: Clean",
        ],
        recommendations: [
          "Enable real-time malware scanning",
          "Implement file integrity monitoring",
          "Add behavioral analysis",
        ],
      },
      {
        category: "DDoS Protection",
        status: Math.random() > 0.5 ? "safe" : "warning",
        score: Math.floor(Math.random() * 40) + 60,
        details: [
          "Rate limiting: Configured",
          "Traffic filtering: Active",
          "CDN protection: Enabled",
          "Bandwidth monitoring: Real-time",
        ],
        recommendations: [
          "Increase rate limiting thresholds",
          "Add geographic filtering",
          "Implement challenge-response system",
        ],
      },
      {
        category: "Data Privacy",
        status: Math.random() > 0.7 ? "safe" : "warning",
        score: Math.floor(Math.random() * 30) + 70,
        details: [
          "GDPR compliance: Partial",
          "Data encryption: AES-256",
          "Privacy policy: Present",
          "Cookie consent: Implemented",
        ],
        recommendations: ["Update privacy policy", "Implement data anonymization", "Add consent management platform"],
      },
    ]

    setWebsiteData(mockWebsiteData)
    setScanResults(mockResults)

    // Calculate overall score
    const avgScore = mockResults.reduce((sum, result) => sum + result.score, 0) / mockResults.length
    setOverallScore(Math.round(avgScore))

    setScanning(false)
    setCurrentScanStep("Scan completed!")
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "safe":
        return "text-green-400"
      case "warning":
        return "text-yellow-400"
      case "danger":
        return "text-red-400"
      default:
        return "text-gray-400"
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "safe":
        return <CheckCircle className="w-5 h-5" />
      case "warning":
        return <AlertTriangle className="w-5 h-5" />
      case "danger":
        return <XCircle className="w-5 h-5" />
      default:
        return <AlertTriangle className="w-5 h-5" />
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-400"
    if (score >= 60) return "text-yellow-400"
    return "text-red-400"
  }

  return (
    <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
      <div className="flex items-center mb-6">
        <Globe className="w-6 h-6 text-green-400 mr-3" />
        <h2 className="text-2xl font-bold text-green-400 font-mono">WEBSITE SECURITY ANALYZER</h2>
      </div>

      {/* URL Input */}
      <div className="mb-6">
        <div className="flex space-x-4">
          <div className="flex-1">
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter website URL (e.g., https://example.com)"
              className="w-full bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 text-green-400 placeholder-green-600 focus:border-green-400 focus:outline-none transition-colors font-mono"
              disabled={scanning}
            />
          </div>
          <button
            onClick={performScan}
            disabled={scanning || !url}
            className="bg-green-600 hover:bg-green-500 disabled:bg-green-800 text-black font-bold py-3 px-6 rounded-lg transition-all duration-300 transform hover:scale-105 disabled:scale-100 font-mono flex items-center space-x-2"
          >
            <Search className="w-4 h-4" />
            <span>{scanning ? "SCANNING..." : "ANALYZE"}</span>
          </button>
        </div>
      </div>

      {/* Scanning Progress */}
      {scanning && (
        <div className="mb-6">
          <div className="flex justify-between text-sm text-green-300 mb-2">
            <span>{currentScanStep}</span>
            <span>{scanProgress}%</span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-3">
            <div
              className="bg-gradient-to-r from-green-600 to-green-400 h-3 rounded-full transition-all duration-300"
              style={{ width: `${scanProgress}%` }}
            />
          </div>
        </div>
      )}

      {/* Website Information */}
      {websiteData && (
        <div className="mb-6">
          <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">WEBSITE INFORMATION</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-gray-900/50 rounded-lg p-4">
              <div className="text-green-400 text-sm font-mono mb-1">TITLE</div>
              <div className="text-green-300 text-sm">{websiteData.title}</div>
            </div>
            <div className="bg-gray-900/50 rounded-lg p-4">
              <div className="text-green-400 text-sm font-mono mb-1">IP ADDRESS</div>
              <div className="text-green-300 text-sm font-mono">{websiteData.ip}</div>
            </div>
            <div className="bg-gray-900/50 rounded-lg p-4">
              <div className="text-green-400 text-sm font-mono mb-1">SERVER</div>
              <div className="text-green-300 text-sm">{websiteData.server}</div>
            </div>
            <div className="bg-gray-900/50 rounded-lg p-4">
              <div className="text-green-400 text-sm font-mono mb-1">LOAD TIME</div>
              <div className="text-green-300 text-sm">{websiteData.loadTime.toFixed(2)}s</div>
            </div>
          </div>

          <div className="mt-4">
            <div className="text-green-400 text-sm font-mono mb-2">TECHNOLOGIES DETECTED</div>
            <div className="flex flex-wrap gap-2">
              {websiteData.technologies.map((tech, index) => (
                <span
                  key={index}
                  className="bg-blue-900/30 border border-blue-500/30 text-blue-400 px-2 py-1 rounded text-xs font-mono"
                >
                  {tech}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Overall Security Score */}
      {scanResults.length > 0 && (
        <div className="mb-6">
          <div className="bg-gray-900/50 rounded-lg p-6 text-center">
            <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">OVERALL SECURITY SCORE</h3>
            <div className={`text-6xl font-bold font-mono mb-2 ${getScoreColor(overallScore)}`}>{overallScore}</div>
            <div className="text-green-300 text-sm mb-4">out of 100</div>
            <div className="w-full bg-gray-800 rounded-full h-4">
              <div
                className={`h-4 rounded-full transition-all duration-1000 ${
                  overallScore >= 80 ? "bg-green-400" : overallScore >= 60 ? "bg-yellow-400" : "bg-red-400"
                }`}
                style={{ width: `${overallScore}%` }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Detailed Scan Results */}
      {scanResults.length > 0 && (
        <div>
          <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">DETAILED SECURITY ANALYSIS</h3>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {scanResults.map((result, index) => (
              <div key={index} className="bg-gray-900/50 rounded-lg p-4 border-l-4 border-l-green-500">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="text-green-400 font-mono font-bold">{result.category}</h4>
                  <div className={`flex items-center space-x-2 ${getStatusColor(result.status)}`}>
                    {getStatusIcon(result.status)}
                    <span className={`text-lg font-bold font-mono ${getScoreColor(result.score)}`}>
                      {result.score}%
                    </span>
                  </div>
                </div>

                <div className="mb-3">
                  <div className="text-green-300 text-sm font-mono mb-2">FINDINGS:</div>
                  <div className="space-y-1">
                    {result.details.map((detail, detailIndex) => (
                      <div key={detailIndex} className="flex items-center text-sm text-green-200">
                        <div className="w-2 h-2 bg-green-400 rounded-full mr-2 flex-shrink-0" />
                        {detail}
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <div className="text-green-300 text-sm font-mono mb-2">RECOMMENDATIONS:</div>
                  <div className="space-y-1">
                    {result.recommendations.map((rec, recIndex) => (
                      <div key={recIndex} className="flex items-center text-sm text-yellow-300">
                        <div className="w-2 h-2 bg-yellow-400 rounded-full mr-2 flex-shrink-0" />
                        {rec}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Quick Actions */}
      {scanResults.length > 0 && (
        <div className="mt-6 pt-6 border-t border-green-500/30">
          <div className="flex flex-wrap gap-4">
            <button className="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm">
              DOWNLOAD REPORT
            </button>
            <button className="bg-yellow-600 hover:bg-yellow-500 text-black font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm">
              SCHEDULE MONITORING
            </button>
            <button className="bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm">
              EMERGENCY RESPONSE
            </button>
            <button className="border border-green-500 text-green-400 hover:bg-green-500/10 font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm">
              RESCAN WEBSITE
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
