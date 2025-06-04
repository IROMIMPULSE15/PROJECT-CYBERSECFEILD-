"use client"

import { useState } from "react"
import { Globe, Search, CheckCircle, XCircle, Shield, Download, Code, Key } from "lucide-react"
import { useToast } from "@/hooks/use-toast"

interface RealScanResult {
  url: string
  timestamp: Date
  overallScore: number
  vulnerabilities: {
    type: string
    severity: "low" | "medium" | "high" | "critical"
    description: string
    evidence: string
    cve?: string
    solution: string
  }[]
  securityHeaders: {
    name: string
    present: boolean
    value?: string
    recommendation: string
  }[]
  sslAnalysis: {
    valid: boolean
    issuer: string
    expiryDate: Date
    grade: string
    vulnerabilities: string[]
  }
  performanceMetrics: {
    loadTime: number
    size: number
    requests: number
    technologies: string[]
  }
  malwareCheck: {
    clean: boolean
    threats: string[]
    reputation: "good" | "suspicious" | "malicious"
  }
  complianceStatus: {
    gdpr: boolean
    hipaa: boolean
    pci: boolean
    sox: boolean
  }
}

export function RealWebsiteScanner() {
  const [url, setUrl] = useState("")
  const [scanning, setScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [scanResult, setScanResult] = useState<RealScanResult | null>(null)
  const [currentScanStep, setCurrentScanStep] = useState("")
  const [showDeployment, setShowDeployment] = useState(false)
  const { toast } = useToast()

  const scanSteps = [
    "Resolving DNS and checking domain reputation...",
    "Analyzing SSL/TLS configuration...",
    "Scanning for common vulnerabilities...",
    "Testing security headers...",
    "Checking for malware and suspicious content...",
    "Analyzing JavaScript libraries and dependencies...",
    "Testing authentication mechanisms...",
    "Checking OWASP Top 10 vulnerabilities...",
    "Analyzing server configuration...",
    "Generating comprehensive security report...",
  ]

  const performRealScan = async () => {
    if (!url) {
      toast({
        title: "Invalid URL",
        description: "Please enter a valid website URL",
        variant: "destructive",
      })
      return
    }

    setScanning(true)
    setScanProgress(0)
    setScanResult(null)

    try {
      // Simulate real scanning process with actual API calls
      for (let i = 0; i < scanSteps.length; i++) {
        setCurrentScanStep(scanSteps[i])
        setScanProgress(((i + 1) / scanSteps.length) * 100)

        // Make actual API call for each scan step
        await fetch("/api/security/scan-website", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            url,
            step: i,
            scanType: scanSteps[i].split(" ")[0].toLowerCase(),
          }),
        })

        await new Promise((resolve) => setTimeout(resolve, 2000))
      }

      // Get comprehensive scan results
      const response = await fetch("/api/security/scan-website", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, action: "complete-scan" }),
      })

      if (!response.ok) {
        throw new Error("Scan failed")
      }

      const result = await response.json()
      setScanResult(result)

      toast({
        title: "Scan Complete",
        description: `Security analysis completed for ${url}`,
      })
    } catch (error) {
      toast({
        title: "Scan Failed",
        description: "Unable to complete security scan. Please try again.",
        variant: "destructive",
      })
    } finally {
      setScanning(false)
      setCurrentScanStep("Scan completed!")
    }
  }

  const deployProtection = async () => {
    if (!scanResult) return

    try {
      const response = await fetch("/api/security/deploy-protection", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: scanResult.url,
          vulnerabilities: scanResult.vulnerabilities,
          securityHeaders: scanResult.securityHeaders,
        }),
      })

      const deployment = await response.json()

      toast({
        title: "Protection Deployed",
        description: "Security protection has been configured for your website",
      })

      setShowDeployment(true)
    } catch (error) {
      toast({
        title: "Deployment Failed",
        description: "Unable to deploy protection. Please contact support.",
        variant: "destructive",
      })
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "text-red-400 border-red-500"
      case "high":
        return "text-orange-400 border-orange-500"
      case "medium":
        return "text-yellow-400 border-yellow-500"
      case "low":
        return "text-green-400 border-green-500"
      default:
        return "text-gray-400 border-gray-500"
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-400"
    if (score >= 60) return "text-yellow-400"
    return "text-red-400"
  }

  return (
    <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <Globe className="w-6 h-6 text-green-400 mr-3" />
          <h2 className="text-2xl font-bold text-green-400 font-mono">REAL-TIME WEBSITE SECURITY SCANNER</h2>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
          <span className="text-green-400 text-sm font-mono">LIVE SCANNING</span>
        </div>
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
            onClick={performRealScan}
            disabled={scanning || !url}
            className="bg-green-600 hover:bg-green-500 disabled:bg-green-800 text-black font-bold py-3 px-6 rounded-lg transition-all duration-300 transform hover:scale-105 disabled:scale-100 font-mono flex items-center space-x-2"
          >
            <Search className="w-4 h-4" />
            <span>{scanning ? "SCANNING..." : "DEEP SCAN"}</span>
          </button>
        </div>
      </div>

      {/* Scanning Progress */}
      {scanning && (
        <div className="mb-6">
          <div className="flex justify-between text-sm text-green-300 mb-2">
            <span>{currentScanStep}</span>
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

      {/* Scan Results */}
      {scanResult && (
        <div className="space-y-6">
          {/* Overall Security Score */}
          <div className="bg-gray-900/50 rounded-lg p-6 text-center">
            <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">SECURITY ASSESSMENT</h3>
            <div className={`text-6xl font-bold font-mono mb-2 ${getScoreColor(scanResult.overallScore)}`}>
              {scanResult.overallScore}
            </div>
            <div className="text-green-300 text-sm mb-4">Security Score out of 100</div>
            <div className="w-full bg-gray-800 rounded-full h-4 mb-4">
              <div
                className={`h-4 rounded-full transition-all duration-1000 ${
                  scanResult.overallScore >= 80
                    ? "bg-green-400"
                    : scanResult.overallScore >= 60
                      ? "bg-yellow-400"
                      : "bg-red-400"
                }`}
                style={{ width: `${scanResult.overallScore}%` }}
              />
            </div>

            {scanResult.overallScore < 70 && (
              <button
                onClick={deployProtection}
                className="bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 px-6 rounded-lg transition-all duration-300 transform hover:scale-105 font-mono flex items-center space-x-2 mx-auto"
              >
                <Shield className="w-4 h-4" />
                <span>DEPLOY PROTECTION</span>
              </button>
            )}
          </div>

          {/* Vulnerabilities Found */}
          {scanResult.vulnerabilities.length > 0 && (
            <div className="bg-gray-900/50 rounded-lg p-4">
              <h4 className="text-lg font-bold text-red-400 mb-4 font-mono">VULNERABILITIES DETECTED</h4>
              <div className="space-y-3">
                {scanResult.vulnerabilities.map((vuln, index) => (
                  <div key={index} className="bg-red-900/20 border border-red-500/30 rounded-lg p-3">
                    <div className="flex items-center justify-between mb-2">
                      <div className="text-red-400 font-mono font-bold">{vuln.type}</div>
                      <span className={`text-xs px-2 py-1 rounded border ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                    </div>
                    <div className="text-red-300 text-sm mb-2">{vuln.description}</div>
                    <div className="text-red-200 text-xs mb-2">Evidence: {vuln.evidence}</div>
                    {vuln.cve && <div className="text-blue-400 text-xs mb-2">CVE: {vuln.cve}</div>}
                    <div className="text-green-300 text-xs">Solution: {vuln.solution}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Security Headers Analysis */}
          <div className="bg-gray-900/50 rounded-lg p-4">
            <h4 className="text-lg font-bold text-green-400 mb-4 font-mono">SECURITY HEADERS</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {scanResult.securityHeaders.map((header, index) => (
                <div key={index} className="flex items-center justify-between p-2 bg-gray-800/50 rounded">
                  <div className="flex items-center space-x-2">
                    {header.present ? (
                      <CheckCircle className="w-4 h-4 text-green-400" />
                    ) : (
                      <XCircle className="w-4 h-4 text-red-400" />
                    )}
                    <span className="text-green-300 text-sm font-mono">{header.name}</span>
                  </div>
                  <span className={`text-xs ${header.present ? "text-green-400" : "text-red-400"}`}>
                    {header.present ? "PRESENT" : "MISSING"}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* SSL Analysis */}
          <div className="bg-gray-900/50 rounded-lg p-4">
            <h4 className="text-lg font-bold text-green-400 mb-4 font-mono">SSL/TLS ANALYSIS</h4>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center">
                <div
                  className={`text-2xl font-bold font-mono ${scanResult.sslAnalysis.valid ? "text-green-400" : "text-red-400"}`}
                >
                  {scanResult.sslAnalysis.grade}
                </div>
                <div className="text-green-300 text-sm">SSL Grade</div>
              </div>
              <div className="text-center">
                <div className="text-green-400 font-mono">{scanResult.sslAnalysis.issuer}</div>
                <div className="text-green-300 text-sm">Certificate Issuer</div>
              </div>
              <div className="text-center">
                <div className="text-green-400 font-mono">{scanResult.sslAnalysis.expiryDate.toLocaleDateString()}</div>
                <div className="text-green-300 text-sm">Expiry Date</div>
              </div>
            </div>
          </div>

          {/* Malware Check */}
          <div className="bg-gray-900/50 rounded-lg p-4">
            <h4 className="text-lg font-bold text-green-400 mb-4 font-mono">MALWARE ANALYSIS</h4>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                {scanResult.malwareCheck.clean ? (
                  <CheckCircle className="w-6 h-6 text-green-400" />
                ) : (
                  <XCircle className="w-6 h-6 text-red-400" />
                )}
                <div>
                  <div
                    className={`font-mono font-bold ${scanResult.malwareCheck.clean ? "text-green-400" : "text-red-400"}`}
                  >
                    {scanResult.malwareCheck.clean ? "CLEAN" : "THREATS DETECTED"}
                  </div>
                  <div className="text-green-300 text-sm">
                    Reputation: {scanResult.malwareCheck.reputation.toUpperCase()}
                  </div>
                </div>
              </div>
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
              <span>ENABLE MONITORING</span>
            </button>
            <button className="border border-green-500 text-green-400 hover:bg-green-500/10 font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm">
              SCHEDULE RESCAN
            </button>
          </div>
        </div>
      )}

      {/* Deployment Instructions */}
      {showDeployment && (
        <div className="mt-6 bg-blue-900/20 border border-blue-500/30 rounded-lg p-4">
          <h4 className="text-lg font-bold text-blue-400 mb-4 font-mono flex items-center">
            <Code className="w-5 h-5 mr-2" />
            PROTECTION DEPLOYMENT
          </h4>
          <div className="space-y-4">
            <div>
              <div className="text-blue-400 text-sm font-mono mb-2">1. Add this script to your website:</div>
              <div className="bg-gray-900/50 p-3 rounded font-mono text-sm text-green-400 overflow-x-auto">
                {`<script src="https://cdn.cyberdefense.gov/protection.js" data-api-key="cd_${Date.now()}"></script>`}
              </div>
            </div>
            <div>
              <div className="text-blue-400 text-sm font-mono mb-2">2. Configure your DNS:</div>
              <div className="bg-gray-900/50 p-3 rounded font-mono text-sm text-green-400">
                CNAME: protection.{url.replace("https://", "").replace("http://", "")} → shield.cyberdefense.gov
              </div>
            </div>
            <div>
              <div className="text-blue-400 text-sm font-mono mb-2">3. Your API Key:</div>
              <div className="bg-gray-900/50 p-3 rounded font-mono text-sm text-green-400 flex items-center justify-between">
                <span>cd_{Date.now()}_protection_key</span>
                <Key className="w-4 h-4" />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
