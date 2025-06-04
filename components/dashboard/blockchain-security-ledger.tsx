"use client"

import { useState, useEffect } from "react"
import { Database, Lock, FileText, CheckCircle, AlertTriangle, Hash } from "lucide-react"

interface BlockchainRecord {
  blockId: string
  timestamp: Date
  hash: string
  previousHash: string
  threatData: {
    incidentId: string
    attackType: string
    severity: "low" | "medium" | "high" | "critical"
    sourceIP: string
    targetVector: string
    mitigationStrategy: string
    aiAnalysis: string
    toolsUsed: string[]
  }
  verified: boolean
}

export function BlockchainSecurityLedger() {
  const [securityBlocks, setSecurityBlocks] = useState<BlockchainRecord[]>([])
  const [selectedBlock, setSelectedBlock] = useState<BlockchainRecord | null>(null)
  const [isVerifying, setIsVerifying] = useState(false)
  const [ledgerStats, setLedgerStats] = useState({
    totalBlocks: 0,
    verifiedBlocks: 0,
    lastVerification: null as Date | null,
  })

  useEffect(() => {
    // Simulate loading blockchain security records
    const loadBlockchainRecords = async () => {
      // In a real implementation, this would fetch from an actual blockchain
      await new Promise((resolve) => setTimeout(resolve, 1500))

      const mockBlocks: BlockchainRecord[] = [
        {
          blockId: "000000000000000000001",
          timestamp: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000),
          hash: "0x7d8f6e5d4c3b2a1098765432100fedcba9876543210fedcba9876543210abcdef",
          previousHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
          threatData: {
            incidentId: "INC-2024-0001",
            attackType: "Distributed Denial of Service (DDoS)",
            severity: "critical",
            sourceIP: "Multiple (Botnet)",
            targetVector: "/api/authentication",
            mitigationStrategy: "Traffic pattern analysis with ML-based filtering and rate limiting",
            aiAnalysis:
              "Attack originated from compromised IoT devices across Eastern Europe. Pattern suggests Mirai botnet variant.",
            toolsUsed: ["Cloudflare DDoS Protection", "Suricata IDS", "Custom ML Traffic Analyzer"],
          },
          verified: true,
        },
        {
          blockId: "000000000000000000002",
          timestamp: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000),
          hash: "0x8e7d6c5b4a3928170654321fedcba9876543210abcdef0123456789abcdef0123",
          previousHash: "0x7d8f6e5d4c3b2a1098765432100fedcba9876543210fedcba9876543210abcdef",
          threatData: {
            incidentId: "INC-2024-0002",
            attackType: "SQL Injection Attempt",
            severity: "high",
            sourceIP: "103.245.67.89",
            targetVector: "/search?query=",
            mitigationStrategy: "Parameterized queries implementation and WAF rule enhancement",
            aiAnalysis:
              "Attack utilized time-based blind injection techniques. Signature matches known threat actor 'SQLShadow'.",
            toolsUsed: ["ModSecurity WAF", "OWASP ZAP", "Snort IPS"],
          },
          verified: true,
        },
        {
          blockId: "000000000000000000003",
          timestamp: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
          hash: "0x9f8e7d6c5b4a392817065432100fedcba9876543210abcdef0123456789abcdef",
          previousHash: "0x8e7d6c5b4a3928170654321fedcba9876543210abcdef0123456789abcdef0123",
          threatData: {
            incidentId: "INC-2024-0003",
            attackType: "Advanced Persistent Threat (APT)",
            severity: "critical",
            sourceIP: "185.173.35.42",
            targetVector: "Multiple endpoints",
            mitigationStrategy: "Zero-trust architecture implementation with behavioral analysis",
            aiAnalysis:
              "Sophisticated multi-stage attack with data exfiltration attempts. LLM analysis indicates nation-state actor with 87% confidence.",
            toolsUsed: ["CrowdStrike Falcon", "Darktrace", "Splunk SIEM", "GPT-4 Security Analyzer"],
          },
          verified: true,
        },
        {
          blockId: "000000000000000000004",
          timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000),
          hash: "0xa0f9e8d7c6b5a4938271605432100fedcba9876543210abcdef0123456789abcd",
          previousHash: "0x9f8e7d6c5b4a392817065432100fedcba9876543210abcdef0123456789abcdef",
          threatData: {
            incidentId: "INC-2024-0004",
            attackType: "Cross-Site Scripting (XSS)",
            severity: "medium",
            sourceIP: "45.89.126.73",
            targetVector: "/comments/post",
            mitigationStrategy: "Content Security Policy implementation and input sanitization",
            aiAnalysis:
              "DOM-based XSS attack targeting user session data. Attack pattern suggests automated vulnerability scanner.",
            toolsUsed: ["OWASP ModSecurity Core Rule Set", "Netsparker", "Content Security Policy"],
          },
          verified: true,
        },
        {
          blockId: "000000000000000000005",
          timestamp: new Date(Date.now() - 12 * 60 * 60 * 1000),
          hash: "0xb1a0f9e8d7c6b5a493827160543210fedcba9876543210abcdef0123456789ab",
          previousHash: "0xa0f9e8d7c6b5a4938271605432100fedcba9876543210abcdef0123456789abcd",
          threatData: {
            incidentId: "INC-2024-0005",
            attackType: "Credential Stuffing",
            severity: "high",
            sourceIP: "Multiple",
            targetVector: "/login",
            mitigationStrategy: "Implementation of CAPTCHA, rate limiting, and anomaly detection",
            aiAnalysis:
              "Distributed attack using credentials from recent data breach. Claude AI identified 95% of attempts as using Rainbow Tables.",
            toolsUsed: ["reCAPTCHA Enterprise", "Auth0 Anomaly Detection", "Claude 3 Opus for Pattern Analysis"],
          },
          verified: true,
        },
      ]

      setSecurityBlocks(mockBlocks)
      setLedgerStats({
        totalBlocks: mockBlocks.length,
        verifiedBlocks: mockBlocks.filter((block) => block.verified).length,
        lastVerification: new Date(Date.now() - 2 * 60 * 60 * 1000),
      })
    }

    loadBlockchainRecords()
  }, [])

  const verifyBlockchain = async () => {
    setIsVerifying(true)

    // Simulate blockchain verification process
    await new Promise((resolve) => setTimeout(resolve, 3000))

    setLedgerStats((prev) => ({
      ...prev,
      verifiedBlocks: securityBlocks.length,
      lastVerification: new Date(),
    }))

    setIsVerifying(false)
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

  const formatDate = (date: Date) => {
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    })
  }

  const truncateHash = (hash: string) => {
    return `${hash.substring(0, 10)}...${hash.substring(hash.length - 10)}`
  }

  return (
    <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <Database className="w-6 h-6 text-green-400 mr-3" />
          <h2 className="text-xl font-bold text-green-400 font-mono">BLOCKCHAIN SECURITY LEDGER</h2>
        </div>
        <button
          onClick={verifyBlockchain}
          disabled={isVerifying}
          className="bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm flex items-center space-x-2"
        >
          {isVerifying ? (
            <>
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              <span>VERIFYING...</span>
            </>
          ) : (
            <>
              <Lock className="w-4 h-4" />
              <span>VERIFY CHAIN</span>
            </>
          )}
        </button>
      </div>

      {/* Ledger Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-blue-400 font-mono">{ledgerStats.totalBlocks}</div>
          <div className="text-xs text-green-300">TOTAL BLOCKS</div>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-green-400 font-mono">{ledgerStats.verifiedBlocks}</div>
          <div className="text-xs text-green-300">VERIFIED BLOCKS</div>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <div className="text-lg font-bold text-yellow-400 font-mono">
            {ledgerStats.lastVerification ? formatDate(ledgerStats.lastVerification) : "Never"}
          </div>
          <div className="text-xs text-green-300">LAST VERIFICATION</div>
        </div>
      </div>

      {/* Blockchain Records */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Block List */}
        <div className="lg:col-span-1">
          <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">SECURITY BLOCKS</h3>
          <div className="space-y-3 max-h-[500px] overflow-y-auto">
            {securityBlocks.map((block) => (
              <div
                key={block.blockId}
                onClick={() => setSelectedBlock(block)}
                className={`bg-gray-900/50 rounded-lg p-3 cursor-pointer hover:bg-gray-800/50 transition-colors ${selectedBlock?.blockId === block.blockId ? "border border-green-500" : ""}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <Hash className="w-4 h-4 text-green-400" />
                    <span className="text-green-400 font-mono text-sm">Block {block.blockId.slice(-3)}</span>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded border ${getSeverityColor(block.threatData.severity)}`}>
                    {block.threatData.severity.toUpperCase()}
                  </span>
                </div>
                <div className="text-green-300 font-bold text-sm mb-1">{block.threatData.attackType}</div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-green-200">{formatDate(block.timestamp)}</span>
                  {block.verified && <CheckCircle className="w-3 h-3 text-green-400" />}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Block Details */}
        <div className="lg:col-span-2">
          <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">ATTACK DETAILS</h3>
          {selectedBlock ? (
            <div className="bg-gray-900/50 rounded-lg p-4">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <AlertTriangle className={`w-5 h-5 ${getSeverityColor(selectedBlock.threatData.severity)}`} />
                  <div>
                    <div className="text-green-400 font-mono font-bold">{selectedBlock.threatData.attackType}</div>
                    <div className="text-green-300 text-sm">Incident ID: {selectedBlock.threatData.incidentId}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-green-300 text-sm">{formatDate(selectedBlock.timestamp)}</div>
                  <div className="flex items-center space-x-1 text-xs text-green-400">
                    <CheckCircle className="w-3 h-3" />
                    <span>Blockchain Verified</span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div>
                  <div className="text-green-400 text-xs font-mono mb-1">SOURCE</div>
                  <div className="text-green-300 text-sm">{selectedBlock.threatData.sourceIP}</div>
                </div>
                <div>
                  <div className="text-green-400 text-xs font-mono mb-1">TARGET</div>
                  <div className="text-green-300 text-sm font-mono">{selectedBlock.threatData.targetVector}</div>
                </div>
              </div>

              <div className="mb-4">
                <div className="text-green-400 text-xs font-mono mb-1">BLOCKCHAIN HASH</div>
                <div className="text-green-300 text-sm font-mono bg-gray-800/50 p-2 rounded overflow-x-auto">
                  {selectedBlock.hash}
                </div>
              </div>

              <div className="mb-4">
                <div className="text-green-400 text-xs font-mono mb-1">AI ANALYSIS</div>
                <div className="text-green-300 text-sm bg-blue-900/20 border border-blue-500/30 p-3 rounded">
                  {selectedBlock.threatData.aiAnalysis}
                </div>
              </div>

              <div className="mb-4">
                <div className="text-green-400 text-xs font-mono mb-1">MITIGATION STRATEGY</div>
                <div className="text-green-300 text-sm">{selectedBlock.threatData.mitigationStrategy}</div>
              </div>

              <div>
                <div className="text-green-400 text-xs font-mono mb-2">SECURITY TOOLS DEPLOYED</div>
                <div className="flex flex-wrap gap-2">
                  {selectedBlock.threatData.toolsUsed.map((tool, index) => (
                    <span
                      key={index}
                      className="bg-green-900/30 border border-green-500/30 text-green-400 px-2 py-1 rounded text-xs font-mono"
                    >
                      {tool}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-gray-900/50 rounded-lg p-8 text-center">
              <FileText className="w-12 h-12 text-green-400/50 mx-auto mb-4" />
              <p className="text-green-300">Select a security block to view attack details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
