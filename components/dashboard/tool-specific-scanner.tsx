"use client"

import { useState } from "react"
import {
  Terminal,
  Settings,
  Play,
  Download,
  Eye,
  Code,
  Database,
  Globe,
  Lock,
  Search,
  Bug,
  Wifi,
  Key,
} from "lucide-react"
import { useToast } from "@/hooks/use-toast"

interface ToolConfig {
  id: string
  name: string
  description: string
  icon: any
  category: string
  options: {
    [key: string]: {
      type: "text" | "number" | "boolean" | "select"
      label: string
      default: any
      options?: string[]
      description: string
    }
  }
}

interface ToolResult {
  tool: string
  output: string
  findings: any[]
  duration: number
  status: "success" | "error"
  command: string
}

export function ToolSpecificScanner() {
  const [selectedTool, setSelectedTool] = useState<string>("")
  const [url, setUrl] = useState("")
  const [toolConfig, setToolConfig] = useState<Record<string, any>>({})
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<ToolResult | null>(null)
  const { toast } = useToast()

  const tools: ToolConfig[] = [
    {
      id: "nmap",
      name: "Nmap",
      description: "Network discovery and security auditing",
      icon: Wifi,
      category: "Network",
      options: {
        scanType: {
          type: "select",
          label: "Scan Type",
          default: "-sV",
          options: ["-sS", "-sT", "-sU", "-sV", "-sC", "-A"],
          description: "Type of scan to perform",
        },
        timing: {
          type: "select",
          label: "Timing Template",
          default: "-T4",
          options: ["-T0", "-T1", "-T2", "-T3", "-T4", "-T5"],
          description: "Scan timing and performance",
        },
        ports: {
          type: "text",
          label: "Port Range",
          default: "",
          description: "Specific ports to scan (e.g., 80,443,22)",
        },
        scripts: {
          type: "text",
          label: "NSE Scripts",
          default: "vuln",
          description: "Nmap Scripting Engine scripts to run",
        },
        aggressive: {
          type: "boolean",
          label: "Aggressive Scan",
          default: false,
          description: "Enable aggressive scanning options",
        },
      },
    },
    {
      id: "nikto",
      name: "Nikto",
      description: "Web server scanner",
      icon: Globe,
      category: "Web",
      options: {
        tuning: {
          type: "text",
          label: "Tuning Options",
          default: "1,2,3,4,5,6",
          description: "Scan tuning (1-9, x for all)",
        },
        evasion: {
          type: "text",
          label: "Evasion Techniques",
          default: "",
          description: "IDS evasion techniques (1-8)",
        },
        timeout: {
          type: "number",
          label: "Timeout (seconds)",
          default: 10,
          description: "Request timeout",
        },
        useragent: {
          type: "text",
          label: "User Agent",
          default: "",
          description: "Custom user agent string",
        },
        ssl: {
          type: "boolean",
          label: "Force SSL",
          default: false,
          description: "Force SSL/TLS connection",
        },
      },
    },
    {
      id: "sqlmap",
      name: "SQLMap",
      description: "SQL injection detection and exploitation",
      icon: Database,
      category: "Vulnerability",
      options: {
        level: {
          type: "select",
          label: "Test Level",
          default: "1",
          options: ["1", "2", "3", "4", "5"],
          description: "Level of tests to perform",
        },
        risk: {
          type: "select",
          label: "Risk Level",
          default: "1",
          options: ["1", "2", "3"],
          description: "Risk of tests to perform",
        },
        technique: {
          type: "text",
          label: "Techniques",
          default: "BEUSTQ",
          description: "SQL injection techniques to use",
        },
        dbms: {
          type: "select",
          label: "DBMS",
          default: "",
          options: ["", "MySQL", "PostgreSQL", "Oracle", "Microsoft SQL Server", "SQLite"],
          description: "Force back-end DBMS",
        },
        threads: {
          type: "number",
          label: "Threads",
          default: 1,
          description: "Number of concurrent threads",
        },
      },
    },
    {
      id: "dirb",
      name: "DIRB",
      description: "Web content scanner",
      icon: Search,
      category: "Discovery",
      options: {
        wordlist: {
          type: "select",
          label: "Wordlist",
          default: "common.txt",
          options: ["common.txt", "big.txt", "small.txt", "vulns.txt"],
          description: "Wordlist to use for directory discovery",
        },
        extensions: {
          type: "text",
          label: "Extensions",
          default: "php,html,js,txt",
          description: "File extensions to search for",
        },
        recursive: {
          type: "boolean",
          label: "Recursive Scan",
          default: false,
          description: "Scan directories recursively",
        },
        silent: {
          type: "boolean",
          label: "Silent Mode",
          default: true,
          description: "Don't show tested words",
        },
        speed: {
          type: "select",
          label: "Scan Speed",
          default: "normal",
          options: ["slow", "normal", "fast"],
          description: "Scanning speed",
        },
      },
    },
    {
      id: "wpscan",
      name: "WPScan",
      description: "WordPress security scanner",
      icon: Code,
      category: "Web",
      options: {
        enumerate: {
          type: "text",
          label: "Enumerate",
          default: "p,t,u",
          description: "Enumeration options (p=plugins, t=themes, u=users)",
        },
        detection: {
          type: "select",
          label: "Plugin Detection",
          default: "passive",
          options: ["passive", "aggressive", "mixed"],
          description: "Plugin detection mode",
        },
        threads: {
          type: "number",
          label: "Threads",
          default: 5,
          description: "Number of threads to use",
        },
        requestTimeout: {
          type: "number",
          label: "Request Timeout",
          default: 60,
          description: "Request timeout in seconds",
        },
        followRedirect: {
          type: "boolean",
          label: "Follow Redirects",
          default: false,
          description: "Follow HTTP redirects",
        },
      },
    },
    {
      id: "sslyze",
      name: "SSLyze",
      description: "SSL/TLS configuration analyzer",
      icon: Lock,
      category: "SSL",
      options: {
        sslv2: {
          type: "boolean",
          label: "Test SSLv2",
          default: true,
          description: "Test for SSLv2 support",
        },
        sslv3: {
          type: "boolean",
          label: "Test SSLv3",
          default: true,
          description: "Test for SSLv3 support",
        },
        tlsv1: {
          type: "boolean",
          label: "Test TLSv1.0",
          default: true,
          description: "Test for TLSv1.0 support",
        },
        tlsv1_1: {
          type: "boolean",
          label: "Test TLSv1.1",
          default: true,
          description: "Test for TLSv1.1 support",
        },
        tlsv1_2: {
          type: "boolean",
          label: "Test TLSv1.2",
          default: true,
          description: "Test for TLSv1.2 support",
        },
        tlsv1_3: {
          type: "boolean",
          label: "Test TLSv1.3",
          default: true,
          description: "Test for TLSv1.3 support",
        },
        certinfo: {
          type: "boolean",
          label: "Certificate Info",
          default: true,
          description: "Retrieve certificate information",
        },
        compression: {
          type: "boolean",
          label: "Test Compression",
          default: true,
          description: "Test for compression vulnerabilities",
        },
      },
    },
    {
      id: "nuclei",
      name: "Nuclei",
      description: "Fast vulnerability scanner",
      icon: Bug,
      category: "Vulnerability",
      options: {
        templates: {
          type: "text",
          label: "Template Tags",
          default: "cves,vulnerabilities",
          description: "Template tags to use (comma-separated)",
        },
        severity: {
          type: "text",
          label: "Severity Filter",
          default: "medium,high,critical",
          description: "Filter by severity levels",
        },
        concurrency: {
          type: "number",
          label: "Concurrency",
          default: 25,
          description: "Number of concurrent requests",
        },
        rateLimit: {
          type: "number",
          label: "Rate Limit",
          default: 150,
          description: "Requests per second",
        },
        timeout: {
          type: "number",
          label: "Timeout",
          default: 5,
          description: "Request timeout in seconds",
        },
        followRedirects: {
          type: "boolean",
          label: "Follow Redirects",
          default: false,
          description: "Follow HTTP redirects",
        },
      },
    },
    {
      id: "testssl",
      name: "testssl.sh",
      description: "SSL/TLS implementation testing",
      icon: Key,
      category: "SSL",
      options: {
        protocols: {
          type: "boolean",
          label: "Test Protocols",
          default: true,
          description: "Test supported protocols",
        },
        ciphers: {
          type: "boolean",
          label: "Test Ciphers",
          default: true,
          description: "Test cipher suites",
        },
        vulnerabilities: {
          type: "boolean",
          label: "Test Vulnerabilities",
          default: true,
          description: "Test for known vulnerabilities",
        },
        serverDefaults: {
          type: "boolean",
          label: "Server Defaults",
          default: true,
          description: "Check server defaults",
        },
        serverPreference: {
          type: "boolean",
          label: "Server Preference",
          default: true,
          description: "Check server cipher preference",
        },
        severity: {
          type: "select",
          label: "Minimum Severity",
          default: "LOW",
          options: ["OK", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
          description: "Minimum severity to report",
        },
      },
    },
  ]

  const runSpecificTool = async () => {
    if (!selectedTool || !url) {
      toast({
        title: "Invalid Configuration",
        description: "Please select a tool and enter a target URL",
        variant: "destructive",
      })
      return
    }

    setScanning(true)
    setResult(null)

    try {
      const response = await fetch("/api/security/run-specific-tool", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tool: selectedTool,
          url,
          config: toolConfig,
        }),
      })

      if (!response.ok) {
        throw new Error("Tool execution failed")
      }

      const toolResult = await response.json()
      setResult(toolResult)

      toast({
        title: "Tool Execution Complete",
        description: `${selectedTool} completed with ${toolResult.findings.length} findings`,
      })
    } catch (error) {
      toast({
        title: "Tool Execution Failed",
        description: "Failed to execute the selected tool. Please try again.",
        variant: "destructive",
      })
    } finally {
      setScanning(false)
    }
  }

  const updateToolConfig = (option: string, value: any) => {
    setToolConfig((prev) => ({
      ...prev,
      [option]: value,
    }))
  }

  const getSelectedToolConfig = () => {
    return tools.find((tool) => tool.id === selectedTool)
  }

  const generateCommand = () => {
    const tool = getSelectedToolConfig()
    if (!tool || !url) return ""

    let command = tool.name.toLowerCase()

    // Add tool-specific command generation logic
    switch (tool.id) {
      case "nmap":
        command += ` ${toolConfig.scanType || "-sV"} ${toolConfig.timing || "-T4"}`
        if (toolConfig.ports) command += ` -p ${toolConfig.ports}`
        if (toolConfig.scripts) command += ` --script=${toolConfig.scripts}`
        if (toolConfig.aggressive) command += " -A"
        command += ` ${new URL(url).hostname}`
        break

      case "nikto":
        command += ` -h ${url}`
        if (toolConfig.tuning) command += ` -Tuning ${toolConfig.tuning}`
        if (toolConfig.evasion) command += ` -evasion ${toolConfig.evasion}`
        if (toolConfig.timeout) command += ` -timeout ${toolConfig.timeout}`
        if (toolConfig.useragent) command += ` -useragent "${toolConfig.useragent}"`
        if (toolConfig.ssl) command += " -ssl"
        break

      case "sqlmap":
        command += ` -u "${url}"`
        command += ` --level=${toolConfig.level || 1} --risk=${toolConfig.risk || 1}`
        if (toolConfig.technique) command += ` --technique=${toolConfig.technique}`
        if (toolConfig.dbms) command += ` --dbms="${toolConfig.dbms}"`
        if (toolConfig.threads) command += ` --threads=${toolConfig.threads}`
        command += " --batch"
        break

      // Add more tool-specific command generation...
    }

    return command
  }

  return (
    <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <Terminal className="w-6 h-6 text-green-400 mr-3" />
          <h2 className="text-xl font-bold text-green-400 font-mono">TOOL-SPECIFIC SCANNER</h2>
        </div>
        <div className="flex items-center space-x-2">
          <Settings className="w-4 h-4 text-blue-400" />
          <span className="text-blue-400 text-sm font-mono">CUSTOM CONFIGURATION</span>
        </div>
      </div>

      {/* Tool Selection and URL Input */}
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
            value={selectedTool}
            onChange={(e) => {
              setSelectedTool(e.target.value)
              setToolConfig({})
            }}
            className="bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 text-green-400 focus:border-green-400 focus:outline-none transition-colors font-mono"
            disabled={scanning}
          >
            <option value="">Select Security Tool</option>
            {tools.map((tool) => (
              <option key={tool.id} value={tool.id}>
                {tool.name} - {tool.description}
              </option>
            ))}
          </select>
        </div>

        {/* Generated Command Preview */}
        {selectedTool && url && (
          <div className="bg-gray-900/50 border border-blue-500/30 rounded-lg p-3">
            <div className="text-blue-400 text-sm font-mono mb-2">GENERATED COMMAND:</div>
            <code className="text-green-400 text-sm font-mono break-all">{generateCommand()}</code>
          </div>
        )}
      </div>

      {/* Tool Configuration */}
      {selectedTool && (
        <div className="mb-6">
          <h3 className="text-lg font-bold text-green-400 mb-4 font-mono">
            {getSelectedToolConfig()?.name.toUpperCase()} CONFIGURATION
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {Object.entries(getSelectedToolConfig()?.options || {}).map(([key, option]) => (
              <div key={key} className="space-y-2">
                <label className="block text-green-400 text-sm font-mono">{option.label}</label>

                {option.type === "text" && (
                  <input
                    type="text"
                    value={toolConfig[key] || option.default || ""}
                    onChange={(e) => updateToolConfig(key, e.target.value)}
                    className="w-full bg-gray-900/50 border border-green-500/30 rounded px-3 py-2 text-green-400 focus:border-green-400 focus:outline-none transition-colors font-mono text-sm"
                    disabled={scanning}
                  />
                )}

                {option.type === "number" && (
                  <input
                    type="number"
                    value={toolConfig[key] || option.default || 0}
                    onChange={(e) => updateToolConfig(key, Number.parseInt(e.target.value))}
                    className="w-full bg-gray-900/50 border border-green-500/30 rounded px-3 py-2 text-green-400 focus:border-green-400 focus:outline-none transition-colors font-mono text-sm"
                    disabled={scanning}
                  />
                )}

                {option.type === "boolean" && (
                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={toolConfig[key] !== undefined ? toolConfig[key] : option.default}
                      onChange={(e) => updateToolConfig(key, e.target.checked)}
                      className="w-4 h-4 text-green-400 bg-gray-900 border-green-500 rounded focus:ring-green-400"
                      disabled={scanning}
                    />
                    <span className="text-green-300 text-sm">Enable</span>
                  </label>
                )}

                {option.type === "select" && (
                  <select
                    value={toolConfig[key] || option.default || ""}
                    onChange={(e) => updateToolConfig(key, e.target.value)}
                    className="w-full bg-gray-900/50 border border-green-500/30 rounded px-3 py-2 text-green-400 focus:border-green-400 focus:outline-none transition-colors font-mono text-sm"
                    disabled={scanning}
                  >
                    {option.options?.map((opt) => (
                      <option key={opt} value={opt}>
                        {opt}
                      </option>
                    ))}
                  </select>
                )}

                <div className="text-green-300 text-xs">{option.description}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Execute Button */}
      <div className="mb-6">
        <button
          onClick={runSpecificTool}
          disabled={scanning || !selectedTool || !url}
          className="bg-green-600 hover:bg-green-500 disabled:bg-green-800 text-black font-bold py-3 px-6 rounded-lg transition-all duration-300 transform hover:scale-105 disabled:scale-100 font-mono flex items-center space-x-2"
        >
          <Play className="w-4 h-4" />
          <span>{scanning ? "EXECUTING..." : "EXECUTE TOOL"}</span>
        </button>
      </div>

      {/* Tool Results */}
      {result && (
        <div className="space-y-6">
          <div className="bg-gray-900/50 rounded-lg p-4">
            <h4 className="text-lg font-bold text-green-400 mb-4 font-mono">EXECUTION RESULTS</h4>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-green-400 font-mono">{result.findings.length}</div>
                <div className="text-green-300 text-sm">Findings</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-400 font-mono">{(result.duration / 1000).toFixed(1)}s</div>
                <div className="text-green-300 text-sm">Duration</div>
              </div>
              <div className="text-center">
                <div
                  className={`text-2xl font-bold font-mono ${result.status === "success" ? "text-green-400" : "text-red-400"}`}
                >
                  {result.status.toUpperCase()}
                </div>
                <div className="text-green-300 text-sm">Status</div>
              </div>
            </div>

            {/* Command Used */}
            <div className="mb-4">
              <div className="text-green-400 text-sm font-mono mb-2">COMMAND EXECUTED:</div>
              <div className="bg-gray-800/50 p-3 rounded font-mono text-sm text-green-400 overflow-x-auto">
                {result.command}
              </div>
            </div>

            {/* Findings */}
            {result.findings.length > 0 && (
              <div className="mb-4">
                <div className="text-green-400 text-sm font-mono mb-2">FINDINGS:</div>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {result.findings.map((finding, index) => (
                    <div key={index} className="bg-gray-800/50 p-3 rounded">
                      <div className="text-green-300 text-sm">
                        {typeof finding === "string" ? finding : JSON.stringify(finding, null, 2)}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Raw Output */}
            <div>
              <div className="text-green-400 text-sm font-mono mb-2">RAW OUTPUT:</div>
              <div className="bg-gray-800/50 p-3 rounded max-h-64 overflow-y-auto">
                <pre className="text-green-300 text-xs font-mono whitespace-pre-wrap">{result.output}</pre>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-4">
            <button className="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm flex items-center space-x-2">
              <Download className="w-4 h-4" />
              <span>DOWNLOAD RESULTS</span>
            </button>
            <button className="bg-green-600 hover:bg-green-500 text-black font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm flex items-center space-x-2">
              <Eye className="w-4 h-4" />
              <span>VIEW DETAILED ANALYSIS</span>
            </button>
            <button className="border border-green-500 text-green-400 hover:bg-green-500/10 font-bold py-2 px-4 rounded-lg transition-colors font-mono text-sm">
              RUN AGAIN
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
