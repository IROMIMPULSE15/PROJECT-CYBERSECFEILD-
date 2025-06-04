"use client"

import { useEffect, useState } from "react"
import { AlertTriangle, CheckCircle, Clock, XCircle } from "lucide-react"

export function AttackMitigation() {
  const [attacks, setAttacks] = useState([
    {
      id: 1,
      type: "DDoS Volumetric",
      target: "gov.portal.main",
      status: "mitigated",
      time: "2m ago",
      severity: "critical",
    },
    {
      id: 2,
      type: "SQL Injection",
      target: "finance.api.endpoint",
      status: "blocked",
      time: "5m ago",
      severity: "high",
    },
    {
      id: 3,
      type: "Brute Force",
      target: "admin.login.system",
      status: "monitoring",
      time: "8m ago",
      severity: "medium",
    },
    {
      id: 4,
      type: "Data Exfiltration",
      target: "secure.database.cluster",
      status: "mitigated",
      time: "12m ago",
      severity: "critical",
    },
  ])

  const [mitigationStats, setMitigationStats] = useState({
    totalAttacks: 1247,
    blocked: 1156,
    mitigated: 91,
    investigating: 0,
  })

  useEffect(() => {
    const interval = setInterval(() => {
      if (Math.random() > 0.8) {
        const newAttack = {
          id: Date.now(),
          type: ["DDoS Volumetric", "Application Layer", "Protocol Attack", "Botnet", "Zero-day Exploit"][
            Math.floor(Math.random() * 5)
          ],
          target: ["gov.portal.main", "finance.api.endpoint", "public.service.app", "secure.database.cluster"][
            Math.floor(Math.random() * 4)
          ],
          status: ["blocked", "mitigated", "monitoring"][Math.floor(Math.random() * 3)],
          time: "now",
          severity: ["low", "medium", "high", "critical"][Math.floor(Math.random() * 4)],
        }

        setAttacks((prev) => [newAttack, ...prev.slice(0, 3)])
        setMitigationStats((prev) => ({
          ...prev,
          totalAttacks: prev.totalAttacks + 1,
          [newAttack.status === "blocked"
            ? "blocked"
            : newAttack.status === "mitigated"
              ? "mitigated"
              : "investigating"]:
            prev[
              newAttack.status === "blocked"
                ? "blocked"
                : newAttack.status === "mitigated"
                  ? "mitigated"
                  : "investigating"
            ] + 1,
        }))
      }
    }, 3000)

    return () => clearInterval(interval)
  }, [])

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "blocked":
        return <XCircle className="w-5 h-5 text-red-400" />
      case "mitigated":
        return <CheckCircle className="w-5 h-5 text-green-400" />
      case "monitoring":
        return <Clock className="w-5 h-5 text-yellow-400" />
      default:
        return <AlertTriangle className="w-5 h-5 text-orange-400" />
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "border-l-red-500 bg-red-900/20"
      case "high":
        return "border-l-orange-500 bg-orange-900/20"
      case "medium":
        return "border-l-yellow-500 bg-yellow-900/20"
      default:
        return "border-l-green-500 bg-green-900/20"
    }
  }

  return (
    <section className="relative py-20 z-10">
      <div className="container mx-auto px-6">
        <div className="text-center mb-16">
          <h2 className="text-4xl font-bold text-green-400 mb-4 font-mono">ATTACK MITIGATION CENTER</h2>
          <p className="text-green-200 text-lg max-w-3xl mx-auto">
            Real-time attack detection and automated response system protecting your infrastructure with military-grade
            precision and speed.
          </p>
        </div>

        {/* Mitigation Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-12">
          <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
            <div className="text-3xl font-bold text-green-400 font-mono mb-2">
              {mitigationStats.totalAttacks.toLocaleString()}
            </div>
            <div className="text-green-300 text-sm">Total Attacks Detected</div>
          </div>
          <div className="bg-black/70 border border-red-500/30 rounded-lg p-6 backdrop-blur-sm">
            <div className="text-3xl font-bold text-red-400 font-mono mb-2">
              {mitigationStats.blocked.toLocaleString()}
            </div>
            <div className="text-red-300 text-sm">Attacks Blocked</div>
          </div>
          <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
            <div className="text-3xl font-bold text-green-400 font-mono mb-2">{mitigationStats.mitigated}</div>
            <div className="text-green-300 text-sm">Threats Mitigated</div>
          </div>
          <div className="bg-black/70 border border-yellow-500/30 rounded-lg p-6 backdrop-blur-sm">
            <div className="text-3xl font-bold text-yellow-400 font-mono mb-2">{mitigationStats.investigating}</div>
            <div className="text-yellow-300 text-sm">Under Investigation</div>
          </div>
        </div>

        {/* Recent Attacks */}
        <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
          <h3 className="text-xl font-bold text-green-400 mb-6 font-mono flex items-center">
            <AlertTriangle className="w-6 h-6 mr-3 animate-pulse" />
            RECENT ATTACK VECTORS
          </h3>

          <div className="space-y-4">
            {attacks.map((attack) => (
              <div key={attack.id} className={`border-l-4 rounded-lg p-4 ${getSeverityColor(attack.severity)}`}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    {getStatusIcon(attack.status)}
                    <div className="text-green-400 font-mono font-bold">{attack.type}</div>
                    <div className="text-xs px-2 py-1 rounded bg-gray-800 text-green-300 uppercase">
                      {attack.severity}
                    </div>
                  </div>
                  <div className="text-green-300 text-sm">{attack.time}</div>
                </div>
                <div className="text-green-200 text-sm">Target: {attack.target}</div>
                <div className="text-green-300 text-xs mt-1 uppercase">Status: {attack.status}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Mitigation Techniques */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-12">
          {[
            {
              title: "Automated Response",
              description: "AI-driven instant threat neutralization",
              features: ["<100ms response", "Pattern recognition", "Adaptive learning"],
            },
            {
              title: "Traffic Filtering",
              description: "Advanced packet inspection and filtering",
              features: ["Deep packet analysis", "Behavioral filtering", "Geo-blocking"],
            },
            {
              title: "Load Balancing",
              description: "Intelligent traffic distribution and scaling",
              features: ["Auto-scaling", "Health monitoring", "Failover protection"],
            },
          ].map((technique, index) => (
            <div key={index} className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
              <h4 className="text-lg font-bold text-green-400 mb-3 font-mono">{technique.title}</h4>
              <p className="text-green-200 mb-4">{technique.description}</p>
              <div className="space-y-2">
                {technique.features.map((feature, featureIndex) => (
                  <div key={featureIndex} className="flex items-center text-sm text-green-300">
                    <div className="w-2 h-2 bg-green-400 rounded-full mr-3" />
                    {feature}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
