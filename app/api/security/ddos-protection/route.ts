import { type NextRequest, NextResponse } from "next/server"

interface DDoSMetrics {
  requests_per_second: number
  peak_rps: number
  attack_duration: number
  attack_type: string
  source_countries: Record<string, number>
  mitigation_status: "active" | "standby" | "under_attack"
  blocked_requests: number
  legitimate_requests: number
}

interface DDoSRule {
  id: string
  name: string
  condition: string
  action: "block" | "challenge" | "rate_limit"
  threshold: number
  enabled: boolean
}

// In-memory storage for demo
const ddosMetrics: DDoSMetrics = {
  requests_per_second: 0,
  peak_rps: 0,
  attack_duration: 0,
  attack_type: "none",
  source_countries: {},
  mitigation_status: "standby",
  blocked_requests: 0,
  legitimate_requests: 0,
}

const ddosRules: DDoSRule[] = [
  {
    id: "rule_001",
    name: "High Request Rate",
    condition: "requests_per_second > 1000",
    action: "rate_limit",
    threshold: 1000,
    enabled: true,
  },
  {
    id: "rule_002",
    name: "Volumetric Attack",
    condition: "bandwidth > 1Gbps",
    action: "block",
    threshold: 1000000000,
    enabled: true,
  },
  {
    id: "rule_003",
    name: "Protocol Attack",
    condition: "syn_flood_detected",
    action: "block",
    threshold: 500,
    enabled: true,
  },
]

export async function GET(request: NextRequest) {
  try {
    // Simulate real-time DDoS monitoring
    updateDDoSMetrics()

    const attackAnalysis = analyzeDDoSPatterns()
    const mitigationRecommendations = generateMitigationRecommendations()

    return NextResponse.json({
      status: "monitoring",
      timestamp: new Date(),
      metrics: ddosMetrics,
      rules: ddosRules,
      attack_analysis: attackAnalysis,
      mitigation_recommendations: mitigationRecommendations,
      protection_layers: getProtectionLayers(),
      capacity_status: getCapacityStatus(),
    })
  } catch (error) {
    console.error("DDoS protection error:", error)
    return NextResponse.json({ error: "DDoS monitoring failed" }, { status: 500 })
  }
}

export async function POST(request: NextRequest) {
  try {
    const { action, config } = await request.json()

    switch (action) {
      case "activate_mitigation":
        return await activateMitigation(config)
      case "update_rules":
        return await updateDDoSRules(config.rules)
      case "emergency_block":
        return await emergencyBlock(config)
      case "whitelist_ip":
        return await whitelistIP(config.ip)
      default:
        return NextResponse.json({ error: "Unknown action" }, { status: 400 })
    }
  } catch (error) {
    console.error("DDoS action error:", error)
    return NextResponse.json({ error: "Action failed" }, { status: 500 })
  }
}

function updateDDoSMetrics() {
  // Simulate real-time metrics updates
  const baseRPS = 100 + Math.random() * 50
  const isUnderAttack = Math.random() > 0.8

  if (isUnderAttack) {
    ddosMetrics.requests_per_second = baseRPS * (10 + Math.random() * 20)
    ddosMetrics.mitigation_status = "under_attack"
    ddosMetrics.attack_type = getRandomAttackType()
    ddosMetrics.attack_duration += 1
  } else {
    ddosMetrics.requests_per_second = baseRPS
    ddosMetrics.mitigation_status = "standby"
    ddosMetrics.attack_type = "none"
    ddosMetrics.attack_duration = 0
  }

  ddosMetrics.peak_rps = Math.max(ddosMetrics.peak_rps, ddosMetrics.requests_per_second)

  // Update blocked vs legitimate requests
  if (ddosMetrics.mitigation_status === "under_attack") {
    ddosMetrics.blocked_requests += Math.floor(ddosMetrics.requests_per_second * 0.8)
    ddosMetrics.legitimate_requests += Math.floor(ddosMetrics.requests_per_second * 0.2)
  } else {
    ddosMetrics.legitimate_requests += ddosMetrics.requests_per_second
  }

  // Update source countries
  const countries = ["China", "Russia", "Brazil", "India", "USA", "Germany"]
  countries.forEach((country) => {
    if (Math.random() > 0.7) {
      ddosMetrics.source_countries[country] =
        (ddosMetrics.source_countries[country] || 0) + Math.floor(Math.random() * 100)
    }
  })
}

function getRandomAttackType(): string {
  const attackTypes = [
    "Volumetric",
    "Protocol",
    "Application Layer",
    "SYN Flood",
    "UDP Flood",
    "HTTP Flood",
    "Slowloris",
    "DNS Amplification",
  ]

  return attackTypes[Math.floor(Math.random() * attackTypes.length)]
}

function analyzeDDoSPatterns() {
  return {
    attack_vectors: [
      {
        type: "HTTP Flood",
        percentage: 45,
        trend: "increasing",
      },
      {
        type: "SYN Flood",
        percentage: 30,
        trend: "stable",
      },
      {
        type: "UDP Flood",
        percentage: 25,
        trend: "decreasing",
      },
    ],
    source_analysis: {
      top_countries: Object.entries(ddosMetrics.source_countries)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
        .map(([country, count]) => ({ country, count })),
      botnet_indicators: Math.random() > 0.5,
      coordinated_attack: ddosMetrics.requests_per_second > 5000,
    },
    attack_sophistication: {
      level:
        ddosMetrics.requests_per_second > 10000 ? "high" : ddosMetrics.requests_per_second > 5000 ? "medium" : "low",
      evasion_techniques: ["IP Rotation", "User-Agent Randomization", "Distributed Sources"],
    },
  }
}

function generateMitigationRecommendations() {
  const recommendations = []

  if (ddosMetrics.requests_per_second > 5000) {
    recommendations.push({
      priority: "high",
      action: "Activate rate limiting",
      description: "Implement aggressive rate limiting to reduce attack impact",
    })
  }

  if (ddosMetrics.mitigation_status === "under_attack") {
    recommendations.push({
      priority: "critical",
      action: "Enable challenge mode",
      description: "Challenge suspicious requests with CAPTCHA or JavaScript challenge",
    })
  }

  if (Object.keys(ddosMetrics.source_countries).length > 10) {
    recommendations.push({
      priority: "medium",
      action: "Geographic blocking",
      description: "Consider blocking traffic from high-risk countries",
    })
  }

  return recommendations
}

function getProtectionLayers() {
  return {
    edge_protection: {
      status: "active",
      capacity: "10 Tbps",
      locations: 200,
      effectiveness: "99.9%",
    },
    network_layer: {
      status: "active",
      protocols: ["TCP", "UDP", "ICMP"],
      filtering_rules: 1500,
      packet_inspection: true,
    },
    application_layer: {
      status: "active",
      waf_rules: 2000,
      bot_detection: true,
      rate_limiting: true,
    },
    behavioral_analysis: {
      status: "active",
      ml_models: 15,
      anomaly_detection: true,
      adaptive_learning: true,
    },
  }
}

function getCapacityStatus() {
  return {
    total_capacity: "10 Tbps",
    current_usage: `${((ddosMetrics.requests_per_second / 100000) * 100).toFixed(1)}%`,
    available_capacity: "9.5 Tbps",
    scaling_status: "auto",
    emergency_reserves: "2 Tbps",
  }
}

async function activateMitigation(config: any) {
  ddosMetrics.mitigation_status = "active"

  return NextResponse.json({
    success: true,
    message: "DDoS mitigation activated",
    level: config.level || "standard",
    estimated_duration: "5-10 minutes",
  })
}

async function updateDDoSRules(rules: DDoSRule[]) {
  // Update rules in memory (use database in production)
  rules.forEach((rule) => {
    const existingIndex = ddosRules.findIndex((r) => r.id === rule.id)
    if (existingIndex >= 0) {
      ddosRules[existingIndex] = rule
    } else {
      ddosRules.push(rule)
    }
  })

  return NextResponse.json({
    success: true,
    message: "DDoS rules updated",
    rules_count: ddosRules.length,
  })
}

async function emergencyBlock(config: any) {
  return NextResponse.json({
    success: true,
    message: "Emergency block activated",
    blocked_ips: config.ips?.length || 0,
    duration: config.duration || "1h",
  })
}

async function whitelistIP(ip: string) {
  return NextResponse.json({
    success: true,
    message: `IP ${ip} added to whitelist`,
    permanent: true,
  })
}
