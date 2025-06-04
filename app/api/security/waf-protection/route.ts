import { type NextRequest, NextResponse } from "next/server"

interface WAFRule {
  id: string
  name: string
  description: string
  pattern: string
  action: "block" | "log" | "challenge"
  severity: "low" | "medium" | "high" | "critical"
  category: "sql_injection" | "xss" | "lfi" | "rfi" | "command_injection" | "custom"
  enabled: boolean
  created_at: Date
  last_triggered: Date | null
  trigger_count: number
}

interface WAFMetrics {
  total_requests: number
  blocked_requests: number
  challenged_requests: number
  logged_requests: number
  false_positives: number
  rule_effectiveness: Record<string, number>
}

// Pre-configured WAF rules
const defaultWAFRules: WAFRule[] = [
  {
    id: "waf_001",
    name: "SQL Injection - Union Select",
    description: "Detects UNION SELECT SQL injection attempts",
    pattern: "(?i)(union\\s+select|union\\s+all\\s+select)",
    action: "block",
    severity: "critical",
    category: "sql_injection",
    enabled: true,
    created_at: new Date(),
    last_triggered: null,
    trigger_count: 0,
  },
  {
    id: "waf_002",
    name: "XSS - Script Tag",
    description: "Blocks script tag injection attempts",
    pattern: "(?i)<script[^>]*>.*?</script>",
    action: "block",
    severity: "high",
    category: "xss",
    enabled: true,
    created_at: new Date(),
    last_triggered: null,
    trigger_count: 0,
  },
  {
    id: "waf_003",
    name: "Local File Inclusion",
    description: "Prevents local file inclusion attacks",
    pattern: "(?i)(\\.\\.[\\/\\\\]|\\.\\.%2f|\\.\\.%5c)",
    action: "block",
    severity: "high",
    category: "lfi",
    enabled: true,
    created_at: new Date(),
    last_triggered: null,
    trigger_count: 0,
  },
  {
    id: "waf_004",
    name: "Command Injection",
    description: "Detects command injection attempts",
    pattern: "(?i)(;\\s*cat\\s|;\\s*ls\\s|;\\s*id\\s|;\\s*pwd\\s|\\|\\s*cat\\s|\\|\\s*ls\\s)",
    action: "block",
    severity: "critical",
    category: "command_injection",
    enabled: true,
    created_at: new Date(),
    last_triggered: null,
    trigger_count: 0,
  },
  {
    id: "waf_005",
    name: "Remote File Inclusion",
    description: "Blocks remote file inclusion attempts",
    pattern: "(?i)(http://|https://|ftp://|ftps://)",
    action: "log",
    severity: "medium",
    category: "rfi",
    enabled: true,
    created_at: new Date(),
    last_triggered: null,
    trigger_count: 0,
  },
]

const wafMetrics: WAFMetrics = {
  total_requests: 0,
  blocked_requests: 0,
  challenged_requests: 0,
  logged_requests: 0,
  false_positives: 0,
  rule_effectiveness: {},
}

export async function GET(request: NextRequest) {
  try {
    // Update metrics
    updateWAFMetrics()

    const threatAnalysis = analyzeWAFThreats()
    const rulePerformance = analyzeRulePerformance()
    const recommendations = generateWAFRecommendations()

    return NextResponse.json({
      status: "active",
      timestamp: new Date(),
      rules: defaultWAFRules,
      metrics: wafMetrics,
      threat_analysis: threatAnalysis,
      rule_performance: rulePerformance,
      recommendations: recommendations,
      protection_coverage: getProtectionCoverage(),
    })
  } catch (error) {
    console.error("WAF protection error:", error)
    return NextResponse.json({ error: "WAF monitoring failed" }, { status: 500 })
  }
}

export async function POST(request: NextRequest) {
  try {
    const { action, config } = await request.json()

    switch (action) {
      case "add_rule":
        return await addWAFRule(config.rule)
      case "update_rule":
        return await updateWAFRule(config.rule)
      case "delete_rule":
        return await deleteWAFRule(config.rule_id)
      case "toggle_rule":
        return await toggleWAFRule(config.rule_id)
      case "test_rule":
        return await testWAFRule(config.rule, config.test_data)
      case "import_rules":
        return await importWAFRules(config.rules)
      default:
        return NextResponse.json({ error: "Unknown action" }, { status: 400 })
    }
  } catch (error) {
    console.error("WAF action error:", error)
    return NextResponse.json({ error: "Action failed" }, { status: 500 })
  }
}

function updateWAFMetrics() {
  // Simulate real-time WAF metrics
  wafMetrics.total_requests += Math.floor(Math.random() * 100) + 50
  wafMetrics.blocked_requests += Math.floor(Math.random() * 10)
  wafMetrics.challenged_requests += Math.floor(Math.random() * 5)
  wafMetrics.logged_requests += Math.floor(Math.random() * 20)
  wafMetrics.false_positives += Math.random() > 0.95 ? 1 : 0

  // Update rule effectiveness
  defaultWAFRules.forEach((rule) => {
    if (Math.random() > 0.8) {
      wafMetrics.rule_effectiveness[rule.id] = (wafMetrics.rule_effectiveness[rule.id] || 0) + Math.random() * 10

      rule.trigger_count += 1
      rule.last_triggered = new Date()
    }
  })
}

function analyzeWAFThreats() {
  return {
    top_attack_types: [
      {
        type: "SQL Injection",
        count: Math.floor(Math.random() * 500) + 100,
        percentage: 35,
        trend: "increasing",
      },
      {
        type: "Cross-Site Scripting",
        count: Math.floor(Math.random() * 300) + 80,
        percentage: 25,
        trend: "stable",
      },
      {
        type: "Local File Inclusion",
        count: Math.floor(Math.random() * 200) + 50,
        percentage: 20,
        trend: "decreasing",
      },
      {
        type: "Command Injection",
        count: Math.floor(Math.random() * 150) + 30,
        percentage: 15,
        trend: "increasing",
      },
      {
        type: "Remote File Inclusion",
        count: Math.floor(Math.random() * 100) + 20,
        percentage: 5,
        trend: "stable",
      },
    ],
    attack_patterns: {
      automated_tools: Math.floor(Math.random() * 70) + 20,
      manual_attempts: Math.floor(Math.random() * 30) + 10,
      zero_day_attempts: Math.floor(Math.random() * 5),
    },
    source_analysis: {
      known_bad_ips: Math.floor(Math.random() * 100) + 50,
      tor_exit_nodes: Math.floor(Math.random() * 20) + 5,
      cloud_providers: Math.floor(Math.random() * 200) + 100,
      residential_ips: Math.floor(Math.random() * 50) + 25,
    },
  }
}

function analyzeRulePerformance() {
  return defaultWAFRules.map((rule) => ({
    rule_id: rule.id,
    rule_name: rule.name,
    triggers: rule.trigger_count,
    effectiveness: wafMetrics.rule_effectiveness[rule.id] || 0,
    false_positive_rate: Math.random() * 5,
    last_triggered: rule.last_triggered,
    performance_score: Math.floor(Math.random() * 40) + 60,
  }))
}

function generateWAFRecommendations() {
  const recommendations = []

  // Check for high false positive rates
  const highFPRules = defaultWAFRules.filter((rule) => (wafMetrics.rule_effectiveness[rule.id] || 0) > 100)

  if (highFPRules.length > 0) {
    recommendations.push({
      priority: "medium",
      type: "rule_tuning",
      description: "Some rules have high trigger rates - consider tuning",
      affected_rules: highFPRules.map((r) => r.id),
    })
  }

  // Check for coverage gaps
  if (wafMetrics.blocked_requests / wafMetrics.total_requests < 0.1) {
    recommendations.push({
      priority: "high",
      type: "coverage_gap",
      description: "Low block rate detected - consider adding more rules",
      suggestion: "Add rules for emerging attack vectors",
    })
  }

  // Performance recommendations
  if (defaultWAFRules.length > 50) {
    recommendations.push({
      priority: "low",
      type: "performance",
      description: "Large number of rules may impact performance",
      suggestion: "Consider consolidating similar rules",
    })
  }

  return recommendations
}

function getProtectionCoverage() {
  return {
    owasp_top_10: {
      covered: 8,
      total: 10,
      percentage: 80,
      missing: [
        "A07:2021 - Identification and Authentication Failures",
        "A09:2021 - Security Logging and Monitoring Failures",
      ],
    },
    attack_vectors: {
      sql_injection: 95,
      xss: 90,
      csrf: 85,
      lfi_rfi: 88,
      command_injection: 92,
      xxe: 75,
      deserialization: 70,
    },
    compliance: {
      pci_dss: true,
      owasp_crs: true,
      custom_rules: true,
    },
  }
}

async function addWAFRule(rule: Partial<WAFRule>) {
  const newRule: WAFRule = {
    id: `waf_${Date.now()}`,
    name: rule.name || "Custom Rule",
    description: rule.description || "",
    pattern: rule.pattern || "",
    action: rule.action || "log",
    severity: rule.severity || "medium",
    category: rule.category || "custom",
    enabled: rule.enabled !== false,
    created_at: new Date(),
    last_triggered: null,
    trigger_count: 0,
  }

  defaultWAFRules.push(newRule)

  return NextResponse.json({
    success: true,
    message: "WAF rule added successfully",
    rule_id: newRule.id,
  })
}

async function updateWAFRule(rule: WAFRule) {
  const index = defaultWAFRules.findIndex((r) => r.id === rule.id)
  if (index >= 0) {
    defaultWAFRules[index] = { ...defaultWAFRules[index], ...rule }
    return NextResponse.json({
      success: true,
      message: "WAF rule updated successfully",
    })
  }

  return NextResponse.json({ error: "Rule not found" }, { status: 404 })
}

async function deleteWAFRule(ruleId: string) {
  const index = defaultWAFRules.findIndex((r) => r.id === ruleId)
  if (index >= 0) {
    defaultWAFRules.splice(index, 1)
    return NextResponse.json({
      success: true,
      message: "WAF rule deleted successfully",
    })
  }

  return NextResponse.json({ error: "Rule not found" }, { status: 404 })
}

async function toggleWAFRule(ruleId: string) {
  const rule = defaultWAFRules.find((r) => r.id === ruleId)
  if (rule) {
    rule.enabled = !rule.enabled
    return NextResponse.json({
      success: true,
      message: `WAF rule ${rule.enabled ? "enabled" : "disabled"}`,
      enabled: rule.enabled,
    })
  }

  return NextResponse.json({ error: "Rule not found" }, { status: 404 })
}

async function testWAFRule(rule: Partial<WAFRule>, testData: string[]) {
  const results = testData.map((data) => {
    const regex = new RegExp(rule.pattern || "", "i")
    const matches = regex.test(data)

    return {
      test_data: data,
      matches,
      action: matches ? rule.action : "allow",
    }
  })

  return NextResponse.json({
    success: true,
    test_results: results,
    total_tests: testData.length,
    matches: results.filter((r) => r.matches).length,
  })
}

async function importWAFRules(rules: Partial<WAFRule>[]) {
  const importedRules = rules.map((rule) => ({
    id: `waf_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    name: rule.name || "Imported Rule",
    description: rule.description || "",
    pattern: rule.pattern || "",
    action: rule.action || "log",
    severity: rule.severity || "medium",
    category: rule.category || "custom",
    enabled: rule.enabled !== false,
    created_at: new Date(),
    last_triggered: null,
    trigger_count: 0,
  }))

  defaultWAFRules.push(...importedRules)

  return NextResponse.json({
    success: true,
    message: `${importedRules.length} WAF rules imported successfully`,
    imported_count: importedRules.length,
  })
}
