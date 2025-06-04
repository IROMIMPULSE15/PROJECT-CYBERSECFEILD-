import { type NextRequest, NextResponse } from "next/server"

interface BotDetection {
  id: string
  ip: string
  user_agent: string
  bot_type: "good" | "bad" | "unknown"
  bot_name: string
  confidence: number
  first_seen: Date
  last_seen: Date
  request_count: number
  blocked: boolean
  whitelist: boolean
}

interface BotMetrics {
  total_bots: number
  good_bots: number
  bad_bots: number
  unknown_bots: number
  blocked_requests: number
  allowed_requests: number
  challenge_requests: number
}

// Known bot patterns
const knownBots = {
  good: [
    { name: "Googlebot", pattern: /googlebot/i },
    { name: "Bingbot", pattern: /bingbot/i },
    { name: "Slurp", pattern: /slurp/i },
    { name: "DuckDuckBot", pattern: /duckduckbot/i },
    { name: "Baiduspider", pattern: /baiduspider/i },
    { name: "YandexBot", pattern: /yandexbot/i },
    { name: "facebookexternalhit", pattern: /facebookexternalhit/i },
    { name: "Twitterbot", pattern: /twitterbot/i },
  ],
  bad: [
    { name: "Scrapy", pattern: /scrapy/i },
    { name: "Selenium", pattern: /selenium/i },
    { name: "PhantomJS", pattern: /phantomjs/i },
    { name: "HeadlessChrome", pattern: /headlesschrome/i },
    { name: "Python-requests", pattern: /python-requests/i },
    { name: "curl", pattern: /curl/i },
    { name: "wget", pattern: /wget/i },
    { name: "HTTPie", pattern: /httpie/i },
  ],
}

const botDetections: BotDetection[] = []
const botMetrics: BotMetrics = {
  total_bots: 0,
  good_bots: 0,
  bad_bots: 0,
  unknown_bots: 0,
  blocked_requests: 0,
  allowed_requests: 0,
  challenge_requests: 0,
}

export async function GET(request: NextRequest) {
  try {
    // Update bot metrics
    updateBotMetrics()

    const botAnalysis = analyzeBotBehavior()
    const threatIntelligence = getBotThreatIntelligence()
    const recommendations = generateBotRecommendations()

    return NextResponse.json({
      status: "monitoring",
      timestamp: new Date(),
      metrics: botMetrics,
      recent_detections: botDetections.slice(-50),
      bot_analysis: botAnalysis,
      threat_intelligence: threatIntelligence,
      recommendations: recommendations,
      protection_rules: getBotProtectionRules(),
    })
  } catch (error) {
    console.error("Bot management error:", error)
    return NextResponse.json({ error: "Bot monitoring failed" }, { status: 500 })
  }
}

export async function POST(request: NextRequest) {
  try {
    const { action, config } = await request.json()

    switch (action) {
      case "analyze_request":
        return await analyzeRequest(config)
      case "block_bot":
        return await blockBot(config.bot_id)
      case "whitelist_bot":
        return await whitelistBot(config.bot_id)
      case "challenge_bot":
        return await challengeBot(config.bot_id)
      case "update_rules":
        return await updateBotRules(config.rules)
      default:
        return NextResponse.json({ error: "Unknown action" }, { status: 400 })
    }
  } catch (error) {
    console.error("Bot action error:", error)
    return NextResponse.json({ error: "Action failed" }, { status: 500 })
  }
}

function updateBotMetrics() {
  // Simulate bot detection updates
  if (Math.random() > 0.7) {
    const detection = generateBotDetection()
    botDetections.push(detection)

    // Keep only last 1000 detections
    if (botDetections.length > 1000) {
      botDetections.splice(0, botDetections.length - 1000)
    }

    // Update metrics
    botMetrics.total_bots = botDetections.length
    botMetrics.good_bots = botDetections.filter((b) => b.bot_type === "good").length
    botMetrics.bad_bots = botDetections.filter((b) => b.bot_type === "bad").length
    botMetrics.unknown_bots = botDetections.filter((b) => b.bot_type === "unknown").length

    if (detection.blocked) {
      botMetrics.blocked_requests += Math.floor(Math.random() * 10) + 1
    } else {
      botMetrics.allowed_requests += Math.floor(Math.random() * 5) + 1
    }
  }
}

function generateBotDetection(): BotDetection {
  const userAgents = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Python-requests/2.25.1",
    "curl/7.68.0",
    "Scrapy/2.5.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.124 Safari/537.36",
  ]

  const userAgent = userAgents[Math.floor(Math.random() * userAgents.length)]
  const botInfo = classifyBot(userAgent)

  return {
    id: `bot_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    ip: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    user_agent: userAgent,
    bot_type: botInfo.type,
    bot_name: botInfo.name,
    confidence: botInfo.confidence,
    first_seen: new Date(),
    last_seen: new Date(),
    request_count: Math.floor(Math.random() * 100) + 1,
    blocked: botInfo.type === "bad" && Math.random() > 0.3,
    whitelist: botInfo.type === "good",
  }
}

function classifyBot(userAgent: string) {
  // Check good bots
  for (const bot of knownBots.good) {
    if (bot.pattern.test(userAgent)) {
      return {
        type: "good" as const,
        name: bot.name,
        confidence: 95,
      }
    }
  }

  // Check bad bots
  for (const bot of knownBots.bad) {
    if (bot.pattern.test(userAgent)) {
      return {
        type: "bad" as const,
        name: bot.name,
        confidence: 90,
      }
    }
  }

  // Advanced bot detection heuristics
  const botIndicators = [/bot/i, /crawler/i, /spider/i, /scraper/i, /automated/i, /headless/i]

  const hasIndicators = botIndicators.some((pattern) => pattern.test(userAgent))

  if (hasIndicators) {
    return {
      type: "unknown" as const,
      name: "Unknown Bot",
      confidence: 70,
    }
  }

  // Check for suspicious patterns
  if (userAgent.length < 20 || userAgent.length > 500) {
    return {
      type: "bad" as const,
      name: "Suspicious User Agent",
      confidence: 60,
    }
  }

  return {
    type: "unknown" as const,
    name: "Potential Bot",
    confidence: 30,
  }
}

function analyzeBotBehavior() {
  const recentBots = botDetections.slice(-100)

  return {
    traffic_patterns: {
      request_frequency: calculateRequestFrequency(recentBots),
      peak_hours: identifyPeakHours(recentBots),
      geographic_distribution: getGeographicDistribution(recentBots),
    },
    behavioral_analysis: {
      session_duration: calculateSessionDuration(recentBots),
      page_depth: calculatePageDepth(recentBots),
      interaction_patterns: analyzeInteractionPatterns(recentBots),
    },
    threat_indicators: {
      rapid_requests: recentBots.filter((b) => b.request_count > 50).length,
      suspicious_agents: recentBots.filter((b) => b.confidence < 50).length,
      blocked_attempts: recentBots.filter((b) => b.blocked).length,
    },
  }
}

function calculateRequestFrequency(bots: BotDetection[]) {
  const totalRequests = bots.reduce((sum, bot) => sum + bot.request_count, 0)
  const timeSpan = Math.max(1, (Date.now() - bots[0]?.first_seen.getTime()) / 1000 / 60) // minutes

  return {
    requests_per_minute: Math.round(totalRequests / timeSpan),
    average_per_bot: Math.round(totalRequests / bots.length),
    peak_frequency: Math.max(...bots.map((b) => b.request_count)),
  }
}

function identifyPeakHours(bots: BotDetection[]) {
  const hourCounts = new Array(24).fill(0)

  bots.forEach((bot) => {
    const hour = bot.last_seen.getHours()
    hourCounts[hour]++
  })

  const maxCount = Math.max(...hourCounts)
  const peakHour = hourCounts.indexOf(maxCount)

  return {
    peak_hour: peakHour,
    peak_count: maxCount,
    distribution: hourCounts,
  }
}

function getGeographicDistribution(bots: BotDetection[]) {
  // Simulate geographic data
  const countries = ["USA", "China", "Russia", "Germany", "Brazil", "India"]
  const distribution: Record<string, number> = {}

  countries.forEach((country) => {
    distribution[country] = Math.floor(Math.random() * 20)
  })

  return distribution
}

function calculateSessionDuration(bots: BotDetection[]) {
  const durations = bots.map(
    (bot) => (bot.last_seen.getTime() - bot.first_seen.getTime()) / 1000 / 60, // minutes
  )

  return {
    average: Math.round(durations.reduce((sum, d) => sum + d, 0) / durations.length),
    median: Math.round(durations.sort()[Math.floor(durations.length / 2)]),
    max: Math.round(Math.max(...durations)),
  }
}

function calculatePageDepth(bots: BotDetection[]) {
  // Simulate page depth analysis
  return {
    average_depth: Math.floor(Math.random() * 10) + 1,
    shallow_sessions: Math.floor(Math.random() * 30) + 10, // 1-2 pages
    deep_sessions: Math.floor(Math.random() * 10) + 5, // 10+ pages
  }
}

function analyzeInteractionPatterns(bots: BotDetection[]) {
  return {
    javascript_execution: Math.floor(Math.random() * 40) + 20, // % of bots executing JS
    form_submissions: Math.floor(Math.random() * 10) + 5,
    mouse_movements: Math.floor(Math.random() * 30) + 10,
    keyboard_events: Math.floor(Math.random() * 25) + 5,
  }
}

function getBotThreatIntelligence() {
  return {
    known_malicious_ips: Math.floor(Math.random() * 100) + 50,
    botnet_indicators: Math.floor(Math.random() * 20) + 5,
    scraping_attempts: Math.floor(Math.random() * 200) + 100,
    ddos_participants: Math.floor(Math.random() * 50) + 10,
    emerging_threats: [
      "New scraping botnet targeting e-commerce sites",
      "AI-powered bots mimicking human behavior",
      "Distributed credential stuffing campaign",
    ],
  }
}

function generateBotRecommendations() {
  const recommendations = []

  const badBotPercentage = (botMetrics.bad_bots / botMetrics.total_bots) * 100

  if (badBotPercentage > 30) {
    recommendations.push({
      priority: "high",
      type: "blocking",
      description: "High percentage of malicious bots detected",
      action: "Implement stricter bot blocking rules",
    })
  }

  if (botMetrics.unknown_bots > 50) {
    recommendations.push({
      priority: "medium",
      type: "analysis",
      description: "Many unknown bots require classification",
      action: "Review and classify unknown bot traffic",
    })
  }

  if (botMetrics.challenge_requests < botMetrics.blocked_requests * 0.1) {
    recommendations.push({
      priority: "low",
      type: "optimization",
      description: "Consider using challenges before blocking",
      action: "Implement CAPTCHA challenges for suspicious bots",
    })
  }

  return recommendations
}

function getBotProtectionRules() {
  return {
    rate_limiting: {
      enabled: true,
      requests_per_minute: 60,
      burst_limit: 10,
    },
    challenge_mode: {
      enabled: true,
      javascript_challenge: true,
      captcha_challenge: true,
      threshold_score: 70,
    },
    behavioral_analysis: {
      enabled: true,
      mouse_tracking: true,
      keyboard_tracking: true,
      session_analysis: true,
    },
    ip_reputation: {
      enabled: true,
      block_known_bad: true,
      whitelist_known_good: true,
      reputation_threshold: 80,
    },
  }
}

async function analyzeRequest(config: any) {
  const { user_agent, ip, headers } = config

  const botInfo = classifyBot(user_agent)
  const riskScore = calculateRiskScore(config)

  return NextResponse.json({
    success: true,
    bot_detected: botInfo.confidence > 50,
    bot_type: botInfo.type,
    bot_name: botInfo.name,
    confidence: botInfo.confidence,
    risk_score: riskScore,
    recommended_action: riskScore > 70 ? "block" : riskScore > 40 ? "challenge" : "allow",
  })
}

function calculateRiskScore(config: any): number {
  let score = 0

  // User agent analysis
  const botInfo = classifyBot(config.user_agent)
  if (botInfo.type === "bad") score += 40
  if (botInfo.type === "unknown") score += 20

  // Request frequency
  if (config.request_frequency > 100) score += 30

  // Missing common headers
  if (!config.headers?.accept) score += 10
  if (!config.headers?.["accept-language"]) score += 10

  // Suspicious patterns
  if (config.user_agent.length < 20) score += 20
  if (!config.headers?.referer && config.method === "POST") score += 15

  return Math.min(100, score)
}

async function blockBot(botId: string) {
  const bot = botDetections.find((b) => b.id === botId)
  if (bot) {
    bot.blocked = true
    return NextResponse.json({
      success: true,
      message: `Bot ${bot.bot_name} has been blocked`,
    })
  }

  return NextResponse.json({ error: "Bot not found" }, { status: 404 })
}

async function whitelistBot(botId: string) {
  const bot = botDetections.find((b) => b.id === botId)
  if (bot) {
    bot.whitelist = true
    bot.blocked = false
    return NextResponse.json({
      success: true,
      message: `Bot ${bot.bot_name} has been whitelisted`,
    })
  }

  return NextResponse.json({ error: "Bot not found" }, { status: 404 })
}

async function challengeBot(botId: string) {
  const bot = botDetections.find((b) => b.id === botId)
  if (bot) {
    botMetrics.challenge_requests += 1
    return NextResponse.json({
      success: true,
      message: `Challenge issued to bot ${bot.bot_name}`,
      challenge_type: "javascript",
    })
  }

  return NextResponse.json({ error: "Bot not found" }, { status: 404 })
}

async function updateBotRules(rules: any) {
  return NextResponse.json({
    success: true,
    message: "Bot protection rules updated",
    rules_updated: Object.keys(rules).length,
  })
}
