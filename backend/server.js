// Advanced Node.js Backend Server for Cybersecurity Platform
const express = require("express")
const cors = require("cors")
const helmet = require("helmet")
const rateLimit = require("express-rate-limit")
const mysql = require("mysql2/promise")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const WebSocket = require("ws")
const http = require("http")
const crypto = require("crypto")
const geoip = require("geoip-lite")
const useragent = require("useragent")

const app = express()
const server = http.createServer(app)
const wss = new WebSocket.Server({ server })

// Security Middleware
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  }),
)

app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true,
  }),
)

app.use(express.json({ limit: "10mb" }))
app.use(express.urlencoded({ extended: true }))

// Advanced Rate Limiting
const createRateLimit = (windowMs, max, message) =>
  rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
  })

app.use("/api/auth", createRateLimit(15 * 60 * 1000, 5, "Too many auth attempts"))
app.use("/api/security", createRateLimit(60 * 1000, 100, "Too many security requests"))

// Database Configuration
const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "password",
  database: process.env.DB_NAME || "cyberdefense_db",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
}

let db

// Initialize Database
async function initializeDatabase() {
  try {
    db = mysql.createPool(dbConfig)

    // Create signup table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS signup (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        plan VARCHAR(50) DEFAULT 'Basic',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        is_verified BOOLEAN DEFAULT FALSE,
        verification_token VARCHAR(255),
        last_login TIMESTAMP NULL,
        failed_login_attempts INT DEFAULT 0,
        account_locked_until TIMESTAMP NULL,
        two_factor_enabled BOOLEAN DEFAULT FALSE,
        two_factor_secret VARCHAR(255),
        INDEX idx_email (email),
        INDEX idx_created_at (created_at)
      )
    `)

    // Create login table for session management
    await db.execute(`
      CREATE TABLE IF NOT EXISTS login (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        session_token VARCHAR(255) UNIQUE NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        user_agent TEXT,
        location VARCHAR(255),
        login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        logout_time TIMESTAMP NULL,
        is_active BOOLEAN DEFAULT TRUE,
        device_fingerprint VARCHAR(255),
        risk_score INT DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES signup(id) ON DELETE CASCADE,
        INDEX idx_user_id (user_id),
        INDEX idx_session_token (session_token),
        INDEX idx_login_time (login_time)
      )
    `)

    // Create security_events table for monitoring
    await db.execute(`
      CREATE TABLE IF NOT EXISTS security_events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        event_type VARCHAR(100) NOT NULL,
        severity VARCHAR(20) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        user_agent TEXT,
        location VARCHAR(255),
        details JSON,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INT NULL,
        blocked BOOLEAN DEFAULT FALSE,
        INDEX idx_event_type (event_type),
        INDEX idx_severity (severity),
        INDEX idx_timestamp (timestamp),
        INDEX idx_ip_address (ip_address)
      )
    `)

    console.log("✅ Database initialized successfully")
  } catch (error) {
    console.error("❌ Database initialization failed:", error)
    process.exit(1)
  }
}

// Security Event Logger
async function logSecurityEvent(eventType, severity, req, details = {}, userId = null) {
  try {
    const ip = req.ip || req.connection.remoteAddress
    const userAgent = req.get("User-Agent") || ""
    const geo = geoip.lookup(ip)
    const location = geo ? `${geo.city}, ${geo.country}` : "Unknown"

    await db.execute(
      `
      INSERT INTO security_events (event_type, severity, ip_address, user_agent, location, details, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
      [eventType, severity, ip, userAgent, location, JSON.stringify(details), userId],
    )

    // Broadcast to WebSocket clients
    broadcastSecurityEvent({
      eventType,
      severity,
      ip,
      location,
      timestamp: new Date().toISOString(),
      details,
    })
  } catch (error) {
    console.error("Failed to log security event:", error)
  }
}

// WebSocket for Real-time Updates
const clients = new Set()

wss.on("connection", (ws, req) => {
  clients.add(ws)
  console.log("New WebSocket connection established")

  ws.on("close", () => {
    clients.delete(ws)
  })

  // Send initial security status
  ws.send(
    JSON.stringify({
      type: "security_status",
      data: {
        activeThreats: 0,
        blockedAttacks: 0,
        protectedSites: 1,
        uptime: "99.99%",
      },
    }),
  )
})

function broadcastSecurityEvent(event) {
  const message = JSON.stringify({
    type: "security_event",
    data: event,
  })

  clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message)
    }
  })
}

// Advanced Security Middleware
async function detectThreats(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress
  const userAgent = req.get("User-Agent") || ""
  const agent = useragent.parse(userAgent)

  let riskScore = 0
  const threats = []

  // Bot Detection
  if (
    userAgent.toLowerCase().includes("bot") ||
    userAgent.toLowerCase().includes("crawler") ||
    userAgent.toLowerCase().includes("spider")
  ) {
    riskScore += 30
    threats.push("Potential Bot Traffic")
  }

  // Suspicious User Agent
  if (!userAgent || userAgent.length < 10) {
    riskScore += 20
    threats.push("Suspicious User Agent")
  }

  // SQL Injection Detection
  const sqlPatterns = [
    /(%27)|(')|(--)|(%23)|(#)/i,
    /((%3D)|(=))[^\n]*((%27)|(')|(--)|(%3B)|(;))/i,
    /\w*((%27)|('))((%6F)|o|(%4F))((%72)|r|(%52))/i,
    /((%27)|('))union/i,
  ]

  const checkSQLInjection = (str) => {
    return sqlPatterns.some((pattern) => pattern.test(str))
  }

  // Check URL and body for SQL injection
  if (
    checkSQLInjection(req.url) ||
    (req.body && typeof req.body === "object" && JSON.stringify(req.body).match(/(%27)|(')|(--)|(%23)|(#)/i))
  ) {
    riskScore += 50
    threats.push("SQL Injection Attempt")
  }

  // XSS Detection
  const xssPatterns = [/<script[^>]*>.*?<\/script>/gi, /javascript:/gi, /on\w+\s*=/gi, /<iframe[^>]*>.*?<\/iframe>/gi]

  const checkXSS = (str) => {
    return xssPatterns.some((pattern) => pattern.test(str))
  }

  if (
    checkXSS(req.url) ||
    (req.body && typeof req.body === "object" && xssPatterns.some((pattern) => pattern.test(JSON.stringify(req.body))))
  ) {
    riskScore += 40
    threats.push("XSS Attempt")
  }

  // Geographic Risk Assessment
  const geo = geoip.lookup(ip)
  const highRiskCountries = ["CN", "RU", "KP", "IR"]
  if (geo && highRiskCountries.includes(geo.country)) {
    riskScore += 15
    threats.push("High Risk Geographic Location")
  }

  // Log high-risk requests
  if (riskScore > 30) {
    await logSecurityEvent("HIGH_RISK_REQUEST", "HIGH", req, {
      riskScore,
      threats,
      userAgent: agent.toString(),
    })
  }

  // Block extremely high-risk requests
  if (riskScore > 70) {
    await logSecurityEvent("BLOCKED_REQUEST", "CRITICAL", req, {
      riskScore,
      threats,
      reason: "Automatic blocking due to high risk score",
    })

    return res.status(403).json({
      error: "Request blocked due to security policy",
      riskScore,
      threats,
    })
  }

  req.securityContext = { riskScore, threats }
  next()
}

app.use(detectThreats)

// Authentication Routes
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password, name } = req.body

    // Input validation
    if (!email || !password || !name) {
      await logSecurityEvent("INVALID_SIGNUP_ATTEMPT", "MEDIUM", req, { email })
      return res.status(400).json({ error: "All fields are required" })
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Invalid email format" })
    }

    // Password strength validation
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" })
    }

    // Check if user exists
    const [existingUsers] = await db.execute("SELECT id FROM signup WHERE email = ?", [email])

    if (existingUsers.length > 0) {
      await logSecurityEvent("DUPLICATE_SIGNUP_ATTEMPT", "LOW", req, { email })
      return res.status(409).json({ error: "User already exists" })
    }

    // Hash password
    const saltRounds = 12
    const passwordHash = await bcrypt.hash(password, saltRounds)

    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString("hex")

    // Insert user
    const [result] = await db.execute(
      `
      INSERT INTO signup (email, password_hash, name, verification_token)
      VALUES (?, ?, ?, ?)
    `,
      [email, passwordHash, name, verificationToken],
    )

    await logSecurityEvent(
      "USER_SIGNUP",
      "INFO",
      req,
      {
        userId: result.insertId,
        email,
      },
      result.insertId,
    )

    res.status(201).json({
      message: "User created successfully",
      userId: result.insertId,
      verificationToken, // In production, send via email
    })
  } catch (error) {
    console.error("Signup error:", error)
    await logSecurityEvent("SIGNUP_ERROR", "HIGH", req, { error: error.message })
    res.status(500).json({ error: "Internal server error" })
  }
})

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      await logSecurityEvent("INVALID_LOGIN_ATTEMPT", "MEDIUM", req, { email })
      return res.status(400).json({ error: "Email and password are required" })
    }

    // Get user
    const [users] = await db.execute(
      `
      SELECT id, email, password_hash, name, plan, failed_login_attempts, 
             account_locked_until, two_factor_enabled
      FROM signup WHERE email = ?
    `,
      [email],
    )

    if (users.length === 0) {
      await logSecurityEvent("LOGIN_ATTEMPT_NONEXISTENT_USER", "MEDIUM", req, { email })
      return res.status(401).json({ error: "Invalid credentials" })
    }

    const user = users[0]

    // Check if account is locked
    if (user.account_locked_until && new Date() < new Date(user.account_locked_until)) {
      await logSecurityEvent("LOGIN_ATTEMPT_LOCKED_ACCOUNT", "HIGH", req, {
        userId: user.id,
        email,
      })
      return res.status(423).json({ error: "Account temporarily locked" })
    }

    // Verify password
    const passwordValid = await bcrypt.compare(password, user.password_hash)

    if (!passwordValid) {
      // Increment failed attempts
      const failedAttempts = user.failed_login_attempts + 1
      let lockUntil = null

      if (failedAttempts >= 5) {
        lockUntil = new Date(Date.now() + 30 * 60 * 1000) // 30 minutes
      }

      await db.execute(
        `
        UPDATE signup 
        SET failed_login_attempts = ?, account_locked_until = ?
        WHERE id = ?
      `,
        [failedAttempts, lockUntil, user.id],
      )

      await logSecurityEvent("FAILED_LOGIN_ATTEMPT", "HIGH", req, {
        userId: user.id,
        email,
        failedAttempts,
      })

      return res.status(401).json({ error: "Invalid credentials" })
    }

    // Reset failed attempts on successful login
    await db.execute(
      `
      UPDATE signup 
      SET failed_login_attempts = 0, account_locked_until = NULL, last_login = NOW()
      WHERE id = ?
    `,
      [user.id],
    )

    // Generate session token
    const sessionToken = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET || "your-secret-key", {
      expiresIn: "24h",
    })

    // Get client info
    const ip = req.ip || req.connection.remoteAddress
    const userAgent = req.get("User-Agent") || ""
    const geo = geoip.lookup(ip)
    const location = geo ? `${geo.city}, ${geo.country}` : "Unknown"
    const deviceFingerprint = crypto
      .createHash("md5")
      .update(userAgent + ip)
      .digest("hex")

    // Create login session
    await db.execute(
      `
      INSERT INTO login (user_id, session_token, ip_address, user_agent, location, device_fingerprint)
      VALUES (?, ?, ?, ?, ?, ?)
    `,
      [user.id, sessionToken, ip, userAgent, location, deviceFingerprint],
    )

    await logSecurityEvent(
      "SUCCESSFUL_LOGIN",
      "INFO",
      req,
      {
        userId: user.id,
        email,
        location,
      },
      user.id,
    )

    res.json({
      message: "Login successful",
      token: sessionToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        plan: user.plan,
      },
    })
  } catch (error) {
    console.error("Login error:", error)
    await logSecurityEvent("LOGIN_ERROR", "HIGH", req, { error: error.message })
    res.status(500).json({ error: "Internal server error" })
  }
})

// Security Monitoring Routes
app.get("/api/security/dashboard", async (req, res) => {
  try {
    // Get security statistics
    const [threatStats] = await db.execute(`
      SELECT 
        COUNT(*) as total_events,
        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_events,
        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_events,
        SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_events
      FROM security_events 
      WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    `)

    const [recentEvents] = await db.execute(`
      SELECT event_type, severity, ip_address, location, timestamp, details
      FROM security_events 
      ORDER BY timestamp DESC 
      LIMIT 10
    `)

    const [topThreats] = await db.execute(`
      SELECT event_type, COUNT(*) as count
      FROM security_events 
      WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
      GROUP BY event_type 
      ORDER BY count DESC 
      LIMIT 5
    `)

    const [geoThreats] = await db.execute(`
      SELECT location, COUNT(*) as count
      FROM security_events 
      WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) AND location != 'Unknown'
      GROUP BY location 
      ORDER BY count DESC 
      LIMIT 10
    `)

    res.json({
      stats: threatStats[0],
      recentEvents,
      topThreats,
      geoThreats,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    console.error("Dashboard error:", error)
    res.status(500).json({ error: "Failed to fetch dashboard data" })
  }
})

// Real-time Threat Detection
app.post("/api/security/analyze-threat", async (req, res) => {
  try {
    const { url, method, headers, body } = req.body

    const analysis = {
      riskScore: 0,
      threats: [],
      recommendations: [],
    }

    // Analyze URL
    if (url) {
      if (url.includes("admin") || url.includes("wp-admin")) {
        analysis.riskScore += 20
        analysis.threats.push("Admin panel access attempt")
      }

      if (url.includes("..") || url.includes("%2e%2e")) {
        analysis.riskScore += 30
        analysis.threats.push("Directory traversal attempt")
      }
    }

    // Analyze headers
    if (headers) {
      if (!headers["user-agent"] || headers["user-agent"].length < 10) {
        analysis.riskScore += 15
        analysis.threats.push("Suspicious or missing User-Agent")
      }
    }

    // Generate recommendations
    if (analysis.riskScore > 50) {
      analysis.recommendations.push("Block this request immediately")
      analysis.recommendations.push("Add IP to blacklist")
    } else if (analysis.riskScore > 20) {
      analysis.recommendations.push("Monitor this source closely")
      analysis.recommendations.push("Implement additional verification")
    }

    await logSecurityEvent("THREAT_ANALYSIS", "INFO", req, analysis)

    res.json(analysis)
  } catch (error) {
    console.error("Threat analysis error:", error)
    res.status(500).json({ error: "Failed to analyze threat" })
  }
})

// DDoS Protection Simulation
app.post("/api/security/ddos-protection", async (req, res) => {
  try {
    const { targetUrl, attackType } = req.body

    // Simulate DDoS protection analysis
    const protection = {
      status: "ACTIVE",
      mitigationLevel: "HIGH",
      attacksBlocked: Math.floor(Math.random() * 10000) + 1000,
      bandwidth: "2.5 Tbps",
      responseTime: "< 50ms",
      uptime: "99.99%",
      protectionMethods: [
        "Rate Limiting",
        "IP Reputation Filtering",
        "Behavioral Analysis",
        "Challenge-Response",
        "Geographic Filtering",
      ],
      attackVectors: {
        volumetric: Math.floor(Math.random() * 100),
        protocol: Math.floor(Math.random() * 100),
        application: Math.floor(Math.random() * 100),
      },
    }

    await logSecurityEvent("DDOS_PROTECTION_CHECK", "INFO", req, {
      targetUrl,
      attackType,
      protection,
    })

    res.json(protection)
  } catch (error) {
    console.error("DDoS protection error:", error)
    res.status(500).json({ error: "Failed to check DDoS protection" })
  }
})

// Initialize and start server
async function startServer() {
  await initializeDatabase()

  const PORT = process.env.PORT || 5000
  server.listen(PORT, () => {
    console.log(`🚀 Advanced Cybersecurity Backend Server running on port ${PORT}`)
    console.log(`🔒 Security monitoring active`)
    console.log(`📊 WebSocket server ready for real-time updates`)
  })
}

startServer().catch(console.error)
