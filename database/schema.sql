-- Advanced Cybersecurity Platform Database Schema
-- MySQL/MariaDB Compatible

-- Create database
CREATE DATABASE IF NOT EXISTS cyberdefense_db;
USE cyberdefense_db;

-- User signup table with advanced security features
CREATE TABLE IF NOT EXISTS signup (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    plan VARCHAR(50) DEFAULT 'Basic',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Security fields
    is_verified BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(255),
    last_login TIMESTAMP NULL,
    failed_login_attempts INT DEFAULT 0,
    account_locked_until TIMESTAMP NULL,
    
    -- Two-factor authentication
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    backup_codes JSON,
    
    -- Account security
    password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    security_questions JSON,
    
    -- Compliance and audit
    gdpr_consent BOOLEAN DEFAULT FALSE,
    gdpr_consent_date TIMESTAMP NULL,
    terms_accepted_version VARCHAR(10),
    terms_accepted_date TIMESTAMP NULL,
    
    -- Indexes for performance
    INDEX idx_email (email),
    INDEX idx_created_at (created_at),
    INDEX idx_last_login (last_login),
    INDEX idx_verification_token (verification_token)
);

-- Login sessions table for comprehensive session management
CREATE TABLE IF NOT EXISTS login (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token VARCHAR(255) UNIQUE,
    
    -- Connection details
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    location VARCHAR(255),
    device_fingerprint VARCHAR(255),
    
    -- Session timing
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    logout_time TIMESTAMP NULL,
    expires_at TIMESTAMP NOT NULL,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Security assessment
    is_active BOOLEAN DEFAULT TRUE,
    risk_score INT DEFAULT 0,
    trust_level ENUM('LOW', 'MEDIUM', 'HIGH') DEFAULT 'MEDIUM',
    
    -- Device and browser info
    device_type VARCHAR(50),
    browser_name VARCHAR(100),
    browser_version VARCHAR(50),
    os_name VARCHAR(100),
    os_version VARCHAR(50),
    
    -- Security flags
    is_suspicious BOOLEAN DEFAULT FALSE,
    requires_verification BOOLEAN DEFAULT FALSE,
    
    FOREIGN KEY (user_id) REFERENCES signup(id) ON DELETE CASCADE,
    
    -- Indexes
    INDEX idx_user_id (user_id),
    INDEX idx_session_token (session_token),
    INDEX idx_login_time (login_time),
    INDEX idx_ip_address (ip_address),
    INDEX idx_expires_at (expires_at),
    INDEX idx_is_active (is_active)
);

-- Security events table for comprehensive monitoring
CREATE TABLE IF NOT EXISTS security_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    
    -- Event classification
    event_type VARCHAR(100) NOT NULL,
    event_category ENUM('AUTHENTICATION', 'AUTHORIZATION', 'ATTACK', 'ANOMALY', 'SYSTEM') NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    
    -- Source information
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    location VARCHAR(255),
    country_code VARCHAR(2),
    
    -- Request details
    request_method VARCHAR(10),
    request_url TEXT,
    request_headers JSON,
    request_body JSON,
    
    -- Response details
    response_status INT,
    response_time_ms INT,
    
    -- Event details
    details JSON,
    threat_indicators JSON,
    
    -- Timing
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Associated user (if applicable)
    user_id INT NULL,
    session_id INT NULL,
    
    -- Action taken
    blocked BOOLEAN DEFAULT FALSE,
    action_taken VARCHAR(255),
    
    -- Risk assessment
    risk_score INT DEFAULT 0,
    confidence_level DECIMAL(3,2) DEFAULT 0.50,
    
    -- Machine learning features
    ml_features JSON,
    ml_prediction VARCHAR(50),
    
    FOREIGN KEY (user_id) REFERENCES signup(id) ON DELETE SET NULL,
    FOREIGN KEY (session_id) REFERENCES login(id) ON DELETE SET NULL,
    
    -- Indexes for performance
    INDEX idx_event_type (event_type),
    INDEX idx_event_category (event_category),
    INDEX idx_severity (severity),
    INDEX idx_timestamp (timestamp),
    INDEX idx_ip_address (ip_address),
    INDEX idx_user_id (user_id),
    INDEX idx_blocked (blocked),
    INDEX idx_risk_score (risk_score)
);

-- Threat intelligence table
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id INT AUTO_INCREMENT PRIMARY KEY,
    
    -- Threat identification
    threat_type VARCHAR(100) NOT NULL,
    threat_name VARCHAR(255),
    threat_description TEXT,
    
    -- Indicators of Compromise (IoCs)
    ip_addresses JSON,
    domains JSON,
    urls JSON,
    file_hashes JSON,
    user_agents JSON,
    
    -- Threat details
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    confidence DECIMAL(3,2) NOT NULL,
    
    -- Source information
    source VARCHAR(255) NOT NULL,
    source_reliability ENUM('A', 'B', 'C', 'D', 'E') DEFAULT 'C',
    
    -- Timing
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Additional context
    tags JSON,
    references JSON,
    
    -- Indexes
    INDEX idx_threat_type (threat_type),
    INDEX idx_severity (severity),
    INDEX idx_first_seen (first_seen),
    INDEX idx_is_active (is_active)
);

-- IP reputation table
CREATE TABLE IF NOT EXISTS ip_reputation (
    id INT AUTO_INCREMENT PRIMARY KEY,
    
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    reputation_score INT NOT NULL DEFAULT 50, -- 0-100 scale
    
    -- Reputation factors
    malware_count INT DEFAULT 0,
    phishing_count INT DEFAULT 0,
    spam_count INT DEFAULT 0,
    botnet_count INT DEFAULT 0,
    
    -- Geographic info
    country_code VARCHAR(2),
    country_name VARCHAR(100),
    region VARCHAR(100),
    city VARCHAR(100),
    
    -- ISP info
    isp VARCHAR(255),
    organization VARCHAR(255),
    
    -- Timing
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Status
    is_whitelisted BOOLEAN DEFAULT FALSE,
    is_blacklisted BOOLEAN DEFAULT FALSE,
    
    -- Additional data
    tags JSON,
    notes TEXT,
    
    -- Indexes
    INDEX idx_ip_address (ip_address),
    INDEX idx_reputation_score (reputation_score),
    INDEX idx_country_code (country_code),
    INDEX idx_is_blacklisted (is_blacklisted),
    INDEX idx_last_updated (last_updated)
);

-- WAF rules table
CREATE TABLE IF NOT EXISTS waf_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    
    -- Rule identification
    rule_name VARCHAR(255) NOT NULL,
    rule_description TEXT,
    rule_category VARCHAR(100) NOT NULL,
    
    -- Rule logic
    rule_pattern TEXT NOT NULL,
    rule_type ENUM('REGEX', 'STRING', 'IP', 'HEADER', 'BODY') NOT NULL,
    
    -- Rule configuration
    action ENUM('BLOCK', 'ALLOW', 'LOG', 'CHALLENGE') NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    
    -- Rule status
    is_active BOOLEAN DEFAULT TRUE,
    is_custom BOOLEAN DEFAULT FALSE,
    
    -- Performance metrics
    match_count INT DEFAULT 0,
    false_positive_count INT DEFAULT 0,
    
    -- Timing
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Rule metadata
    tags JSON,
    references JSON,
    
    -- Indexes
    INDEX idx_rule_category (rule_category),
    INDEX idx_is_active (is_active),
    INDEX idx_severity (severity),
    INDEX idx_created_at (created_at)
);

-- Insert default WAF rules
INSERT INTO waf_rules (rule_name, rule_description, rule_category, rule_pattern, rule_type, action, severity) VALUES
('SQL Injection - Basic', 'Detects basic SQL injection attempts', 'SQL_INJECTION', '(union|select|insert|delete|update|drop|create|alter).*?(from|into|table)', 'REGEX', 'BLOCK', 'HIGH'),
('XSS - Script Tags', 'Detects script tag injection', 'XSS', '<script[^>]*>.*?</script>', 'REGEX', 'BLOCK', 'HIGH'),
('Directory Traversal', 'Detects directory traversal attempts', 'PATH_TRAVERSAL', '(\.\./|\.\.\\\\|%2e%2e%2f|%2e%2e%5c)', 'REGEX', 'BLOCK', 'MEDIUM'),
('Command Injection', 'Detects command injection attempts', 'COMMAND_INJECTION', '(;|&&|\\||`|\\$\\()', 'REGEX', 'BLOCK', 'HIGH'),
('File Upload - Executable', 'Blocks executable file uploads', 'FILE_UPLOAD', '\\.(exe|bat|cmd|com|pif|scr|vbs|js)$', 'REGEX', 'BLOCK', 'HIGH');

-- Create views for common queries
CREATE VIEW active_sessions AS
SELECT 
    l.id,
    l.user_id,
    s.email,
    s.name,
    l.ip_address,
    l.location,
    l.login_time,
    l.last_activity,
    l.risk_score,
    l.trust_level
FROM login l
JOIN signup s ON l.user_id = s.id
WHERE l.is_active = TRUE AND l.expires_at > NOW();

CREATE VIEW security_dashboard AS
SELECT 
    DATE(timestamp) as event_date,
    event_category,
    severity,
    COUNT(*) as event_count,
    SUM(CASE WHEN blocked = TRUE THEN 1 ELSE 0 END) as blocked_count
FROM security_events
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY DATE(timestamp), event_category, severity
ORDER BY event_date DESC, event_count DESC;

-- Create stored procedures for common operations
DELIMITER //

CREATE PROCEDURE GetUserSecuritySummary(IN user_id INT)
BEGIN
    SELECT 
        s.email,
        s.name,
        s.last_login,
        s.failed_login_attempts,
        s.two_factor_enabled,
        COUNT(l.id) as active_sessions,
        COUNT(se.id) as security_events_24h
    FROM signup s
    LEFT JOIN login l ON s.id = l.user_id AND l.is_active = TRUE
    LEFT JOIN security_events se ON s.id = se.user_id AND se.timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    WHERE s.id = user_id
    GROUP BY s.id;
END //

CREATE PROCEDURE CleanupExpiredSessions()
BEGIN
    UPDATE login 
    SET is_active = FALSE, logout_time = NOW()
    WHERE expires_at < NOW() AND is_active = TRUE;
    
    SELECT ROW_COUNT() as sessions_cleaned;
END //

DELIMITER ;

-- Create triggers for audit logging
DELIMITER //

CREATE TRIGGER signup_audit_trigger
AFTER UPDATE ON signup
FOR EACH ROW
BEGIN
    IF OLD.password_hash != NEW.password_hash THEN
        INSERT INTO security_events (event_type, event_category, severity, user_id, details)
        VALUES ('PASSWORD_CHANGED', 'AUTHENTICATION', 'MEDIUM', NEW.id, 
                JSON_OBJECT('timestamp', NOW(), 'ip_address', @user_ip));
    END IF;
END //

DELIMITER ;

-- Performance optimization
ANALYZE TABLE signup, login, security_events, threat_intelligence, ip_reputation, waf_rules;

-- Grant permissions (adjust as needed)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON cyberdefense_db.* TO 'app_user'@'localhost';
-- GRANT EXECUTE ON PROCEDURE cyberdefense_db.GetUserSecuritySummary TO 'app_user'@'localhost';
-- GRANT EXECUTE ON PROCEDURE cyberdefense_db.CleanupExpiredSessions TO 'app_user'@'localhost';

-- Show table information
SELECT 
    TABLE_NAME,
    TABLE_ROWS,
    DATA_LENGTH,
    INDEX_LENGTH,
    CREATE_TIME
FROM information_schema.TABLES 
WHERE TABLE_SCHEMA = 'cyberdefense_db'
ORDER BY TABLE_NAME;
