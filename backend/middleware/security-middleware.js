const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const winston = require('winston');

/**
 * Comprehensive Security Middleware for Production
 * Implements OWASP security best practices
 */
class SecurityMiddleware {
    constructor(options = {}) {
        this.config = {
            // CORS Configuration
            cors: {
                origin: process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3001'],
                credentials: true,
                methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
                allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key'],
                exposedHeaders: ['X-Total-Count', 'X-Rate-Limit-Remaining'],
                maxAge: 86400 // 24 hours
            },
            
            // Rate Limiting Configuration
            rateLimiting: {
                windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000, // 15 minutes
                maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
                skipSuccessfulRequests: false,
                skipFailedRequests: false,
                standardHeaders: true,
                legacyHeaders: false
            },
            
            // Content Security Policy
            csp: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
                    fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
                    scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdnjs.cloudflare.com"],
                    imgSrc: ["'self'", "data:", "https:", "blob:"],
                    connectSrc: ["'self'", "ws:", "wss:", "https:", "http://localhost:*"],
                    mediaSrc: ["'self'", "data:", "blob:"],
                    objectSrc: ["'none'"],
                    frameSrc: ["'self'", "https:"],
                    baseUri: ["'self'"],
                    formAction: ["'self'"]
                },
                reportOnly: process.env.NODE_ENV !== 'production'
            },
            
            // Input Validation
            validation: {
                maxBodySize: '10mb',
                maxParamLength: 100,
                maxHeaderSize: 8192,
                allowedFileTypes: ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', '.txt'],
                maxFileSize: 50 * 1024 * 1024 // 50MB
            },
            
            // Security Headers
            securityHeaders: {
                hsts: {
                    maxAge: 31536000, // 1 year
                    includeSubDomains: true,
                    preload: true
                },
                noSniff: true,
                frameguard: { action: 'deny' },
                xssFilter: true,
                referrerPolicy: 'strict-origin-when-cross-origin'
            },
            
            // Session Security
            session: {
                secure: process.env.NODE_ENV === 'production',
                httpOnly: true,
                sameSite: 'strict',
                maxAge: 24 * 60 * 60 * 1000 // 24 hours
            },
            
            ...options
        };
        
        this.securityLogger = this.setupSecurityLogger();
        this.rateLimitStore = new Map();
        this.suspiciousIPs = new Set();
        this.blockedIPs = new Set();
        
        // Security metrics
        this.metrics = {
            totalRequests: 0,
            blockedRequests: 0,
            suspiciousActivity: 0,
            rateLimitHits: 0,
            validationFailures: 0,
            securityEvents: 0
        };
    }
    
    setupSecurityLogger() {
        return winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
            transports: [
                new winston.transports.File({ 
                    filename: 'logs/security/security-events.log',
                    level: 'warn'
                }),
                new winston.transports.File({ 
                    filename: 'logs/security/security-alerts.log',
                    level: 'error'
                })
            ]
        });
    }
    
    /**
     * Main security middleware setup
     */
    setupSecurity(app) {
        // 1. Basic security headers
        app.use(this.helmetMiddleware());
        
        // 2. CORS configuration
        app.use(this.corsMiddleware());
        
        // 3. Request size limiting
        app.use(this.requestSizeLimiting());
        
        // 4. IP blocking and suspicious activity detection
        app.use(this.ipSecurityMiddleware());
        
        // 5. Rate limiting
        app.use(this.rateLimitingMiddleware());
        
        // 6. Input validation and sanitization
        app.use(this.inputValidationMiddleware());
        
        // 7. Security monitoring
        app.use(this.securityMonitoringMiddleware());
        
        console.log('🛡️ Comprehensive Security Middleware Activated');
    }
    
    /**
     * Helmet security headers
     */
    helmetMiddleware() {
        return helmet({
            contentSecurityPolicy: this.config.csp,
            hsts: this.config.securityHeaders.hsts,
            noSniff: this.config.securityHeaders.noSniff,
            frameguard: this.config.securityHeaders.frameguard,
            xssFilter: this.config.securityHeaders.xssFilter,
            referrerPolicy: { policy: this.config.securityHeaders.referrerPolicy },
            crossOriginEmbedderPolicy: false, // Disable for compatibility
            crossOriginOpenerPolicy: false,   // Disable for compatibility
            crossOriginResourcePolicy: false  // Disable for compatibility
        });
    }
    
    /**
     * CORS middleware with enhanced security
     */
    corsMiddleware() {
        return cors({
            ...this.config.cors,
            optionsSuccessStatus: 200,
            preflightContinue: false
        });
    }
    
    /**
     * Request size limiting
     */
    requestSizeLimiting() {
        return (req, res, next) => {
            // Check content length
            const contentLength = parseInt(req.get('content-length') || '0');
            if (contentLength > 50 * 1024 * 1024) { // 50MB limit
                this.logSecurityEvent('large_request_blocked', {
                    ip: req.ip,
                    contentLength,
                    userAgent: req.get('User-Agent')
                });
                return res.status(413).json({ error: 'Request entity too large' });
            }
            next();
        };
    }
    
    /**
     * IP security and suspicious activity detection
     */
    ipSecurityMiddleware() {
        return (req, res, next) => {
            const clientIP = this.getClientIP(req);
            
            // Check if IP is blocked
            if (this.blockedIPs.has(clientIP)) {
                this.logSecurityEvent('blocked_ip_attempt', { ip: clientIP });
                return res.status(403).json({ error: 'Access denied' });
            }
            
            // Check for suspicious patterns
            if (this.detectSuspiciousActivity(req)) {
                this.suspiciousIPs.add(clientIP);
                this.metrics.suspiciousActivity++;
                
                this.logSecurityEvent('suspicious_activity', {
                    ip: clientIP,
                    userAgent: req.get('User-Agent'),
                    path: req.path,
                    method: req.method
                });
            }
            
            req.clientIP = clientIP;
            next();
        };
    }
    
    /**
     * Advanced rate limiting with dynamic limits
     */
    rateLimitingMiddleware() {
        return rateLimit({
            windowMs: this.config.rateLimiting.windowMs,
            max: async (req) => {
                // Dynamic rate limiting based on user tier
                const userId = req.user?.id;
                if (!userId) return 100; // Anonymous users
                
                // Check user subscription (if available)
                try {
                    const subscription = req.user?.subscription || { tier: 'free' };
                    switch (subscription.tier) {
                        case 'free': return 50;
                        case 'basic': return 500;
                        case 'pro': return 2000;
                        case 'enterprise': return 10000;
                        default: return 100;
                    }
                } catch (error) {
                    return 100;
                }
            },
            standardHeaders: this.config.rateLimiting.standardHeaders,
            legacyHeaders: this.config.rateLimiting.legacyHeaders,
            handler: (req, res) => {
                this.metrics.rateLimitHits++;
                this.logSecurityEvent('rate_limit_exceeded', {
                    ip: req.clientIP || req.ip,
                    userAgent: req.get('User-Agent'),
                    path: req.path
                });
                
                res.status(429).json({
                    error: 'Rate limit exceeded',
                    retryAfter: Math.ceil(this.config.rateLimiting.windowMs / 1000),
                    upgradeUrl: '/api/subscription/upgrade'
                });
            },
            skip: (req) => {
                // Skip rate limiting for health checks
                return req.path === '/health' || req.path === '/api/health';
            }
        });
    }
    
    /**
     * Input validation and sanitization
     */
    inputValidationMiddleware() {
        return (req, res, next) => {
            try {
                // Validate and sanitize common inputs
                this.sanitizeRequest(req);
                
                // Check for malicious patterns
                if (this.detectMaliciousInput(req)) {
                    this.metrics.validationFailures++;
                    this.logSecurityEvent('malicious_input_detected', {
                        ip: req.clientIP || req.ip,
                        path: req.path,
                        method: req.method,
                        body: JSON.stringify(req.body).substring(0, 500)
                    });
                    
                    return res.status(400).json({ error: 'Invalid input detected' });
                }
                
                next();
            } catch (error) {
                this.logSecurityEvent('validation_error', {
                    ip: req.clientIP || req.ip,
                    error: error.message
                });
                next();
            }
        };
    }
    
    /**
     * Security monitoring middleware
     */
    securityMonitoringMiddleware() {
        return (req, res, next) => {
            this.metrics.totalRequests++;
            
            // Add security headers to response
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.setHeader('X-Frame-Options', 'DENY');
            res.setHeader('X-XSS-Protection', '1; mode=block');
            
            if (process.env.NODE_ENV === 'production') {
                res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
            }
            
            next();
        };
    }
    
    /**
     * Get real client IP address
     */
    getClientIP(req) {
        return req.headers['x-forwarded-for']?.split(',')[0] ||
               req.headers['x-real-ip'] ||
               req.connection?.remoteAddress ||
               req.socket?.remoteAddress ||
               req.ip;
    }
    
    /**
     * Detect suspicious activity patterns
     */
    detectSuspiciousActivity(req) {
        const userAgent = req.get('User-Agent') || '';
        const path = req.path;
        
        // Check for bot patterns
        const botPatterns = [
            /bot/i, /crawler/i, /spider/i, /scraper/i,
            /curl/i, /wget/i, /python/i, /java/i
        ];
        
        if (botPatterns.some(pattern => pattern.test(userAgent))) {
            return true;
        }
        
        // Check for suspicious paths
        const suspiciousPaths = [
            /\/admin/i, /\/wp-admin/i, /\/phpmyadmin/i,
            /\.php$/i, /\.asp$/i, /\.jsp$/i,
            /\/\.env/i, /\/config/i, /\/backup/i
        ];
        
        if (suspiciousPaths.some(pattern => pattern.test(path))) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Sanitize request data
     */
    sanitizeRequest(req) {
        if (req.body && typeof req.body === 'object') {
            req.body = this.sanitizeObject(req.body);
        }
        
        if (req.query && typeof req.query === 'object') {
            req.query = this.sanitizeObject(req.query);
        }
    }
    
    /**
     * Sanitize object recursively
     */
    sanitizeObject(obj) {
        if (typeof obj !== 'object' || obj === null) {
            return obj;
        }
        
        const sanitized = {};
        for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'string') {
                sanitized[key] = this.sanitizeString(value);
            } else if (typeof value === 'object') {
                sanitized[key] = this.sanitizeObject(value);
            } else {
                sanitized[key] = value;
            }
        }
        
        return sanitized;
    }
    
    /**
     * Sanitize string input
     */
    sanitizeString(str) {
        if (typeof str !== 'string') return str;
        
        // Remove potential XSS patterns
        return str
            .replace(/<script[^>]*>.*?<\/script>/gi, '')
            .replace(/<iframe[^>]*>.*?<\/iframe>/gi, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+\s*=/gi, '')
            .trim();
    }
    
    /**
     * Detect malicious input patterns
     */
    detectMaliciousInput(req) {
        const content = JSON.stringify({
            body: req.body,
            query: req.query,
            params: req.params
        });
        
        // SQL injection patterns
        const sqlPatterns = [
            /('|(\-\-)|(;)|(\||\|)|(\*|\*))/i,
            /(union|select|insert|delete|update|drop|create|alter|exec|execute)/i
        ];
        
        // XSS patterns
        const xssPatterns = [
            /<script[^>]*>.*?<\/script>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /<iframe[^>]*>/gi
        ];
        
        // Command injection patterns (exclude braces to avoid false positives on JSON)
        const cmdPatterns = [
            /[;&|`$()]/,
            /(cat|ls|pwd|whoami|id|uname|wget|curl)/i
        ];
        
        return [...sqlPatterns, ...xssPatterns, ...cmdPatterns]
            .some(pattern => pattern.test(content));
    }
    
    /**
     * Log security events
     */
    logSecurityEvent(eventType, details) {
        this.metrics.securityEvents++;
        
        const event = {
            timestamp: new Date().toISOString(),
            type: eventType,
            severity: this.getEventSeverity(eventType),
            details,
            metrics: { ...this.metrics }
        };
        
        this.securityLogger.warn('Security Event', event);
        
        // Emit event for real-time monitoring
        if (this.eventEmitter) {
            this.eventEmitter.emit('security_event', event);
        }
    }
    
    /**
     * Get event severity level
     */
    getEventSeverity(eventType) {
        const severityMap = {
            'blocked_ip_attempt': 'high',
            'malicious_input_detected': 'high',
            'suspicious_activity': 'medium',
            'rate_limit_exceeded': 'low',
            'large_request_blocked': 'medium',
            'validation_error': 'low'
        };
        
        return severityMap[eventType] || 'medium';
    }
    
    /**
     * Get security metrics
     */
    getSecurityMetrics() {
        return {
            ...this.metrics,
            blockedIPs: this.blockedIPs.size,
            suspiciousIPs: this.suspiciousIPs.size,
            securityLevel: this.calculateSecurityLevel()
        };
    }
    
    /**
     * Calculate overall security level
     */
    calculateSecurityLevel() {
        const { totalRequests, blockedRequests, suspiciousActivity } = this.metrics;
        
        if (totalRequests === 0) return 'unknown';
        
        const threatRatio = (blockedRequests + suspiciousActivity) / totalRequests;
        
        if (threatRatio > 0.1) return 'high_risk';
        if (threatRatio > 0.05) return 'medium_risk';
        if (threatRatio > 0.01) return 'low_risk';
        return 'secure';
    }
    
    /**
     * Block IP address
     */
    blockIP(ip, reason = 'Security violation') {
        this.blockedIPs.add(ip);
        this.logSecurityEvent('ip_blocked', { ip, reason });
    }
    
    /**
     * Unblock IP address
     */
    unblockIP(ip) {
        this.blockedIPs.delete(ip);
        this.logSecurityEvent('ip_unblocked', { ip });
    }
    
    /**
     * Cleanup and shutdown
     */
    cleanup() {
        // Clear security data
        this.rateLimitStore.clear();
        this.suspiciousIPs.clear();
        
        console.log('🛡️ Security middleware cleaned up');
    }
}

module.exports = SecurityMiddleware;