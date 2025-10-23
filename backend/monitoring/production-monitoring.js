/**
 * COSMOSIO Production Monitoring System
 * Real monitoring, logging, and analytics with CloudWatch, Prometheus
 * Real-time dashboards and alerting
 */

const AWS = require('aws-sdk');
const prometheus = require('prom-client');
const winston = require('winston');
const express = require('express');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const productionDB = require('../database/production-db');
const EventEmitter = require('events');

// Import new monitoring components
const errorTracking = require('./error-tracking');
const loggingSystem = require('./logging-system');
const performanceMonitor = require('./performance-monitor');

class ProductionMonitoring extends EventEmitter {
    constructor() {
        super();
        this.metrics = new Map();
        this.alerts = new Map();
        this.dashboards = new Map();
        this.isActive = false;
        
        // Initialize integrated monitoring components
        this.errorTracking = errorTracking;
        this.loggingSystem = loggingSystem;
        this.performanceMonitor = performanceMonitor;
        
        this.initializeMonitoring();
        console.log('📊 COSMOSIO Production Monitoring - Initializing Real-time Systems!');
    }

    async initializeMonitoring() {
        try {
            // Initialize logging
            await this.setupLogging();
            
            // Initialize metrics collection
            await this.setupMetrics();
            
            // Initialize CloudWatch
            await this.setupCloudWatch();
            
            // Initialize Prometheus
            await this.setupPrometheus();
            
            // Initialize real-time dashboards
            await this.setupDashboards();
            
            // Initialize alerting
            await this.setupAlerting();
            
            // Setup integrated monitoring event handlers
            await this.setupIntegratedMonitoring();
            
            // Start monitoring services
            await this.startMonitoring();
            
            this.isActive = true;
            this.emit('monitoring_ready');
            
            console.log('✅ Production Monitoring System Activated!');
            
        } catch (error) {
            console.error('❌ Failed to initialize Production Monitoring:', error);
            throw error;
        }
    }

    async setupLogging() {
        // Configure Winston logger
        this.logger = winston.createLogger({
            level: process.env.LOG_LEVEL || 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.json()
            ),
            defaultMeta: { service: 'cosmosio-production' },
            transports: [
                // Console logging
                new winston.transports.Console({
                    format: winston.format.combine(
                        winston.format.colorize(),
                        winston.format.simple()
                    )
                }),
                
                // File logging
                new winston.transports.File({ 
                    filename: './logs/error.log', 
                    level: 'error',
                    maxsize: 5242880, // 5MB
                    maxFiles: 5
                }),
                new winston.transports.File({ 
                    filename: './logs/combined.log',
                    maxsize: 5242880, // 5MB
                    maxFiles: 10
                })
            ]
        });

        // Add CloudWatch logging if AWS is configured
        if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
            const WinstonCloudWatch = require('winston-cloudwatch');
            
            this.logger.add(new WinstonCloudWatch({
                logGroupName: process.env.CLOUDWATCH_LOG_GROUP || 'cosmosio-production',
                logStreamName: `${process.env.NODE_ENV || 'production'}-${new Date().toISOString().split('T')[0]}`,
                awsRegion: process.env.AWS_REGION || 'us-east-1',
                jsonMessage: true
            }));
            
            console.log('☁️ CloudWatch Logging Enabled');
        }

        console.log('📝 Production Logging Configured');
    }

    async setupMetrics() {
        // Initialize Prometheus metrics
        this.prometheusMetrics = {
            // HTTP metrics
            httpRequestsTotal: new prometheus.Counter({
                name: 'cosmosio_http_requests_total',
                help: 'Total number of HTTP requests',
                labelNames: ['method', 'route', 'status_code']
            }),
            
            httpRequestDuration: new prometheus.Histogram({
                name: 'cosmosio_http_request_duration_seconds',
                help: 'Duration of HTTP requests in seconds',
                labelNames: ['method', 'route'],
                buckets: [0.1, 0.5, 1, 2, 5, 10]
            }),
            
            // AI metrics
            aiRequestsTotal: new prometheus.Counter({
                name: 'cosmosio_ai_requests_total',
                help: 'Total number of AI requests',
                labelNames: ['provider', 'model', 'status']
            }),
            
            aiRequestDuration: new prometheus.Histogram({
                name: 'cosmosio_ai_request_duration_seconds',
                help: 'Duration of AI requests in seconds',
                labelNames: ['provider', 'model'],
                buckets: [1, 5, 10, 30, 60, 120]
            }),
            
            aiTokensUsed: new prometheus.Counter({
                name: 'cosmosio_ai_tokens_used_total',
                help: 'Total number of AI tokens used',
                labelNames: ['provider', 'model', 'type']
            }),
            
            // System metrics
            systemCpuUsage: new prometheus.Gauge({
                name: 'cosmosio_system_cpu_usage_percent',
                help: 'System CPU usage percentage'
            }),
            
            systemMemoryUsage: new prometheus.Gauge({
                name: 'cosmosio_system_memory_usage_percent',
                help: 'System memory usage percentage'
            }),
            
            systemDiskUsage: new prometheus.Gauge({
                name: 'cosmosio_system_disk_usage_percent',
                help: 'System disk usage percentage'
            }),
            
            // Database metrics
            databaseConnections: new prometheus.Gauge({
                name: 'cosmosio_database_connections_active',
                help: 'Number of active database connections'
            }),
            
            databaseQueryDuration: new prometheus.Histogram({
                name: 'cosmosio_database_query_duration_seconds',
                help: 'Duration of database queries in seconds',
                labelNames: ['operation'],
                buckets: [0.01, 0.05, 0.1, 0.5, 1, 5]
            }),
            
            // Business metrics
            activeUsers: new prometheus.Gauge({
                name: 'cosmosio_active_users_total',
                help: 'Number of active users'
            }),
            
            tasksCompleted: new prometheus.Counter({
                name: 'cosmosio_tasks_completed_total',
                help: 'Total number of completed tasks',
                labelNames: ['agent_type', 'status']
            }),
            
            revenue: new prometheus.Counter({
                name: 'cosmosio_revenue_total',
                help: 'Total revenue generated',
                labelNames: ['currency', 'plan']
            })
        };

        // Register all metrics
        prometheus.register.registerMetric(this.prometheusMetrics.httpRequestsTotal);
        prometheus.register.registerMetric(this.prometheusMetrics.httpRequestDuration);
        prometheus.register.registerMetric(this.prometheusMetrics.aiRequestsTotal);
        prometheus.register.registerMetric(this.prometheusMetrics.aiRequestDuration);
        prometheus.register.registerMetric(this.prometheusMetrics.aiTokensUsed);
        prometheus.register.registerMetric(this.prometheusMetrics.systemCpuUsage);
        prometheus.register.registerMetric(this.prometheusMetrics.systemMemoryUsage);
        prometheus.register.registerMetric(this.prometheusMetrics.systemDiskUsage);
        prometheus.register.registerMetric(this.prometheusMetrics.databaseConnections);
        prometheus.register.registerMetric(this.prometheusMetrics.databaseQueryDuration);
        prometheus.register.registerMetric(this.prometheusMetrics.activeUsers);
        prometheus.register.registerMetric(this.prometheusMetrics.tasksCompleted);
        prometheus.register.registerMetric(this.prometheusMetrics.revenue);

        console.log('📈 Prometheus Metrics Configured');
    }

    async setupCloudWatch() {
        if (process.env.DISABLE_TELEMETRY === '1' || process.env.OFFLINE_MODE === '1') {
            this.cloudWatch = null;
            return;
        }
        if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
            this.cloudWatch = new AWS.CloudWatch({
                region: process.env.AWS_REGION || 'us-east-1'
            });
            
            this.cloudWatchNamespace = 'COSMOSIO/Production';
            
            console.log('☁️ CloudWatch Metrics Configured');
        }
    }

    async setupPrometheus() {
        // Create Prometheus metrics endpoint
        this.metricsApp = express();
        
        this.metricsApp.get('/metrics', async (req, res) => {
            try {
                res.set('Content-Type', prometheus.register.contentType);
                res.end(await prometheus.register.metrics());
            } catch (error) {
                res.status(500).end(error.message);
            }
        });
        
        this.metricsApp.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date(),
                uptime: process.uptime(),
                monitoring: this.isActive
            });
        });
        
        const metricsPort = process.env.METRICS_PORT || 9090;
        this.metricsServer = this.metricsApp.listen(metricsPort, () => {
            console.log(`📊 Prometheus metrics server running on port ${metricsPort}`);
        });
    }

    async setupDashboards() {
        // Create WebSocket server for real-time dashboards
        const dashboardPort = process.env.DASHBOARD_WS_PORT || 9091;
        try {
            this.dashboardServer = new WebSocket.Server({
                port: dashboardPort,
                perMessageDeflate: false,
                clientTracking: true,
                maxPayload: 16 * 1024 * 1024 // 16MB
            });
            
            this.dashboardClients = new Set();
            
            this.dashboardServer.on('connection', (ws, req) => {
                console.log(`📊 Dashboard client connected from ${req.socket.remoteAddress}`);
                this.dashboardClients.add(ws);
                
                // Send initial data
                ws.send(JSON.stringify({
                    type: 'initial_data',
                    data: this.getCurrentMetrics()
                }));
                
                ws.on('close', () => {
                    console.log('📊 Dashboard client disconnected');
                    this.dashboardClients.delete(ws);
                });
                
                ws.on('error', (error) => {
                    console.error('📊 Dashboard WebSocket error:', error);
                });
                
                ws.on('message', (message) => {
                    try {
                        const request = JSON.parse(message);
                        this.handleDashboardRequest(ws, request);
                    } catch (error) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Invalid request format'
                        }));
                    }
                });
            });
            
            this.dashboardServer.on('error', (error) => {
                console.error('📊 Dashboard WebSocket Server error:', error);
            });
            
            console.log(`📱 Real-time Dashboard WebSocket server running on port ${dashboardPort}`);
        } catch (error) {
            console.error('❌ Failed to start Dashboard WebSocket server:', error);
        }
    }

    async setupAlerting() {
        this.alertRules = [
            {
                id: 'high_cpu_usage',
                name: 'High CPU Usage',
                condition: (metrics) => metrics.cpuUsage > 80,
                severity: 'warning',
                cooldown: 300000 // 5 minutes
            },
            {
                id: 'high_memory_usage',
                name: 'High Memory Usage',
                condition: (metrics) => metrics.memoryUsage > 85,
                severity: 'warning',
                cooldown: 300000
            },
            {
                id: 'high_error_rate',
                name: 'High Error Rate',
                condition: (metrics) => metrics.errorRate > 5,
                severity: 'critical',
                cooldown: 180000 // 3 minutes
            },
            {
                id: 'slow_response_time',
                name: 'Slow Response Time',
                condition: (metrics) => metrics.avgResponseTime > 5000,
                severity: 'warning',
                cooldown: 300000
            },
            {
                id: 'database_connection_issues',
                name: 'Database Connection Issues',
                condition: (metrics) => metrics.dbConnectionErrors > 10,
                severity: 'critical',
                cooldown: 120000 // 2 minutes
            }
        ];
        
        this.alertCooldowns = new Map();
        
        console.log('🚨 Alerting System Configured');
    }

    async setupIntegratedMonitoring() {
        // Setup event handlers for integrated monitoring components
        
        // Error tracking events
        this.errorTracking.on('error_captured', (errorData) => {
            this.handleErrorEvent(errorData);
        });
        
        this.errorTracking.on('error_spike', (spikeData) => {
            this.handleErrorSpike(spikeData);
        });
        
        // Performance monitoring events
        this.performanceMonitor.on('performance_alert', (alert) => {
            this.handlePerformanceAlert(alert);
        });
        
        this.performanceMonitor.on('system_metrics', (metrics) => {
            this.updateSystemMetrics(metrics);
        });
        
        // Logging system events
        this.loggingSystem.on('log_statistics', (stats) => {
            this.updateLogStatistics(stats);
        });
        
        this.loggingSystem.on('security_event', (event) => {
            this.handleSecurityEvent(event);
        });
        
        console.log('🔗 Integrated Monitoring Components Connected');
    }

    handleErrorEvent(errorData) {
        // Update error metrics
        this.prometheusMetrics.aiRequestsTotal.inc({
            provider: 'error_tracking',
            model: errorData.category || 'unknown',
            status: 'error'
        });
        
        // Log to main monitoring system
        this.logger.error('Error captured by monitoring', {
            errorId: errorData.id,
            category: errorData.category,
            message: errorData.message
        });
        
        // Send to dashboard
        this.emit('error_event', errorData);
    }

    handleErrorSpike(spikeData) {
        this.logger.warn('Error spike detected', spikeData);
        
        // Create alert
        this.triggerAlert({
            id: 'error_spike',
            name: 'Error Spike Detected',
            condition: () => true,
            severity: 'warning',
            cooldown: 300000
        }, {
            errorSpike: true,
            spikeData: spikeData
        });
    }

    handlePerformanceAlert(alert) {
        this.logger.warn('Performance alert', alert);
        
        // Forward to alerting system
        this.triggerAlert({
            id: 'performance_alert',
            name: 'Performance Alert',
            condition: () => true,
            severity: alert.severity || 'warning',
            cooldown: 300000
        }, {
            performanceAlert: true,
            alertData: alert
        });
    }

    updateSystemMetrics(metrics) {
        // Update Prometheus metrics
        if (metrics.cpu && metrics.cpu.usage_percent !== undefined) {
            this.prometheusMetrics.systemCpuUsage.set(metrics.cpu.usage_percent);
        }
        
        if (metrics.memory && metrics.memory.usage_percent !== undefined) {
            this.prometheusMetrics.systemMemoryUsage.set(metrics.memory.usage_percent);
        }
    }

    updateLogStatistics(stats) {
        // Log statistics for monitoring
        this.logger.info('Log statistics updated', stats);
        
        // Emit for dashboard updates
        this.emit('log_statistics', stats);
    }

    handleSecurityEvent(event) {
        this.logger.warn('Security event detected', event);
        
        // Create high-priority alert for security events
        this.triggerAlert({
            id: 'security_event',
            name: 'Security Event Detected',
            condition: () => true,
            severity: 'critical',
            cooldown: 120000
        }, {
            securityEvent: true,
            eventData: event
        });
    }

    async startMonitoring() {
        if (process.env.DISABLE_ANALYTICS === '1') {
            console.log('🔕 Analytics disabled by policy; monitoring loops are skipped');
            return;
        }
        // Start system metrics collection
        this.systemMetricsInterval = setInterval(() => {
            this.collectSystemMetrics();
        }, 30000); // Every 30 seconds
        
        // Start business metrics collection
        this.businessMetricsInterval = setInterval(() => {
            this.collectBusinessMetrics();
        }, 60000); // Every minute
        
        // Start alert checking
        this.alertCheckInterval = setInterval(() => {
            this.checkAlerts();
        }, 60000); // Every minute
        
        // Start dashboard updates
        this.dashboardUpdateInterval = setInterval(() => {
            this.broadcastDashboardUpdate();
        }, 5000); // Every 5 seconds
        
        console.log('🔄 Monitoring Services Started');
    }

    async collectSystemMetrics() {
        try {
            const os = require('os');
            const fs = require('fs');
            
            // CPU usage
            const cpuUsage = await this.getCPUUsage();
            this.prometheusMetrics.systemCpuUsage.set(cpuUsage);
            
            // Memory usage
            const totalMem = os.totalmem();
            const freeMem = os.freemem();
            const memoryUsage = ((totalMem - freeMem) / totalMem) * 100;
            this.prometheusMetrics.systemMemoryUsage.set(memoryUsage);
            
            // Disk usage (simplified)
            const diskUsage = await this.getDiskUsage();
            this.prometheusMetrics.systemDiskUsage.set(diskUsage);
            
            // Database connections
            const dbConnections = await this.getDatabaseConnections();
            this.prometheusMetrics.databaseConnections.set(dbConnections);
            
            // Send to CloudWatch if configured
            if (this.cloudWatch) {
                await this.sendToCloudWatch([
                    { MetricName: 'CPUUsage', Value: cpuUsage, Unit: 'Percent' },
                    { MetricName: 'MemoryUsage', Value: memoryUsage, Unit: 'Percent' },
                    { MetricName: 'DiskUsage', Value: diskUsage, Unit: 'Percent' },
                    { MetricName: 'DatabaseConnections', Value: dbConnections, Unit: 'Count' }
                ]);
            }
            
            // Store in database
            await this.storeMetrics({
                cpuUsage,
                memoryUsage,
                diskUsage,
                dbConnections,
                timestamp: new Date()
            });
            
        } catch (error) {
            this.logger.error('Failed to collect system metrics:', error);
        }
    }

    async collectBusinessMetrics() {
        try {
            const client = await productionDB.pool.connect();
            
            try {
                // Active users (last 24 hours)
                const activeUsersResult = await client.query(`
                    SELECT COUNT(DISTINCT user_id) as count 
                    FROM analytics 
                    WHERE timestamp > NOW() - INTERVAL '24 hours'
                `);
                const activeUsers = parseInt(activeUsersResult.rows[0].count) || 0;
                this.prometheusMetrics.activeUsers.set(activeUsers);
                
                // Tasks completed (last hour)
                const tasksResult = await client.query(`
                    SELECT agent_type, status, COUNT(*) as count 
                    FROM tasks 
                    WHERE completed_at > NOW() - INTERVAL '1 hour'
                    GROUP BY agent_type, status
                `);
                
                tasksResult.rows.forEach(row => {
                    this.prometheusMetrics.tasksCompleted
                        .labels(row.agent_type, row.status)
                        .inc(parseInt(row.count));
                });
                
                // Revenue (last hour)
                const revenueResult = await client.query(`
                    SELECT currency, SUM(amount) as total 
                    FROM billing 
                    WHERE processed_at > NOW() - INTERVAL '1 hour' AND status = 'completed'
                    GROUP BY currency
                `);
                
                revenueResult.rows.forEach(row => {
                    this.prometheusMetrics.revenue
                        .labels(row.currency, 'all')
                        .inc(parseFloat(row.total));
                });
                
                // Send to CloudWatch
                if (this.cloudWatch) {
                    await this.sendToCloudWatch([
                        { MetricName: 'ActiveUsers', Value: activeUsers, Unit: 'Count' },
                        { MetricName: 'TasksCompleted', Value: tasksResult.rows.length, Unit: 'Count' }
                    ]);
                }
                
            } finally {
                client.release();
            }
            
        } catch (error) {
            this.logger.error('Failed to collect business metrics:', error);
        }
    }

    async checkAlerts() {
        try {
            const currentMetrics = await this.getCurrentMetrics();
            
            for (const rule of this.alertRules) {
                const lastAlert = this.alertCooldowns.get(rule.id);
                const now = Date.now();
                
                // Check cooldown
                if (lastAlert && (now - lastAlert) < rule.cooldown) {
                    continue;
                }
                
                // Check condition
                if (rule.condition(currentMetrics)) {
                    await this.triggerAlert(rule, currentMetrics);
                    this.alertCooldowns.set(rule.id, now);
                }
            }
            
        } catch (error) {
            this.logger.error('Failed to check alerts:', error);
        }
    }

    async triggerAlert(rule, metrics) {
        const alert = {
            id: uuidv4(),
            ruleId: rule.id,
            name: rule.name,
            severity: rule.severity,
            metrics,
            timestamp: new Date(),
            status: 'active'
        };
        
        this.alerts.set(alert.id, alert);
        
        // Log alert
        this.logger.warn('Alert triggered:', alert);
        
        // Store in database
        await productionDB.logEvent({
            eventType: 'alert_triggered',
            eventData: alert
        });
        
        // Send notifications (email, Slack, etc.)
        await this.sendAlertNotifications(alert);
        
        // Broadcast to dashboards
        this.broadcastAlert(alert);
        
        console.log(`🚨 Alert triggered: ${rule.name} (${rule.severity})`);
    }

    async sendAlertNotifications(alert) {
        // In production, integrate with email service, Slack, PagerDuty, etc.
        console.log(`📧 Alert notification: ${alert.name}`);
        
        // Example: Send to Slack webhook
        if (process.env.SLACK_WEBHOOK_URL) {
            try {
                const axios = require('axios');
                await axios.post(process.env.SLACK_WEBHOOK_URL, {
                    text: `🚨 COSMOSIO Alert: ${alert.name}`,
                    attachments: [{
                        color: alert.severity === 'critical' ? 'danger' : 'warning',
                        fields: [
                            { title: 'Severity', value: alert.severity, short: true },
                            { title: 'Time', value: alert.timestamp.toISOString(), short: true }
                        ]
                    }]
                });
            } catch (error) {
                this.logger.error('Failed to send Slack notification:', error);
            }
        }
    }

    async broadcastDashboardUpdate() {
        if (this.dashboardClients.size === 0) return;
        
        const metrics = await this.getCurrentMetrics();
        const update = {
            type: 'metrics_update',
            data: metrics,
            timestamp: new Date()
        };
        
        this.dashboardClients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(update));
            }
        });
    }

    broadcastAlert(alert) {
        const alertMessage = {
            type: 'alert',
            data: alert
        };
        
        this.dashboardClients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(alertMessage));
            }
        });
    }

    async handleDashboardRequest(ws, request) {
        switch (request.type) {
            case 'get_metrics':
                const metrics = await this.getCurrentMetrics();
                ws.send(JSON.stringify({
                    type: 'metrics_response',
                    data: metrics
                }));
                break;
                
            case 'get_alerts':
                const alerts = Array.from(this.alerts.values());
                ws.send(JSON.stringify({
                    type: 'alerts_response',
                    data: alerts
                }));
                break;
                
            case 'acknowledge_alert':
                if (request.alertId && this.alerts.has(request.alertId)) {
                    const alert = this.alerts.get(request.alertId);
                    alert.status = 'acknowledged';
                    alert.acknowledgedAt = new Date();
                    
                    ws.send(JSON.stringify({
                        type: 'alert_acknowledged',
                        alertId: request.alertId
                    }));
                }
                break;
        }
    }

    // Helper Methods
    async getCPUUsage() {
        return new Promise((resolve) => {
            const os = require('os');
            const cpus = os.cpus();
            
            let totalIdle = 0;
            let totalTick = 0;
            
            cpus.forEach(cpu => {
                for (const type in cpu.times) {
                    totalTick += cpu.times[type];
                }
                totalIdle += cpu.times.idle;
            });
            
            const idle = totalIdle / cpus.length;
            const total = totalTick / cpus.length;
            const usage = 100 - ~~(100 * idle / total);
            
            resolve(usage);
        });
    }

    async getDiskUsage() {
        // Simplified disk usage calculation
        return Math.random() * 100; // In production, use actual disk usage
    }

    async getDatabaseConnections() {
        try {
            const client = await productionDB.pool.connect();
            try {
                const result = await client.query('SELECT count(*) FROM pg_stat_activity');
                return parseInt(result.rows[0].count) || 0;
            } finally {
                client.release();
            }
        } catch (error) {
            return 0;
        }
    }

    async getCurrentMetrics() {
        const os = require('os');
        
        return {
            cpuUsage: await this.getCPUUsage(),
            memoryUsage: ((os.totalmem() - os.freemem()) / os.totalmem()) * 100,
            diskUsage: await this.getDiskUsage(),
            dbConnections: await this.getDatabaseConnections(),
            uptime: process.uptime(),
            timestamp: new Date()
        };
    }

    async sendToCloudWatch(metrics) {
        if (process.env.DISABLE_TELEMETRY === '1' || process.env.OFFLINE_MODE === '1' || !this.cloudWatch) return;
        
        const params = {
            Namespace: this.cloudWatchNamespace,
            MetricData: metrics.map(metric => ({
                ...metric,
                Timestamp: new Date()
            }))
        };
        
        try {
            await this.cloudWatch.putMetricData(params).promise();
        } catch (error) {
            this.logger.error('Failed to send metrics to CloudWatch:', error);
        }
    }

    async storeMetrics(metrics) {
        try {
            // Use the correct database method
            if (productionDB && productionDB.storeMetrics) {
                await productionDB.storeMetrics(metrics);
            } else {
                // Fallback: just log the metrics
                console.log('📊 System Metrics:', JSON.stringify(metrics, null, 2));
            }
        } catch (error) {
            this.logger.error('Failed to store metrics in database:', error);
            // Don't throw error to prevent crashes
        }
    }

    // Public API Methods
    recordHttpRequest(method, route, statusCode, duration) {
        if (process.env.DISABLE_ANALYTICS === '1') return;
        this.prometheusMetrics.httpRequestsTotal
            .labels(method, route, statusCode.toString())
            .inc();
            
        this.prometheusMetrics.httpRequestDuration
            .labels(method, route)
            .observe(duration / 1000); // Convert to seconds
    }

    recordAIRequest(provider, model, status, duration, tokensUsed = 0) {
        if (process.env.DISABLE_ANALYTICS === '1') return;
        this.prometheusMetrics.aiRequestsTotal
            .labels(provider, model, status)
            .inc();
            
        this.prometheusMetrics.aiRequestDuration
            .labels(provider, model)
            .observe(duration / 1000);
            
        if (tokensUsed > 0) {
            this.prometheusMetrics.aiTokensUsed
                .labels(provider, model, 'total')
                .inc(tokensUsed);
        }
    }

    recordMetrics(metricsData) {
        try {
            // Record custom metrics
            if (metricsData && typeof metricsData === 'object') {
                Object.entries(metricsData).forEach(([key, value]) => {
                    if (typeof value === 'number') {
                        this.metrics.set(key, {
                            value,
                            timestamp: new Date(),
                            type: 'gauge'
                        });
                    }
                });
            }
        } catch (error) {
            console.error('Error recording metrics:', error);
        }
    }

    // Compatibility wrapper for single metric recording
    recordMetric(metricName, data) {
        try {
            // Store structured data or numeric value
            if (typeof data === 'number') {
                this.metrics.set(metricName, {
                    value: data,
                    timestamp: new Date(),
                    type: 'gauge'
                });
            } else {
                this.metrics.set(metricName, {
                    value: data,
                    timestamp: new Date(),
                    type: 'object'
                });
            }

            // Optionally forward to Prometheus/CloudWatch in future
        } catch (error) {
            if (this.logger) {
                this.logger.warn(`Failed to record metric ${metricName}: ${error.message}`);
            } else {
                console.warn(`Failed to record metric ${metricName}: ${error.message}`);
            }
        }
    }

    async getMonitoringStatus() {
        return {
            isActive: this.isActive,
            uptime: process.uptime(),
            metrics: await this.getCurrentMetrics(),
            activeAlerts: Array.from(this.alerts.values()).filter(a => a.status === 'active'),
            dashboardClients: this.dashboardClients.size,
            timestamp: new Date()
        };
    }

    async getSystemHealth() {
        // Summarize production monitoring health without sending telemetry
        return {
            productionMonitoring: {
                status: this.isActive ? 'active' : 'inactive',
                activeAlerts: Array.from(this.alerts.values()).filter(a => a.status === 'active').length,
                monitoring: {
                    loops: this.isActive,
                    prometheus: !!this.prometheusMetrics,
                    cloudWatch: !!this.cloudWatch,
                    dashboard: !!this.dashboardServer,
                    metricsServer: !!this.metricsServer
                }
            }
        };
    }

    async stopMonitoring() {
        this.isActive = false;
        
        if (this.systemMetricsInterval) clearInterval(this.systemMetricsInterval);
        if (this.businessMetricsInterval) clearInterval(this.businessMetricsInterval);
        if (this.alertCheckInterval) clearInterval(this.alertCheckInterval);
        if (this.dashboardUpdateInterval) clearInterval(this.dashboardUpdateInterval);
        
        if (this.metricsServer) this.metricsServer.close();
        if (this.dashboardServer) this.dashboardServer.close();
        
        console.log('🛑 Production Monitoring Stopped');
    }
}

// Export singleton instance
const productionMonitoring = new ProductionMonitoring();
module.exports = productionMonitoring;

console.log('📊 COSMOSIO Production Monitoring - Real-time Intelligence Activated!');