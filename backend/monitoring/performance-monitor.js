/**
 * COSMOSIO Performance Monitoring System
 * Real-time performance tracking, metrics collection, and optimization insights
 * Integration with system resources, database performance, and API response times
 */

const os = require('os');
const process = require('process');
const EventEmitter = require('events');
const { v4: uuidv4 } = require('uuid');
const AWS = require('aws-sdk');

class PerformanceMonitor extends EventEmitter {
    constructor() {
        super();
        this.metrics = new Map();
        this.performanceData = {
            system: {},
            application: {},
            database: {},
            api: {},
            memory: {},
            cpu: {}
        };
        this.alerts = [];
        this.thresholds = {
            cpu: 80,
            memory: 85,
            responseTime: 2000,
            errorRate: 5,
            diskUsage: 90
        };
        
        this.initializeMonitoring();
        console.log('📊 COSMOSIO Performance Monitor - Initializing System Monitoring!');
    }

    async initializeMonitoring() {
        try {
            // Setup system monitoring
            await this.setupSystemMonitoring();
            
            // Setup application monitoring
            await this.setupApplicationMonitoring();
            
            // Setup database monitoring
            await this.setupDatabaseMonitoring();
            
            // Setup API monitoring
            await this.setupAPIMonitoring();
            
            // Setup CloudWatch integration
            await this.setupCloudWatchMetrics();
            
            // Start monitoring loops
            this.startMonitoringLoops();
            
            console.log('✅ Performance Monitor initialized');
        } catch (error) {
            console.error('❌ Performance Monitor initialization failed:', error);
        }
    }

    async setupSystemMonitoring() {
        this.systemMetrics = {
            startTime: Date.now(),
            hostname: os.hostname(),
            platform: os.platform(),
            arch: os.arch(),
            nodeVersion: process.version,
            totalMemory: os.totalmem(),
            cpuCount: os.cpus().length
        };
    }

    async setupApplicationMonitoring() {
        this.appMetrics = {
            requests: {
                total: 0,
                successful: 0,
                failed: 0,
                pending: 0
            },
            responses: {
                averageTime: 0,
                slowest: 0,
                fastest: Infinity,
                times: []
            },
            errors: {
                total: 0,
                rate: 0,
                recent: []
            },
            users: {
                active: new Set(),
                concurrent: 0,
                peak: 0
            }
        };
    }

    async setupDatabaseMonitoring() {
        this.dbMetrics = {
            connections: {
                active: 0,
                total: 0,
                peak: 0
            },
            queries: {
                total: 0,
                successful: 0,
                failed: 0,
                averageTime: 0,
                slowQueries: []
            },
            performance: {
                readLatency: 0,
                writeLatency: 0,
                throughput: 0
            }
        };
    }

    async setupAPIMonitoring() {
        this.apiMetrics = {
            endpoints: new Map(),
            globalStats: {
                totalRequests: 0,
                averageResponseTime: 0,
                errorRate: 0,
                throughput: 0
            },
            statusCodes: {
                '2xx': 0,
                '3xx': 0,
                '4xx': 0,
                '5xx': 0
            }
        };
    }

    async setupCloudWatchMetrics() {
        if (process.env.DISABLE_TELEMETRY === '1' || process.env.OFFLINE_MODE === '1') {
            this.cloudWatch = null;
            return;
        }
        if (process.env.AWS_REGION) {
            this.cloudWatch = new AWS.CloudWatch({
                region: process.env.AWS_REGION
            });
        }
    }

    startMonitoringLoops() {
        // System metrics every 30 seconds
        setInterval(() => {
            this.collectSystemMetrics();
        }, 30000);
        
        // Application metrics every 10 seconds
        setInterval(() => {
            this.collectApplicationMetrics();
        }, 10000);
        
        // Performance analysis every minute (skip if analytics disabled)
        if (process.env.DISABLE_ANALYTICS !== '1') {
            setInterval(() => {
                this.analyzePerformance();
            }, 60000);
        }
        
        // Send metrics to CloudWatch every 5 minutes
        setInterval(() => {
            this.sendMetricsToCloudWatch();
        }, 300000);
        
        // Clean old data every hour
        setInterval(() => {
            this.cleanOldData();
        }, 3600000);
    }

    collectSystemMetrics() {
        try {
            const memUsage = process.memoryUsage();
            const cpuUsage = process.cpuUsage();
            const loadAvg = os.loadavg();
            const freeMemory = os.freemem();
            const totalMemory = os.totalmem();
            
            this.performanceData.system = {
                timestamp: Date.now(),
                uptime: process.uptime(),
                memory: {
                    used: memUsage.heapUsed,
                    total: memUsage.heapTotal,
                    external: memUsage.external,
                    rss: memUsage.rss,
                    free: freeMemory,
                    total_system: totalMemory,
                    usage_percent: ((totalMemory - freeMemory) / totalMemory) * 100
                },
                cpu: {
                    user: cpuUsage.user,
                    system: cpuUsage.system,
                    load_avg: loadAvg,
                    usage_percent: this.calculateCPUUsage()
                },
                process: {
                    pid: process.pid,
                    ppid: process.ppid,
                    title: process.title,
                    version: process.version
                }
            };
            
            // Check thresholds
            this.checkSystemThresholds();
            
            // Emit metrics event
            this.emit('system_metrics', this.performanceData.system);
            
        } catch (error) {
            console.error('Failed to collect system metrics:', error);
        }
    }

    calculateCPUUsage() {
        // Simple CPU usage calculation
        const cpus = os.cpus();
        let totalIdle = 0;
        let totalTick = 0;
        
        cpus.forEach(cpu => {
            for (const type in cpu.times) {
                totalTick += cpu.times[type];
            }
            totalIdle += cpu.times.idle;
        });
        
        return 100 - ~~(100 * totalIdle / totalTick);
    }

    collectApplicationMetrics() {
        try {
            this.performanceData.application = {
                timestamp: Date.now(),
                requests: { ...this.appMetrics.requests },
                responses: {
                    ...this.appMetrics.responses,
                    averageTime: this.calculateAverageResponseTime()
                },
                errors: {
                    ...this.appMetrics.errors,
                    rate: this.calculateErrorRate()
                },
                users: {
                    active: this.appMetrics.users.active.size,
                    concurrent: this.appMetrics.users.concurrent,
                    peak: this.appMetrics.users.peak
                },
                eventLoop: {
                    delay: this.measureEventLoopDelay(),
                    utilization: this.calculateEventLoopUtilization()
                }
            };
            
            this.emit('application_metrics', this.performanceData.application);
            
        } catch (error) {
            console.error('Failed to collect application metrics:', error);
        }
    }

    calculateAverageResponseTime() {
        const times = this.appMetrics.responses.times;
        if (times.length === 0) return 0;
        
        const sum = times.reduce((a, b) => a + b, 0);
        return sum / times.length;
    }

    calculateErrorRate() {
        const total = this.appMetrics.requests.total;
        const errors = this.appMetrics.errors.total;
        
        return total > 0 ? (errors / total) * 100 : 0;
    }

    measureEventLoopDelay() {
        const start = process.hrtime.bigint();
        setImmediate(() => {
            const delay = Number(process.hrtime.bigint() - start) / 1000000; // Convert to ms
            return delay;
        });
        return 0; // Placeholder
    }

    calculateEventLoopUtilization() {
        // This would require more complex implementation
        // For now, return a placeholder
        return 0;
    }

    checkSystemThresholds() {
        const system = this.performanceData.system;
        
        // Check CPU usage
        if (system.cpu.usage_percent > this.thresholds.cpu) {
            this.createAlert('HIGH_CPU_USAGE', {
                current: system.cpu.usage_percent,
                threshold: this.thresholds.cpu,
                severity: 'warning'
            });
        }
        
        // Check memory usage
        if (system.memory.usage_percent > this.thresholds.memory) {
            this.createAlert('HIGH_MEMORY_USAGE', {
                current: system.memory.usage_percent,
                threshold: this.thresholds.memory,
                severity: 'warning'
            });
        }
    }

    createAlert(type, data) {
        const alert = {
            id: uuidv4(),
            type,
            timestamp: Date.now(),
            data,
            acknowledged: false
        };
        
        this.alerts.push(alert);
        this.emit('performance_alert', alert);
        
        console.warn(`🚨 Performance Alert: ${type}`, data);
    }

    // API monitoring methods
    trackRequest(req, res) {
        const startTime = Date.now();
        const endpoint = `${req.method} ${req.route?.path || req.path}`;
        
        // Track request start
        this.appMetrics.requests.total++;
        this.appMetrics.requests.pending++;
        
        // Track user activity
        if (req.user?.id) {
            this.appMetrics.users.active.add(req.user.id);
        }
        
        // Update concurrent users
        this.appMetrics.users.concurrent++;
        if (this.appMetrics.users.concurrent > this.appMetrics.users.peak) {
            this.appMetrics.users.peak = this.appMetrics.users.concurrent;
        }
        
        res.on('finish', () => {
            const duration = Date.now() - startTime;
            
            // Update request metrics
            this.appMetrics.requests.pending--;
            
            if (res.statusCode >= 200 && res.statusCode < 400) {
                this.appMetrics.requests.successful++;
            } else {
                this.appMetrics.requests.failed++;
                this.appMetrics.errors.total++;
            }
            
            // Update response time metrics
            this.appMetrics.responses.times.push(duration);
            if (this.appMetrics.responses.times.length > 1000) {
                this.appMetrics.responses.times = this.appMetrics.responses.times.slice(-1000);
            }
            
            if (duration > this.appMetrics.responses.slowest) {
                this.appMetrics.responses.slowest = duration;
            }
            
            if (duration < this.appMetrics.responses.fastest) {
                this.appMetrics.responses.fastest = duration;
            }
            
            // Update API endpoint metrics
            this.updateEndpointMetrics(endpoint, duration, res.statusCode);
            
            // Update status code metrics
            const statusGroup = `${Math.floor(res.statusCode / 100)}xx`;
            this.apiMetrics.statusCodes[statusGroup] = 
                (this.apiMetrics.statusCodes[statusGroup] || 0) + 1;
            
            // Decrease concurrent users
            this.appMetrics.users.concurrent--;
            
            // Check for slow requests
            if (duration > this.thresholds.responseTime) {
                this.createAlert('SLOW_REQUEST', {
                    endpoint,
                    duration,
                    threshold: this.thresholds.responseTime,
                    severity: 'warning'
                });
            }
        });
    }

    updateEndpointMetrics(endpoint, duration, statusCode) {
        if (!this.apiMetrics.endpoints.has(endpoint)) {
            this.apiMetrics.endpoints.set(endpoint, {
                requests: 0,
                totalTime: 0,
                averageTime: 0,
                minTime: Infinity,
                maxTime: 0,
                errors: 0,
                statusCodes: {}
            });
        }
        
        const metrics = this.apiMetrics.endpoints.get(endpoint);
        metrics.requests++;
        metrics.totalTime += duration;
        metrics.averageTime = metrics.totalTime / metrics.requests;
        
        if (duration < metrics.minTime) metrics.minTime = duration;
        if (duration > metrics.maxTime) metrics.maxTime = duration;
        
        if (statusCode >= 400) {
            metrics.errors++;
        }
        
        metrics.statusCodes[statusCode] = (metrics.statusCodes[statusCode] || 0) + 1;
    }

    // Database monitoring methods
    trackDatabaseQuery(query, duration, success = true) {
        this.dbMetrics.queries.total++;
        
        if (success) {
            this.dbMetrics.queries.successful++;
        } else {
            this.dbMetrics.queries.failed++;
        }
        
        // Update average query time
        const totalTime = this.dbMetrics.queries.averageTime * (this.dbMetrics.queries.total - 1) + duration;
        this.dbMetrics.queries.averageTime = totalTime / this.dbMetrics.queries.total;
        
        // Track slow queries
        if (duration > 1000) { // Queries slower than 1 second
            this.dbMetrics.queries.slowQueries.push({
                query: query.substring(0, 100),
                duration,
                timestamp: Date.now()
            });
            
            // Keep only last 50 slow queries
            if (this.dbMetrics.queries.slowQueries.length > 50) {
                this.dbMetrics.queries.slowQueries = 
                    this.dbMetrics.queries.slowQueries.slice(-50);
            }
        }
    }

    trackDatabaseConnection(action) {
        switch (action) {
            case 'connect':
                this.dbMetrics.connections.active++;
                this.dbMetrics.connections.total++;
                if (this.dbMetrics.connections.active > this.dbMetrics.connections.peak) {
                    this.dbMetrics.connections.peak = this.dbMetrics.connections.active;
                }
                break;
            case 'disconnect':
                this.dbMetrics.connections.active--;
                break;
        }
    }

    analyzePerformance() {
        try {
            const analysis = {
                timestamp: Date.now(),
                system: this.analyzeSystemPerformance(),
                application: this.analyzeApplicationPerformance(),
                database: this.analyzeDatabasePerformance(),
                recommendations: this.generateRecommendations()
            };
            
            this.emit('performance_analysis', analysis);
            
        } catch (error) {
            console.error('Failed to analyze performance:', error);
        }
    }

    analyzeSystemPerformance() {
        const system = this.performanceData.system;
        
        return {
            health: this.calculateSystemHealth(),
            trends: this.calculateSystemTrends(),
            bottlenecks: this.identifySystemBottlenecks()
        };
    }

    analyzeApplicationPerformance() {
        const app = this.performanceData.application;
        
        return {
            throughput: this.calculateThroughput(),
            responseTime: this.analyzeResponseTimes(),
            errorAnalysis: this.analyzeErrors(),
            userActivity: this.analyzeUserActivity()
        };
    }

    analyzeDatabasePerformance() {
        return {
            queryPerformance: this.analyzeQueryPerformance(),
            connectionHealth: this.analyzeConnectionHealth(),
            slowQueries: this.dbMetrics.queries.slowQueries.slice(-10)
        };
    }

    calculateSystemHealth() {
        const system = this.performanceData.system;
        let score = 100;
        
        if (system.cpu?.usage_percent > 80) score -= 20;
        if (system.memory?.usage_percent > 85) score -= 20;
        if (system.cpu?.load_avg?.[0] > system.cpu?.load_avg?.[1]) score -= 10;
        
        return Math.max(0, score);
    }

    calculateThroughput() {
        const requests = this.appMetrics.requests.total;
        const uptime = process.uptime();
        
        return uptime > 0 ? requests / uptime : 0;
    }

    generateRecommendations() {
        const recommendations = [];
        
        // System recommendations
        if (this.performanceData.system.memory?.usage_percent > 80) {
            recommendations.push({
                type: 'memory',
                priority: 'high',
                message: 'Consider increasing memory allocation or optimizing memory usage'
            });
        }
        
        // Application recommendations
        if (this.appMetrics.responses.averageTime > 1000) {
            recommendations.push({
                type: 'response_time',
                priority: 'medium',
                message: 'Average response time is high. Consider optimizing API endpoints'
            });
        }
        
        // Database recommendations
        if (this.dbMetrics.queries.slowQueries.length > 10) {
            recommendations.push({
                type: 'database',
                priority: 'medium',
                message: 'Multiple slow queries detected. Consider query optimization'
            });
        }
        
        return recommendations;
    }

    async sendMetricsToCloudWatch() {
        if (!this.cloudWatch) return;
        
        try {
            const metricData = [
                {
                    MetricName: 'CPUUsage',
                    Value: this.performanceData.system.cpu?.usage_percent || 0,
                    Unit: 'Percent'
                },
                {
                    MetricName: 'MemoryUsage',
                    Value: this.performanceData.system.memory?.usage_percent || 0,
                    Unit: 'Percent'
                },
                {
                    MetricName: 'RequestCount',
                    Value: this.appMetrics.requests.total,
                    Unit: 'Count'
                },
                {
                    MetricName: 'AverageResponseTime',
                    Value: this.appMetrics.responses.averageTime,
                    Unit: 'Milliseconds'
                },
                {
                    MetricName: 'ErrorRate',
                    Value: this.calculateErrorRate(),
                    Unit: 'Percent'
                }
            ];
            
            await this.cloudWatch.putMetricData({
                Namespace: 'COSMOSIO/Application',
                MetricData: metricData
            }).promise();
            
        } catch (error) {
            console.error('Failed to send metrics to CloudWatch:', error);
        }
    }

    cleanOldData() {
        // Clean old alerts (keep last 100)
        if (this.alerts.length > 100) {
            this.alerts = this.alerts.slice(-100);
        }
        
        // Clean old response times
        if (this.appMetrics.responses.times.length > 1000) {
            this.appMetrics.responses.times = this.appMetrics.responses.times.slice(-1000);
        }
        
        // Clean old user activity
        this.appMetrics.users.active.clear();
    }

    // Express middleware
    middleware() {
        return (req, res, next) => {
            this.trackRequest(req, res);
            next();
        };
    }

    async getPerformanceReport() {
        return {
            timestamp: Date.now(),
            system: this.performanceData.system,
            application: this.performanceData.application,
            database: this.dbMetrics,
            api: {
                endpoints: Object.fromEntries(this.apiMetrics.endpoints),
                globalStats: this.apiMetrics.globalStats,
                statusCodes: this.apiMetrics.statusCodes
            },
            alerts: this.alerts.slice(-20),
            health: {
                system: this.calculateSystemHealth(),
                overall: this.calculateOverallHealth()
            }
        };
    }

    calculateOverallHealth() {
        const systemHealth = this.calculateSystemHealth();
        const errorRate = this.calculateErrorRate();
        const avgResponseTime = this.appMetrics.responses.averageTime;
        
        let health = systemHealth;
        
        if (errorRate > 5) health -= 20;
        if (avgResponseTime > 2000) health -= 15;
        
        return Math.max(0, health);
    }

    async getSystemHealth() {
        return {
            performance: {
                status: 'active',
                systemHealth: this.calculateSystemHealth(),
                overallHealth: this.calculateOverallHealth(),
                activeAlerts: this.alerts.filter(a => !a.acknowledged).length,
                monitoring: {
                    system: !!this.performanceData.system.timestamp,
                    application: !!this.performanceData.application.timestamp,
                    database: this.dbMetrics.queries.total > 0,
                    cloudWatch: !!this.cloudWatch
                }
            }
        };
    }
}

const performanceMonitor = new PerformanceMonitor();
module.exports = performanceMonitor;

console.log('📊 COSMOSIO Performance Monitor - System Monitoring Activated!');