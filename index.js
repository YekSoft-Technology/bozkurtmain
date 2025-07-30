const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

// Modülleri import et
const { blockManager } = require("./block.js");
const { logAnalyzer } = require("./bozkurt.js");

class SecurityServer {
    constructor() {
        this.connections = new Set();
        this.messages = [];
        this.blockedIPs = [];
        this.stats = {
            totalBlocked: 0,
            activeConnections: 0,
            uptime: Date.now(),
            lastActivity: Date.now()
        };
        
        // Güvenlik ayarları
        this.rateLimiter = new Map();
        this.bannedIPs = new Set();
        this.adminToken = process.env.ADMIN_TOKEN || this.generateToken();
        
        // MIME types
        this.mimeTypes = {
            '.html': 'text/html; charset=utf-8',
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.json': 'application/json',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.svg': 'image/svg+xml',
            '.ico': 'image/x-icon',
            '.txt': 'text/plain'
        };

        this.setupServer();
        this.startLogAnalysis();
        this.setupPeriodicCleanup();
        
        console.log(`🔐 Admin Token: ${this.adminToken}`);
    }

    generateToken() {
        return crypto.randomBytes(32).toString('hex');
    }

    // Rate limiting kontrolü
    checkRateLimit(ip, endpoint = 'default') {
        const key = `${ip}:${endpoint}`;
        const now = Date.now();
        const windowMs = 60000; // 1 dakika
        const maxRequests = endpoint === 'api' ? 30 : 100;

        if (!this.rateLimiter.has(key)) {
            this.rateLimiter.set(key, []);
        }

        const requests = this.rateLimiter.get(key);
        const validRequests = requests.filter(time => time > now - windowMs);
        
        if (validRequests.length >= maxRequests) {
            return false;
        }

        validRequests.push(now);
        this.rateLimiter.set(key, validRequests);
        return true;
    }

    // IP yasaklama
    banIP(ip, duration = 3600000) { // 1 saat default
        this.bannedIPs.add(ip);
        console.log(`🚫 IP yasaklandı: ${ip}`);
        
        setTimeout(() => {
            this.bannedIPs.delete(ip);
            console.log(`✅ IP yasağı kaldırıldı: ${ip}`);
        }, duration);
    }

    // Güvenlik kontrolü
    isSecureRequest(req) {
        const clientIP = this.getClientIP(req);
        
        // Yasaklı IP kontrolü
        if (this.bannedIPs.has(clientIP)) {
            return false;
        }

        // Rate limiting kontrolü
        const endpoint = req.url.startsWith('/api/') ? 'api' : 'default';
        if (!this.checkRateLimit(clientIP, endpoint)) {
            console.log(`⚠️ Rate limit aşıldı: ${clientIP} - ${req.url}`);
            this.banIP(clientIP, 300000); // 5 dakika yasak
            return false;
        }

        return true;
    }

    getClientIP(req) {
        return req.headers['x-forwarded-for'] || 
               req.headers['x-real-ip'] || 
               req.connection.remoteAddress || 
               req.socket.remoteAddress ||
               (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
               '127.0.0.1';
    }

    setupServer() {
        this.server = http.createServer((req, res) => {
            this.handleRequest(req, res);
        });

        this.server.on('connection', (socket) => {
            this.connections.add(socket);
            this.stats.activeConnections = this.connections.size;
            
            socket.on('close', () => {
                this.connections.delete(socket);
                this.stats.activeConnections = this.connections.size;
            });
        });
    }

    async handleRequest(req, res) {
        try {
            const clientIP = this.getClientIP(req);
            const parsedUrl = url.parse(req.url, true);
            
            // Güvenlik kontrolü
            if (!this.isSecureRequest(req)) {
                this.sendError(res, 429, 'Too Many Requests');
                return;
            }

            // CORS headers
            this.setCORSHeaders(res);

            // OPTIONS request handling
            if (req.method === 'OPTIONS') {
                res.writeHead(200);
                res.end();
                return;
            }

            // Route handling
            await this.routeRequest(req, res, parsedUrl, clientIP);
            
        } catch (error) {
            console.error('❌ İstek işleme hatası:', error);
            this.sendError(res, 500, 'Internal Server Error');
        }
    }

    setCORSHeaders(res) {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Token');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
    }

    async routeRequest(req, res, parsedUrl, clientIP) {
        const pathname = parsedUrl.pathname;

        // API endpoints
        if (pathname.startsWith('/api/')) {
            await this.handleAPI(req, res, pathname, parsedUrl.query, req);
            return;
        }

        // SSE Events endpoint
        if (pathname === '/events') {
            this.handleSSE(req, res, clientIP);
            return;
        }

        // Static file serving
        if (pathname === '/' || pathname === '/index.html') {
            this.serveFile(res, 'public/index.html');
            return;
        }

        if (pathname === '/uptime.html') {
            this.serveFile(res, 'public/uptime.html');
            return;
        }

        // Other static files
        this.serveStaticFile(req, res, pathname);
    }

    async handleAPI(req, res, pathname, query, request) {
        // Admin token kontrolü
        const adminToken = request.headers['x-admin-token'] || query.token;
        
        // Public endpoints (token gerektirmeyen)
        const publicEndpoints = ['/api/stats', '/api/status'];
        
        if (!publicEndpoints.includes(pathname) && adminToken !== this.adminToken) {
            this.sendJSON(res, { error: 'Unauthorized', code: 401 }, 401);
            return;
        }

        try {
            switch (pathname) {
                case '/api/stats':
                    await this.handleStatsAPI(res);
                    break;
                
                case '/api/status':
                    await this.handleStatusAPI(res);
                    break;
                
                case '/api/blocked':
                    await this.handleBlockedAPI(res);
                    break;
                
                case '/api/whitelist':
                    await this.handleWhitelistAPI(req, res, query);
                    break;
                
                case '/api/unblock':
                    await this.handleUnblockAPI(req, res, query);
                    break;
                
                case '/api/block':
                    await this.handleManualBlockAPI(req, res, query);
                    break;
                
                case '/api/logs':
                    await this.handleLogsAPI(res, query);
                    break;
                
                case '/api/analyze':
                    await this.handleAnalyzeAPI(req, res, query);
                    break;
                
                case '/api/settings':
                    await this.handleSettingsAPI(req, res, query);
                    break;
                
                default:
                    this.sendJSON(res, { error: 'Not Found', code: 404 }, 404);
            }
        } catch (error) {
            console.error('❌ API hatası:', error);
            this.sendJSON(res, { error: 'Internal Server Error', message: error.message }, 500);
        }
    }

    async handleStatsAPI(res) {
        const stats = {
            ...this.stats,
            uptime: Date.now() - this.stats.uptime,
            blockManager: blockManager.getStats(),
            logAnalyzer: logAnalyzer.getStats(),
            totalMessages: this.messages.length,
            serverMemory: process.memoryUsage(),
            timestamp: Date.now()
        };
        
        this.sendJSON(res, stats);
    }

    async handleStatusAPI(res) {
        const status = {
            status: 'online',
            version: '2.0.0',
            uptime: Date.now() - this.stats.uptime,
            lastActivity: this.stats.lastActivity,
            isAnalyzing: logAnalyzer.getStats().isRunning,
            blockedIPs: blockManager.getStats().blockedCount,
            timestamp: Date.now()
        };
        
        this.sendJSON(res, status);
    }

    async handleBlockedAPI(res) {
        const blockedIPs = blockManager.getBlockedIPs();
        const history = blockManager.getBlockHistory();
        
        this.sendJSON(res, {
            blocked: blockedIPs,
            history: history.slice(-100), // Son 100 kayıt
            total: blockedIPs.length
        });
    }

    async handleWhitelistAPI(req, res, query) {
        if (req.method === 'GET') {
            const whitelist = blockManager.getWhitelist();
            this.sendJSON(res, { whitelist, total: whitelist.length });
            return;
        }

        if (req.method === 'POST' && query.ip) {
            const success = blockManager.addToWhitelist(query.ip);
            this.sendJSON(res, { 
                success, 
                message: success ? 'IP beyaz listeye eklendi' : 'Geçersiz IP adresi',
                ip: query.ip 
            });
            return;
        }

        if (req.method === 'DELETE' && query.ip) {
            const success = blockManager.removeFromWhitelist(query.ip);
            this.sendJSON(res, { 
                success, 
                message: success ? 'IP beyaz listeden çıkarıldı' : 'IP bulunamadı',
                ip: query.ip 
            });
            return;
        }

        this.sendJSON(res, { error: 'Bad Request' }, 400);
    }

    async handleUnblockAPI(req, res, query) {
        if (!query.ip) {
            this.sendJSON(res, { error: 'IP parametresi gerekli' }, 400);
            return;
        }

        const success = blockManager.unblockIP(query.ip);
        this.sendJSON(res, {
            success,
            message: success ? 'IP engeli kaldırıldı' : 'IP bulunamadı veya zaten engellenmiş değil',
            ip: query.ip
        });
    }

    async handleManualBlockAPI(req, res, query) {
        if (!query.ip) {
            this.sendJSON(res, { error: 'IP parametresi gerekli' }, 400);
            return;
        }

        try {
            const results = await blockManager.blockIP([query.ip]);
            const result = results[0];
            
            this.sendJSON(res, {
                success: result.success,
                message: result.message,
                ip: query.ip,
                timestamp: result.timestamp
            });
        } catch (error) {
            this.sendJSON(res, { 
                success: false, 
                message: error.message, 
                ip: query.ip 
            }, 500);
        }
    }

    async handleLogsAPI(res, query) {
        try {
            const logDir = path.join(__dirname, 'logs');
            const limit = parseInt(query.limit) || 100;
            
            if (!fs.existsSync(logDir)) {
                this.sendJSON(res, { logs: [], total: 0 });
                return;
            }

            const logFile = path.join(logDir, 'suspicious_activity.log');
            if (!fs.existsSync(logFile)) {
                this.sendJSON(res, { logs: [], total: 0 });
                return;
            }

            const data = fs.readFileSync(logFile, 'utf8');
            const lines = data.split('\n').filter(line => line.trim());
            const logs = lines.slice(-limit).map(line => {
                try {
                    return JSON.parse(line);
                } catch {
                    return { raw: line, timestamp: Date.now() };
                }
            });

            this.sendJSON(res, { logs, total: lines.length });
        } catch (error) {
            this.sendJSON(res, { error: 'Log okunamadı', message: error.message }, 500);
        }
    }

    async handleAnalyzeAPI(req, res, query) {
        if (req.method === 'POST') {
            // Manuel analiz başlat
            if (query.logfile) {
                const logPath = path.resolve(query.logfile);
                
                // Güvenlik kontrolü - sadece belirli dizinlerdeki dosyalara izin ver
                const allowedPaths = [
                    path.resolve(__dirname, 'test'),
                    path.resolve(__dirname, 'logs'),
                    '/var/log',
                    '/opt/logs'
                ];
                
                const isAllowed = allowedPaths.some(allowedPath => 
                    logPath.startsWith(allowedPath)
                );
                
                if (!isAllowed) {
                    this.sendJSON(res, { error: 'Dosya yoluna erişim izni yok' }, 403);
                    return;
                }
                
                let foundIPs = [];
                await logAnalyzer.analyzeLogFile(logPath, (ip) => {
                    foundIPs.push(ip);
                });
                
                this.sendJSON(res, {
                    success: true,
                    analyzed: true,
                    foundIPs: foundIPs,
                    total: foundIPs.length,
                    logfile: query.logfile
                });
                return;
            }
        }

        // Mevcut analiz durumunu döndür
        const analyzerStats = logAnalyzer.getStats();
        this.sendJSON(res, {
            isRunning: analyzerStats.isRunning,
            stats: analyzerStats,
            recentIPs: Array.from(this.blockedIPs).slice(-20)
        });
    }

    async handleSettingsAPI(req, res, query) {
        if (req.method === 'GET') {
            const settings = {
                rateLimitEnabled: true,
                maxRequestsPerMinute: 100,
                apiMaxRequestsPerMinute: 30,
                banDuration: 3600000,
                autoAnalysisEnabled: logAnalyzer.getStats().isRunning,
                blockedIPsCount: blockManager.getStats().blockedCount,
                whitelistCount: blockManager.getStats().whitelistCount
            };
            
            this.sendJSON(res, settings);
            return;
        }

        // Settings update işlemleri burada yapılabilir
        this.sendJSON(res, { error: 'Settings update not implemented' }, 501);
    }

    handleSSE(req, res, clientIP) {
        // SSE headers
        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Cache-Control'
        });

        console.log(`📡 SSE bağlantısı kuruldu: ${clientIP}`);

        // Heartbeat
        const heartbeat = setInterval(() => {
            res.write(':heartbeat\n\n');
        }, 30000);

        // Mesaj gönderimi
        const messageInterval = setInterval(() => {
            if (this.messages.length > 0) {
                const message = this.messages.shift();
                res.write(`data: ${JSON.stringify(message)}\n\n`);
            }
        }, 100);

        // Bağlantı kapanma
        req.on('close', () => {
            clearInterval(heartbeat);
            clearInterval(messageInterval);
            console.log(`📡 SSE bağlantısı kapatıldı: ${clientIP}`);
        });

        // İlk durumu gönder
        res.write(`data: ${JSON.stringify({
            type: 'connected',
            timestamp: Date.now(),
            message: 'SSE bağlantısı kuruldu'
        })}\n\n`);
    }

    serveFile(res, filePath) {
        const fullPath = path.join(__dirname, filePath);
        
        if (!fs.existsSync(fullPath)) {
            this.sendError(res, 404, 'File Not Found');
            return;
        }

        const ext = path.extname(fullPath).toLowerCase();
        const contentType = this.mimeTypes[ext] || 'application/octet-stream';

        try {
            res.writeHead(200, { 
                'Content-Type': contentType,
                'Cache-Control': 'public, max-age=3600'
            });
            
            const fileStream = fs.createReadStream(fullPath);
            fileStream.pipe(res);
            
            fileStream.on('error', (error) => {
                console.error('❌ Dosya okuma hatası:', error);
                if (!res.headersSent) {
                    this.sendError(res, 500, 'File Read Error');
                }
            });
        } catch (error) {
            this.sendError(res, 500, 'Server Error');
        }
    }

    serveStaticFile(req, res, pathname) {
        // Path traversal saldırılarına karşı güvenlik
        const safePath = path.normalize(pathname).replace(/^(\.\.[\/\\])+/, '');
        const filePath = path.join(__dirname, 'public', safePath);
        
        // public dizini dışına çıkışı engelle
        if (!filePath.startsWith(path.join(__dirname, 'public'))) {
            this.sendError(res, 403, 'Forbidden');
            return;
        }

        this.serveFile(res, path.relative(__dirname, filePath));
    }

    sendJSON(res, data, statusCode = 200) {
        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data, null, 2));
    }

    sendError(res, statusCode, message) {
        if (res.headersSent) return;
        
        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
            error: message, 
            code: statusCode,
            timestamp: Date.now()
        }));
    }

    addMessage(message) {
        const msgObj = {
            type: 'block_result',
            message: message,
            timestamp: Date.now()
        };
        
        this.messages.push(msgObj);
        this.stats.lastActivity = Date.now();
        
        // Mesaj geçmişini sınırla
        if (this.messages.length > 1000) {
            this.messages = this.messages.slice(-500);
        }
    }

    startLogAnalysis() {
        // Log dosyalarını otomatik tespit et
        const logPaths = [
            "./test/botnet.log",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/var/log/httpd/access_log"
        ].filter(logPath => fs.existsSync(logPath));

        if (logPaths.length === 0) {
            console.log('⚠️ Analiz edilecek log dosyası bulunamadı');
            return;
        }

        console.log(`🔍 Log analizi başlatılıyor: ${logPaths.length} dosya`);
        
        logAnalyzer.start(logPaths, (ip) => {
            console.log(`🚨 Şüpheli IP tespit edildi: ${ip}`);
            this.blockedIPs.push(ip);
            this.stats.totalBlocked++;
            
            // IP'yi engelle
            blockManager.blockIP([ip], (result) => {
                console.log(`🛡️ Engelleme sonucu: ${result}`);
                this.addMessage(result);
            });
        });
    }

    setupPeriodicCleanup() {
        // Her 5 dakikada bir temizlik
        setInterval(() => {
            this.cleanupRateLimiter();
        }, 5 * 60 * 1000);

        // Her saatte bir detaylı temizlik
        setInterval(() => {
            this.performDetailedCleanup();
        }, 60 * 60 * 1000);
    }

    cleanupRateLimiter() {
        const now = Date.now();
        const windowMs = 60000;
        
        for (const [key, requests] of this.rateLimiter.entries()) {
            const validRequests = requests.filter(time => time > now - windowMs);
            if (validRequests.length === 0) {
                this.rateLimiter.delete(key);
            } else {
                this.rateLimiter.set(key, validRequests);
            }
        }
    }

    performDetailedCleanup() {
        // Eski yasaklı IP'leri temizle (zaten timeout ile otomatik kalkıyor)
        // Mesaj geçmişini temizle
        if (this.messages.length > 500) {
            this.messages = this.messages.slice(-250);
        }
        
        // Blocked IP listesini temizle
        if (this.blockedIPs.length > 1000) {
            this.blockedIPs = this.blockedIPs.slice(-500);
        }

        console.log('🧹 Periyodik temizlik tamamlandı');
    }

    start(port = 3000) {
        this.server.listen(port, () => {
            console.log(`🚀 Güvenli IP Engelleme Sistemi başlatıldı`);
            console.log(`🌐 Server: http://localhost:${port}`);
            console.log(`📊 İstatistikler: http://localhost:${port}/uptime.html`);
            console.log(`🔑 Admin Token: ${this.adminToken}`);
            console.log(`📡 SSE Events: http://localhost:${port}/events`);
        });

        // Graceful shutdown
        process.on('SIGINT', () => {
            console.log('\n🛑 Sistem kapatılıyor...');
            this.shutdown();
        });

        process.on('SIGTERM', () => {
            console.log('\n🛑 Sistem sonlandırılıyor...');
            this.shutdown();
        });
    }

    shutdown() {
        console.log('💾 Veriler kaydediliyor...');
        blockManager.saveData();
        
        console.log('🔌 Bağlantılar kapatılıyor...');
        for (const socket of this.connections) {
            socket.destroy();
        }
        
        this.server.close(() => {
            console.log('✅ Server güvenli şekilde kapatıldı');
            process.exit(0);
        });
    }
}

// Server'ı başlat
const server = new SecurityServer();
const PORT = process.env.PORT || 3000;
server.start(PORT);
