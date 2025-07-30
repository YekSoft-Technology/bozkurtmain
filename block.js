const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const net = require("net");

class IPBlockManager {
    constructor() {
        this.loadConfig();
        this.blockedIPs = new Set();
        this.whitelist = new Set();
        this.blockHistory = new Map();
        this.rateLimiter = new Map();
        this.maxRetries = 3;
        this.retryDelay = 2000;
        
        // Kritik IP'ler (asla engellenmamalı)
        this.criticalIPs = new Set([
            '8.8.8.8', '8.8.4.4',          // Google DNS
            '1.1.1.1', '1.0.0.1',          // Cloudflare DNS
            '208.67.222.222', '208.67.220.220', // OpenDNS
            '127.0.0.1', 'localhost'        // Localhost
        ]);

        // Özel IP aralıkları
        this.privateRanges = [
            { start: '10.0.0.0', end: '10.255.255.255' },
            { start: '172.16.0.0', end: '172.31.255.255' },
            { start: '192.168.0.0', end: '192.168.255.255' },
            { start: '127.0.0.0', end: '127.255.255.255' }
        ];

        this.loadData();
        this.setupPeriodicSave();
        this.setupRateLimiterCleanup();
    }

    loadConfig() {
        try {
            const configPath = path.join(__dirname, '.config.json');
            if (!fs.existsSync(configPath)) {
                throw new Error('Konfigürasyon dosyası bulunamadı. .config.json dosyasını oluşturun.');
            }
            
            const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
            
            if (!config.cpanel_user || !config.cpanel_token || !config.cpanel_host) {
                throw new Error('Eksik konfigürasyon: cpanel_user, cpanel_token, cpanel_host gerekli');
            }
            
            this.config = config;
            this.secretKey = process.env.BLOCK_SECRET || config.secret_key || this.generateSecretKey();
            
        } catch (error) {
            console.error('❌ Konfigürasyon hatası:', error.message);
            process.exit(1);
        }
    }

    generateSecretKey() {
        return crypto.randomBytes(32).toString('hex');
    }

    // IP validasyon fonksiyonları
    isValidIP(ip) {
        return net.isIP(ip) !== 0;
    }

    ipToNumber(ip) {
        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
    }

    isPrivateIP(ip) {
        const ipNum = this.ipToNumber(ip);
        return this.privateRanges.some(range => {
            const startNum = this.ipToNumber(range.start);
            const endNum = this.ipToNumber(range.end);
            return ipNum >= startNum && ipNum <= endNum;
        });
    }

    isCriticalIP(ip) {
        return this.criticalIPs.has(ip);
    }

    isWhitelisted(ip) {
        return this.whitelist.has(ip);
    }

    canBlock(ip) {
        if (!this.isValidIP(ip)) return { allowed: false, reason: 'Geçersiz IP formatı' };
        if (this.isPrivateIP(ip)) return { allowed: false, reason: 'Özel IP aralığı' };
        if (this.isCriticalIP(ip)) return { allowed: false, reason: 'Kritik sistem IP\'si' };
        if (this.isWhitelisted(ip)) return { allowed: false, reason: 'Beyaz listede' };
        if (this.isBlocked(ip)) return { allowed: false, reason: 'Zaten engellenmiş' };
        return { allowed: true, reason: 'Engellenebilir' };
    }

    // Rate limiting
    checkRateLimit(ip) {
        const now = Date.now();
        const windowMs = 60000; // 1 dakika
        const maxRequests = 5;

        if (!this.rateLimiter.has(ip)) {
            this.rateLimiter.set(ip, []);
        }

        const requests = this.rateLimiter.get(ip);
        const validRequests = requests.filter(time => time > now - windowMs);
        
        if (validRequests.length >= maxRequests) {
            return false;
        }

        validRequests.push(now);
        this.rateLimiter.set(ip, validRequests);
        return true;
    }

    setupRateLimiterCleanup() {
        setInterval(() => {
            const now = Date.now();
            const windowMs = 60000;
            
            for (const [ip, requests] of this.rateLimiter.entries()) {
                const validRequests = requests.filter(time => time > now - windowMs);
                if (validRequests.length === 0) {
                    this.rateLimiter.delete(ip);
                } else {
                    this.rateLimiter.set(ip, validRequests);
                }
            }
        }, 60000);
    }

    // Ana engelleme fonksiyonu
    async blockIP(addresses, callback) {
        if (!Array.isArray(addresses)) {
            addresses = [addresses];
        }

        const results = [];
        
        for (const ip of addresses) {
            try {
                // Rate limiting kontrolü
                if (!this.checkRateLimit(ip)) {
                    const msg = `${ip}\t❌ Rate limit aşıldı`;
                    results.push({ ip, success: false, message: msg });
                    if (callback) callback(msg);
                    continue;
                }

                // IP engelleme kontrolü
                const validation = this.canBlock(ip);
                if (!validation.allowed) {
                    const msg = `${ip}\t❌ ${validation.reason}`;
                    results.push({ ip, success: false, message: msg });
                    if (callback) callback(msg);
                    continue;
                }

                const result = await this.performBlock(ip);
                results.push(result);
                if (callback) callback(result.message);
                
                // Başarılıysa kaydet
                if (result.success) {
                    this.addToBlockedList(ip);
                }

            } catch (error) {
                const msg = `${ip}\t❌ Hata: ${error.message}`;
                results.push({ ip, success: false, message: msg });
                if (callback) callback(msg);
            }
        }

        return results;
    }

    async performBlock(ip, retryCount = 0) {
        return new Promise((resolve, reject) => {
            const timestamp = Date.now();
            const nonce = crypto.randomBytes(16).toString('hex');
            const signature = this.generateSignature(ip, timestamp, nonce);
            
            const options = {
                hostname: this.config.cpanel_host,
                port: this.config.cpanel_port || 2083,
                path: `/execute/BlockIP/add_ip?ip=${encodeURIComponent(ip)}`,
                method: 'GET',
                headers: {
                    'Authorization': `cpanel ${this.config.cpanel_user}:${this.config.cpanel_token}`,
                    'Accept': 'application/json',
                    'User-Agent': 'Advanced-IPBlocker/2.0',
                    'X-Timestamp': timestamp,
                    'X-Nonce': nonce,
                    'X-Signature': signature,
                    'X-IP-Target': ip
                },
                timeout: 15000,
                rejectUnauthorized: this.config.ssl_verify !== false
            };

            const req = https.request(options, (res) => {
                let data = '';
                let statusCode = res.statusCode;
                
                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    try {
                        if (statusCode !== 200) {
                            throw new Error(`HTTP ${statusCode}: ${data}`);
                        }

                        const response = JSON.parse(data);
                        const success = response.status === 1;
                        const message = `${ip}\t${success ? '✅' : '❌'} ${response.statusmsg || 'Bilinmeyen durum'}`;
                        
                        resolve({
                            ip,
                            success,
                            message,
                            timestamp: Date.now(),
                            response: response
                        });

                    } catch (parseError) {
                        if (retryCount < this.maxRetries) {
                            console.log(`🔄 Yeniden deneniyor (${retryCount + 1}/${this.maxRetries}): ${ip}`);
                            setTimeout(() => {
                                this.performBlock(ip, retryCount + 1)
                                    .then(resolve)
                                    .catch(reject);
                            }, this.retryDelay * (retryCount + 1));
                        } else {
                            reject(new Error(`Parse hatası: ${parseError.message}`));
                        }
                    }
                });
            });

            req.on('error', (error) => {
                if (retryCount < this.maxRetries) {
                    console.log(`🔄 Bağlantı hatası, yeniden deneniyor: ${ip}`);
                    setTimeout(() => {
                        this.performBlock(ip, retryCount + 1)
                            .then(resolve)
                            .catch(reject);
                    }, this.retryDelay * (retryCount + 1));
                } else {
                    reject(new Error(`Bağlantı hatası: ${error.message}`));
                }
            });

            req.on('timeout', () => {
                req.destroy();
                if (retryCount < this.maxRetries) {
                    setTimeout(() => {
                        this.performBlock(ip, retryCount + 1)
                            .then(resolve)
                            .catch(reject);
                    }, this.retryDelay * (retryCount + 1));
                } else {
                    reject(new Error('İstek zaman aşımına uğradı'));
                }
            });

            req.end();
        });
    }

    generateSignature(ip, timestamp, nonce) {
        const data = `${ip}:${timestamp}:${nonce}`;
        return crypto.createHmac('sha256', this.secretKey).update(data).digest('hex');
    }

    // Veri yönetimi
    addToBlockedList(ip) {
        this.blockedIPs.add(ip);
        this.blockHistory.set(ip, {
            blockedAt: Date.now(),
            reason: 'Otomatik engelleme',
            source: 'system'
        });
        this.saveData();
    }

    isBlocked(ip) {
        return this.blockedIPs.has(ip);
    }

    unblockIP(ip) {
        const success = this.blockedIPs.delete(ip);
        if (success) {
            this.blockHistory.delete(ip);
            this.saveData();
        }
        return success;
    }

    addToWhitelist(ip) {
        if (this.isValidIP(ip)) {
            this.whitelist.add(ip);
            this.saveData();
            return true;
        }
        return false;
    }

    removeFromWhitelist(ip) {
        const success = this.whitelist.delete(ip);
        if (success) {
            this.saveData();
        }
        return success;
    }

    // Veri dosyası işlemleri
    getDataPath() {
        const dataDir = path.join(__dirname, 'data');
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
        return path.join(dataDir, 'ip_data.json');
    }

    loadData() {
        try {
            const filePath = this.getDataPath();
            if (fs.existsSync(filePath)) {
                const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                this.blockedIPs = new Set(data.blocked || []);
                this.whitelist = new Set(data.whitelist || []);
                this.blockHistory = new Map(data.history || []);
                console.log(`📂 Veri yüklendi: ${this.blockedIPs.size} engellenmiş, ${this.whitelist.size} beyaz liste`);
            }
        } catch (error) {
            console.error('⚠️ Veri yüklenemedi:', error.message);
        }
    }

    saveData() {
        try {
            const filePath = this.getDataPath();
            const data = {
                blocked: Array.from(this.blockedIPs),
                whitelist: Array.from(this.whitelist),
                history: Array.from(this.blockHistory.entries()),
                lastUpdated: Date.now(),
                version: '2.0'
            };

            const backup = filePath + '.backup';
            if (fs.existsSync(filePath)) {
                fs.copyFileSync(filePath, backup);
            }

            fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
        } catch (error) {
            console.error('❌ Veri kaydedilemedi:', error.message);
        }
    }

    setupPeriodicSave() {
        setInterval(() => {
            this.saveData();
        }, 300000); // 5 dakikada bir kaydet
    }

    // İstatistik fonksiyonları
    getStats() {
        return {
            blockedCount: this.blockedIPs.size,
            whitelistCount: this.whitelist.size,
            historyCount: this.blockHistory.size,
            rateLimiterEntries: this.rateLimiter.size
        };
    }

    getBlockedIPs() {
        return Array.from(this.blockedIPs);
    }

    getWhitelist() {
        return Array.from(this.whitelist);
    }

    getBlockHistory() {
        return Array.from(this.blockHistory.entries()).map(([ip, data]) => ({
            ip,
            ...data
        }));
    }

    // Temizlik fonksiyonları
    clearOldHistory(days = 30) {
        const cutoff = Date.now() - (days * 24 * 60 * 60 * 1000);
        let cleared = 0;
        
        for (const [ip, data] of this.blockHistory.entries()) {
            if (data.blockedAt < cutoff) {
                this.blockHistory.delete(ip);
                cleared++;
            }
        }
        
        if (cleared > 0) {
            this.saveData();
            console.log(`🧹 ${cleared} eski kayıt temizlendi`);
        }
        
        return cleared;
    }
}

// Singleton instance
const blockManager = new IPBlockManager();

// Export fonksiyonları (backward compatibility)
function blockIP(addresses, callback) {
    return blockManager.blockIP(addresses, callback);
}

module.exports = {
    blockIP,
    blockManager,
    IPBlockManager
};
