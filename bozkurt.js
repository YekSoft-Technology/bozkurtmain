const fs = require('fs');
const readline = require('readline');
const path = require('path');
const crypto = require('crypto');

class LogAnalyzer {
    constructor() {
        this.startLines = {};
        this.detectedIPs = new Set();
        this.suspiciousPatterns = new Map();
        this.logFiles = [];
        this.isRunning = false;
        this.currentLogIndex = 0;
        this.analysisResults = [];
        
        // Ay isimleri
        this.months = {
            Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
            Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11
        };

        // Şüpheli URL kalıpları
        this.suspiciousURLs = [
            /\/wp-admin/,
            /\/wp-login/,
            /\/admin/,
            /\/phpmyadmin/,
            /\/xmlrpc\.php/,
            /\/\.env/,
            /\/config\.php/,
            /\.sql$/,
            /\/shell/,
            /\/backdoor/,
            /eval\(/,
            /base64_decode/,
            /\/etc\/passwd/,
            /\/proc\//
        ];

        // Şüpheli User-Agent kalıpları
        this.suspiciousUserAgents = [
            /bot/i,
            /crawler/i,
            /scanner/i,
            /nikto/i,
            /sqlmap/i,
            /nmap/i,
            /masscan/i,
            /python-requests/i,
            /curl/i,
            /wget/i
        ];

        this.setupLogRotation();
    }

    // Unix zaman dönüştürücü
    parseTimestamp(str) {
        const regex = /(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([\+\-]\d{4})/;
        const match = str.match(regex);
        if (!match) return null;

        const [_, day, month, year, h, m, s] = match;
        const date = new Date(Date.UTC(+year, this.months[month], +day, +h, +m, +s));
        return Math.floor(date.getTime() / 1000);
    }

    // Gelişmiş log parsing
    parseLogLine(line) {
        const logPattern = /^(?<ip>\S+) \S+ \S+ \[(?<timestamp>[^\]]+)\] "(?<method>\S+) (?<url>\S+) (?<protocol>\S+)" (?<status_code>\d+) (?<bytes_sent>\S+) "(?<referrer>[^"]*)" "(?<user_agent>[^"]*)"/;
        const match = line.match(logPattern);
        
        if (!match) return null;

        const { ip, referrer, url, timestamp, method, status_code, bytes_sent, user_agent } = match.groups;
        const unixTime = this.parseTimestamp(timestamp);
        
        if (!unixTime) return null;

        return {
            ip,
            referrer,
            url: decodeURIComponent(url),
            time: unixTime,
            method,
            statusCode: parseInt(status_code),
            bytessent: bytes_sent === '-' ? 0 : parseInt(bytes_sent),
            userAgent: user_agent,
            raw: line
        };
    }

    // Gelişmiş şüpheli aktivite tespiti
    analyzeEntry(entry) {
        const suspiciousScore = this.calculateSuspiciousScore(entry);
        
        if (suspiciousScore > 50) {
            return {
                ip: entry.ip,
                suspicious: true,
                score: suspiciousScore,
                reasons: this.getSuspiciousReasons(entry),
                entry: entry
            };
        }
        
        return null;
    }

    calculateSuspiciousScore(entry) {
        let score = 0;
        
        // URL tabanlı scoring
        for (const pattern of this.suspiciousURLs) {
            if (pattern.test(entry.url)) {
                score += 25;
            }
        }

        // User-Agent tabanlı scoring
        for (const pattern of this.suspiciousUserAgents) {
            if (pattern.test(entry.userAgent)) {
                score += 20;
            }
        }

        // HTTP status code analizi
        if (entry.statusCode === 404) score += 5;
        if (entry.statusCode === 403) score += 10;
        if (entry.statusCode === 500) score += 15;

        // HTTP method analizi
        if (entry.method === 'POST') score += 10;
        if (entry.method === 'PUT') score += 15;
        if (entry.method === 'DELETE') score += 20;

        // Uzun URL'ler şüpheli
        if (entry.url.length > 100) score += 10;

        // SQL injection girişimi
        if (/(\bor\b|\band\b|union|select|insert|update|delete|drop|create|alter|exec)/i.test(entry.url)) {
            score += 30;
        }

        // XSS girişimi
        if (/<script|javascript:|vbscript:|onload=|onerror=/i.test(entry.url)) {
            score += 25;
        }

        return score;
    }

    getSuspiciousReasons(entry) {
        const reasons = [];
        
        for (const pattern of this.suspiciousURLs) {
            if (pattern.test(entry.url)) {
                reasons.push(`Şüpheli URL kalıbı: ${pattern.source}`);
            }
        }

        for (const pattern of this.suspiciousUserAgents) {
            if (pattern.test(entry.userAgent)) {
                reasons.push(`Şüpheli User-Agent: ${pattern.source}`);
            }
        }

        if (entry.statusCode >= 400) {
            reasons.push(`HTTP error code: ${entry.statusCode}`);
        }

        if (/(\bor\b|\band\b|union|select)/i.test(entry.url)) {
            reasons.push('SQL injection girişimi tespit edildi');
        }

        if (/<script|javascript:/i.test(entry.url)) {
            reasons.push('XSS girişimi tespit edildi');
        }

        return reasons;
    }

    // Belirli aralıktaki satırları okuma
    async readLogLines(logFilePath, startLine = 0, batchSize = 1000, callback) {
        return new Promise((resolve) => {
            if (!fs.existsSync(logFilePath)) {
                console.error(`❌ Log dosyası bulunamadı: ${logFilePath}`);
                resolve();
                return;
            }

            const entries = [];
            let lineIndex = 0;
            
            const rl = readline.createInterface({
                input: fs.createReadStream(logFilePath),
                crlfDelay: Infinity
            });

            rl.on('line', (line) => {
                lineIndex++;
                
                if (lineIndex < startLine) return;
                
                const parsed = this.parseLogLine(line);
                if (parsed) {
                    const analysis = this.analyzeEntry(parsed);
                    if (analysis && analysis.suspicious) {
                        entries.push(analysis);
                    }
                }

                if (entries.length >= batchSize) {
                    this.startLines[logFilePath] = lineIndex;
                    callback(entries);
                    rl.close();
                    resolve();
                    return;
                }
            });

            rl.on('close', () => {
                if (entries.length > 0) {
                    callback(entries);
                }
                resolve();
            });

            rl.on('error', (error) => {
                console.error(`❌ Log okuma hatası: ${error.message}`);
                resolve();
            });
        });
    }

    // Dosyanın sonundaki satırları okuma
    async readLastLines(logPath, lineCount = 1000, callback) {
        return new Promise((resolve) => {
            const entries = [];
            
            const rl = readline.createInterface({
                input: fs.createReadStream(logPath, { encoding: "utf-8" }),
                crlfDelay: Infinity,
            });

            const lines = [];
            rl.on("line", (line) => {
                lines.push(line);
                if (lines.length > lineCount) {
                    lines.shift(); // En eski satırı çıkar
                }
            });

            rl.on("close", () => {
                for (const line of lines) {
                    const parsed = this.parseLogLine(line);
                    if (parsed) {
                        const analysis = this.analyzeEntry(parsed);
                        if (analysis && analysis.suspicious) {
                            entries.push(analysis);
                        }
                    }
                }
                callback(entries);
                resolve();
            });

            rl.on('error', (error) => {
                console.error(`❌ Son satırları okuma hatası: ${error.message}`);
                resolve();
            });
        });
    }

    // IP bazında analiz
    analyzeIPBehavior(entries) {
        const ipStats = new Map();
        
        for (const entry of entries) {
            const ip = entry.ip;
            
            if (!ipStats.has(ip)) {
                ipStats.set(ip, {
                    totalRequests: 0,
                    suspiciousRequests: 0,
                    totalScore: 0,
                    firstSeen: entry.entry.time,
                    lastSeen: entry.entry.time,
                    urls: new Set(),
                    userAgents: new Set(),
                    reasons: new Set()
                });
            }
            
            const stats = ipStats.get(ip);
            stats.totalRequests++;
            stats.suspiciousRequests++;
            stats.totalScore += entry.score;
            stats.lastSeen = Math.max(stats.lastSeen, entry.entry.time);
            stats.urls.add(entry.entry.url);
            stats.userAgents.add(entry.entry.userAgent);
            
            for (const reason of entry.reasons) {
                stats.reasons.add(reason);
            }
        }

        return ipStats;
    }

    // Şüpheli IP'leri bulma
    findSuspiciousIPs(entries, callback) {
        const ipStats = this.analyzeIPBehavior(entries);
        const suspiciousIPs = new Set();

        for (const [ip, stats] of ipStats.entries()) {
            let shouldBlock = false;
            const blockReasons = [];

            // Yüksek şüpheli skor
            if (stats.totalScore > 100) {
                shouldBlock = true;
                blockReasons.push(`Yüksek şüpheli skor: ${stats.totalScore}`);
            }

            // Çok fazla şüpheli istek
            if (stats.suspiciousRequests > 50) {
                shouldBlock = true;
                blockReasons.push(`Çok fazla şüpheli istek: ${stats.suspiciousRequests}`);
            }

            // Kısa sürede çok istek
            const duration = stats.lastSeen - stats.firstSeen;
            if (duration < 60 && stats.totalRequests > 100) {
                shouldBlock = true;
                blockReasons.push(`Hızlı istek: ${stats.totalRequests} istek ${duration} saniyede`);
            }

            // Çok farklı URL denenmiş
            if (stats.urls.size > 30) {
                shouldBlock = true;
                blockReasons.push(`Çok sayıda farklı URL: ${stats.urls.size}`);
            }

            if (shouldBlock) {
                suspiciousIPs.add(ip);
                console.log(`🚨 Şüpheli IP tespit edildi: ${ip}`);
                console.log(`   Nedenler: ${blockReasons.join(', ')}`);
                
                this.logSuspiciousActivity(ip, stats, blockReasons);
            }
        }

        callback(suspiciousIPs);
    }

    // Şüpheli aktiviteyi loglama
    logSuspiciousActivity(ip, stats, reasons) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            ip: ip,
            totalRequests: stats.totalRequests,
            suspiciousScore: stats.totalScore,
            duration: stats.lastSeen - stats.firstSeen,
            uniqueURLs: stats.urls.size,
            reasons: reasons,
            sampleURLs: Array.from(stats.urls).slice(0, 5),
            userAgents: Array.from(stats.userAgents)
        };

        try {
            const logDir = path.join(__dirname, 'logs');
            if (!fs.existsSync(logDir)) {
                fs.mkdirSync(logDir, { recursive: true });
            }

            const logFile = path.join(logDir, 'suspicious_activity.log');
            fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
        } catch (error) {
            console.error('❌ Şüpheli aktivite loglanamadı:', error.message);
        }
    }

    // Log rotasyonu
    setupLogRotation() {
        setInterval(() => {
            this.rotateLogFile();
        }, 24 * 60 * 60 * 1000); // Günlük
    }

    rotateLogFile() {
        try {
            const logDir = path.join(__dirname, 'logs');
            const logFile = path.join(logDir, 'suspicious_activity.log');
            
            if (fs.existsSync(logFile)) {
                const stats = fs.statSync(logFile);
                const date = new Date().toISOString().split('T')[0];
                const rotatedFile = path.join(logDir, `suspicious_activity_${date}.log`);
                
                if (stats.size > 10 * 1024 * 1024) { // 10MB'dan büyükse
                    fs.renameSync(logFile, rotatedFile);
                    console.log(`📁 Log dosyası rotate edildi: ${rotatedFile}`);
                }
            }
        } catch (error) {
            console.error('❌ Log rotation hatası:', error.message);
        }
    }

    // Ana analiz döngüsü
    async processNextLog(callback) {
        if (this.logFiles.length === 0 || !this.isRunning) {
            return;
        }

        this.currentLogIndex = this.currentLogIndex % this.logFiles.length;
        const logFile = this.logFiles[this.currentLogIndex];

        try {
            console.log(`📊 Analiz ediliyor: ${path.basename(logFile)}`);
            
            await this.readLogLines(
                logFile, 
                this.startLines[logFile] || 0, 
                2000, 
                (entries) => {
                    if (entries.length > 0) {
                        this.findSuspiciousIPs(entries, (suspiciousIPs) => {
                            for (const ip of suspiciousIPs) {
                                if (!this.detectedIPs.has(ip)) {
                                    this.detectedIPs.add(ip);
                                    callback(ip);
                                }
                            }
                        });
                    }
                }
            );

        } catch (error) {
            console.error(`❌ Log işleme hatası: ${error.message}`);
        }

        this.currentLogIndex++;
        
        // Sonraki analiz için bekle
        setTimeout(() => {
            this.processNextLog(callback);
        }, 3000);
    }

    // Sistem başlatma
    start(logFiles = [], callback) {
        if (this.isRunning) {
            console.log('⚠️ Sistem zaten çalışıyor');
            return;
        }

        this.logFiles = logFiles.filter(file => {
            if (fs.existsSync(file)) {
                return true;
            } else {
                console.error(`❌ Log dosyası bulunamadı: ${file}`);
                return false;
            }
        });

        if (this.logFiles.length === 0) {
            console.error('❌ Geçerli log dosyası bulunamadı');
            return;
        }

        console.log(`🚀 Log analiz sistemi başlatılıyor...`);
        console.log(`📁 İzlenecek dosyalar: ${this.logFiles.length}`);
        
        // Başlangıç pozisyonlarını sıfırla
        this.logFiles.forEach(file => {
            this.startLines[file] = 0;
        });

        this.isRunning = true;
        this.detectedIPs.clear();
        
        // İlk analizi başlat
        this.processNextLog(callback);
        
        console.log('✅ Sistem başarıyla başlatıldı');
    }

    // Sistem durdurma
    stop() {
        if (!this.isRunning) {
            console.log('⚠️ Sistem zaten durmuş');
            return;
        }

        this.isRunning = false;
        console.log('🛑 Log analiz sistemi durduruldu');
    }

    // İstatistikler
    getStats() {
        return {
            isRunning: this.isRunning,
            logFiles: this.logFiles.length,
            detectedIPs: this.detectedIPs.size,
            currentLogIndex: this.currentLogIndex,
            startLines: { ...this.startLines }
        };
    }

    // Tespit edilen IP'leri temizle
    clearDetectedIPs() {
        this.detectedIPs.clear();
        console.log('🧹 Tespit edilen IP listesi temizlendi');
    }

    // Manuel analiz (tek seferlik)
    async analyzeLogFile(logPath, callback) {
        if (!fs.existsSync(logPath)) {
            console.error(`❌ Log dosyası bulunamadı: ${logPath}`);
            return;
        }

        console.log(`🔍 Manuel analiz başlatılıyor: ${path.basename(logPath)}`);
        
        await this.readLastLines(logPath, 5000, (entries) => {
            if (entries.length > 0) {
                console.log(`📊 ${entries.length} şüpheli entry bulundu`);
                
                this.findSuspiciousIPs(entries, (suspiciousIPs) => {
                    console.log(`🚨 ${suspiciousIPs.size} şüpheli IP tespit edildi`);
                    
                    for (const ip of suspiciousIPs) {
                        callback(ip);
                    }
                });
            } else {
                console.log('✅ Şüpheli aktivite bulunamadı');
            }
        });
    }

    // Gerçek zamanlı log izleme
    watchLogFile(logPath, callback) {
        if (!fs.existsSync(logPath)) {
            console.error(`❌ Log dosyası bulunamadı: ${logPath}`);
            return;
        }

        console.log(`👁️ Gerçek zamanlı izleme başlatılıyor: ${path.basename(logPath)}`);
        
        const watcher = fs.watchFile(logPath, { interval: 1000 }, (curr, prev) => {
            if (curr.mtime > prev.mtime) {
                // Dosya değişti, yeni satırları analiz et
                this.analyzeNewLines(logPath, callback);
            }
        });

        return watcher;
    }

    async analyzeNewLines(logPath, callback) {
        try {
            const lastPosition = this.startLines[logPath] || 0;
            await this.readLogLines(logPath, lastPosition, 500, (entries) => {
                if (entries.length > 0) {
                    this.findSuspiciousIPs(entries, (suspiciousIPs) => {
                        for (const ip of suspiciousIPs) {
                            if (!this.detectedIPs.has(ip)) {
                                this.detectedIPs.add(ip);
                                callback(ip);
                            }
                        }
                    });
                }
            });
        } catch (error) {
            console.error(`❌ Yeni satır analiz hatası: ${error.message}`);
        }
    }

    // Rapor oluşturma
    generateReport() {
        const report = {
            timestamp: new Date().toISOString(),
            stats: this.getStats(),
            detectedIPs: Array.from(this.detectedIPs),
            suspiciousPatterns: Object.fromEntries(this.suspiciousPatterns),
            analysisResults: this.analysisResults.slice(-100) // Son 100 sonuç
        };

        try {
            const reportDir = path.join(__dirname, 'reports');
            if (!fs.existsSync(reportDir)) {
                fs.mkdirSync(reportDir, { recursive: true });
            }

            const date = new Date().toISOString().split('T')[0];
            const reportFile = path.join(reportDir, `analysis_report_${date}.json`);
            
            fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));
            console.log(`📋 Rapor oluşturuldu: ${reportFile}`);
            
            return reportFile;
        } catch (error) {
            console.error('❌ Rapor oluşturulamadı:', error.message);
            return null;
        }
    }

    // Hafıza temizleme
    cleanup() {
        // Eski analiz sonuçlarını temizle
        if (this.analysisResults.length > 1000) {
            this.analysisResults = this.analysisResults.slice(-500);
        }

        // Eski şüpheli kalıpları temizle
        const now = Date.now();
        const maxAge = 24 * 60 * 60 * 1000; // 24 saat
        
        for (const [key, value] of this.suspiciousPatterns.entries()) {
            if (now - value.lastSeen > maxAge) {
                this.suspiciousPatterns.delete(key);
            }
        }

        console.log('🧹 Hafıza temizleme tamamlandı');
    }
}

// Singleton instance
const logAnalyzer = new LogAnalyzer();

// Backward compatibility exports
function start(logs, callback) {
    return logAnalyzer.start(logs, callback);
}

function find(list, callback) {
    // Eski API uyumluluğu için basit wrapper
    const entries = list.map(entry => ({
        ip: entry.ip,
        suspicious: true,
        score: 75,
        reasons: ['Legacy detection'],
        entry: entry
    }));
    
    logAnalyzer.findSuspiciousIPs(entries, callback);
}

// Periyodik temizlik
setInterval(() => {
    logAnalyzer.cleanup();
}, 60 * 60 * 1000); // Her saat

module.exports = {
    start,
    find,
    logAnalyzer,
    LogAnalyzer
};
