const http = require('http');
const bozkurt = require("./bozkurt.js");
const block = require("./block.js");
const fs = require('fs');
const path = require('path');

let temp = [];
let list = [];
let message = [];

bozkurt.start(
  ["./test/botnet.log"],
  (ip) => {
    list.push(ip);
    temp.push(ip);
    console.log("ip", ip);
    block.blockIP([ip], (res) => {
      console.log("block", res);
      message.push(res);
    });
  }
);

// Ýçerik tipleri haritasý
const mimeTypes = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml'
};

const server = http.createServer((req, res) => {
  try {
    // SSE endpoint
    if (req.url === '/events') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*'
      });

      // Heartbeat (opsiyonel, baðlantýyý açýk tutar)
      const heartbeat = setInterval(() => {
        res.write(':heartbeat\n\n');
      }, 15000);

      // Yeni mesajlarý sýk sýk gönder
      const interval = setInterval(() => {
        if (message.length > 0) {
          const data = message.shift();
          if (data) {
            res.write(`data: ${data}\n\n`);
          }
        }
      }, 100);

      req.on('close', () => {
        clearInterval(interval);
        clearInterval(heartbeat);
        res.end();
      });
      return;
    }

    // Ana sayfa
    if (req.url === '/' || req.url === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      const index = fs.createReadStream(path.join(__dirname, 'public', 'index.html'));
      index.pipe(res);
      return;
    }

    // Statik dosya yolu güvenli þekilde oluþturuluyor
    const safeUrl = decodeURIComponent(req.url);
    const filePath = path.join(__dirname, 'public', path.normalize(safeUrl).replace(/^(\.\.[\/\\])+/, ''));

    // Dosya var mý kontrol et
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      const contentType = mimeTypes[ext] || 'application/octet-stream';

      res.writeHead(200, { 'Content-Type': contentType });
      const fileStream = fs.createReadStream(filePath);
      fileStream.pipe(res);
      fileStream.on('error', () => {
        res.writeHead(500);
        res.end('Dosya okunurken hata oluþtu.');
      });
    } else {
      // Dosya bulunamazsa 404 dön
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Dosya bulunamadý.');
    }
  } catch (error) {
    console.error('Sunucu hatasý:', error);
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Sunucu hatasý oluþtu.');
  }
});

const PORT = 3000;
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
