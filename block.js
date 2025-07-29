const https = require("https");
const fs = require("fs");
const path = require("path");

// Load cPanel credentials from .config.json
const { cpanel_user, cpanel_token, cpanel_host } = require("./.config.json");

/**
 * IP adreslerini cPanel üzerinden engelleyen fonksiyon
 * @param {string[]} addresses - Engellenecek IP adresleri
 * @param {function} callback - Her IP için geri bildirim yapılacak fonksiyon
 */
function blockIP(addresses, callback) {
    addresses.forEach(ip => {
        const options = {
            hostname: cpanel_host,
            port: 2083,
            path: `/execute/BlockIP/add_ip?ip=${ip}`,
            method: "GET",
            headers: {
                "Authorization": `cpanel ${cpanel_user}:${cpanel_token}`,
                "Accept": "application/json"
            },
            rejectUnauthorized: false // ⚠️ Gerçek sunucuda kapatılmalı
        };

        const req = https.request(options, res => {
            let data = "";
            res.on("data", chunk => { data += chunk; });
            res.on("end", () => {
                try {
                    const response = JSON.parse(data);
                    callback(`${ip}\t${response.status ? "✅" : "❌"}`);
                } catch (e) {
                    callback(`${ip}\t❌ (JSON parse error)`);
                }
            });
        });

        req.on("error", error => {
            callback(`❌ Error blocking ${ip}: ${error.message}`);
        });

        req.end();
    });
}

// Bu kod Block.txt dosyasından IP leri okuyup engeller
/*
const filePath = path.join(__dirname, "Block.txt");
const source = fs.readFileSync(filePath, "utf8").split(" ");
blockIP(source, console.log);
*/

exports.blockIP = blockIP;
