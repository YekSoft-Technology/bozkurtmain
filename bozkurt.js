const fs = require('fs');
const readline = require('readline');

// IP log başlangıç satırları
let startLines = {};

// Ay isimleri
const months = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11
};

// Unix zaman dönüştürücü
function UnixTime(str) {
  const regex = /(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([\+\-]\d{4})/;
  const match = str.match(regex);
  if (!match) return null;

  const [_, day, month, year, h, m, s] = match;
  const date = new Date(Date.UTC(+year, months[month], +day, +h, +m, +s));
  return Math.floor(date.getTime() / 1000);
}

// Log'a IP yaz
function log(str) {
  fs.appendFile('./blocked.log', str, () => {});
}

// Tek bir log satırını parse et
function parse(line) {
  const logPattern = /(?<ip>\S+) \S+ \S+ \[(?<timestamp>[^\]]+)\] "(?<method>\S+) (?<url>\S+) (?<protocol>\S+)" (?<status_code>\d+) (?<bytes_sent>\S+) "(?<referrer>[^"]*)" "(?<user_agent>[^"]*)"/;
  const match = line.match(logPattern);
  if (!match) return null;

  const { ip, referrer, url, timestamp } = match.groups;
  const unixTime = UnixTime(timestamp);
  return { ip, referrer, url, time: unixTime };
}

// Belirli aralıktaki satırları oku
function linesAll(logFilePath, startLine = 0, period = 1000, removePeriod = 200, callback) {
  return new Promise((resolve) => {
    let list = [];
    let index = 0;
    const rl = readline.createInterface({ input: fs.createReadStream(logFilePath) });

    rl.on('line', (line) => {
      index++;
      if (index < startLine) return;
      const parsed = parse(line);
      if (parsed) list.push(parsed);
      if (list.length === period) {
        callback(list);
        startLines[logFilePath] = index;
        list.splice(0, removePeriod);
      }
    });

    rl.on('close', () => resolve());
  });
}

// Dosyanın sonundaki satırları oku
function linesLast(path, period = 1000, callback) {
  return new Promise((resolve) => {
    const list = [];
    const rl = readline.createInterface({
      input: fs.createReadStream(path, { encoding: "utf-8" }),
      crlfDelay: Infinity,
    });

    rl.on("line", (line) => {
      const parsed = parse(line);
      if (parsed) list.push(parsed);
      if (list.length === period) {
        rl.close();
        callback(list);
        resolve();
      }
    });

    rl.on("close", () => {
      callback(list);
      resolve();
    });
  });
}

// IP’leri belirli bir zaman aralığında filtrele
function filter(entries, seconds, onMatch) {
  entries.sort((a, b) => a.time - b.time);
  const detected = {};
  const datas = {};
  const flagged = [];

  for (const entry of entries) {
    const { ip, time } = entry;

    detected[ip] = (detected[ip] || []).filter(t => t >= time - seconds);
    datas[ip] = (datas[ip] || []).filter(t => t.time >= time - seconds);

    detected[ip].push(time);
    datas[ip].push(entry);

    onMatch(Object.values(datas[ip]), flagged);
  }

  return flagged;
}

// Şüpheli IP’leri bul
function find(list, callback) {
  const founded = new Set();

  filter(list, 5, (datas, flagged) => {
    if (datas.filter(e => e.url === "/").length > 10) {
      flagged.push(datas);
    }
  }).forEach(f => founded.add(f[0].ip));

  filter(list, 60, (datas, flagged) => {
    if (datas.filter(e => e.url === "/").length > 120) {
      flagged.push(datas);
    }
  }).forEach(f => founded.add(f[0].ip));

  callback(founded);
}

// Sürekli logları işle
let ips = new Set();
let logs = [];
let logIndex = 0;
const method = linesAll;

function next(callback) {
  if (logs.length === 0) return;

  logIndex = logIndex % logs.length;
  const file = logs[logIndex];

  method(file, startLines[file], 2000, 200, (data) => {
    find(data, (_ips) => {
      for (const ip of _ips) {
        if (ips.has(ip)) continue;
        ips.add(ip);
        log(ip + "\n");
        callback(ip);
      }
    });
  }).then(() => {
    logIndex++;
    setTimeout(() => next(callback), 2000);
  });
}

// Başlat
function start(_logs = [], callback) {
  logs = _logs;
  logs.forEach(f => { startLines[f] = 0; });
  next(callback);
}

exports.start = start;
