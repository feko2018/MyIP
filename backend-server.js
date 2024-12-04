import dotenv from 'dotenv';
import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import mapHandler from './apis/map.js';
import ipinfoHandler from './apis/ipinfo.js';
import ipapicomHandler from './apis/ipapicom.js';
import keycdnHandler from './apis/keycdn.js';
import ipCheckingHandler from './apis/ipchecking.js';
import ipsbHandler from './apis/ipsb.js';
import cfHander from './apis/cfradar.js';
import validateConfigs from './apis/configs.js';
import dnsResolver from './apis/dnsresolver.js';
import rateLimit from 'express-rate-limit';
import { slowDown } from 'express-slow-down'
import whois from './apis/whois.js';
import ipapiisHandler from './apis/ipapiis.js';
import invisibilitytestHandler from './apis/invisibilitytest.js';
import macChecker from './apis/macchecker.js';
import maxmindHandler from './apis/maxmind.js';

dotenv.config();

const app = express();
const backEndPort = parseInt(process.env.BACKEND_PORT || 11966, 10);
const blackListIPLogFilePath = process.env.SECURITY_BLACKLIST_LOG_FILE_PATH || 'logs/blacklist-ip.log';
const rateLimitSet = parseInt(process.env.SECURITY_RATE_LIMIT || 0, 10);
const speedLimitSet = parseInt(process.env.SECURITY_DELAY_AFTER || 0, 10);

app.set('trust proxy', 1);

// 获取客户端 IP 的辅助函数
function getClientIp(req) {
    const cfIp = req.headers['cf-connecting-ip']; // Cloudflare IP
    const forwardedIps = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0] : null;
    const cfIpV6 = req.headers['cf-connecting-ipv6'];
    return cfIp || forwardedIps || cfIpV6 || req.ip;
}

// 记录限流触发的 IP 地址
function formatDate(timestamp) {
    return new Date(timestamp).toLocaleString('en-US', { timeZone: 'Asia/Shanghai' });
}

function logLimitedIP(ip) {
    const logPath = path.join(__dirname, blackListIPLogFilePath);

    // 如果 logs 目录不存在，则创建
    const logDir = path.dirname(logPath);
    if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
        console.log('Created log directory:', logDir);
    }

    // 读取日志文件，更新 IP 计数，如果文件不存在则创建新的日志文件
    fs.readFile(logPath, 'utf8', (err, data) => {
        if (err && err.code !== 'ENOENT') {
            console.error('Error reading the log file:', err);
            return;
        }

        const now = Date.now();
        let newCount = 1;
        let logExists = false;
        let updatedData = '';

        if (data) {
            const lines = data.split('\n');
            updatedData = lines.map(line => {
                const [currentIp, count, timestamp] = line.split(',');
                if (currentIp === ip) {
                    newCount = parseInt(count, 10) + 1;
                    logExists = true;
                    console.log(`IP ${ip} has been limited ${newCount} times`);
                    return `${ip},${newCount},${timestamp}`;  // Update count but keep the original timestamp
                }
                return line;
            }).join('\n');
        }

        if (!logExists) {
            const newLine = `${ip},${newCount},${formatDate(now)}`;
            updatedData += (updatedData ? '\n' : '') + newLine;
            console.log(`IP ${ip} has been limited for the first time`);
        }

        fs.writeFile(logPath, updatedData, 'utf8', err => {
            if (err) {
                console.error('Failed to write to log file:', err);
            }
        });
    });
}

const rateLimiter = rateLimit({
    windowMs: 20 * 60 * 1000,
    max: rateLimitSet,
    message: 'Too Many Requests',
    handler: (req, res, next) => {
        const ip = getClientIp(req);
        if (req.rateLimit.current === req.rateLimit.limit + 1 && blackListIPLogFilePath) {
            logLimitedIP(ip);
        }
        res.status(429).json({ message: 'Too Many Requests' });
    }
});

const speedLimiter = slowDown({
	windowMs: 60 * 60 * 1000,
	delayAfter: speedLimitSet,
	delayMs: (hits) => hits * 400,
})

// 如果 rateLimitSet 为 0，则不启用限流
if (rateLimitSet !== 0) {
    app.use('/apis', rateLimiter);
    console.log('Rate limiter is enabled, limit:', rateLimitSet, 'requests per 60 minutes');
}

// 如果 deleyAfter 为 0，则不启用延迟
if (speedLimitSet !== 0) {
    app.use('/apis', speedLimiter);
    console.log('Speed limiter is enabled, slowing down after:', speedLimitSet, 'requests');
}


// APIs
app.get('/apis/map', mapHandler);
app.get('/apis/ipinfo', ipinfoHandler);
app.get('/apis/ipapicom', ipapicomHandler);
app.get('/apis/keycdn', keycdnHandler);
app.get('/apis/ipchecking', ipCheckingHandler);
app.get('/apis/ipsb', ipsbHandler);
app.get('/apis/cfradar', cfHander);
app.get('/apis/dnsresolver', dnsResolver);
app.get('/apis/whois', whois);
app.get('/apis/ipapiis', ipapiisHandler);
app.get('/apis/invisibility', invisibilitytestHandler);
app.get('/apis/macchecker', macChecker);
app.get('/apis/maxmind', maxmindHandler);

// 使用查询参数处理所有配置请求
app.get('/apis/configs', validateConfigs);

// 设置静态文件服务
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, './dist')));


// 启动服务器
app.listen(backEndPort, () => {
    console.log(`Backend server running on http://localhost:${backEndPort}`);
});
