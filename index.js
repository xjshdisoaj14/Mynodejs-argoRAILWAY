/**
 * 最小化 VLESS + Cloudflare Argo 隧道节点
 *
 * 设计原则：
 *  1. 不使用任何混淆代码，全部逻辑可读可审计
 *  2. 不在运行时下载可执行文件（cloudflared / xray 在 Docker 构建阶段装好）
 *  3. 不向任何第三方上报节点信息
 *  4. 隧道异常时有限次重试，不会无限递归把进程卡死
 *
 * 环境变量：
 *  PORT          HTTP 服务端口（Railway 会自动注入，必须用它）
 *  UUID          节点 UUID，不填自动生成
 *  SUB_PATH      订阅路径，默认 sub
 *  NAME          节点名前缀，默认 argo
 *  CFIP          优选域名/IP（可选），留空则直接用隧道域名
 *  CFPORT        优选端口，默认 443
 *  XRAY_PORT     本地 Xray 监听端口，默认 8001
 */

const http = require('http');
const path = require('path');
const fs = require('fs');
const net = require('net');
const https = require('https');
const crypto = require('crypto');
const { spawn } = require('child_process');

const PORT = Number(process.env.PORT || process.env.SERVER_PORT || 8000);
const UUID = process.env.UUID || crypto.randomUUID();
const SUB_PATH = (process.env.SUB_PATH || 'sub').replace(/^\/+|\/+$/g, '');
const NAME = process.env.NAME || 'argo';
const CFIP = (process.env.CFIP || '').trim();
const CFPORT = Number(process.env.CFPORT || 443);
const XRAY_PORT = Number(process.env.XRAY_PORT || process.env.ARGO_PORT || 8001);

// 运行时文件必须写到可写目录：Hostless 的容器根文件系统是只读的（EROFS）
const WORKDIR = process.env.RUNTIME_DIR || '/tmp';
const XRAY_BIN = process.env.XRAY_BIN || '/usr/local/bin/xray';
const CFD_BIN = process.env.CFD_BIN || '/usr/local/bin/cloudflared';

try {
  fs.mkdirSync(WORKDIR, { recursive: true });
} catch (e) {
  console.error('无法创建运行目录', WORKDIR, e.message);
}

let domain = '';
let subText = '';
let cfdProc = null;
let xrayProc = null;

/* ---- 自愈参数 ---- */
// 进程存活超过这个时长后重置重启计数，避免「累计三次就永久放弃」
const RESTART_RESET_MS = 10 * 60 * 1000;
const MAX_RESTARTS = 5;
// 保活：周期访问隧道域名，确认端到端可用，同时避免 quick tunnel 因闲置被回收
const KEEPALIVE = String(process.env.KEEPALIVE || 'true').toLowerCase() !== 'false';
const PING_INTERVAL_MS = Number(process.env.PING_INTERVAL || 300) * 1000;
const WATCHDOG_INTERVAL_MS = 60 * 1000;

let cfdRestarts = 0;
let xrayRestarts = 0;
let cfdStartedAt = 0;
let xrayStartedAt = 0;
let pingFails = 0;

function log(...args) {
  console.log(`[${new Date().toISOString()}]`, ...args);
}

// 兜底：任何未捕获异常都不允许把 HTTP 服务带走（否则平台会判定启动失败）
process.on('uncaughtException', (e) => log('未捕获异常（已忽略，服务继续）:', e && e.message));
process.on('unhandledRejection', (e) => log('未处理拒绝（已忽略）:', e && e.message));

/* ---------------- Xray ---------------- */

function writeXrayConfig() {
  const config = {
    log: { loglevel: 'warning' },
    inbounds: [
      {
        listen: '127.0.0.1',
        port: XRAY_PORT,
        protocol: 'vless',
        settings: {
          clients: [{ id: UUID, flow: '' }],
          decryption: 'none',
        },
        streamSettings: {
          network: 'ws',
          security: 'none',
          wsSettings: { path: '/' },
        },
        sniffing: { enabled: false },
      },
    ],
    outbounds: [
      { protocol: 'freedom', settings: { domainStrategy: 'UseIP' } },
      { protocol: 'blackhole', settings: {}, tag: 'block' },
    ],
  };
  const file = path.join(WORKDIR, 'xray.json');
  fs.writeFileSync(file, JSON.stringify(config, null, 2));
  return file;
}

function startXray() {
  let cfgFile;
  try {
    cfgFile = writeXrayConfig();
  } catch (e) {
    log('写 xray 配置失败:', e.message);
    return;
  }

  try {
    xrayProc = spawn(XRAY_BIN, ['run', '-c', cfgFile], { stdio: ['ignore', 'inherit', 'inherit'] });
  } catch (e) {
    log('xray 启动失败:', e.message);
    return;
  }

  xrayStartedAt = Date.now();
  xrayProc.on('error', (e) => log('xray 启动失败:', e.message));
  xrayProc.on('exit', (code, sig) => {
    log(`xray 退出 code=${code} sig=${sig}`);
    // 稳定运行过一段时间就清零，避免计数终身累积
    if (Date.now() - xrayStartedAt > RESTART_RESET_MS) xrayRestarts = 0;
    xrayRestarts += 1;
    if (xrayRestarts > MAX_RESTARTS) {
      log(`xray 连续失败超过 ${MAX_RESTARTS} 次，交给看门狗兜底`);
      return;
    }
    setTimeout(startXray, Math.min(3000 * xrayRestarts, 30000));
  });
  log(`xray 已启动，监听 127.0.0.1:${XRAY_PORT}`);
}

/* ---------------- cloudflared ---------------- */

function buildNodes() {
  const hosts = [];
  // 直连隧道域名
  hosts.push({ addr: domain, port: 443 });
  // 可选：优选域名，作为备用节点
  if (CFIP && CFIP !== domain) {
    hosts.push({ addr: CFIP, port: CFPORT });
  }

  return hosts.map((h, i) => {
    const tag = i === 0 ? 'direct' : 'cfip';
    const params = new URLSearchParams({
      encryption: 'none',
      security: 'tls',
      sni: domain,
      fp: 'chrome',
      type: 'ws',
      host: domain,
      path: '/',
    });
    const name = `${NAME}-${tag}`;
    return `vless://${UUID}@${h.addr}:${h.port}?${params.toString()}#${encodeURIComponent(name)}`;
  });
}

function refreshSub() {
  if (!domain) return;
  const nodes = buildNodes();
  subText = Buffer.from(nodes.join('\n'), 'utf8').toString('base64');
  log('订阅已生成，节点数:', nodes.length);
  nodes.forEach((n) => log('  ' + n));
}

function startCloudflared() {
  try {
    cfdProc = spawn(
      CFD_BIN,
      ['tunnel', '--no-autoupdate', '--edge-ip-version', 'auto', '--url', `http://127.0.0.1:${XRAY_PORT}`],
      { stdio: ['ignore', 'pipe', 'pipe'] }
    );
  } catch (e) {
    log('cloudflared 启动失败:', e.message);
    return;
  }

  const onChunk = (buf) => {
    const text = buf.toString();
    if (!domain) {
      const m = text.match(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)/i);
      if (m) {
        domain = m[1];
        log('隧道域名:', domain);
        refreshSub();
      }
    }
  };

  cfdProc.stdout.on('data', onChunk);
  cfdProc.stderr.on('data', onChunk);

  cfdProc.on('error', (e) => log('cloudflared 启动失败:', e.message));

  cfdStartedAt = Date.now();
  cfdProc.on('exit', (code, sig) => {
    log(`cloudflared 退出 code=${code} sig=${sig}`);
    if (Date.now() - cfdStartedAt > RESTART_RESET_MS) cfdRestarts = 0;
    cfdRestarts += 1;
    if (cfdRestarts > MAX_RESTARTS) {
      log(`cloudflared 连续失败超过 ${MAX_RESTARTS} 次，交给看门狗兜底`);
      return;
    }
    domain = '';
    subText = '';
    setTimeout(startCloudflared, Math.min(5000 * cfdRestarts, 60000));
  });

  log('cloudflared 已启动，等待隧道地址…');
}

/* ---------------- HTTP ---------------- */

const HOME_HTML = `<!doctype html>
<html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Node Status</title>
<style>body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:640px;margin:80px auto;padding:0 20px;color:#1f2328;background:#fff}
code{background:#f6f8fa;padding:2px 6px;border-radius:4px;font-size:13px}
.ok{color:#1a7f37}.wait{color:#9a6700}li{margin:8px 0}</style></head>
<body><h2>节点运行中</h2>
<ul>
<li>状态：<span id="s">检测中…</span></li>
<li>订阅路径：<code id="p">…</code></li>
<li>隧道域名：<code id="d">…</code></li>
</ul>
<p style="color:#656d76;font-size:13px">仅限个人自用。请遵守所在地法律法规。</p>
<script>
fetch('/status').then(r=>r.json()).then(j=>{
  const s=document.getElementById('s');
  s.textContent=j.ready?'就绪':'等待隧道';
  s.className=j.ready?'ok':'wait';
  document.getElementById('p').textContent='/'+j.subPath;
  document.getElementById('d').textContent=j.domain||'(未获取)';
}).catch(()=>{document.getElementById('s').textContent='状态接口异常'});
</script></body></html>`;

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const p = url.pathname.replace(/\/+$/, '') || '/';

  if (p === '/' + SUB_PATH) {
    if (!subText) {
      res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('隧道尚未就绪，请稍后刷新');
    }
    res.writeHead(200, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'Profile-Update-Interval': '6',
    });
    return res.end(subText);
  }

  if (p === '/status') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    return res.end(
      JSON.stringify(
        {
          ready: Boolean(domain),
          domain,
          subPath: SUB_PATH,
          uuid: UUID,
          keepalive: KEEPALIVE,
          pingIntervalSec: PING_INTERVAL_MS / 1000,
          pingFails,
          xrayRestarts,
          cfdRestarts,
          uptimeSec: Math.round(process.uptime()),
        },
        null,
        2
      )
    );
  }

  if (p === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(HOME_HTML);
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found');
});

server.listen(PORT, '0.0.0.0', () => {
  log(`HTTP 服务已监听 0.0.0.0:${PORT}`);
  log(`订阅地址: /${SUB_PATH}`);
});

/* ---------------- 看门狗 & 保活 ---------------- */

// 探测本地端口是否真的在监听（能发现「进程还在但服务已死」）
function checkPort(port, host = '127.0.0.1', timeout = 3000) {
  return new Promise((resolve) => {
    const sock = net.connect({ port, host });
    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch (_) {}
      resolve(ok);
    };
    sock.setTimeout(timeout);
    sock.on('connect', () => finish(true));
    sock.on('timeout', () => finish(false));
    sock.on('error', () => finish(false));
  });
}

async function watchdog() {
  // 1) Xray 端口
  if (!(await checkPort(XRAY_PORT))) {
    log('看门狗: xray 端口不通，强制重启');
    try { xrayProc && xrayProc.kill('SIGKILL'); } catch (_) {}
    xrayRestarts = 0;
    setTimeout(startXray, 1000);
  }

  // 2) cloudflared 进程
  const cfdAlive = cfdProc && cfdProc.exitCode === null && !cfdProc.killed;
  if (!cfdAlive) {
    log('看门狗: cloudflared 不在运行，重启');
    cfdRestarts = 0;
    setTimeout(startCloudflared, 1000);
  } else if (!domain) {
    log('看门狗: cloudflared 在跑但还没拿到隧道域名，继续等待');
  }
}

// 周期访问隧道域名：既确认端到端可用，也让 quick tunnel 保持活跃
function pingTunnel() {
  if (!domain) return;
  const req = https.get(
    `https://${domain}/`,
    { timeout: 15000, headers: { 'User-Agent': 'vless-argo-keepalive' } },
    (res) => {
      res.resume();
      if (pingFails) log(`保活: 隧道恢复（此前连续失败 ${pingFails} 次）`);
      pingFails = 0;
    }
  );
  req.on('timeout', () => req.destroy(new Error('timeout')));
  req.on('error', (e) => {
    pingFails += 1;
    log(`保活: 隧道探测失败 ${pingFails} 次 - ${e.message}`);
    if (pingFails >= 3) {
      log('保活: 连续失败 3 次，重启 cloudflared 换新隧道');
      pingFails = 0;
      try { cfdProc && cfdProc.kill('SIGKILL'); } catch (_) {}
      domain = '';
      subText = '';
      cfdRestarts = 0;
      setTimeout(startCloudflared, 2000);
    }
  });
}

setInterval(watchdog, WATCHDOG_INTERVAL_MS);
log(`看门狗已开启，每 ${WATCHDOG_INTERVAL_MS / 1000} 秒检查一次`);

if (KEEPALIVE) {
  setTimeout(pingTunnel, 60 * 1000);
  setInterval(pingTunnel, PING_INTERVAL_MS);
  log(`保活已开启，每 ${PING_INTERVAL_MS / 1000} 秒探测一次隧道`);
} else {
  log('保活已关闭（KEEPALIVE=false）');
}

/* ---------------- 启动 ---------------- */

function shutdown() {
  log('收到退出信号，清理子进程');
  try { cfdProc && cfdProc.kill('SIGTERM'); } catch (_) {}
  try { xrayProc && xrayProc.kill('SIGTERM'); } catch (_) {}
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

log('UUID:', UUID);
startXray();
setTimeout(startCloudflared, 1500);
