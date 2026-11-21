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
const crypto = require('crypto');
const { spawn } = require('child_process');

const PORT = Number(process.env.PORT || process.env.SERVER_PORT || 8000);
const UUID = process.env.UUID || crypto.randomUUID();
const SUB_PATH = (process.env.SUB_PATH || 'sub').replace(/^\/+|\/+$/g, '');
const NAME = process.env.NAME || 'argo';
const CFIP = (process.env.CFIP || '').trim();
const CFPORT = Number(process.env.CFPORT || 443);
const XRAY_PORT = Number(process.env.XRAY_PORT || process.env.ARGO_PORT || 8001);

const WORKDIR = __dirname;
const XRAY_BIN = process.env.XRAY_BIN || '/usr/local/bin/xray';
const CFD_BIN = process.env.CFD_BIN || '/usr/local/bin/cloudflared';

let domain = '';
let subText = '';
let cfdRestarts = 0;
let cfdProc = null;
let xrayProc = null;

function log(...args) {
  console.log(`[${new Date().toISOString()}]`, ...args);
}

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
  const cfgFile = writeXrayConfig();
  xrayProc = spawn(XRAY_BIN, ['run', '-c', cfgFile], { stdio: ['ignore', 'inherit', 'inherit'] });

  xrayProc.on('error', (e) => log('xray 启动失败:', e.message));
  xrayProc.on('exit', (code, sig) => {
    log(`xray 退出 code=${code} sig=${sig}`);
    // 有限次重启，避免死循环刷日志
    if (cfdRestarts < 3) {
      setTimeout(startXray, 3000);
    }
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
  cfdProc = spawn(
    CFD_BIN,
    ['tunnel', '--no-autoupdate', '--edge-ip-version', 'auto', '--url', `http://127.0.0.1:${XRAY_PORT}`],
    { stdio: ['ignore', 'pipe', 'pipe'] }
  );

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

  cfdProc.on('exit', (code, sig) => {
    log(`cloudflared 退出 code=${code} sig=${sig}`);
    if (cfdRestarts >= 3) {
      log('cloudflared 连续失败 3 次，停止重试。请检查出口网络或改用固定隧道。');
      return;
    }
    cfdRestarts += 1;
    domain = '';
    setTimeout(startCloudflared, 5000 * cfdRestarts);
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
      JSON.stringify({ ready: Boolean(domain), domain, subPath: SUB_PATH, uuid: UUID }, null, 2)
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
