const fs = require("fs");
const path = require("path");
const os = require('os');
const axios = require("axios");
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const { execSync, spawn } = require('child_process');
const net = require('net');

// ==========================================
// 环境变量配置 (Appwrite 环境变量需在控制台设置)
// ==========================================
// 注意：FILE_PATH 强制指定为 /tmp/.npm，因为 Appwrite 只有 /tmp 可写
const FILE_PATH = '/tmp/.npm'; 

const UPLOAD_URL = process.env.UPLOAD_URL || '';      
const PROJECT_URL = process.env.PROJECT_URL || '';    
const AUTO_ACCESS = process.env.AUTO_ACCESS || false; 
const SUB_PATH = process.env.SUB_PATH || '123';       
const UUID = process.env.UUID || '973a7a99-dbc4-4300-b1f4-d38804e9f85a';  
const NEZHA_SERVER = process.env.NEZHA_SERVER || 'nezha.ylm52.dpdns.org:443';      
const NEZHA_PORT = process.env.NEZHA_PORT || '';           
const NEZHA_KEY = process.env.NEZHA_KEY || 'ricZCX8ODNyN0X4UlSRSnZ9l92zn4UDB';            
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || '';       
const ARGO_AUTH = process.env.ARGO_AUTH || '';           
const ARGO_PORT = process.env.ARGO_PORT || 8001;         
const TUIC_PORT = process.env.TUIC_PORT || 60000;           
const HY2_PORT = process.env.HY2_PORT || 27287;             
const REALITY_PORT = process.env.REALITY_PORT || 27247;     
const CFIP = process.env.CFIP || 'cf.877774.xyz';      
const CFPORT = process.env.CFPORT || 443;                
const NAME = process.env.NAME || 'appwrite';               
const CHAT_ID = process.env.CHAT_ID || '2117746804';                
const BOT_TOKEN = process.env.BOT_TOKEN || '5279043230:AAFI4qfyo0oP7HJ-39jLqjqq9Wh6OeWrTjw';                     
const ALLOW_UDP = String(process.env.ALLOW_UDP || 'true').toLowerCase() === 'true'; 

const FRP_IP = process.env.FRP_IP || '85.237.179.121';                 
const FRP_PORT = process.env.FRP_PORT || '27253';         
const FRP_TOKEN = process.env.FRP_TOKEN || '39497981';            

// 全局变量定义
let privateKey = '';
let publicKey = '';
let npmPath = path.join(FILE_PATH, 'npm');
let phpPath = path.join(FILE_PATH, 'php');
let webPath = path.join(FILE_PATH, 'web');
let botPath = path.join(FILE_PATH, 'bot');
let frpcPath = path.join(FILE_PATH, 'frpc');
let subPath = path.join(FILE_PATH, 'sub.txt');
let listPath = path.join(FILE_PATH, 'list.txt');
let bootLogPath = path.join(FILE_PATH, 'boot.log');
let configPath = path.join(FILE_PATH, 'config.json');

// ==========================================
// 工具函数定义 (保持在 handler 外部)
// ==========================================

function getSystemArchitecture() {
  const arch = os.arch();
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return 'arm';
  } else {
    return 'amd';
  }
}

function spawnDetached(binaryPath, argsArray, name) {
  try {
    const child = spawn(binaryPath, argsArray, {
      detached: true,
      stdio: 'ignore'
    });
    child.unref();
    console.log(`${name} is running`);
    return child;
  } catch (e) {
    console.error(`${name} running error: ${e}`);
    return null;
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function deleteNodes() {
  try {
    if (!UPLOAD_URL) return;
    if (!fs.existsSync(subPath)) return;
    let fileContent;
    try { fileContent = fs.readFileSync(subPath, 'utf-8'); } catch { return null; }
    const decoded = Buffer.from(fileContent, 'base64').toString('utf-8');
    const nodes = decoded.split('\n').filter(line => 
      /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line)
    );
    if (nodes.length === 0) return;
    return axios.post(`${UPLOAD_URL}/api/delete-nodes`, 
      JSON.stringify({ nodes }),
      { headers: { 'Content-Type': 'application/json' } }
    ).catch((error) => { return null; });
  } catch (err) { return null; }
}

function cleanupOldFiles() {
  const pathsToDelete = [ 'web', 'bot', 'npm', 'php', 'frpc', 'boot.log', 'list.txt'];
  pathsToDelete.forEach(file => {
    const filePath = path.join(FILE_PATH, file);
    try {
      if (fs.existsSync(filePath)) {
        const stat = fs.statSync(filePath);
        if (stat.isDirectory()) {
          fs.rmSync(filePath, { recursive: true, force: true });
        } else {
          fs.rmSync(filePath, { force: true });
        }
      }
    } catch {}
  });
}

function downloadFile(fileName, fileUrl, callback) {
  const filePath = path.join(FILE_PATH, fileName);
  const writer = fs.createWriteStream(filePath);
  axios({
    method: 'get',
    url: fileUrl,
    responseType: 'stream',
  })
  .then(response => {
    response.data.pipe(writer);
    writer.on('finish', () => {
      writer.close();
      console.log(`Download ${fileName} successfully`);
      callback(null, fileName);
    });
    writer.on('error', err => {
      fs.unlink(filePath, () => { });
      const errorMessage = `Download ${fileName} failed: ${err.message}`;
      console.error(errorMessage); 
      callback(errorMessage);
    });
  })
  .catch(err => {
    const errorMessage = `Download ${fileName} failed: ${err.message}`;
    console.error(errorMessage); 
    callback(errorMessage);
  });
}

function getFilesForArchitecture(architecture) {
  let baseFiles;
  if (architecture === 'arm') {
    baseFiles = [
      { fileName: "web", fileUrl: "https://arm64.ssss.nyc.mn/sb" },
      { fileName: "bot", fileUrl: "https://arm64.ssss.nyc.mn/2go" },
      { fileName: "frpc", fileUrl: "https://arm64.ssss.nyc.mn/frpc" }
    ];
  } else {
    baseFiles = [
      { fileName: "web", fileUrl: "https://amd64.ssss.nyc.mn/sb" },
      { fileName: "bot", fileUrl: "https://amd64.ssss.nyc.mn/2go" },
      { fileName: "frpc", fileUrl: "https://amd64.ssss.nyc.mn/frpc" }
    ];
  }
  if (NEZHA_SERVER && NEZHA_KEY) {
    if (NEZHA_PORT) {
      const npmUrl = architecture === 'arm' ? "https://arm64.ssss.nyc.mn/agent" : "https://amd64.ssss.nyc.mn/agent";
      baseFiles.unshift({ fileName: "npm", fileUrl: npmUrl });
    } else {
      const phpUrl = architecture === 'arm' ? "https://arm64.ssss.nyc.mn/v1" : "https://amd64.ssss.nyc.mn/v1";
      baseFiles.unshift({ fileName: "php", fileUrl: phpUrl });
    }
  }
  return baseFiles;
}

async function downloadFilesAndRun() {
  const architecture = getSystemArchitecture();
  const filesToDownload = getFilesForArchitecture(architecture);
  if (filesToDownload.length === 0) return;

  const downloadPromises = filesToDownload.map(fileInfo => {
    return new Promise((resolve, reject) => {
      downloadFile(fileInfo.fileName, fileInfo.fileUrl, (err, fileName) => {
        if (err) reject(err); else resolve(fileName);
      });
    });
  });

  try {
    await Promise.all(downloadPromises);
  } catch (err) {
    console.error('Error downloading files:', err);
    return;
  }

  function authorizeFiles(filePaths) {
    const newPermissions = 0o775;
    filePaths.forEach(relativeFilePath => {
      const absoluteFilePath = path.join(FILE_PATH, relativeFilePath);
      if (fs.existsSync(absoluteFilePath)) {
        fs.chmod(absoluteFilePath, newPermissions, (err) => {});
      }
    });
  }
  const filesToAuthorize = NEZHA_PORT ? ['./npm', './web', './bot', './frpc'] : ['./php', './web', './bot', './frpc'];
  authorizeFiles(filesToAuthorize);

  // 1. NEZHA Config
  if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
      const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
      const tlsPorts = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
      const nezhatls = tlsPorts.has(port) ? 'true' : 'false';
      const configYaml = `
client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 1
server: ${NEZHA_SERVER}
tls: ${nezhatls}
uuid: ${UUID}`;
      fs.writeFileSync(path.join(FILE_PATH, 'config.yaml'), configYaml);
    }
  }

  // 2. FRPC Config
  if (TUIC_PORT || HY2_PORT || REALITY_PORT) {
    if (FRP_IP && FRP_PORT && FRP_TOKEN) {
      const HOSTNAME = os.hostname();
      const configTaml = `
serverAddr = "${FRP_IP}"
serverPort = ${FRP_PORT}
loginFailExit = false
auth.method = "token"
auth.token = "${FRP_TOKEN}"
transport.heartbeatInterval = 10
transport.heartbeatTimeout = 30
transport.poolCount = 5

[[proxies]]
name = "${HOSTNAME}_hy2"
type = "udp"
localIP = "127.0.0.1"
localPort = ${HY2_PORT}
remotePort = ${HY2_PORT}

[[proxies]]
name = "${HOSTNAME}_tuic"
type = "udp"
localIP = "127.0.0.1"
localPort = ${TUIC_PORT}
remotePort = ${TUIC_PORT}

[[proxies]]
name = "${HOSTNAME}_reality"
type = "tcp"
localIP = "127.0.0.1"
localPort = ${REALITY_PORT}
remotePort = ${REALITY_PORT}`;
      fs.writeFileSync(path.join(FILE_PATH, 'frpc.toml'), configTaml);
    }
  }

  // 3. Reality Keys
  const keyFilePath = path.join(FILE_PATH, 'key.txt');
  if (!fs.existsSync(keyFilePath)) {
     try {
         // Appwrite 环境下生成 key 可能会慢或者失败，这里简单处理
         execSync(`${path.join(FILE_PATH, 'web')} generate reality-keypair > ${keyFilePath}`);
     } catch(e) { console.error("Key gen failed", e); }
  }
  
  if (fs.existsSync(keyFilePath)) {
      const content = fs.readFileSync(keyFilePath, 'utf8');
      const privateKeyMatch = content.match(/PrivateKey:\s*(.*)/);
      const publicKeyMatch = content.match(/PublicKey:\s*(.*)/);
      privateKey = privateKeyMatch ? privateKeyMatch[1] : '';
      publicKey = publicKeyMatch ? publicKeyMatch[1] : '';
  }

  // 4. Generate Certs
  try {
      execSync(`openssl ecparam -genkey -name prime256v1 -out "${path.join(FILE_PATH, 'private.key')}"`);
      execSync(`openssl req -new -x509 -days 3650 -key "${path.join(FILE_PATH, 'private.key')}" -out "${path.join(FILE_PATH, 'cert.pem')}" -subj "/CN=bing.com"`);
  } catch(e) { console.error("Cert gen failed", e); }

  // 5. Sing-box Config (web)
  const config = {
    "log": { "disabled": true, "level": "info", "timestamp": true },
    "dns": { "servers": [{ "address": "8.8.8.8", "address_resolver": "local" }, { "tag": "local", "address": "local" }] },
    "inbounds": [
      {
        "tag": "vmess-ws-in", "type": "vmess", "listen": "::", "listen_port": ARGO_PORT,
        "users": [{ "uuid": UUID }],
        "transport": { "type": "ws", "path": "/vmess-argo", "early_data_header_name": "Sec-WebSocket-Protocol" }
      },
      {
        "tag": "vless-in", "type": "vless", "listen": "::", "listen_port": REALITY_PORT,
        "users": [{ "uuid": UUID, "flow": "xtls-rprx-vision" }],
        "tls": { "enabled": true, "server_name": "www.iij.ad.jp", "reality": { "enabled": true, "handshake": { "server": "www.iij.ad.jp", "server_port": 443 }, "private_key": privateKey, "short_id": [""] } }
      },
      {
        "tag": "hysteria-in", "type": "hysteria2", "listen": "::", "listen_port": HY2_PORT,
        "users": [{ "password": UUID }],
        "masquerade": "https://bing.com",
        "tls": { "enabled": true, "alpn": ["h3"], "certificate_path": path.join(FILE_PATH, 'cert.pem'), "key_path": path.join(FILE_PATH, 'private.key') }
      },
      {
        "tag": "tuic-in", "type": "tuic", "listen": "::", "listen_port": TUIC_PORT,
        "users": [{ "uuid": UUID }],
        "congestion_control": "bbr",
        "tls": { "enabled": true, "alpn": ["h3"], "certificate_path": path.join(FILE_PATH, 'cert.pem'), "key_path": path.join(FILE_PATH, 'private.key') }
      }
    ],
    "outbounds": [{ "type": "direct", "tag": "direct" }]
  };
  fs.writeFileSync(path.join(FILE_PATH, 'config.json'), JSON.stringify(config, null, 2));

  // --- 启动进程 ---
  // Nezha
  if (NEZHA_SERVER && NEZHA_KEY) {
      if (NEZHA_PORT) {
          spawnDetached(path.join(FILE_PATH, 'npm'), ['-s', `${NEZHA_SERVER}:${NEZHA_PORT}`, '-p', NEZHA_KEY, ...(NEZHA_PORT==='443'?['--tls']:[])], 'npm');
      } else {
          spawnDetached(path.join(FILE_PATH, 'php'), ['-c', path.join(FILE_PATH, 'config.yaml')], 'php');
      }
  }
  // Frpc
  if (TUIC_PORT || HY2_PORT || REALITY_PORT) {
      if (FRP_IP && FRP_PORT && FRP_TOKEN) {
          spawnDetached(path.join(FILE_PATH, 'frpc'), ['-c', path.join(FILE_PATH, 'frpc.toml')], 'frpc');
      }
  }
  // Web (Sing-box)
  spawnDetached(path.join(FILE_PATH, 'web'), ['run', '-c', path.join(FILE_PATH, 'config.json')], 'web');
  
  // Bot (Argo)
  if (fs.existsSync(path.join(FILE_PATH, 'bot'))) {
      let botArgs = [];
      if (ARGO_AUTH && ARGO_AUTH.match(/TunnelSecret/)) {
           // Complex Tunnel logic omitted for brevity, fallback to basic
           botArgs = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2', 'run', '--token', ARGO_AUTH];
      } else {
           botArgs = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2', '--url', `http://localhost:${ARGO_PORT}`];
      }
      spawnDetached(path.join(FILE_PATH, 'bot'), botArgs, 'bot');
  }

  // 等待并生成订阅
  await sleep(3000);
  await extractDomains();
}

async function extractDomains() {
    // 简化版域名提取和生成 sub.txt
    // 在 Appwrite 中，argoDomain 可能还没生成函数就结束了，这里尽力而为
    let argoDomain = ARGO_DOMAIN || 'trycloudflare.com'; 
    // 读取日志获取真实域名逻辑省略，防止阻塞太久

    const vmessNode = `vmess://${Buffer.from(JSON.stringify({ v: '2', ps: `${NAME}`, add: CFIP, port: CFPORT, id: UUID, aid: '0', scy: 'none', net: 'ws', type: 'none', host: argoDomain, path: '/vmess-argo?ed=2048', tls: 'tls', sni: argoDomain, alpn: '' })).toString('base64')}`;
    let subTxt = vmessNode;
    
    // 写入文件
    fs.writeFileSync(subPath, Buffer.from(subTxt).toString('base64'));
    if (CHAT_ID && BOT_TOKEN) {
        // 尝试发送 TG
        try {
            await axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
                chat_id: CHAT_ID,
                text: `**Appwrite节点**\n\`\`\`${subTxt}\`\`\``,
                parse_mode: 'MarkdownV2'
            });
        } catch(e) {}
    }
}

// ==========================================
// APPWRITE 入口函数 (Module Exports)
// ==========================================
module.exports = async ({ req, res, log, error }) => {
  log("Function Triggered.");

  // 1. 创建目录
  if (!fs.existsSync(FILE_PATH)) {
    fs.mkdirSync(FILE_PATH);
    log("Created /tmp/.npm");
  }

  // 2. 路由：订阅处理
  if (req.path === '/' + SUB_PATH || req.path === '/sub') {
    if (fs.existsSync(subPath)) {
      const content = fs.readFileSync(subPath, 'utf-8');
      return res.send(content, 200, { 'Content-Type': 'text/plain; charset=utf-8' });
    } else {
      return res.send("Nodes initializing or not ready.", 202);
    }
  }

  // 3. 核心逻辑：启动下载和运行
  // 注意：如果是第一次运行，会进行下载。如果容器复用，则直接运行。
  try {
    // 检查是否已经有进程在运行不太容易，Appwrite 是无状态的。
    // 我们每次都尝试启动清理和重新下载逻辑，或者判断文件存在则跳过下载
    
    // 执行主逻辑
    await downloadFilesAndRun();
    
    // 运行到这里说明启动命令已下发
    log("Processes spawned.");

    // 返回成功信息
    return res.send("Appwrite Function Executed. Nodes spawned in background (will die when function timeouts). Check TG or /sub path.");

  } catch (err) {
    error(err.toString());
    return res.send("Error: " + err.toString(), 500);
  }
};
