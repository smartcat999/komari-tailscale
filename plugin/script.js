const server = require('server');
const fs = require('node:fs');
const path = require('node:path');

function readSnapshot() {
  try {
    const data = JSON.parse(fs.readFileSync(path.join(__storageDir__, 'status.json'), 'utf8'));
    if (data.schema !== 1 || !Array.isArray(data.nodes)) throw new Error('Invalid snapshot');
    return data;
  } catch (_) {
    throw new Error('状态采集尚未就绪，请稍后刷新或检查采集服务。');
  }
}

function extractPayload(a, b) {
  if (a && typeof a === 'object' && a.action) return a;
  if (a && typeof a === 'object' && a.params && typeof a.params === 'object' && a.params.action) return a.params;
  if (b && typeof b === 'object' && b.action) return b;
  if (b && typeof b === 'object' && b.params && typeof b.params === 'object' && b.params.action) return b.params;
  return a || {};
}

function load() {
  server.registerRPC('plugin:tailscaleStatus', () => {
    return readSnapshot();
  });

  server.registerRPC('plugin:tailscaleAction', (arg0, arg1) => {
    const payload = extractPayload(arg0, arg1);
    if (!payload || typeof payload.action !== 'string' || !payload.action) {
      throw new Error('缺少操作指令参数 (action)。');
    }
    let token = '';
    try {
      token = fs.readFileSync(path.join(__storageDir__, '.control_token'), 'utf8').trim();
    } catch (_) {
      throw new Error('本地控制服务尚未就绪（缺少认证凭据），请检查 komari-tailscale-collector 服务。');
    }

    let endpoint = 'http://127.0.0.1:25779';
    try {
      const customEndpoint = fs.readFileSync(path.join(__storageDir__, '.control_endpoint'), 'utf8').trim();
      if (customEndpoint && /^https?:\/\/127\.0\.0\.1:\d+$/.test(customEndpoint)) {
        endpoint = customEndpoint;
      }
    } catch (_) {}

    const xhr = new XMLHttpRequest();
    xhr.open('POST', endpoint + '/action', false);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.setRequestHeader('X-Control-Token', token);
    xhr.send(JSON.stringify(payload));

    if (xhr.status === 0) {
      throw new Error('无法连接本地管控服务 (' + endpoint + ')，请确认采集与控制守护进程正在运行。');
    }
    let result = null;
    try {
      result = JSON.parse(xhr.responseText || '{}');
    } catch (_) {
      throw new Error('管控服务返回格式异常 (HTTP ' + xhr.status + ')。');
    }
    if (xhr.status < 200 || xhr.status >= 300 || !result || result.ok !== true) {
      throw new Error((result && result.error) || ('操作执行失败 (HTTP ' + xhr.status + ')'));
    }
    return result;
  });
}
