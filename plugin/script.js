const server = require('server');
const fs = require('node:fs');
const path = require('node:path');

function extractParams(a, b) {
  if (a && typeof a === 'object' && (a.action || a.lang)) return a;
  if (a && typeof a === 'object' && a.params && typeof a.params === 'object') return a.params;
  if (b && typeof b === 'object' && (b.action || b.lang)) return b;
  if (b && typeof b === 'object' && b.params && typeof b.params === 'object') return b.params;
  return a || {};
}

function isEnglish(params) {
  const lang = params && typeof params.lang === 'string' ? params.lang.trim().toLowerCase() : '';
  return lang === 'en' || lang.startsWith('en-') || lang.startsWith('en_');
}

function readSnapshot(en) {
  try {
    const data = JSON.parse(fs.readFileSync(path.join(__storageDir__, 'status.json'), 'utf8'));
    if (data.schema !== 1 || !Array.isArray(data.nodes)) throw new Error('Invalid snapshot');
    return data;
  } catch (_) {
    throw new Error(
      en
        ? 'Status snapshot is not ready yet. Please refresh later or check the collector service.'
        : '状态采集尚未就绪，请稍后刷新或检查采集服务。'
    );
  }
}

function load() {
  server.registerRPC('plugin:tailscaleStatus', (arg0, arg1) => {
    const params = extractParams(arg0, arg1);
    return readSnapshot(isEnglish(params));
  });

  server.registerRPC('plugin:tailscaleAction', (arg0, arg1) => {
    const payload = extractParams(arg0, arg1);
    const en = isEnglish(payload);
    if (!payload || typeof payload.action !== 'string' || !payload.action) {
      throw new Error(en ? 'Missing action parameter.' : '缺少操作指令参数 (action)。');
    }
    let token = '';
    try {
      token = fs.readFileSync(path.join(__storageDir__, '.control_token'), 'utf8').trim();
    } catch (_) {
      throw new Error(
        en
          ? 'Local control service is not ready (missing auth token). Please check komari-tailscale-collector.'
          : '本地控制服务尚未就绪（缺少认证凭据），请检查 komari-tailscale-collector 服务。'
      );
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
      throw new Error(
        en
          ? 'Unable to connect to local control service (' + endpoint + '). Please ensure the collector daemon is running.'
          : '无法连接本地管控服务 (' + endpoint + ')，请确认采集与控制守护进程正在运行。'
      );
    }
    let result = null;
    try {
      result = JSON.parse(xhr.responseText || '{}');
    } catch (_) {
      throw new Error(
        en
          ? 'Invalid response from control service (HTTP ' + xhr.status + ').'
          : '管控服务返回格式异常 (HTTP ' + xhr.status + ')。'
      );
    }
    if (xhr.status < 200 || xhr.status >= 300 || !result || result.ok !== true) {
      throw new Error(
        (result && result.error) ||
          (en ? 'Action failed (HTTP ' + xhr.status + ')' : '操作执行失败 (HTTP ' + xhr.status + ')')
      );
    }
    return result;
  });
}
