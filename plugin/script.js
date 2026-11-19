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

function normalizeLang(params) {
  const raw = params && typeof params.lang === 'string' ? params.lang.trim().toLowerCase().replace(/_/g, '-') : '';
  if (!raw) return 'zh';
  if (
    raw === 'zh-tw' ||
    raw === 'zh-hk' ||
    raw === 'zh-mo' ||
    raw === 'zh-hant' ||
    raw.startsWith('zh-tw-') ||
    raw.startsWith('zh-hk-') ||
    raw.startsWith('zh-mo-') ||
    raw.startsWith('zh-hant-')
  ) {
    return 'zh-TW';
  }
  if (raw === 'zh' || raw.startsWith('zh-')) return 'zh';
  if (raw === 'ja' || raw.startsWith('ja-')) return 'ja';
  if (raw === 'id' || raw === 'in' || raw.startsWith('id-') || raw.startsWith('in-')) return 'id';
  return 'en';
}

const MESSAGES = {
  zh: {
    notReady: '状态采集尚未就绪，请稍后刷新或检查采集服务。',
    missingAction: '缺少操作指令参数 (action)。',
    missingToken: '本地控制服务尚未就绪（缺少认证凭据），请检查 komari-tailscale-collector 服务。',
    connFailed: endpoint => '无法连接本地管控服务 (' + endpoint + ')，请确认采集与控制守护进程正在运行。',
    badResp: status => '管控服务返回格式异常 (HTTP ' + status + ')。',
    actFailed: status => '操作执行失败 (HTTP ' + status + ')',
  },
  'zh-TW': {
    notReady: '狀態採集尚未就緒，請稍後重新整理或檢查採集服務。',
    missingAction: '缺少操作指令參數 (action)。',
    missingToken: '本機控制服務尚未就緒（缺少驗證憑證），請檢查 komari-tailscale-collector 服務。',
    connFailed: endpoint => '無法連線本機管控服務 (' + endpoint + ')，請確認採集與控制常駐程式正在執行。',
    badResp: status => '管控服務回傳格式異常 (HTTP ' + status + ')。',
    actFailed: status => '操作執行失敗 (HTTP ' + status + ')',
  },
  en: {
    notReady: 'Status snapshot is not ready yet. Please refresh later or check the collector service.',
    missingAction: 'Missing action parameter.',
    missingToken: 'Local control service is not ready (missing auth token). Please check komari-tailscale-collector.',
    connFailed: endpoint => 'Unable to connect to local control service (' + endpoint + '). Please ensure the collector daemon is running.',
    badResp: status => 'Invalid response from control service (HTTP ' + status + ').',
    actFailed: status => 'Action failed (HTTP ' + status + ')',
  },
  ja: {
    notReady: '状態スナップショットがまだ準備できていません。しばらくしてから更新するか、コレクターサービスを確認してください。',
    missingAction: '操作パラメータ (action) が不足しています。',
    missingToken: 'ローカル制御サービスが未準備です（認証トークンが見つかりません）。komari-tailscale-collector サービスを確認してください。',
    connFailed: endpoint => 'ローカル制御サービス (' + endpoint + ') に接続できません。コレクターデーモンが起動しているか確認してください。',
    badResp: status => '制御サービスからの応答形式が不正です (HTTP ' + status + ')。',
    actFailed: status => '操作の実行に失敗しました (HTTP ' + status + ')',
  },
  id: {
    notReady: 'Snapshot status belum siap. Silakan muat ulang nanti atau periksa layanan kolektor.',
    missingAction: 'Parameter aksi (action) tidak ditemukan.',
    missingToken: 'Layanan kontrol lokal belum siap (token autentikasi tidak ditemukan). Periksa layanan komari-tailscale-collector.',
    connFailed: endpoint => 'Tidak dapat terhubung ke layanan kontrol lokal (' + endpoint + '). Pastikan daemon kolektor sedang berjalan.',
    badResp: status => 'Format respons layanan kontrol tidak valid (HTTP ' + status + ').',
    actFailed: status => 'Aksi gagal dijalankan (HTTP ' + status + ')',
  },
};

function msg(lang) {
  return MESSAGES[lang] || MESSAGES.en;
}

function readSnapshot(lang) {
  try {
    const data = JSON.parse(fs.readFileSync(path.join(__storageDir__, 'status.json'), 'utf8'));
    if (data.schema !== 1 || !Array.isArray(data.nodes)) throw new Error('Invalid snapshot');
    return data;
  } catch (_) {
    throw new Error(msg(lang).notReady);
  }
}

function load() {
  server.registerRPC('plugin:tailscaleStatus', (arg0, arg1) => {
    const params = extractParams(arg0, arg1);
    return readSnapshot(normalizeLang(params));
  });

  server.registerRPC('plugin:tailscaleAction', (arg0, arg1) => {
    const payload = extractParams(arg0, arg1);
    const lang = normalizeLang(payload);
    const m = msg(lang);
    if (!payload || typeof payload.action !== 'string' || !payload.action) {
      throw new Error(m.missingAction);
    }
    let token = '';
    try {
      token = fs.readFileSync(path.join(__storageDir__, '.control_token'), 'utf8').trim();
    } catch (_) {
      throw new Error(m.missingToken);
    }

    let endpoint = 'http://127.0.0.1:25779';
    try {
      const customEndpoint = fs.readFileSync(path.join(__storageDir__, '.control_endpoint'), 'utf8').trim();
      if (customEndpoint && /^https?:\/\/127\.0\.0\.1:\d+$/.test(customEndpoint)) {
        endpoint = customEndpoint;
      }
    } catch (_) {}

    const forwardPayload = Object.assign({}, payload, { lang });
    const xhr = new XMLHttpRequest();
    xhr.open('POST', endpoint + '/action', false);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.setRequestHeader('X-Control-Token', token);
    xhr.send(JSON.stringify(forwardPayload));

    if (xhr.status === 0) {
      throw new Error(m.connFailed(endpoint));
    }
    let result = null;
    try {
      result = JSON.parse(xhr.responseText || '{}');
    } catch (_) {
      throw new Error(m.badResp(xhr.status));
    }
    if (xhr.status < 200 || xhr.status >= 300 || !result || result.ok !== true) {
      throw new Error((result && result.error) || m.actFailed(xhr.status));
    }
    return result;
  });
}
