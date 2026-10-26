/*!
 * 2FA 驗證器 — 前端核心邏輯 (v2.0.0)
 *
 * 本檔案以「瀏覽器全域腳本」與「Node CJS 模組」雙模式設計：
 * - 瀏覽器：由 index.html 以 <script src="/app.js" defer> 載入，boot() 於結尾啟動。
 * - Node：純函式（OTP、Base32、匯入解析）可透過 module.exports 供單元測試使用。
 *
 * 嚴禁使用 inline event handler（CSP script-src 'self'），所有事件於 boot 時繫結。
 */

/* ================================================================
 * 常數與狀態
 * ============================================================== */
'use strict';

var APP_VERSION = '2.0.0';

var PBKDF2_ITERATIONS = {
    V1_KEY_HASH: 50000,
    V1_DERIVE_KEY: 100000,
    V2: 600000
};
var CURRENT_VERSION = 2;

var STORAGE_KEYS = {
    SESSION: '2fa_session',
    SETTINGS: '2fa_settings',
    LOCKOUT: '2fa_lockout',
    OFFLINE_META: '2fa_offline_metadata'
};

var DEFAULT_SETTINGS = {
    theme: 'auto',            // auto | light | dark
    autoLockMinutes: 1440,    // 0 = 永不；預設 24 小時
    privacyMode: false,       // 遮罩驗證碼
    clearClipboard: false,    // 複製 60 秒後自動清除剪貼簿
    remember: true            // 預設記住登入狀態（localStorage）
};

var AUTO_LOCK_OPTIONS = [
    { value: 15, label: '15 分鐘' },
    { value: 60, label: '1 小時' },
    { value: 240, label: '4 小時' },
    { value: 720, label: '12 小時' },
    { value: 1440, label: '24 小時' },
    { value: 4320, label: '3 天' },
    { value: 10080, label: '7 天' },
    { value: 0, label: '永不' }
];

var SUBTLE_ALGO = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
var SUPPORTED_ALGOS = ['SHA1', 'SHA256', 'SHA512'];

var MAX_IMPORT_FILE_BYTES = 2 * 1024 * 1024;   // 匯入檔上限 2MB
var MAX_IMAGE_BYTES = 5 * 1024 * 1024;         // QR 圖片上限 5MB
var LOGIN_MAX_FAILS = 5;                        // 連續失敗幾次後鎖定
var CLIPBOARD_CLEAR_MS = 60000;                 // 剪貼簿自動清除延遲

// 執行期狀態
var masterKey = null;
var keys = [];
var currentKeyHash = null;
var currentSalt = null;
var updateInterval = null;
var autoLockInterval = null;
var lockoutInterval = null;
var settings = cloneObj(DEFAULT_SETTINGS);

// QR 掃描狀態
var qrStream = null;
var qrScanInterval = null;

// 渲染狀態
var searchFilter = '';
var cachedCodes = new Map();       // id -> code 字串
var lastRemainingMap = new Map();  // id -> 上一秒的剩餘秒數（偵測週期翻轉）
var privacyRevealed = new Set();   // 隱私模式下被單顆顯示的 id
var pendingImport = null;          // 匯入預覽資料
var pendingConfirm = null;         // confirmModal resolver
var clipboardTimers = [];          // 剪貼簿自動清除計時器
var dragArmed = false;             // 拖曳把手已按下
var dragSrcId = null;

/* ================================================================
 * 小型工具（無 DOM 依賴）
 * ============================================================== */
function cloneObj(o) { return JSON.parse(JSON.stringify(o)); }

function generateId() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    return Date.now() + '-' + Math.random().toString(36).substring(2, 11);
}

function toInt(v, def) {
    var n = parseInt(v, 10);
    return isNaN(n) ? def : n;
}

function clampInt(v, lo, hi, def) {
    var n = toInt(v, def);
    if (n < lo || n > hi) return def;
    return n;
}

/** 清理 Base32 字串：大寫、去空白/連字號/補位符 */
function cleanSecret(s) {
    return String(s || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
}

/** Base32 字串是否合法（至少 8 字元 ≈ 5 bytes） */
function isValidSecret(s) {
    var c = cleanSecret(s);
    return c.length >= 8 && /^[A-Z2-7]+$/.test(c);
}

/** 正規化演算法名稱 → SHA1 / SHA256 / SHA512 / MD5（不支援）/ null（未知） */
function normalizeAlgo(a) {
    if (!a) return 'SHA1';
    var s = String(a).toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (s === 'SHA1' || s === 'SHA' || s === 'HMACSHA1') return 'SHA1';
    if (s === 'SHA256' || s === 'HMACSHA256') return 'SHA256';
    if (s === 'SHA512' || s === 'HMACSHA512') return 'SHA512';
    if (s === 'MD5' || s === 'HMACMD5') return 'MD5';
    return null;
}

/** 從 "issuer:account" 形式的 label 取出 account 部分 */
function accountFromLabel(label) {
    var l = String(label || '').trim();
    if (!l) return '';
    var i = l.indexOf(':');
    return i >= 0 ? l.slice(i + 1).trim() : l;
}

/** 位元組陣列 → Base32 字串（FreeOTP 等以 int[] 存 secret） */
function bytesToBase32(bytes) {
    var CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    var bits = 0, value = 0, out = '';
    for (var i = 0; i < bytes.length; i++) {
        value = (value << 8) | (bytes[i] & 0xff);
        bits += 8;
        while (bits >= 5) {
            out += CHARS[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) out += CHARS[(value << (5 - bits)) & 31];
    return out;
}

function base64ToBytes(b64) {
    var norm = String(b64).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
    var bin = atob(norm);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function safeDecodeURIComponent(s) {
    try { return decodeURIComponent(s); } catch (e) { return s; }
}

/* ================================================================
 * Base32 解碼
 * ============================================================== */
var BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(str) {
    str = cleanSecret(str);
    var bytes = [];
    var bits = 0, value = 0;
    for (var i = 0; i < str.length; i++) {
        var val = BASE32_CHARS.indexOf(str[i]);
        if (val === -1) continue;
        value = (value << 5) | val;
        bits += 5;
        if (bits >= 8) {
            bytes.push((value >>> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    return new Uint8Array(bytes);
}

/* ================================================================
 * OTP 核心：TOTP / HOTP（支援自訂位數、週期、演算法）
 * ============================================================== */
async function hotpCore(secretBytes, counter, opts) {
    var digits = (opts && opts.digits) || 6;
    var algoName = SUBTLE_ALGO[(opts && opts.algorithm) || 'SHA1'] || 'SHA-1';

    var counterBytes = new Uint8Array(8);
    var temp = counter;
    for (var i = 7; i >= 0; i--) {
        counterBytes[i] = temp & 0xff;
        temp = Math.floor(temp / 256);
    }

    var key = await crypto.subtle.importKey(
        'raw', secretBytes, { name: 'HMAC', hash: algoName }, false, ['sign']
    );
    var signature = await crypto.subtle.sign('HMAC', key, counterBytes);
    var hash = new Uint8Array(signature);

    var offset = hash[hash.length - 1] & 0x0f;
    var binary =
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);

    var mod = Math.pow(10, digits);
    return (binary % mod).toString().padStart(digits, '0');
}

/** 產生 TOTP 驗證碼。opts: {digits, period, algorithm} */
async function generateTOTP(secret, opts, time) {
    opts = opts || {};
    var period = opts.period || 30;
    var t = (time === undefined ? Date.now() : time);
    var counter = Math.floor(t / 1000 / period);
    return hotpCore(base32Decode(secret), counter, opts);
}

/** 產生 HOTP 驗證碼。opts: {digits, algorithm} */
async function generateHOTP(secret, counter, opts) {
    return hotpCore(base32Decode(secret), toInt(counter, 0), opts || {});
}

/** 依金鑰物件的參數產生驗證碼 */
async function generateOTP(keyObj, time) {
    var opts = keyOpts(keyObj);
    if (keyObj.type === 'hotp') {
        return generateHOTP(keyObj.secret, keyObj.counter || 0, opts);
    }
    return generateTOTP(keyObj.secret, opts, time);
}

/** 取出金鑰的 OTP 參數（含預設值） */
function keyOpts(k) {
    return {
        digits: k.digits || 6,
        period: k.period || 30,
        algorithm: k.algorithm || 'SHA1'
    };
}

/** 正規化金鑰物件：補 id、清 secret、僅儲存非預設參數（與舊資料相容） */
function normalizeKey(k) {
    var type = String(k.type || 'totp').toLowerCase() === 'hotp' ? 'hotp' : 'totp';
    var key = {
        id: k.id || generateId(),
        name: String(k.name || '未命名').trim().slice(0, 64) || '未命名',
        secret: cleanSecret(k.secret)
    };
    if (type === 'hotp') key.type = 'hotp';
    var digits = clampInt(k.digits, 6, 10, 6);
    if (digits !== 6) key.digits = digits;
    if (type === 'totp') {
        var period = clampInt(k.period, 5, 600, 30);
        if (period !== 30) key.period = period;
    }
    var algo = normalizeAlgo(k.algorithm);
    if (algo && algo !== 'SHA1' && SUPPORTED_ALGOS.indexOf(algo) !== -1) key.algorithm = algo;
    if (type === 'hotp') key.counter = Math.max(0, toInt(k.counter, 0));
    if (k.account) key.account = String(k.account).trim().slice(0, 128);
    if (k.issuer) key.issuer = String(k.issuer).trim().slice(0, 64);
    return key;
}

/* ================================================================
 * otpauth:// URI 解析（TOTP + HOTP，完整參數）
 * ============================================================== */
function parseOtpauthUri(uri) {
    if (!uri) return null;
    var m = String(uri).trim().match(/^otpauth:\/\/(totp|hotp)\/([^\s]*)$/i);
    if (!m) return null;
    var type = m[1].toLowerCase();
    var rest = m[2];

    var label = '', query = '';
    var qi = rest.indexOf('?');
    if (qi >= 0) { label = rest.slice(0, qi); query = rest.slice(qi + 1); }
    else { label = rest; }

    var params;
    try { params = new URLSearchParams(query); } catch (e) { return null; }

    var secret = params.get('secret');
    if (!secret || !cleanSecret(secret)) return null;

    label = safeDecodeURIComponent(label.replace(/\+/g, ' '));
    var issuerParam = params.get('issuer');
    var prefix = '', account = label;
    var ci = label.indexOf(':');
    if (ci >= 0) {
        prefix = label.slice(0, ci).trim();
        account = label.slice(ci + 1).trim();
    }
    var name = (issuerParam || prefix || account || label || '').trim();

    var algo = normalizeAlgo(params.get('algorithm'));
    var entry = {
        name: name || '未命名',
        account: account && account !== name ? account : '',
        issuer: (issuerParam || prefix || '').trim(),
        secret: cleanSecret(secret),
        type: type,
        digits: clampInt(params.get('digits'), 6, 10, 6),
        algorithm: algo && algo !== 'MD5' ? algo : null,
        period: type === 'totp' ? clampInt(params.get('period'), 5, 600, 30) : 30,
        counter: type === 'hotp' ? Math.max(0, toInt(params.get('counter'), 0)) : 0
    };
    if (algo === 'MD5') entry._invalidReason = '不支援 MD5 演算法';
    return entry;
}

/** 由金鑰物件組回 otpauth:// URI（供匯出） */
function buildOtpauthUri(k) {
    var opts = keyOpts(k);
    var isHOTP = k.type === 'hotp';
    var label = k.issuer
        ? encodeURIComponent(k.issuer) + ':' + encodeURIComponent(k.account || k.name)
        : encodeURIComponent(k.name);
    var p = new URLSearchParams();
    p.set('secret', k.secret);
    if (k.issuer) p.set('issuer', k.issuer);
    if (opts.algorithm !== 'SHA1') p.set('algorithm', opts.algorithm);
    if (opts.digits !== 6) p.set('digits', String(opts.digits));
    if (isHOTP) p.set('counter', String(k.counter || 0));
    else if (opts.period !== 30) p.set('period', String(opts.period));
    return 'otpauth://' + (isHOTP ? 'hotp' : 'totp') + '/' + label + '?' + p.toString();
}

/* ================================================================
 * Google Authenticator 遷移資料（otpauth-migration:// protobuf）解析
 * ============================================================== */
function pbReadVarint(buf, pos) {
    var result = 0, shift = 1, p = pos;
    while (p < buf.length) {
        var b = buf[p++];
        result += (b & 0x7f) * shift;
        if ((b & 0x80) === 0) return { value: result, pos: p };
        shift *= 128;
        if (shift > Math.pow(2, 53)) break; // 防溢位
    }
    return null;
}

function pbReadFields(buf) {
    var fields = [];
    var pos = 0;
    while (pos < buf.length) {
        var kv = pbReadVarint(buf, pos);
        if (!kv) break;
        pos = kv.pos;
        var num = Math.floor(kv.value / 8), wire = kv.value % 8;
        if (wire === 0) {
            var v = pbReadVarint(buf, pos);
            if (!v) break;
            pos = v.pos;
            fields.push({ num: num, wire: 0, value: v.value });
        } else if (wire === 2) {
            var len = pbReadVarint(buf, pos);
            if (!len || pos + len.value > buf.length) break;
            pos = len.pos;
            fields.push({ num: num, wire: 2, bytes: buf.slice(pos, pos + len.value) });
            pos += len.value;
        } else if (wire === 5) { pos += 4; }
        else if (wire === 1) { pos += 8; }
        else break;
    }
    return fields;
}

/** 解析 otpauth-migration://offline?data=BASE64 → 項目陣列 */
function decodeMigrationPayload(uri) {
    var m = String(uri).match(/[?&]data=([^&\s]+)/);
    if (!m) return [];
    var bytes;
    try { bytes = base64ToBytes(safeDecodeURIComponent(m[1])); } catch (e) { return []; }

    var ALGO_MAP = { 0: 'SHA1', 1: 'SHA1', 2: 'SHA256', 3: 'SHA512', 4: 'MD5' };
    var DIGITS_MAP = { 0: 6, 1: 6, 2: 8 };
    var TYPE_MAP = { 0: 'totp', 1: 'hotp', 2: 'totp' };

    var out = [];
    var topFields = pbReadFields(bytes);
    for (var i = 0; i < topFields.length; i++) {
        var f = topFields[i];
        if (f.num !== 1 || f.wire !== 2) continue; // OtpParameters
        var sub = pbReadFields(f.bytes);
        var get = function (n, w) {
            for (var j = 0; j < sub.length; j++) if (sub[j].num === n && sub[j].wire === w) return sub[j];
            return null;
        };
        var secretF = get(1, 2);
        if (!secretF || !secretF.bytes.length) continue;
        var nameF = get(2, 2), issuerF = get(3, 2);
        var algoF = get(4, 0), digitsF = get(5, 0), typeF = get(6, 0), counterF = get(7, 0);

        var name = nameF ? new TextDecoder().decode(nameF.bytes) : '';
        var issuer = issuerF ? new TextDecoder().decode(issuerF.bytes) : '';
        // GA 的 name 常為 "issuer:account" 或 "account"
        var account = name;
        if (name.indexOf(':') >= 0) account = name.slice(name.indexOf(':') + 1);
        var algo = ALGO_MAP[algoF ? algoF.value : 0] || 'SHA1';
        var entry = {
            name: (issuer || name || '未命名').trim(),
            account: account && account !== issuer ? account.trim() : '',
            issuer: issuer.trim(),
            secret: bytesToBase32(secretF.bytes),
            type: TYPE_MAP[typeF ? typeF.value : 0] || 'totp',
            digits: DIGITS_MAP[digitsF ? digitsF.value : 0] || 6,
            algorithm: algo,
            period: 30,
            counter: counterF ? counterF.value : 0
        };
        if (algo === 'MD5') entry._invalidReason = '不支援 MD5 演算法';
        out.push(entry);
    }
    return out;
}

/* ================================================================
 * 萬用匯入解析器
 * 支援：本應用 JSON v1/v2、Aegis（未加密）、2FAS（未加密）、Ente、
 *       Bitwarden、FreeOTP/FreeOTP+、Raivo、OTP Auth (iOS)、
 *       otpauth:// URI 清單（JSON 陣列或純文字）、
 *       Google Authenticator 遷移資料（otpauth-migration://）
 * ============================================================== */
function newImportResult(format) {
    return { format: format || null, entries: [], encrypted: false, error: null };
}

/** 把一個來源項目加入結果（統一驗證與正規化） */
function pushImportEntry(res, raw) {
    var name = String(raw.name || raw.issuer || raw.account || '未命名').trim().slice(0, 64) || '未命名';
    var secret = raw.secret;
    if (Array.isArray(secret) || secret instanceof Uint8Array) {
        secret = bytesToBase32(secret); // FreeOTP int[] 形式
    }
    secret = cleanSecret(secret);
    var type = String(raw.type || 'totp').toLowerCase() === 'hotp' ? 'hotp' : 'totp';
    var algo = normalizeAlgo(raw.algorithm || raw.algo);
    var entry = {
        name: name,
        account: raw.account ? String(raw.account).trim().slice(0, 128) : '',
        issuer: raw.issuer ? String(raw.issuer).trim().slice(0, 64) : '',
        secret: secret,
        type: type,
        digits: clampInt(raw.digits, 6, 10, 6),
        period: type === 'totp' ? clampInt(raw.period, 5, 600, 30) : 30,
        algorithm: (algo && SUPPORTED_ALGOS.indexOf(algo) !== -1) ? algo : null,
        counter: type === 'hotp' ? Math.max(0, toInt(raw.counter, 0)) : 0,
        invalidReason: raw._invalidReason || null
    };
    if (!entry.secret || entry.secret.length < 8) {
        entry.invalidReason = entry.invalidReason || '金鑰無效或過短';
    }
    if (algo === 'MD5') {
        entry.invalidReason = '不支援 MD5 演算法';
    }
    if (algo === null && (raw.algorithm || raw.algo)) {
        entry.algorithm = null; // 未知演算法 → 以 SHA1 處理
    }
    res.entries.push(entry);
}

/** 從任意物件推導項目（通用欄位名） */
function pushFromGenericObject(res, item) {
    if (!item || typeof item !== 'object') return;
    var uri = item.uri || item.payload || item.otpauth || item.url;
    if (typeof uri === 'string' && uri.indexOf('otpauth://') === 0) {
        var parsedUri = parseOtpauthUri(uri);
        if (parsedUri) {
            // 保留原有 name（若來源有自訂名稱）
            if (item.name && parsedUri.name !== item.name) parsedUri.name = String(item.name).trim().slice(0, 64);
            pushImportEntry(res, parsedUri);
            return;
        }
    }
    var otp = item.otp || item.info || item.login || item;
    var secret = otp.secret || otp.totp || item.secret || item.key || item.token;
    if (!secret) return;
    if (typeof secret === 'string' && secret.indexOf('otpauth://') === 0) {
        var parsed2 = parseOtpauthUri(secret);
        if (parsed2) {
            if (item.name) parsed2.name = String(item.name).trim().slice(0, 64);
            pushImportEntry(res, parsed2);
            return;
        }
    }
    var typeRaw = String(item.type || otp.type || otp.tokenType || item.tokenType || 'totp').toUpperCase();
    pushImportEntry(res, {
        name: item.name || item.title || item.issuer || otp.issuer || accountFromLabel(item.label || otp.label) || item.account || otp.account || '',
        account: item.account || otp.account || accountFromLabel(item.label || otp.label) || '',
        issuer: item.issuer || otp.issuer || '',
        secret: secret,
        type: typeRaw.indexOf('HOTP') === 0 ? 'hotp' : 'totp',
        digits: otp.digits || item.digits || otp.digitCount,
        period: otp.period || item.period || item.timer || otp.timer,
        algorithm: otp.algorithm || otp.algo || item.algorithm || item.algo,
        counter: (otp.counter !== undefined ? otp.counter : item.counter)
    });
}

/** 解析 JSON 資料（各驗證器格式偵測） */
function parseJsonImport(data, res) {
    if (!data || typeof data !== 'object') return false;

    // ---- 陣列：Raivo / FreeOTP / URI 字串陣列 ----
    if (Array.isArray(data)) {
        res.format = 'list';
        for (var i = 0; i < data.length; i++) {
            var it = data[i];
            if (typeof it === 'string') {
                if (it.indexOf('otpauth://') === 0) {
                    var pu = parseOtpauthUri(it);
                    if (pu) pushImportEntry(res, pu);
                } else if (it.indexOf('otpauth-migration://') === 0) {
                    var mig = decodeMigrationPayload(it);
                    for (var mi = 0; mi < mig.length; mi++) pushImportEntry(res, mig[mi]);
                    res.format = 'google';
                }
            } else {
                pushFromGenericObject(res, it);
            }
        }
        return true;
    }

    // ---- Aegis ----
    if ((data.db !== undefined && data.header !== undefined) || (data.db && typeof data.db === 'object' && Array.isArray(data.db.entries))) {
        res.format = 'aegis';
        if (data.header && Array.isArray(data.header.slots) && data.header.slots.length > 0) {
            res.encrypted = true;
            return true;
        }
        var aegisEntries = (data.db && Array.isArray(data.db.entries)) ? data.db.entries : [];
        for (var a = 0; a < aegisEntries.length; a++) {
            var e = aegisEntries[a];
            if (!e || typeof e !== 'object') continue;
            var etype = String(e.type || '').toLowerCase();
            if (etype !== 'totp' && etype !== 'hotp') {
                // steam 等其他類型不支援 → 顯示為無效項目（透明化，而非默默跳過）
                pushImportEntry(res, {
                    name: e.issuer || e.name,
                    secret: e.info ? e.info.secret : null,
                    _invalidReason: '不支援的類型（' + (etype || '未知') + '）'
                });
                continue;
            }
            pushImportEntry(res, {
                name: e.issuer || e.name,
                account: (e.issuer && e.name && e.name !== e.issuer) ? e.name : '',
                issuer: e.issuer || '',
                secret: e.info ? e.info.secret : null,
                type: etype,
                digits: e.info ? e.info.digits : 6,
                period: e.info ? e.info.period : 30,
                algorithm: e.info ? (e.info.algo || e.info.algorithm) : 'SHA1',
                counter: e.info ? e.info.counter : 0
            });
        }
        return true;
    }

    // ---- 2FAS ----
    if (data.app === '2fas' || (Array.isArray(data.services) && (data.backupVersion !== undefined || (data.services.length > 0 && data.services[0] && (data.services[0].otp !== undefined || data.services[0].key !== undefined))))) {
        res.format = '2fas';
        if (data.encryption || (data.services || []).some(function (s) { return s && (s.encrypted || (s.data && !s.otp)); })) {
            res.encrypted = true;
            return true;
        }
        var services = Array.isArray(data.services) ? data.services : [];
        for (var s = 0; s < services.length; s++) {
            var svc = services[s];
            if (!svc) continue;
            var otp = svc.otp || {};
            var tt = String(otp.tokenType || otp.type || svc.type || 'TOTP').toUpperCase();
            pushImportEntry(res, {
                name: otp.issuer || svc.name || accountFromLabel(otp.label) || otp.account || '',
                account: otp.account || accountFromLabel(otp.label) || '',
                issuer: otp.issuer || '',
                secret: otp.secret || svc.secret,
                type: tt.indexOf('HOTP') === 0 ? 'hotp' : 'totp',
                digits: otp.digits,
                period: otp.period,
                algorithm: otp.algorithm,
                counter: otp.counter !== undefined ? otp.counter : svc.counter
            });
        }
        return true;
    }

    // ---- Ente Auth ----
    if (Array.isArray(data.items) && data.items.length > 0 && data.items.every(function (x) { return x && typeof x.payload === 'string'; })) {
        res.format = 'ente';
        for (var en = 0; en < data.items.length; en++) {
            var ent = data.items[en];
            if (ent.isDeleted) continue;
            if (ent.payload.indexOf('otpauth://') === 0) {
                var pe = parseOtpauthUri(ent.payload);
                if (pe) pushImportEntry(res, pe);
            } else if (ent.payload.indexOf('otpauth-migration://') === 0) {
                var mige = decodeMigrationPayload(ent.payload);
                for (var mg = 0; mg < mige.length; mg++) pushImportEntry(res, mige[mg]);
            }
        }
        return true;
    }

    // ---- Bitwarden ----
    if (Array.isArray(data.items) && (data.encrypted !== undefined || data.folders !== undefined ||
        (data.items.length > 0 && data.items[0] && data.items[0].login !== undefined))) {
        res.format = 'bitwarden';
        if (data.encrypted === true) { res.encrypted = true; return true; }
        for (var b = 0; b < data.items.length; b++) {
            var bw = data.items[b];
            if (!bw || !bw.login || !bw.login.totp) continue;
            var totp = String(bw.login.totp);
            if (totp.indexOf('otpauth://') === 0) {
                var pb = parseOtpauthUri(totp);
                if (pb) {
                    if (bw.name) pb.name = String(bw.name).trim().slice(0, 64);
                    pushImportEntry(res, pb);
                }
            } else if (isValidSecret(totp)) {
                pushImportEntry(res, { name: bw.name || '', secret: totp });
            }
        }
        return true;
    }

    // ---- FreeOTP / FreeOTP+ ----
    if (Array.isArray(data.tokens)) {
        res.format = 'freeotp';
        for (var f = 0; f < data.tokens.length; f++) {
            var tk = data.tokens[f];
            if (!tk) continue;
            pushImportEntry(res, {
                name: tk.issuer || tk.label || tk.account || '',
                account: tk.account || tk.label || '',
                issuer: tk.issuer || '',
                secret: tk.secret,
                type: String(tk.type || 'totp').toLowerCase(),
                digits: tk.digits,
                period: tk.period,
                algorithm: tk.algo || tk.algorithm,
                counter: tk.counter
            });
        }
        return true;
    }

    // ---- OTP Auth (iOS) ----
    if (Array.isArray(data.entries) && (data.source !== undefined || (data.entries.length > 0 && data.entries[0] && data.entries[0].uri !== undefined))) {
        res.format = 'otpauth';
        for (var oa = 0; oa < data.entries.length; oa++) {
            pushFromGenericObject(res, data.entries[oa]);
        }
        return true;
    }

    // ---- 本應用 JSON v1/v2 / 通用 keys 陣列 ----
    if (Array.isArray(data.keys)) {
        res.format = data.app === '2fa-authenticator' || data.version ? 'own' : 'generic';
        for (var k = 0; k < data.keys.length; k++) {
            pushFromGenericObject(res, data.keys[k]);
        }
        return true;
    }

    return false;
}

/** 純文字 URI 清單解析（每行一個 otpauth:// 或 otpauth-migration://） */
function parseUriListText(text, res) {
    var lines = String(text).split(/\r?\n/);
    var found = 0;
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim();
        if (!line) continue;
        if (line.indexOf('otpauth-migration://') === 0) {
            var mig = decodeMigrationPayload(line);
            for (var m = 0; m < mig.length; m++) pushImportEntry(res, mig[m]);
            res.format = 'google';
            found += mig.length;
        } else if (line.indexOf('otpauth://') === 0) {
            var pu = parseOtpauthUri(line);
            if (pu) { pushImportEntry(res, pu); res.format = res.format || 'uris'; found++; }
        }
    }
    return found > 0;
}

/** 最終兜底：從任意文字中正則掃出所有 otpauth URI */
function sweepOtpauthUris(text, res) {
    var re = /otpauth:\/\/(?:totp|hotp)\/[^\s"',<>)\]]+/gi;
    var matches = String(text).match(re);
    if (!matches || !matches.length) return false;
    var seen = new Set();
    for (var i = 0; i < matches.length; i++) {
        var uri = matches[i];
        if (seen.has(uri)) continue;
        seen.add(uri);
        var pu = parseOtpauthUri(uri);
        if (pu) { pushImportEntry(res, pu); }
    }
    res.format = res.format || 'uris';
    return res.entries.length > 0;
}

/**
 * 解析匯入內容。回傳 {format, entries, encrypted, error}
 * error 可能值：'empty' | 'too-large' | 'encrypted' | 'unsupported' | 'parse'
 */
function parseImportContent(text) {
    var res = newImportResult();
    var trimmed = String(text || '').trim();
    if (!trimmed) { res.error = 'empty'; return res; }

    // 1) JSON
    if (trimmed[0] === '{' || trimmed[0] === '[') {
        try {
            var data = JSON.parse(trimmed);
            var handled = parseJsonImport(data, res);
            if (res.encrypted) { res.error = 'encrypted'; return res; }
            if (handled && res.entries.length > 0) { dedupeImportEntries(res); return res; }
            if (handled && res.entries.length === 0) {
                // 格式認識但無有效項目（如 Bitwarden 無 totp 項目）
                res.error = 'no-keys';
                return res;
            }
        } catch (e) {
            // JSON 解析失敗 → 往下走 URI 解析
        }
    }

    // 2) 純文字 URI 清單（含 otpauth-migration）
    res = newImportResult();
    if (parseUriListText(trimmed, res)) { dedupeImportEntries(res); return res; }

    // 3) 兜底掃描
    res = newImportResult();
    if (sweepOtpauthUris(trimmed, res)) { dedupeImportEntries(res); return res; }

    res.error = 'unsupported';
    return res;
}

/** 去除檔案內重複項目（secret + type 相同；無效項目保留供顯示，不去重） */
function dedupeImportEntries(res) {
    var seen = new Set();
    res.entries = res.entries.filter(function (e) {
        if (e.invalidReason) return true;
        var sig = e.secret + '|' + e.type;
        if (seen.has(sig)) return false;
        seen.add(sig);
        return true;
    });
}

/** 比對現有金鑰，標記重複項目 */
function markImportDuplicates(entries, existingKeys) {
    var names = new Set(existingKeys.map(function (k) { return k.name; }));
    var secrets = new Set(existingKeys.map(function (k) { return cleanSecret(k.secret) + '|' + (k.type === 'hotp' ? 'hotp' : 'totp'); }));
    return entries.map(function (e) {
        var dup = false;
        if (!e.invalidReason) {
            if (names.has(e.name) || secrets.has(e.secret + '|' + e.type)) dup = true;
        }
        return Object.assign({}, e, { duplicate: dup });
    });
}

/* ================================================================
 * 加密 / 金鑰派生（與既有雲端資料完全相容，勿改參數）
 * ============================================================== */
async function deriveKeyHash(password, iterations) {
    iterations = iterations || PBKDF2_ITERATIONS.V2;
    var enc = new TextEncoder();
    var fixedSalt = enc.encode('2fa-sync-v1-key-hash');
    var keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: fixedSalt, iterations: iterations, hash: 'SHA-256' },
        keyMaterial, 256
    );
    return Array.from(new Uint8Array(bits)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
}

function generateSalt() {
    var salt = crypto.getRandomValues(new Uint8Array(16));
    return btoa(String.fromCharCode.apply(null, salt));
}

function decodeSalt(saltStr) {
    return Uint8Array.from(atob(saltStr), function (c) { return c.charCodeAt(0); });
}

async function deriveKey(password, salt, iterations) {
    iterations = iterations || PBKDF2_ITERATIONS.V2;
    var enc = new TextEncoder();
    var keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true, ['encrypt', 'decrypt']
    );
}

async function exportKeyB64(key) {
    var exported = await crypto.subtle.exportKey('raw', key);
    return btoa(String.fromCharCode.apply(null, new Uint8Array(exported)));
}

async function importKeyFromB64(keyStr) {
    var keyData = Uint8Array.from(atob(keyStr), function (c) { return c.charCodeAt(0); });
    return crypto.subtle.importKey('raw', keyData, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

async function encrypt(data, key) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var enc = new TextEncoder();
    var encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(JSON.stringify(data)));
    var combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    return btoa(String.fromCharCode.apply(null, combined));
}

async function decrypt(encryptedData, key) {
    var combined = Uint8Array.from(atob(encryptedData), function (c) { return c.charCodeAt(0); });
    var iv = combined.slice(0, 12);
    var data = combined.slice(12);
    var decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, data);
    return JSON.parse(new TextDecoder().decode(decrypted));
}

/* ================================================================
 * 設定（localStorage）
 * ============================================================== */
function loadSettings() {
    try {
        var raw = localStorage.getItem(STORAGE_KEYS.SETTINGS);
        if (raw) {
            var parsed = JSON.parse(raw);
            settings = Object.assign(cloneObj(DEFAULT_SETTINGS), parsed);
        }
    } catch (e) {
        settings = cloneObj(DEFAULT_SETTINGS);
    }
    if (AUTO_LOCK_OPTIONS.every(function (o) { return o.value !== settings.autoLockMinutes; })) {
        settings.autoLockMinutes = DEFAULT_SETTINGS.autoLockMinutes;
    }
    return settings;
}

function saveSettings() {
    try { localStorage.setItem(STORAGE_KEYS.SETTINGS, JSON.stringify(settings)); } catch (e) { /* 忽略 */ }
}

function updateSetting(key, value) {
    settings[key] = value;
    saveSettings();
}

/* ================================================================
 * 工作階段（記住登入 + 閒置自動鎖定）
 *
 * remember = true  → localStorage（關閉瀏覽器後仍保留，到期自動鎖定）
 * remember = false → sessionStorage（僅本次分頁有效）
 * ============================================================== */
function sessionExpiryMs() {
    if (!settings.autoLockMinutes || settings.autoLockMinutes <= 0) return null; // 永不
    return Date.now() + settings.autoLockMinutes * 60000;
}

function saveSession(keyStr, keyHash, salt, remember) {
    var payload = {
        v: 2,
        keyStr: keyStr,
        keyHash: keyHash,
        salt: salt,
        remember: !!remember,
        expiresAt: sessionExpiryMs()
    };
    try {
        // 先清掉另一邊的舊工作階段，避免殘留
        localStorage.removeItem(STORAGE_KEYS.SESSION);
        sessionStorage.removeItem(STORAGE_KEYS.SESSION);
        if (remember) localStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(payload));
        else sessionStorage.setItem(STORAGE_KEYS.SESSION, JSON.stringify(payload));
    } catch (e) {
        console.error('saveSession failed:', e);
    }
}

function loadSession() {
    var raw = null;
    try {
        raw = sessionStorage.getItem(STORAGE_KEYS.SESSION) || localStorage.getItem(STORAGE_KEYS.SESSION);
    } catch (e) { return null; }
    if (!raw) return null;
    try {
        var s = JSON.parse(raw);
        if (!s || !s.keyStr || !s.keyHash || !s.salt) { clearSession(); return null; }
        if (typeof s.expiresAt === 'number' && Date.now() > s.expiresAt) {
            clearSession();
            return null; // 閒置逾時 → 需重新登入
        }
        return s;
    } catch (e) {
        clearSession();
        return null;
    }
}

/** 只讀取工作階段（不判定過期），供自動鎖定檢查 */
function peekSession() {
    try {
        var raw = sessionStorage.getItem(STORAGE_KEYS.SESSION) || localStorage.getItem(STORAGE_KEYS.SESSION);
        return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
}

function clearSession() {
    try {
        localStorage.removeItem(STORAGE_KEYS.SESSION);
        sessionStorage.removeItem(STORAGE_KEYS.SESSION);
    } catch (e) { /* 忽略 */ }
}

var lastSessionTouch = 0;

/** 使用者活動 → 展延工作階段（30 秒節流） */
function touchSession() {
    var now = Date.now();
    if (now - lastSessionTouch < 30000) return;
    lastSessionTouch = now;
    var s = peekSession();
    if (!s || !s.keyStr) return;
    var expiry = sessionExpiryMs();
    if (expiry === null) {
        if (s.expiresAt !== null && s.expiresAt !== undefined) {
            s.expiresAt = null;
            writeSessionBack(s);
        }
        return;
    }
    s.expiresAt = expiry;
    writeSessionBack(s);
}

function writeSessionBack(s) {
    try {
        var json = JSON.stringify(s);
        if (s.remember) localStorage.setItem(STORAGE_KEYS.SESSION, json);
        else sessionStorage.setItem(STORAGE_KEYS.SESSION, json);
    } catch (e) { /* 忽略 */ }
}

/* ================================================================
 * 登入節流（連續失敗 → 冷卻）
 * ============================================================== */
function getLockout() {
    try {
        var raw = localStorage.getItem(STORAGE_KEYS.LOCKOUT);
        return raw ? JSON.parse(raw) : { fails: 0, until: 0 };
    } catch (e) { return { fails: 0, until: 0 }; }
}

function setLockout(state) {
    try { localStorage.setItem(STORAGE_KEYS.LOCKOUT, JSON.stringify(state)); } catch (e) { /* 忽略 */ }
}

function recordLoginFail() {
    var s = getLockout();
    s.fails += 1;
    if (s.fails >= LOGIN_MAX_FAILS) {
        var backoff = Math.min(30000 * Math.pow(2, s.fails - LOGIN_MAX_FAILS), 300000);
        s.until = Date.now() + backoff;
    }
    setLockout(s);
    return s;
}

function clearLoginLockout() {
    setLockout({ fails: 0, until: 0 });
}

function lockoutRemainingMs() {
    var s = getLockout();
    if (s.until && s.until > Date.now()) return s.until - Date.now();
    return 0;
}

/* ================================================================
 * API Client
 * ============================================================== */
async function apiGet(keyHash) {
    var response = await fetch('/api/data?key=' + encodeURIComponent(keyHash), {
        headers: { 'Accept': 'application/json' }
    });
    if (!response.ok) throw new Error('API ' + response.status);
    return response.json();
}

async function apiSave(keyHash, encryptedData, salt, version) {
    var response = await fetch('/api/data', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: keyHash, data: encryptedData, salt: salt, version: version || CURRENT_VERSION })
    });
    if (!response.ok) throw new Error('API ' + response.status);
    return response.json();
}

async function apiDelete(keyHash) {
    var response = await fetch('/api/data?key=' + encodeURIComponent(keyHash), { method: 'DELETE' });
    if (!response.ok) throw new Error('API ' + response.status);
    return response.json();
}

/* ================================================================
 * 離線快取（IndexedDB）
 * ============================================================== */
var OFFLINE_CONFIG = {
    DB_NAME: '2fa-offline-db',
    DB_VERSION: 1,
    STORE_NAME: 'encrypted-data',
    METADATA_KEY: STORAGE_KEYS.OFFLINE_META,
    CACHE_EXPIRY_DAYS: 7
};

var offlineManager = {
    db: null,

    get isOnline() {
        return typeof navigator === 'undefined' || navigator.onLine !== false;
    },

    init: function () {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (typeof indexedDB === 'undefined') { resolve(); return; }
            var request = indexedDB.open(OFFLINE_CONFIG.DB_NAME, OFFLINE_CONFIG.DB_VERSION);
            request.onerror = function () { reject(request.error); };
            request.onsuccess = function () { self.db = request.result; resolve(); };
            request.onupgradeneeded = function (event) {
                var db = event.target.result;
                if (!db.objectStoreNames.contains(OFFLINE_CONFIG.STORE_NAME)) {
                    db.createObjectStore(OFFLINE_CONFIG.STORE_NAME, { keyPath: 'keyHash' });
                }
            };
        });
    },

    saveOfflineCache: function (keyHash, encryptedData, salt, version, cloudUpdatedAt) {
        var self = this;
        if (!this.db) return Promise.resolve();
        var now = Date.now();
        var cacheData = {
            keyHash: keyHash,
            encryptedData: encryptedData,
            salt: salt,
            version: version || CURRENT_VERSION,
            updatedAt: cloudUpdatedAt || now,
            cachedAt: now,
            locallyModified: !cloudUpdatedAt
        };
        return new Promise(function (resolve, reject) {
            try {
                var tx = self.db.transaction([OFFLINE_CONFIG.STORE_NAME], 'readwrite');
                var store = tx.objectStore(OFFLINE_CONFIG.STORE_NAME);
                var request = store.put(cacheData);
                request.onsuccess = function () { self.updateMetadata(keyHash, now); resolve(); };
                request.onerror = function () { reject(request.error); };
            } catch (e) { resolve(); }
        });
    },

    getOfflineCache: function (keyHash) {
        var self = this;
        if (!this.db) return Promise.resolve(null);
        return new Promise(function (resolve) {
            try {
                var tx = self.db.transaction([OFFLINE_CONFIG.STORE_NAME], 'readonly');
                var store = tx.objectStore(OFFLINE_CONFIG.STORE_NAME);
                var request = store.get(keyHash);
                request.onsuccess = function () {
                    var data = request.result;
                    if (!data) { resolve(null); return; }
                    var age = Date.now() - data.cachedAt;
                    var maxAge = OFFLINE_CONFIG.CACHE_EXPIRY_DAYS * 24 * 60 * 60 * 1000;
                    if (age > maxAge) { self.deleteOfflineCache(keyHash); resolve(null); }
                    else resolve(data);
                };
                request.onerror = function () { resolve(null); };
            } catch (e) { resolve(null); }
        });
    },

    deleteOfflineCache: function (keyHash) {
        var self = this;
        if (!this.db) return Promise.resolve();
        return new Promise(function (resolve) {
            try {
                var tx = self.db.transaction([OFFLINE_CONFIG.STORE_NAME], 'readwrite');
                var store = tx.objectStore(OFFLINE_CONFIG.STORE_NAME);
                var request = store.delete(keyHash);
                request.onsuccess = function () { self.deleteMetadata(keyHash); resolve(); };
                request.onerror = function () { resolve(); };
            } catch (e) { resolve(); }
        });
    },

    /** 清除本裝置所有離線快取 */
    clearAll: function () {
        var self = this;
        if (!this.db) return Promise.resolve();
        return new Promise(function (resolve) {
            try {
                var tx = self.db.transaction([OFFLINE_CONFIG.STORE_NAME], 'readwrite');
                tx.objectStore(OFFLINE_CONFIG.STORE_NAME).clear();
                tx.oncomplete = function () {
                    try { localStorage.removeItem(OFFLINE_CONFIG.METADATA_KEY); } catch (e) { /* 忽略 */ }
                    resolve();
                };
                tx.onerror = function () { resolve(); };
            } catch (e) { resolve(); }
        });
    },

    updateMetadata: function (keyHash, timestamp) {
        var metadata = this.getAllMetadata();
        metadata[keyHash] = {
            cachedAt: timestamp,
            expiresAt: timestamp + OFFLINE_CONFIG.CACHE_EXPIRY_DAYS * 24 * 60 * 60 * 1000
        };
        try { localStorage.setItem(OFFLINE_CONFIG.METADATA_KEY, JSON.stringify(metadata)); } catch (e) { /* 忽略 */ }
    },

    getAllMetadata: function () {
        try {
            var data = localStorage.getItem(OFFLINE_CONFIG.METADATA_KEY);
            return data ? JSON.parse(data) : {};
        } catch (e) { return {}; }
    },

    deleteMetadata: function (keyHash) {
        var metadata = this.getAllMetadata();
        delete metadata[keyHash];
        try { localStorage.setItem(OFFLINE_CONFIG.METADATA_KEY, JSON.stringify(metadata)); } catch (e) { /* 忽略 */ }
    },

    detectConflict: function (localData, cloudUpdatedAt) {
        if (!localData || !localData.locallyModified) return false;
        var localTime = localData.updatedAt || 0;
        return Math.abs(localTime - cloudUpdatedAt) > 5000;
    },

    setupOnlineListener: function () {
        window.addEventListener('online', function () {
            hideOfflineBanner();
            showToast('網路已恢復', 'success');
            triggerSyncCheck();
        });
        window.addEventListener('offline', function () {
            showOfflineBanner();
        });
    }
};

/* ================================================================
 * 雲端資料讀寫
 * ============================================================== */
async function saveKeys() {
    if (!masterKey || !currentKeyHash) return;
    var encrypted = await encrypt(keys, masterKey);

    if (offlineManager.isOnline) {
        try {
            await apiSave(currentKeyHash, encrypted, currentSalt);
            await offlineManager.saveOfflineCache(currentKeyHash, encrypted, currentSalt, CURRENT_VERSION);
        } catch (error) {
            console.error('Save to cloud failed:', error);
            await offlineManager.saveOfflineCache(currentKeyHash, encrypted, currentSalt, CURRENT_VERSION);
            showToast('已儲存到本機（雲端同步失敗）', 'error');
        }
    } else {
        await offlineManager.saveOfflineCache(currentKeyHash, encrypted, currentSalt, CURRENT_VERSION);
        showToast('已儲存到本機（離線模式）', 'info');
    }
}

async function loadKeysFromCloud(keyHash) {
    var result = await apiGet(keyHash);
    if (!result.exists) return { exists: false, data: null, salt: null };

    var stored;
    try {
        stored = JSON.parse(result.data);
    } catch (e) {
        console.error('Invalid server response format:', e);
        throw new Error('伺服器回應格式錯誤');
    }
    if (!stored || typeof stored.encryptedData !== 'string' || typeof stored.salt !== 'string') {
        console.error('Missing required fields in server response');
        throw new Error('伺服器回應資料不完整');
    }
    return { exists: true, data: stored.encryptedData, salt: stored.salt, updatedAt: stored.updatedAt };
}

/** 解密後正規化金鑰清單（補 id、清 secret，相容舊資料） */
function sanitizeKeys(arr) {
    if (!Array.isArray(arr)) return [];
    return arr.filter(function (k) { return k && k.secret; }).map(function (k) { return normalizeKey(k); });
}

/* ================================================================
 * UI 小工具：toast / 錯誤區塊 / 自訂確認視窗（取代 alert/confirm）
 * ============================================================== */
function $(id) { return document.getElementById(id); }

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

var toastTimer = null;
function showToast(message, type) {
    var toast = $('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.className = 'toast show ' + (type || 'success');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toast.classList.remove('show'); }, type === 'error' ? 3500 : 2000);
}

function showError(elementId, message) {
    var el = $(elementId);
    if (!el) return;
    el.textContent = message;
    el.classList.remove('hidden');
}

function hideError(elementId) {
    var el = $(elementId);
    if (el) el.classList.add('hidden');
}

/**
 * 自訂確認視窗，回傳 Promise<boolean>
 * options: {title, message, confirmText, cancelText, danger, requireText}
 * requireText：需輸入指定文字才能按下確認（危險操作）
 */
function confirmModal(options) {
    var opts = Object.assign({ title: '確認操作', message: '', confirmText: '確定', cancelText: '取消', danger: false, requireText: null }, options);
    return new Promise(function (resolve) {
        pendingConfirm = resolve;
        $('confirm-title').textContent = opts.title;
        $('confirm-message').textContent = opts.message;
        var okBtn = $('confirm-ok');
        okBtn.textContent = opts.confirmText;
        okBtn.classList.toggle('btn-danger-solid', !!opts.danger);
        okBtn.classList.toggle('btn-primary', !opts.danger);
        $('confirm-cancel').textContent = opts.cancelText;
        var inputWrap = $('confirm-input-wrap');
        var input = $('confirm-input');
        if (opts.requireText) {
            inputWrap.classList.remove('hidden');
            input.value = '';
            input.placeholder = '請輸入「' + opts.requireText + '」';
            input.dataset.requireText = opts.requireText;
            okBtn.disabled = true;
        } else {
            inputWrap.classList.add('hidden');
            delete input.dataset.requireText;
            okBtn.disabled = false;
        }
        $('confirm-modal').classList.remove('hidden');
    });
}

function resolveConfirm(result) {
    $('confirm-modal').classList.add('hidden');
    if (pendingConfirm) { var r = pendingConfirm; pendingConfirm = null; r(result); }
}

/* ================================================================
 * 密碼強度 / 可見度切換
 * ============================================================== */
function passwordStrength(pw) {
    var score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^a-zA-Z0-9]/.test(pw)) score++;
    if (pw.length >= 16) score++;
    if (score <= 2) return { level: 1, label: '弱' };
    if (score === 3) return { level: 2, label: '普通' };
    if (score === 4) return { level: 3, label: '強' };
    return { level: 4, label: '很強' };
}

function renderPasswordStrength(pw) {
    var meter = $('pw-strength');
    if (!meter) return;
    if (!pw) { meter.classList.add('hidden'); return; }
    var s = passwordStrength(pw);
    meter.classList.remove('hidden');
    meter.dataset.level = s.level;
    meter.querySelectorAll('.pw-seg').forEach(function (seg, i) {
        seg.classList.toggle('on', i < s.level);
    });
    var label = meter.querySelector('.pw-label');
    if (label) label.textContent = '強度：' + s.label;
}

function togglePasswordVisibility(button) {
    var targetId = button.dataset.togglePw;
    var input = $(targetId);
    if (!input) return;
    var show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    button.classList.toggle('pw-visible', show);
    button.setAttribute('aria-label', show ? '隱藏密碼' : '顯示密碼');
}

function validatePassword(password) {
    if (password.length < 8) return { valid: false, error: '密碼至少需要 8 個字元' };
    if (!/[a-zA-Z]/.test(password)) return { valid: false, error: '密碼需要包含至少一個字母' };
    if (!/[0-9]/.test(password)) return { valid: false, error: '密碼需要包含至少一個數字' };
    return { valid: true };
}

/* ================================================================
 * 主題（auto / light / dark）
 * ============================================================== */
var themeMediaQuery = null;

function applyTheme() {
    var t = settings.theme || 'auto';
    var dark;
    if (t === 'dark') dark = true;
    else if (t === 'light') dark = false;
    else dark = !!(themeMediaQuery && themeMediaQuery.matches);
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
    var btn = $('theme-btn');
    if (btn) {
        btn.dataset.mode = t;
        btn.setAttribute('title', t === 'auto' ? '主題：跟隨系統' : t === 'light' ? '主題：淺色' : '主題：深色');
    }
}

function cycleTheme() {
    var order = ['auto', 'light', 'dark'];
    var idx = order.indexOf(settings.theme || 'auto');
    settings.theme = order[(idx + 1) % order.length];
    saveSettings();
    applyTheme();
    var names = { auto: '跟隨系統', light: '淺色', dark: '深色' };
    showToast('主題：' + names[settings.theme], 'info');
}

function initThemeListener() {
    if (typeof matchMedia !== 'function') return;
    themeMediaQuery = matchMedia('(prefers-color-scheme: dark)');
    var handler = function () { if ((settings.theme || 'auto') === 'auto') applyTheme(); };
    if (themeMediaQuery.addEventListener) themeMediaQuery.addEventListener('change', handler);
    else if (themeMediaQuery.addListener) themeMediaQuery.addListener(handler);
}

/* ================================================================
 * 建立帳戶 / 解鎖 / 鎖定
 * ============================================================== */
function showSetupForm() {
    $('setup-password').classList.remove('hidden');
    $('enter-password').classList.add('hidden');
    hideError('setup-error');
    var el = $('new-password');
    if (el) setTimeout(function () { el.focus(); }, 50);
}

function showLoginForm() {
    $('setup-password').classList.add('hidden');
    $('enter-password').classList.remove('hidden');
    hideError('unlock-error');
    var el = $('password');
    if (el) setTimeout(function () { el.focus(); }, 50);
}

function setButtonLoading(button, loading, loadingText) {
    if (!button) return;
    if (loading) {
        button.dataset.origText = button.textContent;
        button.textContent = loadingText || '處理中…';
        button.disabled = true;
        button.classList.add('loading');
    } else {
        if (button.dataset.origText) button.textContent = button.dataset.origText;
        button.disabled = false;
        button.classList.remove('loading');
    }
}

async function setupPassword() {
    var password = $('new-password').value;
    var confirmPw = $('confirm-password').value;
    var btn = $('setup-submit');
    hideError('setup-error');

    var validation = validatePassword(password);
    if (!validation.valid) { showError('setup-error', validation.error); return; }
    if (password !== confirmPw) { showError('setup-error', '兩次輸入的密碼不一致'); return; }

    setButtonLoading(btn, true, '建立中…');
    try {
        var oldKeyHash = await deriveKeyHash(password, PBKDF2_ITERATIONS.V1_KEY_HASH);
        var oldCloudData = await loadKeysFromCloud(oldKeyHash);
        if (oldCloudData.exists) {
            showError('setup-error', '此密碼已被使用，請直接登入');
            return;
        }
        currentKeyHash = await deriveKeyHash(password, PBKDF2_ITERATIONS.V2);
        var cloudData = await loadKeysFromCloud(currentKeyHash);
        if (cloudData.exists) {
            showError('setup-error', '此密碼已被使用，請換一個密碼或直接登入');
            return;
        }
        currentSalt = generateSalt();
        masterKey = await deriveKey(password, decodeSalt(currentSalt), PBKDF2_ITERATIONS.V2);
        keys = [];
        await saveKeys();
        var remember = $('remember-me') ? $('remember-me').checked : settings.remember;
        settings.remember = remember; saveSettings();
        saveSession(await exportKeyB64(masterKey), currentKeyHash, currentSalt, remember);
        clearLoginLockout();
        showMainApp();
        showToast('帳戶建立成功', 'success');
    } catch (error) {
        console.error('setupPassword error:', error);
        showError('setup-error', '網路錯誤，請重試');
    } finally {
        setButtonLoading(btn, false);
    }
}

function startLockoutCountdown() {
    var ms = lockoutRemainingMs();
    if (ms <= 0) return false;
    var show = function () {
        var left = lockoutRemainingMs();
        if (left <= 0) {
            clearInterval(lockoutInterval); lockoutInterval = null;
            hideError('unlock-error');
            setButtonLoading($('unlock-submit'), false);
            return;
        }
        showError('unlock-error', '嘗試次數過多，請於 ' + Math.ceil(left / 1000) + ' 秒後再試');
    };
    setButtonLoading($('unlock-submit'), true, '已鎖定');
    show();
    if (lockoutInterval) clearInterval(lockoutInterval);
    lockoutInterval = setInterval(show, 1000);
    return true;
}

async function unlock() {
    if (lockoutRemainingMs() > 0) { startLockoutCountdown(); return; }

    var password = $('password').value;
    var btn = $('unlock-submit');
    hideError('unlock-error');

    if (!password) { showError('unlock-error', '請輸入密碼'); return; }

    setButtonLoading(btn, true, '解鎖中…');
    try {
        if (offlineManager.isOnline) {
            // ---- 線上模式 ----
            var oldKeyHash = await deriveKeyHash(password, PBKDF2_ITERATIONS.V1_KEY_HASH);
            var oldCloudData = await loadKeysFromCloud(oldKeyHash);
            if (oldCloudData.exists) {
                var migrateResult = await migrateFromV1(password, oldKeyHash, oldCloudData);
                if (!migrateResult.success) {
                    showError('unlock-error', migrateResult.error);
                    if (migrateResult.error === '密碼錯誤') { afterWrongPassword(); }
                    return;
                }
                await offlineManager.saveOfflineCache(currentKeyHash, await encrypt(keys, masterKey), currentSalt, CURRENT_VERSION);
                finishUnlock(true);
                return;
            }

            currentKeyHash = await deriveKeyHash(password, PBKDF2_ITERATIONS.V2);
            var cloudData = await loadKeysFromCloud(currentKeyHash);

            if (!cloudData.exists) {
                var offlineData = await offlineManager.getOfflineCache(currentKeyHash);
                if (offlineData) {
                    currentSalt = offlineData.salt;
                    masterKey = await deriveKey(password, decodeSalt(currentSalt), PBKDF2_ITERATIONS.V2);
                    try {
                        keys = sanitizeKeys(await decrypt(offlineData.encryptedData, masterKey));
                        finishUnlock(true, '使用離線快取（雲端無資料）');
                        return;
                    } catch (e) {
                        resetAuthState();
                        showError('unlock-error', '密碼錯誤');
                        afterWrongPassword();
                        return;
                    }
                } else {
                    showError('unlock-error', '密碼錯誤或帳戶不存在');
                    afterWrongPassword();
                    return;
                }
            }

            currentSalt = cloudData.salt;
            masterKey = await deriveKey(password, decodeSalt(currentSalt), PBKDF2_ITERATIONS.V2);

            try {
                keys = sanitizeKeys(await decrypt(cloudData.data, masterKey));
                var offlineCache = await offlineManager.getOfflineCache(currentKeyHash);
                if (offlineCache && offlineManager.detectConflict(offlineCache, cloudData.updatedAt || Date.now())) {
                    setButtonLoading(btn, false);
                    await showConflictModal(offlineCache, cloudData);
                    return;
                }
                await offlineManager.saveOfflineCache(currentKeyHash, cloudData.data, currentSalt, CURRENT_VERSION, cloudData.updatedAt);
            } catch (e) {
                resetAuthState();
                showError('unlock-error', '密碼錯誤');
                afterWrongPassword();
                return;
            }
            finishUnlock(true);
        } else {
            // ---- 離線模式 ----
            currentKeyHash = await deriveKeyHash(password, PBKDF2_ITERATIONS.V2);
            var offlineOnly = await offlineManager.getOfflineCache(currentKeyHash);
            if (!offlineOnly) {
                showError('unlock-error', '離線模式需要先線上登入過一次');
                return;
            }
            currentSalt = offlineOnly.salt;
            masterKey = await deriveKey(password, decodeSalt(currentSalt), PBKDF2_ITERATIONS.V2);
            try {
                keys = sanitizeKeys(await decrypt(offlineOnly.encryptedData, masterKey));
            } catch (e) {
                resetAuthState();
                showError('unlock-error', '密碼錯誤');
                afterWrongPassword();
                return;
            }
            finishUnlock(true, '離線模式');
        }
    } catch (error) {
        console.error('Unlock error:', error);
        // 網路錯誤 → 嘗試離線快取
        try {
            currentKeyHash = await deriveKeyHash(password, PBKDF2_ITERATIONS.V2);
            var offlineData2 = await offlineManager.getOfflineCache(currentKeyHash);
            if (offlineData2) {
                currentSalt = offlineData2.salt;
                masterKey = await deriveKey(password, decodeSalt(currentSalt), PBKDF2_ITERATIONS.V2);
                try {
                    keys = sanitizeKeys(await decrypt(offlineData2.encryptedData, masterKey));
                    finishUnlock(true, '網路錯誤，使用離線快取');
                    return;
                } catch (e2) {
                    resetAuthState();
                    showError('unlock-error', '密碼錯誤');
                    afterWrongPassword();
                    return;
                }
            }
        } catch (e3) { /* 忽略 */ }
        showError('unlock-error', '網路錯誤，請重試');
    } finally {
        setButtonLoading(btn, false);
    }
}

function afterWrongPassword() {
    recordLoginFail();
    $('password').value = '';
    $('password').focus();
    startLockoutCountdown();
}

function resetAuthState() {
    masterKey = null;
    currentKeyHash = null;
    currentSalt = null;
    keys = [];
}

function finishUnlock(remember, bannerText) {
    var rememberChecked = $('remember-me') ? $('remember-me').checked : settings.remember;
    settings.remember = rememberChecked;
    saveSettings();
    exportKeyB64(masterKey).then(function (keyStr) {
        saveSession(keyStr, currentKeyHash, currentSalt, rememberChecked);
    });
    clearLoginLockout();
    $('password').value = '';
    showMainApp();
    if (bannerText) showOfflineBanner(bannerText);
    else hideOfflineBanner();
}

async function migrateFromV1(password, oldKeyHash, oldCloudData) {
    try {
        var oldKey = await deriveKey(password, decodeSalt(oldCloudData.salt), PBKDF2_ITERATIONS.V1_DERIVE_KEY);
        try {
            keys = sanitizeKeys(await decrypt(oldCloudData.data, oldKey));
        } catch (e) {
            return { success: false, error: '密碼錯誤' };
        }
        currentKeyHash = await deriveKeyHash(password, PBKDF2_ITERATIONS.V2);
        currentSalt = generateSalt();
        masterKey = await deriveKey(password, decodeSalt(currentSalt), PBKDF2_ITERATIONS.V2);
        var encrypted = await encrypt(keys, masterKey);
        await apiSave(currentKeyHash, encrypted, currentSalt, CURRENT_VERSION);
        await apiDelete(oldKeyHash);
        return { success: true };
    } catch (error) {
        console.error('Migration failed:', error);
        return { success: false, error: '遷移失敗，請重試' };
    }
}

function showMainApp() {
    $('unlock-screen').classList.add('hidden');
    $('main-app').classList.remove('hidden');
    renderKeys();
    startUpdateInterval();
    startAutoLockWatch();
}

function lockScreen(reason) {
    if (updateInterval) { clearInterval(updateInterval); updateInterval = null; }
    stopAutoLockWatch();
    clearSession();
    resetAuthState();
    cachedCodes.clear();
    lastRemainingMap.clear();
    privacyRevealed.clear();
    searchFilter = '';
    var searchInput = $('search-input');
    if (searchInput) searchInput.value = '';
    $('main-app').classList.add('hidden');
    $('unlock-screen').classList.remove('hidden');
    $('password').value = '';
    showLoginForm();
    if (reason) showToast(reason, 'info');
}

function logout() {
    lockScreen(null);
    showToast('已登出', 'info');
}

/* ---- 閒置自動鎖定 ---- */
function startAutoLockWatch() {
    stopAutoLockWatch();
    autoLockInterval = setInterval(function () {
        var s = peekSession();
        if (!s || !s.keyStr) return;
        if (typeof s.expiresAt === 'number' && Date.now() > s.expiresAt) {
            lockScreen('因閒置已自動鎖定');
        }
    }, 15000);
}

function stopAutoLockWatch() {
    if (autoLockInterval) { clearInterval(autoLockInterval); autoLockInterval = null; }
}

function onUserActivity() {
    if (!masterKey) return;
    touchSession();
}

/* ================================================================
 * 驗證碼列表渲染
 * ============================================================== */
function formatCode(code) {
    var half = Math.ceil(code.length / 2);
    return code.slice(0, half) + ' ' + code.slice(half);
}

function maskedCode(k) {
    var digits = (k && k.digits) || 6;
    return formatCode('•'.repeat(digits));
}

/** 名稱 → 色相（頭像配色穩定） */
function nameHue(name) {
    var h = 0;
    for (var i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) % 360;
    return h;
}

function avatarLetter(name) {
    var ch = (name || '未').trim()[0] || '未';
    return /[a-zA-Z]/.test(ch) ? ch.toUpperCase() : ch;
}

function keyBadgesHtml(k) {
    var opts = keyOpts(k);
    var badges = [];
    if (k.type === 'hotp') badges.push('HOTP');
    if (opts.digits !== 6) badges.push(opts.digits + ' 位');
    if (k.type !== 'hotp' && opts.period !== 30) badges.push(opts.period + ' 秒');
    if (opts.algorithm !== 'SHA1') badges.push(opts.algorithm.replace('SHA', 'SHA-'));
    if (!badges.length) return '';
    return '<div class="token-badges">' + badges.map(function (b) {
        return '<span class="badge">' + escapeHtml(b) + '</span>';
    }).join('') + '</div>';
}

function getProgressRingClass(remaining) {
    if (remaining <= 5) return 'critical';
    if (remaining <= 10) return 'warning';
    return '';
}

async function renderKeys() {
    var list = $('token-list');
    var empty = $('empty-state');
    var countEl = $('keys-count');
    var filteredKeys = getFilteredKeys();

    if (countEl) {
        countEl.textContent = keys.length ? ('共 ' + keys.length + ' 個金鑰') : '';
        countEl.classList.toggle('hidden', !keys.length);
    }

    if (keys.length === 0) {
        list.innerHTML = '';
        empty.classList.remove('hidden');
        cachedCodes.clear();
        lastRemainingMap.clear();
        return;
    }
    empty.classList.add('hidden');

    if (filteredKeys.length === 0) {
        list.innerHTML = '<div class="no-results">找不到符合的金鑰</div>';
        return;
    }

    var now = Date.now();
    var circumference = 2 * Math.PI * 15;
    cachedCodes.clear();
    lastRemainingMap.clear();

    var codes = await Promise.all(filteredKeys.map(function (k) {
        return generateOTP(k, now).catch(function () { return null; });
    }));

    var canDrag = !searchFilter;
    var html = '';
    for (var i = 0; i < filteredKeys.length; i++) {
        var k = filteredKeys[i];
        var code = codes[i] || '------';
        cachedCodes.set(k.id, code);
        var isHOTP = k.type === 'hotp';
        var remaining = isHOTP ? 0 : (keyOpts(k).period - Math.floor(now / 1000 % keyOpts(k).period));
        if (!isHOTP) lastRemainingMap.set(k.id, remaining);

        var masked = settings.privacyMode && !privacyRevealed.has(k.id);
        var displayCode = code === '------' ? code : (masked ? maskedCode(k) : formatCode(code));
        var hue = nameHue(k.name);

        var rightHtml;
        if (isHOTP) {
            rightHtml =
                '<div class="hotp-box">' +
                '<button class="btn-next" data-action="next" title="產生下一個驗證碼">' +
                '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>' +
                '</button>' +
                '<div class="hotp-counter">#' + (k.counter || 0) + '</div>' +
                '</div>';
        } else {
            var progress = (remaining / keyOpts(k).period) * 100;
            var offset = circumference * (1 - progress / 100);
            rightHtml =
                '<svg class="progress-ring ' + getProgressRingClass(remaining) + '" viewBox="0 0 36 36">' +
                '<circle class="bg" cx="18" cy="18" r="15"></circle>' +
                '<circle class="progress" cx="18" cy="18" r="15" stroke-dasharray="' + circumference.toFixed(2) + '" stroke-dashoffset="' + offset.toFixed(2) + '"></circle>' +
                '<text class="progress-text" x="18" y="18">' + remaining + '</text>' +
                '</svg>';
        }

        html +=
            '<div class="token-item" data-key-id="' + escapeHtml(String(k.id)) + '" data-type="' + (isHOTP ? 'hotp' : 'totp') + '"' +
            ' style="--token-delay:' + Math.min(i * 30, 300) + 'ms"' +
            (canDrag ? ' draggable="false"' : '') + '>' +
            '<div class="token-main">' +
            '<div class="token-avatar" style="--avatar-hue:' + hue + '">' + escapeHtml(avatarLetter(k.name)) + '</div>' +
            '<div class="token-info">' +
            '<div class="token-name" title="' + escapeHtml(k.name) + '">' + escapeHtml(k.name) + '</div>' +
            '<div class="token-code' + (masked ? ' masked' : '') + '">' + escapeHtml(displayCode) + '</div>' +
            (k.account && k.account !== k.name ? '<div class="token-account">' + escapeHtml(k.account) + '</div>' : '') +
            keyBadgesHtml(k) +
            '</div>' +
            '</div>' +
            '<div class="token-actions">' +
            rightHtml +
            '<div class="token-btn-group">' +
            (settings.privacyMode ? '<button class="btn-mini" data-action="reveal" title="' + (masked ? '顯示' : '隱藏') + '驗證碼">' + (masked ? iconEye() : iconEyeOff()) + '</button>' : '') +
            (canDrag ? '<button class="btn-mini drag-handle" data-action="drag" title="拖曳以重新排序">' + iconGrip() + '</button>' : '') +
            '<button class="btn-mini" data-action="edit" title="編輯">' + iconEdit() + '</button>' +
            '<button class="btn-mini danger" data-action="delete" title="刪除">' + iconTrash() + '</button>' +
            '</div>' +
            '</div>' +
            '</div>';
    }
    list.innerHTML = html;
}

function iconEye() {
    return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
}
function iconEyeOff() {
    return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>';
}
function iconGrip() {
    return '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><circle cx="9" cy="6" r="1.6"></circle><circle cx="15" cy="6" r="1.6"></circle><circle cx="9" cy="12" r="1.6"></circle><circle cx="15" cy="12" r="1.6"></circle><circle cx="9" cy="18" r="1.6"></circle><circle cx="15" cy="18" r="1.6"></circle></svg>';
}
function iconEdit() {
    return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>';
}
function iconTrash() {
    return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="15" y1="11" x2="15" y2="17"></line></svg>';
}

/* ---- 每秒增量更新（各金鑰獨立週期） ---- */
async function updateDisplay() {
    if (keys.length === 0 || $('main-app').classList.contains('hidden')) return;
    var now = Date.now();
    var circumference = 2 * Math.PI * 15;
    var items = document.querySelectorAll('#token-list .token-item');

    for (var i = 0; i < items.length; i++) {
        var item = items[i];
        var id = item.dataset.keyId;
        if (item.dataset.type === 'hotp') continue;
        var k = keys.find(function (x) { return String(x.id) === id; });
        if (!k) continue;
        var period = keyOpts(k).period;
        var remaining = period - Math.floor(now / 1000 % period);
        var last = lastRemainingMap.has(id) ? lastRemainingMap.get(id) : remaining;
        lastRemainingMap.set(id, remaining);

        if (remaining > last) {
            // 週期翻轉 → 重新產生驗證碼
            try {
                var code = await generateOTP(k, now);
                cachedCodes.set(id, code);
                var codeEl = item.querySelector('.token-code');
                if (codeEl) {
                    var masked = settings.privacyMode && !privacyRevealed.has(id);
                    codeEl.textContent = masked ? maskedCode(k) : formatCode(code);
                }
            } catch (e) { /* 忽略單筆錯誤 */ }
        }

        var ring = item.querySelector('.progress-ring');
        if (ring) {
            ring.setAttribute('class', 'progress-ring ' + getProgressRingClass(remaining));
            var pc = ring.querySelector('.progress');
            if (pc) pc.setAttribute('stroke-dashoffset', (circumference * (1 - remaining / period)).toFixed(2));
            var tx = ring.querySelector('.progress-text');
            if (tx) tx.textContent = remaining;
        }
    }
}

function startUpdateInterval() {
    if (updateInterval) clearInterval(updateInterval);
    updateInterval = setInterval(updateDisplay, 1000);
}

/* ---- 搜尋 ---- */
function filterKeys() {
    var input = $('search-input');
    var clearBtn = $('search-clear');
    searchFilter = input.value.toLowerCase().trim();
    clearBtn.classList.toggle('hidden', !searchFilter);
    renderKeys();
}

function clearSearch() {
    $('search-input').value = '';
    searchFilter = '';
    $('search-clear').classList.add('hidden');
    renderKeys();
}

function getFilteredKeys() {
    if (!searchFilter) return keys;
    return keys.filter(function (key) {
        return key.name.toLowerCase().includes(searchFilter) ||
            (key.account && key.account.toLowerCase().includes(searchFilter)) ||
            (key.issuer && key.issuer.toLowerCase().includes(searchFilter));
    });
}

/* ---- 複製 ---- */
async function copyCode(code, tokenItem) {
    if (tokenItem) {
        tokenItem.classList.add('copied-flash');
        setTimeout(function () { tokenItem.classList.remove('copied-flash'); }, 300);
    }
    var ok = false;
    try {
        await navigator.clipboard.writeText(code);
        ok = true;
    } catch (err) {
        console.error('Clipboard API failed:', err);
        var textarea = document.createElement('textarea');
        textarea.value = code;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        textarea.style.pointerEvents = 'none';
        document.body.appendChild(textarea);
        textarea.select();
        try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
        document.body.removeChild(textarea);
    }
    showToast(ok ? '已複製驗證碼' : '複製失敗', ok ? 'success' : 'error');
    if (ok && settings.clearClipboard) {
        var timer = setTimeout(async function () {
            try {
                var current = await navigator.clipboard.readText();
                if (current === code) await navigator.clipboard.writeText('');
            } catch (e) { /* 瀏覽器不支援讀取剪貼簿時略過 */ }
        }, CLIPBOARD_CLEAR_MS);
        clipboardTimers.push(timer);
    }
    return ok;
}

/* ---- 金鑰操作 ---- */
async function deleteKey(id) {
    var k = keys.find(function (x) { return String(x.id) === String(id); });
    if (!k) return;
    var okDelete = await confirmModal({
        title: '刪除金鑰',
        message: '確定要刪除「' + k.name + '」嗎？刪除後對應網站將無法取得驗證碼，此操作無法復原。',
        confirmText: '刪除',
        danger: true
    });
    if (!okDelete) return;
    keys = keys.filter(function (x) { return String(x.id) !== String(id); });
    await saveKeys();
    renderKeys();
    showToast('已刪除「' + k.name + '」', 'info');
}

async function nextHotp(id) {
    var k = keys.find(function (x) { return String(x.id) === String(id); });
    if (!k || k.type !== 'hotp') return;
    k.counter = (k.counter || 0) + 1;
    await saveKeys();
    renderKeys();
}

function toggleReveal(id) {
    if (privacyRevealed.has(id)) privacyRevealed.delete(id);
    else privacyRevealed.add(id);
    renderKeys();
}

/* ---- 拖曳重新排序 ---- */
function onDragStart(e) {
    var item = e.target.closest ? e.target.closest('.token-item') : null;
    if (!item || !dragArmed) { e.preventDefault(); return; }
    dragSrcId = item.dataset.keyId;
    item.classList.add('dragging');
    if (e.dataTransfer) {
        e.dataTransfer.effectAllowed = 'move';
        try { e.dataTransfer.setData('text/plain', dragSrcId); } catch (err) { /* 忽略 */ }
    }
}

function onDragOver(e) {
    if (!dragSrcId) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
    var item = e.target.closest ? e.target.closest('.token-item') : null;
    document.querySelectorAll('.token-item.drop-before').forEach(function (el) { el.classList.remove('drop-before'); });
    document.querySelectorAll('.token-item.drop-after').forEach(function (el) { el.classList.remove('drop-after'); });
    if (item && item.dataset.keyId !== dragSrcId) {
        var rect = item.getBoundingClientRect();
        var after = (e.clientY - rect.top) > rect.height / 2;
        item.classList.add(after ? 'drop-after' : 'drop-before');
    }
}

function onDrop(e) {
    if (!dragSrcId) return;
    e.preventDefault();
    var item = e.target.closest ? e.target.closest('.token-item') : null;
    if (item && item.dataset.keyId !== dragSrcId) {
        var rect = item.getBoundingClientRect();
        var after = (e.clientY - rect.top) > rect.height / 2;
        var fromIdx = keys.findIndex(function (k) { return String(k.id) === dragSrcId; });
        var toIdx = keys.findIndex(function (k) { return String(k.id) === item.dataset.keyId; });
        if (fromIdx !== -1 && toIdx !== -1) {
            var moved = keys.splice(fromIdx, 1)[0];
            var insertIdx = keys.findIndex(function (k) { return String(k.id) === item.dataset.keyId; });
            keys.splice(after ? insertIdx + 1 : insertIdx, 0, moved);
            saveKeys().then(renderKeys);
        }
    }
    onDragEnd();
}

function onDragEnd() {
    dragSrcId = null;
    dragArmed = false;
    document.querySelectorAll('.token-item.dragging').forEach(function (el) { el.classList.remove('dragging'); });
    document.querySelectorAll('.token-item.drop-before,.token-item.drop-after').forEach(function (el) {
        el.classList.remove('drop-before', 'drop-after');
    });
    document.querySelectorAll('.token-item[draggable="true"]').forEach(function (el) { el.setAttribute('draggable', 'false'); });
}

/* ================================================================
 * 新增金鑰 modal
 * ============================================================== */
function showAddModal() {
    $('key-name').value = '';
    $('key-secret').value = '';
    resetAdvancedOptions();
    hideError('add-error');
    $('add-modal').classList.remove('hidden');
    switchInputTab('manual');
    setTimeout(function () { $('key-name').focus(); }, 80);
}

function hideAddModal() {
    stopQrScanner();
    clearUploadPreview();
    $('add-modal').classList.add('hidden');
}

function resetAdvancedOptions() {
    var details = $('adv-details');
    if (details) details.open = false;
    setVal('adv-type', 'totp');
    setVal('adv-digits', '6');
    setVal('adv-period', '30');
    setVal('adv-algo', 'SHA1');
    setVal('adv-counter', '0');
    updateAdvancedVisibility();
}

function setVal(id, v) { var el = $(id); if (el) el.value = v; }
function getVal(id) { var el = $(id); return el ? el.value : ''; }

function updateAdvancedVisibility() {
    var isHOTP = getVal('adv-type') === 'hotp';
    var periodWrap = $('adv-period-wrap');
    var counterWrap = $('adv-counter-wrap');
    if (periodWrap) periodWrap.classList.toggle('hidden', isHOTP);
    if (counterWrap) counterWrap.classList.toggle('hidden', !isHOTP);
}

function readAdvancedOptions(prefix) {
    return {
        type: getVal(prefix + '-type') || 'totp',
        digits: getVal(prefix + '-digits') || '6',
        period: getVal(prefix + '-period') || '30',
        algorithm: getVal(prefix + '-algo') || 'SHA1',
        counter: getVal(prefix + '-counter') || '0'
    };
}

async function addKey() {
    var name = $('key-name').value.trim();
    var secret = $('key-secret').value.trim();
    var adv = readAdvancedOptions('adv');
    hideError('add-error');

    if (!name) { showError('add-error', '請輸入名稱'); return; }
    if (!secret) { showError('add-error', '請輸入金鑰'); return; }
    if (!isValidSecret(secret)) { showError('add-error', '金鑰格式無效（需為 Base32，至少 8 個字元）'); return; }
    if (keys.some(function (k) { return k.name === name; })) { showError('add-error', '該名稱已存在'); return; }

    var candidate = normalizeKey(Object.assign({ name: name, secret: secret }, adv));
    try {
        await generateOTP(candidate);
    } catch (e) {
        showError('add-error', '金鑰格式無效，無法產生驗證碼');
        return;
    }
    var btn = $('add-confirm');
    setButtonLoading(btn, true, '新增中…');
    try {
        keys.push(candidate);
        await saveKeys();
        hideAddModal();
        renderKeys();
        showToast('已新增「' + candidate.name + '」', 'success');
    } finally {
        setButtonLoading(btn, false);
    }
}

/* ---- 分頁切換 ---- */
function switchInputTab(tab) {
    stopQrScanner();
    clearUploadPreview();
    document.querySelectorAll('.input-tabs button').forEach(function (t) {
        t.classList.toggle('active', t.dataset.tab === tab);
    });
    document.querySelectorAll('.tab-content').forEach(function (c) {
        c.classList.toggle('active', c.id === 'tab-' + tab);
    });
    var actionsManual = $('modal-actions-manual');
    var actionsOther = $('modal-actions-other');
    actionsManual.classList.toggle('hidden', tab !== 'manual');
    actionsOther.classList.toggle('hidden', tab === 'manual');
}

function clearUploadPreview() {
    var preview = $('qr-preview');
    if (!preview) return;
    if (preview.src && preview.src.startsWith('blob:')) URL.revokeObjectURL(preview.src);
    preview.classList.remove('show');
    preview.removeAttribute('src');
}

/* ================================================================
 * QR 掃描（相機）
 * ============================================================== */
async function startQrScanner() {
    var video = $('qr-video');
    var canvas = $('qr-canvas');
    var status = $('qr-camera-status');
    hideError('add-error');

    if (typeof jsQR === 'undefined') {
        showError('add-error', 'QR code 辨識函式庫載入失敗，請重新整理頁面');
        return;
    }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        showError('add-error', '瀏覽器不支援相機存取（需 HTTPS 環境）');
        return;
    }

    status.textContent = '正在要求相機權限…';
    try {
        qrStream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } }
        });
        video.srcObject = qrStream;
        await video.play();
        canvas.width = video.videoWidth || 640;
        canvas.height = video.videoHeight || 480;
        status.textContent = '掃描中…';
        qrScanInterval = setInterval(function () { scanQrFrame(video, canvas); }, 200);
    } catch (err) {
        stopQrScanner();
        if (err.name === 'NotAllowedError') showError('add-error', '相機權限被拒絕，請在瀏覽器設定中允許');
        else if (err.name === 'NotFoundError') showError('add-error', '未偵測到相機裝置');
        else {
            console.error('Camera error:', err);
            showError('add-error', '相機啟動失敗，請檢查裝置和權限設定');
        }
        status.textContent = '相機啟動失敗';
    }
}

function stopQrScanner() {
    if (qrScanInterval) { clearInterval(qrScanInterval); qrScanInterval = null; }
    if (qrStream) {
        qrStream.getTracks().forEach(function (t) { t.stop(); });
        qrStream = null;
    }
    var video = $('qr-video');
    if (video) video.srcObject = null;
    var status = $('qr-camera-status');
    if (status) status.textContent = '點擊下方按鈕啟動相機';
}

function scanQrFrame(video, canvas) {
    if (!qrStream) return;
    var ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    var imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    var code = jsQR(imageData.data, imageData.width, imageData.height);
    if (code && code.data) {
        stopQrScanner();
        processQrCode(code.data);
    }
}

/** 處理掃描結果：單筆 otpauth → 填入表單；批次遷移資料 → 匯入預覽 */
function processQrCode(data) {
    var text = String(data).trim();
    if (text.indexOf('otpauth-migration://') === 0) {
        var mig = decodeMigrationPayload(text);
        if (mig.length > 0) {
            hideAddModal();
            openImportPreview({ format: 'google', entries: mig, encrypted: false, error: null });
        } else {
            showError('add-error', '無法解析此遷移 QR code');
        }
        return;
    }
    var parsed = parseOtpauthUri(text);
    if (!parsed) {
        showError('add-error', '僅支援 otpauth://totp/ 或 otpauth://hotp/ 格式的 QR code');
        return;
    }
    $('key-name').value = parsed.name;
    $('key-secret').value = parsed.secret;
    setVal('adv-type', parsed.type);
    setVal('adv-digits', String(parsed.digits || 6));
    setVal('adv-period', String(parsed.period || 30));
    setVal('adv-algo', parsed.algorithm && SUPPORTED_ALGOS.indexOf(parsed.algorithm) !== -1 ? parsed.algorithm : 'SHA1');
    setVal('adv-counter', String(parsed.counter || 0));
    updateAdvancedVisibility();
    if (parsed.digits !== 6 || parsed.period !== 30 || (parsed.algorithm && parsed.algorithm !== 'SHA1') || parsed.type === 'hotp') {
        var details = $('adv-details');
        if (details) details.open = true;
    }
    switchInputTab('manual');
}

/* ================================================================
 * QR 圖片上傳 / 貼上
 * ============================================================== */
function setupUploadZone() {
    var zone = $('upload-zone');
    var input = $('qr-upload');

    zone.addEventListener('click', function () { input.click(); });
    zone.addEventListener('dragover', function (e) { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', function () { zone.classList.remove('dragover'); });
    zone.addEventListener('drop', function (e) {
        e.preventDefault();
        zone.classList.remove('dragover');
        var file = e.dataTransfer.files[0];
        if (file) handleQrUpload(file);
    });
    input.addEventListener('change', function (e) {
        var file = e.target.files[0];
        if (file) handleQrUpload(file);
        input.value = '';
    });
    document.addEventListener('paste', function (e) {
        var modal = $('add-modal');
        var uploadTab = $('tab-upload');
        if (modal.classList.contains('hidden') || !uploadTab.classList.contains('active')) return;
        var items = e.clipboardData && e.clipboardData.items;
        if (!items) return;
        for (var i = 0; i < items.length; i++) {
            var item = items[i];
            if (item.type && item.type.indexOf('image/') === 0) {
                var file = item.getAsFile();
                if (file) handleQrUpload(file);
                break;
            }
        }
    });
}

function handleQrUpload(file) {
    hideError('add-error');
    var preview = $('qr-preview');

    if (typeof jsQR === 'undefined') {
        showError('add-error', 'QR code 辨識函式庫載入失敗，請重新整理頁面');
        return;
    }
    if (!file.type.match(/^image\/(png|jpeg|webp)$/)) {
        showError('add-error', '僅支援 PNG / JPG / WEBP 格式圖片');
        return;
    }
    if (file.size > MAX_IMAGE_BYTES) {
        showError('add-error', '圖片檔案過大，請選擇小於 5MB 的圖片');
        return;
    }
    clearUploadPreview();

    var objectUrl = URL.createObjectURL(file);
    preview.src = objectUrl;
    preview.classList.add('show');

    var img = new Image();
    img.onload = function () {
        // 大圖縮放以加速辨識
        var maxDim = 1200;
        var scale = Math.min(1, maxDim / Math.max(img.width, img.height));
        var canvas = document.createElement('canvas');
        canvas.width = Math.max(1, Math.round(img.width * scale));
        canvas.height = Math.max(1, Math.round(img.height * scale));
        var ctx = canvas.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        var imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        var code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code && code.data) {
            processQrCode(code.data);
        } else {
            showError('add-error', '圖片中未辨識到 QR code');
        }
        URL.revokeObjectURL(objectUrl);
    };
    img.onerror = function () {
        showError('add-error', '圖片載入失敗');
        URL.revokeObjectURL(objectUrl);
    };
    img.src = objectUrl;
}

/* ================================================================
 * 編輯金鑰 modal（名稱 + 金鑰 + 進階參數）
 * ============================================================== */
function showEditModal(id) {
    var k = keys.find(function (x) { return String(x.id) === String(id); });
    if (!k) return;
    $('edit-key-id').value = String(id);
    $('edit-name').value = k.name;
    $('edit-secret').value = k.secret;
    setVal('edit-type', k.type === 'hotp' ? 'hotp' : 'totp');
    setVal('edit-digits', String(keyOpts(k).digits));
    setVal('edit-period', String(keyOpts(k).period));
    setVal('edit-algo', keyOpts(k).algorithm);
    setVal('edit-counter', String(k.counter || 0));
    updateEditVisibility();
    hideError('edit-error');
    $('edit-modal').classList.remove('hidden');
    setTimeout(function () { $('edit-name').focus(); $('edit-name').select(); }, 80);
}

function updateEditVisibility() {
    var isHOTP = getVal('edit-type') === 'hotp';
    var periodWrap = $('edit-period-wrap');
    var counterWrap = $('edit-counter-wrap');
    if (periodWrap) periodWrap.classList.toggle('hidden', isHOTP);
    if (counterWrap) counterWrap.classList.toggle('hidden', !isHOTP);
}

function hideEditModal() {
    $('edit-modal').classList.add('hidden');
}

async function saveEdit() {
    var id = $('edit-key-id').value;
    var k = keys.find(function (x) { return String(x.id) === String(id); });
    if (!k) return;
    var newName = $('edit-name').value.trim();
    var newSecret = $('edit-secret').value.trim();
    hideError('edit-error');

    if (!newName) { showError('edit-error', '名稱不能為空'); return; }
    if (!isValidSecret(newSecret)) { showError('edit-error', '金鑰格式無效（需為 Base32，至少 8 個字元）'); return; }
    if (keys.some(function (x) { return x !== k && x.name === newName; })) { showError('edit-error', '該名稱已存在'); return; }

    var adv = readAdvancedOptions('edit');
    var updated = normalizeKey(Object.assign({}, k, { name: newName, secret: newSecret }, adv));
    updated.id = k.id;
    try {
        await generateOTP(updated);
    } catch (e) {
        showError('edit-error', '參數無效，無法產生驗證碼');
        return;
    }
    var idx = keys.findIndex(function (x) { return String(x.id) === String(id); });
    keys[idx] = updated;
    privacyRevealed.delete(updated.id);
    await saveKeys();
    hideEditModal();
    renderKeys();
    showToast('已更新「' + updated.name + '」', 'success');
}

/* ================================================================
 * 匯入（萬用格式 + 預覽確認）
 * ============================================================== */
var IMPORT_FORMAT_NAMES = {
    aegis: 'Aegis 備份',
    '2fas': '2FAS 備份',
    ente: 'Ente Auth 備份',
    bitwarden: 'Bitwarden 備份',
    freeotp: 'FreeOTP 備份',
    otpauth: 'OTP Auth 備份',
    google: 'Google Authenticator 遷移資料',
    uris: 'otpauth URI 清單',
    own: '本應用備份',
    generic: '通用格式',
    list: '清單格式'
};

function importKeys() {
    var input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,.txt,application/json,text/plain';
    input.addEventListener('change', async function (e) {
        var file = e.target.files[0];
        if (!file) return;
        if (file.size > MAX_IMPORT_FILE_BYTES) {
            showToast('檔案過大，請選擇小於 2MB 的備份檔案', 'error');
            return;
        }
        var text;
        try {
            text = await file.text();
        } catch (err) {
            showToast('檔案讀取失敗', 'error');
            return;
        }
        var result = parseImportContent(text);
        if (result.error === 'encrypted') {
            showImportError('該備份已加密。請先在來源應用中選擇「未加密／明文」匯出後再試一次。');
            return;
        }
        if (result.error === 'unsupported' || result.error === 'parse') {
            showImportError('無法辨識的備份格式。支援：Aegis、2FAS、Ente、Bitwarden、FreeOTP、Raivo、OTP Auth、Google Authenticator 遷移資料、otpauth:// URI 清單及本應用 JSON 備份。');
            return;
        }
        if (result.error === 'no-keys' || result.entries.length === 0) {
            showImportError('檔案中找不到可匯入的金鑰。');
            return;
        }
        openImportPreview(result);
    });
    input.click();
}

function showImportError(message) {
    pendingImport = null;
    $('import-summary').textContent = '';
    $('import-list').innerHTML = '';
    showError('import-error', message);
    $('import-confirm').classList.add('hidden');
    $('import-modal').classList.remove('hidden');
}

function openImportPreview(result) {
    var entries = markImportDuplicates(result.entries, keys);
    pendingImport = entries;
    hideError('import-error');

    var newCount = entries.filter(function (e) { return !e.duplicate && !e.invalidReason; }).length;
    var dupCount = entries.filter(function (e) { return e.duplicate; }).length;
    var invalidCount = entries.filter(function (e) { return !!e.invalidReason; }).length;
    var formatName = IMPORT_FORMAT_NAMES[result.format] || '備份檔案';

    var parts = ['偵測到 ' + entries.length + ' 個項目（' + formatName + '）'];
    if (newCount) parts.push(newCount + ' 個可匯入');
    if (dupCount) parts.push(dupCount + ' 個已存在');
    if (invalidCount) parts.push(invalidCount + ' 個無效');
    $('import-summary').textContent = parts.join(' · ');

    var html = '';
    entries.forEach(function (e, idx) {
        var disabled = e.duplicate || !!e.invalidReason;
        var metaParts = [];
        if (e.type === 'hotp') metaParts.push('HOTP');
        metaParts.push((e.digits || 6) + ' 位');
        if (e.type !== 'hotp') metaParts.push((e.period || 30) + ' 秒');
        if (e.algorithm && e.algorithm !== 'SHA1') metaParts.push(e.algorithm.replace('SHA', 'SHA-'));
        if (e.account && e.account !== e.name) metaParts.push(e.account);

        var badge;
        if (e.invalidReason) badge = '<span class="badge badge-invalid">' + escapeHtml(e.invalidReason) + '</span>';
        else if (e.duplicate) badge = '<span class="badge badge-dup">已存在</span>';
        else badge = '<span class="badge badge-new">新增</span>';

        html +=
            '<label class="import-item' + (disabled ? ' disabled' : '') + '">' +
            '<input type="checkbox" data-idx="' + idx + '"' + (disabled ? ' disabled' : ' checked') + '>' +
            '<span class="import-avatar" style="--avatar-hue:' + nameHue(e.name) + '">' + escapeHtml(avatarLetter(e.name)) + '</span>' +
            '<span class="import-info">' +
            '<span class="import-name">' + escapeHtml(e.name) + '</span>' +
            '<span class="import-meta">' + escapeHtml(metaParts.join(' · ')) + '</span>' +
            '</span>' +
            badge +
            '</label>';
    });
    $('import-list').innerHTML = html;

    var confirmBtn = $('import-confirm');
    confirmBtn.classList.remove('hidden');
    confirmBtn.textContent = '匯入 ' + newCount + ' 個金鑰';
    confirmBtn.disabled = newCount === 0;
    $('import-modal').classList.remove('hidden');
}

function hideImportModal() {
    $('import-modal').classList.add('hidden');
    pendingImport = null;
}

async function confirmImport() {
    if (!pendingImport) { hideImportModal(); return; }
    var checkboxes = document.querySelectorAll('#import-list input[type="checkbox"]');
    var toAdd = [];
    checkboxes.forEach(function (cb) {
        if (!cb.checked) return;
        var e = pendingImport[toInt(cb.dataset.idx, -1)];
        if (e && !e.duplicate && !e.invalidReason) toAdd.push(e);
    });
    hideImportModal();
    if (toAdd.length === 0) return;

    var btn = $('import-confirm');
    setButtonLoading(btn, true, '匯入中…');
    try {
        for (var i = 0; i < toAdd.length; i++) {
            keys.push(normalizeKey(Object.assign({}, toAdd[i], { id: generateId() })));
        }
        await saveKeys();
        await renderKeys();
        showToast('已匯入 ' + toAdd.length + ' 個金鑰', 'success');
    } finally {
        setButtonLoading(btn, false);
    }
}

/* ================================================================
 * 匯出（JSON 備份 / otpauth URI 清單）
 * ============================================================== */
function showExportModal() {
    if (keys.length === 0) {
        showToast('沒有可匯出的金鑰', 'error');
        return;
    }
    var jsonRadio = $('export-format-json');
    if (jsonRadio) jsonRadio.checked = true;
    $('export-count').textContent = '共 ' + keys.length + ' 個金鑰';
    $('export-modal').classList.remove('hidden');
}

function hideExportModal() {
    $('export-modal').classList.add('hidden');
}

function downloadBlob(content, filename, mime) {
    var blob = new Blob([content], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
}

/* ---- 各匯出格式建構器（純函式，可供測試） ---- */
function buildOwnExportData(list) {
    return {
        app: '2fa-authenticator',
        version: 2,
        exported_at: new Date().toISOString(),
        keys: list.map(function (k) {
            var o = { name: k.name, secret: k.secret };
            if (k.type === 'hotp') { o.type = 'hotp'; o.counter = k.counter || 0; }
            if (k.digits) o.digits = k.digits;
            if (k.period) o.period = k.period;
            if (k.algorithm) o.algorithm = k.algorithm;
            if (k.account) o.account = k.account;
            if (k.issuer) o.issuer = k.issuer;
            return o;
        })
    };
}

function buildUriExportText(list) {
    return list.map(buildOtpauthUri).join('\n') + '\n';
}

/** Aegis Authenticator 原生（未加密）備份格式 */
function buildAegisExportData(list) {
    return {
        version: 1,
        header: { slots: null, params: null },
        db: {
            version: 1,
            entries: list.map(function (k) {
                var opts = keyOpts(k);
                var info = {
                    secret: k.secret,
                    algo: opts.algorithm.toLowerCase(),
                    digits: opts.digits
                };
                if (k.type === 'hotp') info.counter = k.counter || 0;
                else info.period = opts.period;
                return {
                    type: k.type === 'hotp' ? 'hotp' : 'totp',
                    uuid: generateId(),
                    name: k.account || k.name,
                    issuer: k.issuer || '',
                    note: '',
                    icon: null,
                    icon_mime: null,
                    info: info
                };
            })
        }
    };
}

/** 2FAS Authenticator 原生備份格式 */
function build2FASExportData(list) {
    var now = Date.now();
    var services = list.map(function (k, i) {
        var opts = keyOpts(k);
        var issuer = k.issuer || '';
        var account = k.account || '';
        var otp = {
            account: account || k.name,
            issuer: issuer,
            label: issuer ? (issuer + ':' + (account || k.name)) : k.name,
            digits: opts.digits,
            period: opts.period,
            algorithm: opts.algorithm,
            secret: k.secret,
            tokenType: k.type === 'hotp' ? 'HOTP' : 'TOTP',
            source: 'Manual'
        };
        if (k.type === 'hotp') otp.counter = k.counter || 0;
        return {
            key: generateId(),
            name: issuer || k.name,
            secret: k.secret,
            order: i,
            otp: otp,
            serviceTypeID: null,
            updatedAt: now,
            createdAt: now
        };
    });
    return {
        app: '2fas',
        appVersion: '5.0.0',
        backupVersion: 3,
        createdAt: now,
        updatedAt: now,
        groups: [],
        services: services,
        servicesOrder: services.map(function (s) { return s.key; })
    };
}

function exportKeys() {
    if (keys.length === 0) {
        showToast('沒有可匯出的金鑰', 'error');
        return;
    }
    var dateStr = new Date().toISOString().slice(0, 10);
    var format = 'json';
    ['uri', 'aegis', '2fas'].forEach(function (f) {
        var el = $('export-format-' + f);
        if (el && el.checked) format = f;
    });

    if (format === 'uri') {
        downloadBlob(buildUriExportText(keys), '2fa-otpauth-' + dateStr + '.txt', 'text/plain;charset=utf-8');
        showToast('已匯出 otpauth URI 清單', 'success');
    } else if (format === 'aegis') {
        downloadBlob(JSON.stringify(buildAegisExportData(keys), null, 2), '2fa-aegis-' + dateStr + '.json', 'application/json');
        showToast('已匯出 Aegis 相容備份', 'success');
    } else if (format === '2fas') {
        downloadBlob(JSON.stringify(build2FASExportData(keys), null, 2), '2fa-2fas-' + dateStr + '.json', 'application/json');
        showToast('已匯出 2FAS 相容備份', 'success');
    } else {
        downloadBlob(JSON.stringify(buildOwnExportData(keys), null, 2), '2fa-backup-' + dateStr + '.json', 'application/json');
        showToast('已匯出 JSON 備份', 'success');
    }
    hideExportModal();
}

/* ================================================================
 * 資料衝突處理
 * ============================================================== */
var conflictData = null;

async function showConflictModal(localData, cloudData) {
    conflictData = { local: localData, cloud: cloudData };
    var modal = $('conflict-modal');
    $('local-update-time').textContent = new Date(localData.updatedAt).toLocaleString('zh-TW');
    $('cloud-update-time').textContent = new Date(cloudData.updatedAt || Date.now()).toLocaleString('zh-TW');
    try {
        var localKeys = await decrypt(localData.encryptedData, masterKey);
        var cloudKeys = await decrypt(cloudData.data, masterKey);
        $('local-key-count').textContent = localKeys.length;
        $('cloud-key-count').textContent = cloudKeys.length;
    } catch (e) {
        $('local-key-count').textContent = '無法解密';
        $('cloud-key-count').textContent = '無法解密';
    }
    modal.classList.remove('hidden');
}

async function resolveConflict(choice) {
    $('conflict-modal').classList.add('hidden');
    if (!conflictData) return;
    try {
        if (choice === 'local') {
            keys = sanitizeKeys(await decrypt(conflictData.local.encryptedData, masterKey));
            await apiSave(currentKeyHash, conflictData.local.encryptedData, currentSalt, CURRENT_VERSION);
            showToast('已使用本機資料並同步到雲端', 'success');
        } else {
            keys = sanitizeKeys(await decrypt(conflictData.cloud.data, masterKey));
            await offlineManager.saveOfflineCache(currentKeyHash, conflictData.cloud.data, currentSalt, CURRENT_VERSION, conflictData.cloud.updatedAt);
            showToast('已使用雲端資料並更新本機快取', 'success');
        }
        saveSession(await exportKeyB64(masterKey), currentKeyHash, currentSalt, settings.remember);
        showMainApp();
    } catch (error) {
        console.error('Conflict resolution error:', error);
        showToast('資料解密失敗，請重新登入', 'error');
        lockScreen(null);
    }
    conflictData = null;
}

async function triggerSyncCheck() {
    if (!masterKey || !currentKeyHash || !offlineManager.isOnline) return;
    try {
        var cloudData = await loadKeysFromCloud(currentKeyHash);
        var offlineData = await offlineManager.getOfflineCache(currentKeyHash);
        if (cloudData.exists && offlineData && offlineManager.detectConflict(offlineData, cloudData.updatedAt || Date.now())) {
            await showConflictModal(offlineData, cloudData);
        } else if (cloudData.exists) {
            await offlineManager.saveOfflineCache(currentKeyHash, cloudData.data, currentSalt, CURRENT_VERSION, cloudData.updatedAt);
            keys = sanitizeKeys(await decrypt(cloudData.data, masterKey));
            renderKeys();
        }
    } catch (error) {
        console.error('Sync check error:', error);
    }
}

/* ================================================================
 * 離線 UI
 * ============================================================== */
function updateNetworkStatus(isOnline) {
    var indicator = $('network-status');
    if (!indicator) return;
    var text = indicator.querySelector('.status-text');
    indicator.classList.toggle('offline', !isOnline);
    indicator.classList.toggle('online', isOnline);
    if (text) text.textContent = isOnline ? '線上' : '離線';
}

function showOfflineBanner(customText) {
    var banner = $('offline-banner');
    var text = $('offline-banner-text');
    text.textContent = customText || '離線模式';
    banner.classList.remove('hidden');
    updateNetworkStatus(false);
}

function hideOfflineBanner() {
    $('offline-banner').classList.add('hidden');
    updateNetworkStatus(offlineManager.isOnline);
}

/* ================================================================
 * 設定 modal
 * ============================================================== */
function showSettingsModal() {
    // 主題分段按鈕
    document.querySelectorAll('#settings-modal [data-theme-value]').forEach(function (b) {
        b.classList.toggle('active', b.dataset.themeValue === (settings.theme || 'auto'));
    });
    // 自動鎖定
    var sel = $('autolock-select');
    if (sel) sel.value = String(settings.autoLockMinutes);
    // 開關
    var priv = $('privacy-toggle'); if (priv) priv.checked = !!settings.privacyMode;
    var clip = $('clipboard-toggle'); if (clip) clip.checked = !!settings.clearClipboard;
    var ver = $('settings-version'); if (ver) ver.textContent = '版本 ' + APP_VERSION;
    hideError('settings-error');
    $('settings-modal').classList.remove('hidden');
}

function hideSettingsModal() {
    $('settings-modal').classList.add('hidden');
}

function onThemeSegmentClick(button) {
    settings.theme = button.dataset.themeValue || 'auto';
    saveSettings();
    applyTheme();
    document.querySelectorAll('#settings-modal [data-theme-value]').forEach(function (b) {
        b.classList.toggle('active', b === button);
    });
}

function onAutoLockChange(value) {
    settings.autoLockMinutes = toInt(value, DEFAULT_SETTINGS.autoLockMinutes);
    saveSettings();
    // 立即套用新的期限
    if (masterKey) touchSessionNow();
    showToast('自動鎖定：' + (settings.autoLockMinutes > 0 ? labelOfAutoLock(settings.autoLockMinutes) : '永不'), 'info');
}

function labelOfAutoLock(v) {
    var opt = AUTO_LOCK_OPTIONS.find(function (o) { return o.value === v; });
    return opt ? opt.label : (v + ' 分鐘');
}

function touchSessionNow() {
    lastSessionTouch = 0; // 強制下一次 touchSession 立即寫入
    touchSession();
}

function onPrivacyToggle(checked) {
    updateSetting('privacyMode', checked);
    privacyRevealed.clear();
    if (masterKey) renderKeys();
    showToast(checked ? '隱私模式已開啟：驗證碼已遮蔽' : '隱私模式已關閉', 'info');
}

function onClipboardToggle(checked) {
    updateSetting('clearClipboard', checked);
    if (!checked) {
        clipboardTimers.forEach(clearTimeout);
        clipboardTimers = [];
    }
    showToast(checked ? '複製 60 秒後將自動清除剪貼簿' : '已關閉剪貼簿自動清除', 'info');
}

async function clearLocalCache() {
    var ok = await confirmModal({
        title: '清除本機快取',
        message: '將清除這臺裝置上的離線快取。雲端資料不受影響，但清除後需聯網才能登入。',
        confirmText: '清除',
        danger: true
    });
    if (!ok) return;
    await offlineManager.clearAll();
    showToast('已清除本機離線快取', 'success');
}

async function deleteCloudData() {
    var ok = await confirmModal({
        title: '刪除雲端資料',
        message: '將永久刪除伺服器上的加密資料，此操作無法復原。請先確認已匯出備份。刪除後將自動登出。',
        confirmText: '永久刪除',
        danger: true,
        requireText: '刪除'
    });
    if (!ok) return;
    try {
        if (currentKeyHash && offlineManager.isOnline) {
            await apiDelete(currentKeyHash);
        }
        showToast('雲端資料已刪除', 'success');
        hideSettingsModal();
        lockScreen(null);
    } catch (e) {
        showToast('刪除失敗：網路錯誤', 'error');
    }
}

/* ================================================================
 * 事件繫結（不使用 inline handler）
 * ============================================================== */
function setupEventWiring() {
    // ---- 解鎖 / 建立帳戶 ----
    $('setup-link').addEventListener('click', showSetupForm);
    $('unlock-link').addEventListener('click', showLoginForm);
    document.querySelectorAll('a[role="button"]').forEach(function (link) {
        link.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); link.click(); }
        });
    });
    $('setup-submit').addEventListener('click', setupPassword);
    $('unlock-submit').addEventListener('click', unlock);
    $('password').addEventListener('keypress', function (e) { if (e.key === 'Enter') unlock(); });
    $('new-password').addEventListener('keypress', function (e) { if (e.key === 'Enter') $('confirm-password').focus(); });
    $('confirm-password').addEventListener('keypress', function (e) { if (e.key === 'Enter') setupPassword(); });
    $('new-password').addEventListener('input', function () { renderPasswordStrength(this.value); });
    document.querySelectorAll('[data-toggle-pw]').forEach(function (btn) {
        btn.addEventListener('click', function () { togglePasswordVisibility(btn); });
    });
    var remember = $('remember-me');
    if (remember) remember.checked = settings.remember !== false;

    // ---- 主畫面頂欄 ----
    $('add-btn').addEventListener('click', showAddModal);
    $('theme-btn').addEventListener('click', cycleTheme);
    $('settings-btn').addEventListener('click', showSettingsModal);
    $('logout-btn').addEventListener('click', logout);

    // ---- 搜尋 ----
    $('search-input').addEventListener('input', filterKeys);
    $('search-clear').addEventListener('click', clearSearch);

    // ---- 底部 ----
    $('import-btn').addEventListener('click', importKeys);
    $('export-btn').addEventListener('click', showExportModal);

    // ---- 新增 modal ----
    $('add-cancel').addEventListener('click', hideAddModal);
    $('add-cancel-other').addEventListener('click', hideAddModal);
    $('add-confirm').addEventListener('click', addKey);
    $('scan-start-btn').addEventListener('click', startQrScanner);
    document.querySelectorAll('.input-tabs button').forEach(function (btn) {
        btn.addEventListener('click', function () { switchInputTab(btn.dataset.tab); });
    });
    $('adv-type').addEventListener('change', updateAdvancedVisibility);
    $('add-modal').addEventListener('click', function (e) { if (e.target === this) hideAddModal(); });
    $('key-secret').addEventListener('keypress', function (e) { if (e.key === 'Enter') addKey(); });

    // ---- 編輯 modal ----
    $('edit-cancel').addEventListener('click', hideEditModal);
    $('edit-confirm').addEventListener('click', saveEdit);
    $('edit-type').addEventListener('change', updateEditVisibility);
    $('edit-modal').addEventListener('click', function (e) { if (e.target === this) hideEditModal(); });
    $('edit-name').addEventListener('keypress', function (e) { if (e.key === 'Enter') saveEdit(); });

    // ---- 匯入 modal ----
    $('import-cancel').addEventListener('click', hideImportModal);
    $('import-confirm').addEventListener('click', confirmImport);
    $('import-modal').addEventListener('click', function (e) { if (e.target === this) hideImportModal(); });

    // ---- 匯出 modal ----
    $('export-cancel').addEventListener('click', hideExportModal);
    $('export-confirm').addEventListener('click', exportKeys);
    $('export-modal').addEventListener('click', function (e) { if (e.target === this) hideExportModal(); });

    // ---- 設定 modal ----
    $('settings-close').addEventListener('click', hideSettingsModal);
    $('settings-modal').addEventListener('click', function (e) { if (e.target === this) hideSettingsModal(); });
    document.querySelectorAll('#settings-modal [data-theme-value]').forEach(function (btn) {
        btn.addEventListener('click', function () { onThemeSegmentClick(btn); });
    });
    $('autolock-select').addEventListener('change', function () { onAutoLockChange(this.value); });
    $('privacy-toggle').addEventListener('change', function () { onPrivacyToggle(this.checked); });
    $('clipboard-toggle').addEventListener('change', function () { onClipboardToggle(this.checked); });
    $('clear-cache-btn').addEventListener('click', clearLocalCache);
    $('delete-cloud-btn').addEventListener('click', deleteCloudData);

    // ---- 確認 modal ----
    $('confirm-cancel').addEventListener('click', function () { resolveConfirm(false); });
    $('confirm-ok').addEventListener('click', function () { resolveConfirm(true); });
    $('confirm-input').addEventListener('input', function () {
        var req = this.dataset.requireText;
        $('confirm-ok').disabled = !!(req && this.value.trim() !== req);
    });
    $('confirm-modal').addEventListener('click', function (e) {
        if (e.target === this && !$('confirm-ok').disabled) resolveConfirm(false);
    });

    // ---- 衝突 modal ----
    $('conflict-local').addEventListener('click', function () { resolveConflict('local'); });
    $('conflict-cloud').addEventListener('click', function () { resolveConflict('cloud'); });

    // ---- 金鑰清單（事件委派） ----
    var list = $('token-list');
    list.addEventListener('click', function (e) {
        var item = e.target.closest('.token-item');
        if (!item) return;
        var id = item.dataset.keyId;
        var actionEl = e.target.closest('[data-action]');
        if (actionEl) {
            var action = actionEl.dataset.action;
            if (action === 'edit') { showEditModal(id); return; }
            if (action === 'delete') { deleteKey(id); return; }
            if (action === 'next') { nextHotp(id); return; }
            if (action === 'reveal') { toggleReveal(id); return; }
            if (action === 'drag') { return; } // 拖曳由 mousedown 處理
        }
        var code = cachedCodes.get(id);
        if (code) copyCode(code, item);
    });
    list.addEventListener('mousedown', function (e) {
        var handle = e.target.closest('[data-action="drag"]');
        if (!handle) return;
        var item = handle.closest('.token-item');
        if (item) {
            dragArmed = true;
            item.setAttribute('draggable', 'true');
        }
    });
    list.addEventListener('dragstart', onDragStart);
    list.addEventListener('dragover', onDragOver);
    list.addEventListener('drop', onDrop);
    list.addEventListener('dragend', onDragEnd);
    document.addEventListener('mouseup', function () {
        if (dragArmed && !dragSrcId) {
            dragArmed = false;
            onDragEnd();
        }
    });

    // ---- 鍵盤快速鍵 ----
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            // 依序關閉最上層 modal（衝突 modal 必須選擇，不可 Esc 關閉）
            if (!$('confirm-modal').classList.contains('hidden')) { if (!$('confirm-ok').disabled) resolveConfirm(false); return; }
            if (!$('import-modal').classList.contains('hidden')) { hideImportModal(); return; }
            if (!$('export-modal').classList.contains('hidden')) { hideExportModal(); return; }
            if (!$('settings-modal').classList.contains('hidden')) { hideSettingsModal(); return; }
            if (!$('edit-modal').classList.contains('hidden')) { hideEditModal(); return; }
            if (!$('add-modal').classList.contains('hidden')) { hideAddModal(); return; }
        }
        if (e.key === '/' && !$('main-app').classList.contains('hidden')) {
            var tag = (document.activeElement && document.activeElement.tagName) || '';
            if (tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT') {
                var openModal = document.querySelector('.modal-overlay:not(.hidden)');
                if (!openModal) { e.preventDefault(); $('search-input').focus(); }
            }
        }
    });

    // ---- 活動 → 展延工作階段 ----
    ['pointerdown', 'keydown'].forEach(function (evt) {
        document.addEventListener(evt, onUserActivity, { passive: true });
    });
    document.addEventListener('visibilitychange', function () {
        if (document.hidden) {
            stopQrScanner();
        } else {
            // 回到前台：檢查是否已閒置逾時
            var s = peekSession();
            if (s && typeof s.expiresAt === 'number' && Date.now() > s.expiresAt && masterKey) {
                lockScreen('因閒置已自動鎖定');
            } else if (masterKey) {
                touchSession();
                updateDisplay();
            }
        }
    });

    window.addEventListener('beforeunload', function () { stopQrScanner(); });
}

/* ================================================================
 * 初始化
 * ============================================================== */
async function restoreSession() {
    var session = loadSession();
    if (!session) return false;
    try {
        masterKey = await importKeyFromB64(session.keyStr);
        currentKeyHash = session.keyHash;
        currentSalt = session.salt;

        if (offlineManager.isOnline) {
            try {
                var cloudData = await loadKeysFromCloud(currentKeyHash);
                if (cloudData.exists) {
                    keys = sanitizeKeys(await decrypt(cloudData.data, masterKey));
                    await offlineManager.saveOfflineCache(currentKeyHash, cloudData.data, currentSalt, CURRENT_VERSION, cloudData.updatedAt);
                    showMainApp();
                    hideOfflineBanner();
                    return true;
                }
            } catch (error) {
                console.error('Cloud load failed, trying offline:', error);
            }
        }

        var offlineData = await offlineManager.getOfflineCache(currentKeyHash);
        if (offlineData) {
            keys = sanitizeKeys(await decrypt(offlineData.encryptedData, masterKey));
            showMainApp();
            if (!offlineManager.isOnline) showOfflineBanner();
            return true;
        }
        // 兩邊都沒有資料 → 登出
        resetAuthState();
        clearSession();
        return false;
    } catch (e) {
        console.error('Session restore failed:', e);
        resetAuthState();
        clearSession();
        return false;
    }
}

function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) return;
    window.addEventListener('load', function () {
        navigator.serviceWorker.register('/service-worker.js')
            .then(function (registration) {
                registration.addEventListener('updatefound', function () {
                    var newWorker = registration.installing;
                    if (!newWorker) return;
                    newWorker.addEventListener('statechange', function () {
                        if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                            showToast('發現新版本，請重新整理頁面', 'info');
                        }
                    });
                });
            })
            .catch(function (error) {
                console.error('[SW] Registration failed:', error);
            });
    });
}

async function init() {
    loadSettings();
    initThemeListener();
    applyTheme();

    try {
        await offlineManager.init();
        offlineManager.setupOnlineListener();
    } catch (error) {
        console.error('Offline manager initialization failed:', error);
        offlineManager.db = null;
    }

    updateNetworkStatus(offlineManager.isOnline);
    if (!offlineManager.isOnline) showOfflineBanner();

    setupUploadZone();
    setupEventWiring();
    registerServiceWorker();

    // 登入冷卻倒數（若有）
    if (lockoutRemainingMs() > 0) startLockoutCountdown();

    var restored = await restoreSession();
    if (!restored) {
        $('setup-password').classList.add('hidden');
        $('enter-password').classList.remove('hidden');
        if (lockoutRemainingMs() <= 0) {
            setTimeout(function () { $('password').focus(); }, 100);
        }
    }
}

/* ================================================================
 * 啟動（僅瀏覽器）
 * ============================================================== */
if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { init(); });
    } else {
        init();
    }
}

/* ================================================================
 * Node CJS 匯出（僅供單元測試，瀏覽器端忽略）
 * ============================================================== */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        // 純函式
        base32Decode: base32Decode,
        bytesToBase32: bytesToBase32,
        generateTOTP: generateTOTP,
        generateHOTP: generateHOTP,
        generateOTP: generateOTP,
        keyOpts: keyOpts,
        normalizeKey: normalizeKey,
        cleanSecret: cleanSecret,
        isValidSecret: isValidSecret,
        normalizeAlgo: normalizeAlgo,
        parseOtpauthUri: parseOtpauthUri,
        buildOtpauthUri: buildOtpauthUri,
        decodeMigrationPayload: decodeMigrationPayload,
        parseImportContent: parseImportContent,
        buildOwnExportData: buildOwnExportData,
        buildUriExportText: buildUriExportText,
        buildAegisExportData: buildAegisExportData,
        build2FASExportData: build2FASExportData,
        markImportDuplicates: markImportDuplicates,
        passwordStrength: passwordStrength,
        validatePassword: validatePassword,
        formatCode: formatCode,
        PBKDF2_ITERATIONS: PBKDF2_ITERATIONS
    };
}
