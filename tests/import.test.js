'use strict';
// 執行：npm test（需要 Node >= 18）
const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../public/app.js');

const S1 = 'JBSWY3DPEHPK3PXP';
const S2 = 'KRSXG5CTMVRXEZLU';
const S3 = 'MFRGGZDFMZTWQ2LK';
const S4 = 'NBSWY3DPFQQHO33S';

const parse = (obj) => app.parseImportContent(typeof obj === 'string' ? obj : JSON.stringify(obj));
const valid = (r) => r.entries.filter((e) => !e.invalidReason);
const invalid = (r) => r.entries.filter((e) => e.invalidReason);

/* ---------- 1. Steam 不可被當成普通 TOTP ---------- */
test('andOTP STEAM 項目標為無效，不當成 6 位 TOTP', () => {
  const r = parse([
    { secret: S1, issuer: 'GitHub', label: 'u', digits: 6, type: 'TOTP', algorithm: 'SHA1', period: 30 },
    { secret: S2, issuer: 'Steam', label: 's', digits: 5, type: 'STEAM', algorithm: 'SHA1', period: 30 },
  ]);
  assert.equal(valid(r).length, 1);
  assert.equal(valid(r)[0].name, 'GitHub');
  assert.equal(invalid(r).length, 1);
  assert.match(invalid(r)[0].invalidReason, /Steam/);
});

test('Bitwarden steam:// 不會被匯入成被污染的金鑰', () => {
  const r = parse({
    encrypted: false,
    items: [
      { type: 1, name: 'S', login: { totp: 'steam://' + S4 } },
      { type: 1, name: 'GH', login: { totp: 'otpauth://totp/GH:u?secret=' + S1 + '&issuer=GH' } },
    ],
  });
  assert.equal(r.format, 'bitwarden');
  assert.equal(valid(r).length, 1);
  assert.equal(valid(r)[0].name, 'GH');
  const bad = invalid(r);
  assert.equal(bad.length, 1);
  assert.ok(!bad[0].secret.startsWith('STEAM'), '不應產生 STEAM 前綴的假金鑰');
});

test('Aegis steam 仍標為無效（回歸）', () => {
  const r = parse({
    version: 1, header: { slots: null, params: null },
    db: { version: 2, entries: [
      { type: 'totp', name: 'acc', issuer: 'GH', info: { secret: S1, algo: 'SHA1', digits: 6, period: 30 } },
      { type: 'steam', name: 's', issuer: 'Steam', info: { secret: S2, algo: 'SHA1', digits: 5, period: 30 } },
    ] },
  });
  assert.equal(valid(r).length, 1);
  assert.equal(invalid(r).length, 1);
});

test('otpauth URI 帶 encoder=steam 標為無效', () => {
  const r = parse('otpauth://totp/Steam:me?secret=' + S1 + '&issuer=Steam&digits=5&encoder=steam');
  assert.equal(valid(r).length, 0);
  assert.equal(invalid(r).length, 1);
});

test('含非 Base32 字元的金鑰標為無效，而非默默清洗', () => {
  const r = parse({ entries: [], tokens: [{ issuer: 'X', label: 'y', secret: 'abc!!def1890zzzz', type: 'TOTP' }] });
  assert.equal(valid(r).length, 0);
  assert.equal(invalid(r).length, 1);
});

test('小寫、含空白與連字號的合法 Base32 仍可匯入', () => {
  const r = parse([{ issuer: 'X', account: 'y', secret: 'jbsw y3dp-ehpk 3pxp', type: 'TOTP' }]);
  assert.equal(valid(r).length, 1);
  assert.equal(valid(r)[0].secret, S1);
});

/* ---------- 2. Raivo 的 kind 欄位 ---------- */
test('Raivo HOTP（kind）正確識別，counter 與 digits 保留', () => {
  const r = parse([
    { kind: 'TOTP', issuer: 'GitHub', account: 'a@b.c', secret: S1, algorithm: 'SHA1', digits: '6', timer: '30', counter: '0' },
    { kind: 'HOTP', issuer: 'Bank', account: 'y', secret: S2, algorithm: 'SHA256', digits: '8', timer: '30', counter: '5' },
  ]);
  assert.equal(valid(r).length, 2);
  const hotp = valid(r).find((e) => e.name === 'Bank');
  assert.equal(hotp.type, 'hotp');
  assert.equal(hotp.counter, 5);
  assert.equal(hotp.digits, 8);
  assert.equal(hotp.algorithm, 'SHA256');
  assert.equal(valid(r).find((e) => e.name === 'GitHub').type, 'totp');
});

/* ---------- 3. 重複判斷 ---------- */
test('同服務不同帳號不會因 name 相同被標為重複', () => {
  const r = parse(
    'otpauth://totp/GitHub:alice?secret=' + S1 + '&issuer=GitHub\n' +
    'otpauth://totp/GitHub:bob?secret=' + S2 + '&issuer=GitHub'
  );
  const marked = app.markImportDuplicates(r.entries, [{ name: 'GitHub', secret: S3, type: 'totp' }]);
  assert.deepEqual(marked.map((e) => e.duplicate), [false, false]);
});

test('相同 secret + type 仍標為重複（即使名稱不同）', () => {
  const r = parse('otpauth://totp/Renamed:me?secret=' + S1 + '&issuer=Renamed');
  const marked = app.markImportDuplicates(r.entries, [{ name: 'GitHub', secret: S1.toLowerCase(), type: 'totp' }]);
  assert.equal(marked[0].duplicate, true);
});

test('相同 secret 但 type 不同不算重複', () => {
  const r = parse([{ kind: 'HOTP', issuer: 'X', account: 'y', secret: S1, counter: '1' }]);
  const marked = app.markImportDuplicates(r.entries, [{ name: 'X', secret: S1, type: 'totp' }]);
  assert.equal(marked[0].duplicate, false);
});

/* ---------- 4. 2FAS 加密備份 ---------- */
test('2FAS 加密備份（servicesEncrypted）回報 encrypted', () => {
  const r = parse({ services: [], groups: [], servicesEncrypted: 'a:b:c', reference: 'r', schemaVersion: 4 });
  assert.equal(r.error, 'encrypted');
  assert.equal(r.format, '2fas');
});

test('2FAS 明文備份仍可匯入（回歸）', () => {
  const r = parse({
    services: [{ name: 'GitHub', secret: S1, otp: { account: 'u', issuer: 'GitHub', digits: 6, period: 30, algorithm: 'SHA1', tokenType: 'TOTP' }, order: { position: 0 } }],
    groups: [], schemaVersion: 4,
  });
  assert.equal(r.format, '2fas');
  assert.equal(valid(r).length, 1);
  assert.equal(valid(r)[0].account, 'u');
});

/* ---------- 其他格式回歸 ---------- */
test('FreeOTP+ int[] secret', () => {
  const r = parse({ tokens: [{ algo: 'SHA1', counter: 0, digits: 6, issuer: 'GH', label: 'u', period: 30, secret: [-111, 22, 33, 44, 55, 66, 77, 88, 99, 12], type: 'TOTP' }] });
  assert.equal(r.format, 'freeotp');
  assert.equal(valid(r).length, 1);
});

test('Aegis 加密備份回報 encrypted', () => {
  const r = parse({ version: 1, header: { slots: [{ type: 1 }], params: {} }, db: 'base64==' });
  assert.equal(r.error, 'encrypted');
});

test('Ente / 本應用備份 / URI 清單 / 無有效項目 / 無法辨識', () => {
  assert.equal(parse({ items: [{ payload: 'otpauth://totp/GH:u?secret=' + S1 + '&issuer=GH' }] }).format, 'ente');
  assert.equal(parse({ app: '2fa-authenticator', version: 2, keys: [{ name: 'GH', secret: S1 }] }).format, 'own');
  assert.equal(parse('otpauth://totp/a?secret=' + S1 + '\notpauth://hotp/b?secret=' + S2 + '&counter=3').entries.length, 2);
  assert.equal(parse({ encrypted: false, items: [{ type: 1, name: 'n', login: {} }] }).error, 'no-keys');
  assert.equal(parse('hello world').error, 'unsupported');
  assert.equal(parse('').error, 'empty');
});

test('自家 JSON 匯出格式可無損往返', () => {
  const exported = { app: '2fa-authenticator', version: 2, keys: [
    { name: 'GH', secret: S1, account: 'u', issuer: 'GH' },
    { name: 'Bank', secret: S2, type: 'hotp', counter: 7, digits: 8, algorithm: 'SHA256' },
    { name: 'Slow', secret: S3, period: 60 },
  ] };
  const r = parse(exported);
  assert.equal(valid(r).length, 3);
  const bank = valid(r).find((e) => e.name === 'Bank');
  assert.deepEqual([bank.type, bank.counter, bank.digits, bank.algorithm], ['hotp', 7, 8, 'SHA256']);
  assert.equal(valid(r).find((e) => e.name === 'Slow').period, 60);
});
