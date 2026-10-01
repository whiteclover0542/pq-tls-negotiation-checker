// 실행: node check.js — 논문 표 2·7의 결과가 판정 로직에서 그대로 나오는지 확인한다
var assert = require('assert');
var fs = require('fs');
var A = require('./analyze.js');
var S = require('./samples.js');
var byId = {}; S.forEach(function (s) { byId[s.id] = A.analyzeLog(s.text); });

// 3.5.6 DEFAULT: HRR 뒤 하이브리드 (표 7)
assert.strictEqual(byId.fixed.level, 'ok');
assert.strictEqual(byId.fixed.facts.hrr, true);
assert.strictEqual(byId.fixed.facts.negotiated, 'X25519MLKEM768');
// 3.5.5 DEFAULT + 고전 우선 클라이언트: C3 이지만 서버 목록은 하이브리드 1순위 → 경고
assert.strictEqual(byId.cve.level, 'warn');
assert.strictEqual(byId.cve.facts.hrr, false);
assert.deepStrictEqual(byId.cve.facts.serverGroups.slice(0, 2), ['X25519MLKEM768', 'X25519']);
// 합성 C2 → 단일 tuple: C2형 PQ 누락 (표 2)
assert.strictEqual(byId.c2.level, 'bad');
assert.deepStrictEqual(byId.c2.facts.advertised, ['X25519MLKEM768', 'X25519']);
assert.deepStrictEqual(byId.c2.facts.keyShares, ['X25519']);

// 잘못된 입력에도 멈추지 않는다
['', 'hello', null, undefined, '    ClientHello, Length=1\n'].forEach(function (x) {
  assert.ok(['error'].indexOf(A.analyzeLog(x).level) >= 0);
});

var C = function (impl, version, groups) { return A.analyzeConfig({ impl: impl, version: version, groups: groups }); };
assert.strictEqual(C('openssl', '3.5.5', 'X25519MLKEM768:X25519').level, 'bad');             // S1
assert.strictEqual(C('openssl', '3.5.5', 'X25519MLKEM768:X25519').suggestion, 'X25519MLKEM768/X25519');
assert.strictEqual(C('openssl', '3.5.5', 'X25519MLKEM768/X25519').level, 'ok');              // S2
assert.strictEqual(C('openssl', '3.5.5', 'DEFAULT').level, 'bad');                           // S3 영향
assert.strictEqual(C('openssl', '3.6.1', 'DEFAULT').level, 'bad');
assert.strictEqual(C('openssl', '3.5.6', 'DEFAULT').level, 'ok');                            // S3 수정
assert.strictEqual(C('openssl', '3.6.2', 'DEFAULT').level, 'ok');
assert.strictEqual(C('openssl', '3.7.0', 'DEFAULT').level, 'warn');                          // 근거 범위 밖
assert.strictEqual(C('openssl', '4.0.0', 'DEFAULT').level, 'warn');
assert.strictEqual(C('openssl', '', 'DEFAULT').level, 'warn');
assert.strictEqual(C('openssl', '3.5.5', '').level, 'ok');                                   // S4
assert.strictEqual(C('openssl', '3.5.6', 'ssl_ecdh_curve X25519MLKEM768:X25519;').level, 'bad');
assert.strictEqual(C('openssl', '3.5.6', 'X25519:secp256r1').level, 'warn');
assert.strictEqual(C('openssl', '3.0.13', 'X25519').level, 'info');
assert.deepStrictEqual(C('nss').predictions, ['하이브리드', '고전 (HRR 없음)', '고전 (클라이언트 선호)']);
assert.deepStrictEqual(C('go').predictions[2], 'HRR → 하이브리드');
['abc', '///', ':::', '*'].forEach(function (g) { C('openssl', 'x.y', g); });
C(); C('nope', null, null);

// 요약 줄만 남은 trace도 최종 협상 그룹을 읽고, 화면은 키보드 제출 경로를 제공한다.
var summaryOnly = '    ClientHello, Length=1\n      extension_type=supported_groups(10)\n        X25519MLKEM768 (4588)\n    ServerHello, Length=1\nNegotiated TLS1.3 group: X25519MLKEM768\n';
assert.strictEqual(A.analyzeLog(summaryOnly).facts.negotiated, 'X25519MLKEM768');
var page = fs.readFileSync('index.html', 'utf8');
assert.ok(page.indexOf('<form id="logForm">') >= 0);
assert.ok(page.indexOf('<form id="cfgForm">') >= 0);
assert.ok(page.indexOf('button:focus-visible') >= 0);

console.log('check.js: 모든 확인 통과');
