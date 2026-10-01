// 판정 로직. 모든 규칙은 논문 docs/PAPER.md 의 §2.1(용어), 표 2(협상 함수), 표 7·8(CVE-2026-2673)에서 가져왔다.
// 브라우저(<script>)와 node(check.js) 양쪽에서 쓴다.

var GROUP_NAMES = {
  23: 'secp256r1', 24: 'secp384r1', 25: 'secp521r1', 29: 'X25519', 30: 'X448',
  256: 'ffdhe2048', 257: 'ffdhe3072', 258: 'ffdhe4096', 259: 'ffdhe6144', 260: 'ffdhe8192',
  512: 'MLKEM512', 513: 'MLKEM768', 514: 'MLKEM1024',
  4587: 'SecP256r1MLKEM768', 4588: 'X25519MLKEM768', 4589: 'SecP384r1MLKEM1024',
  25497: 'X25519Kyber768Draft00', 25498: 'SecP256r1Kyber768Draft00'
};

function isPQ(name) { return /mlkem|kyber/i.test(name); }

function groupName(raw, code) {
  return GROUP_NAMES[code] || raw.replace(/^ecdh_/, '');
}

// RFC 8446 HRR 고정 random 의 뒤 28바이트 (s_client -trace 는 앞 4바이트를 gmt_unix_time 으로 따로 찍는다)
var HRR_RANDOM_TAIL = 'E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C';

// openssl s_client -trace 출력에서 핸드셰이크 메시지를 뽑는다
function parseTrace(text) {
  var lines = String(text || '').replace(/\r/g, '').split('\n');
  var msgs = [], cur = null, field = null, summaryGroup = null;
  for (var i = 0; i < lines.length; i++) {
    var l = lines[i], m;
    if ((m = l.match(/^\s*(ClientHello|ServerHello|EncryptedExtensions), Length=/))) {
      cur = { type: m[1], groups: [], shares: [], random: '' };
      msgs.push(cur); field = null; continue;
    }
    if ((m = l.match(/^Negotiated TLS1\.3 group:\s*(\S+)/))) summaryGroup = m[1];
    if (!cur) continue;
    if (/^\S/.test(l) || /^\s*$/.test(l)) { cur = null; field = null; continue; }
    if (/extension_type=supported_groups\(10\)/.test(l)) { field = 'groups'; continue; }
    if (/extension_type=key_share\(51\)/.test(l)) { field = 'shares'; continue; }
    if (/extension_type=/.test(l)) { field = null; continue; }
    if ((m = l.match(/random_bytes \(len=\d+\):\s*([0-9A-Fa-f]+)/))) { cur.random = m[1].toUpperCase(); continue; }
    if (field === 'groups' && (m = l.match(/^\s+(.+?) \((\d+)\)\s*$/))) cur.groups.push(groupName(m[1], +m[2]));
    if (field === 'shares' && (m = l.match(/NamedGroup:\s*(.+?) \((\d+)\)/))) cur.shares.push(groupName(m[1], +m[2]));
  }
  return { msgs: msgs, summaryGroup: summaryGroup };
}

function analyzeLog(text) {
  var p = parseTrace(text);
  var hellos = p.msgs.filter(function (m) { return m.type === 'ClientHello'; });
  var servers = p.msgs.filter(function (m) { return m.type === 'ServerHello'; });
  var ee = p.msgs.filter(function (m) { return m.type === 'EncryptedExtensions'; })[0];
  if (!hellos.length) {
    return { level: 'error', title: 'ClientHello를 찾지 못했습니다',
      reasons: ['openssl s_client 의 -trace 출력이 아니거나 앞부분이 잘렸습니다.'],
      advice: ['아래 명령의 출력 전체를 붙여 넣으세요: openssl s_client -connect 호스트:443 -trace </dev/null'] };
  }
  var ch = hellos[0];
  var hrr = servers.some(function (s) { return s.random === HRR_RANDOM_TAIL; }) || hellos.length > 1;
  var finalSH = servers.filter(function (s) { return s.random !== HRR_RANDOM_TAIL; }).pop();
  var final = (finalSH && finalSH.shares[0]) || p.summaryGroup;
  var facts = {
    advertised: ch.groups, keyShares: ch.shares, hrr: hrr,
    negotiated: final || null, serverGroups: ee && ee.groups.length ? ee.groups : null
  };
  var r = { facts: facts, reasons: [], advice: [] };
  if (!final) {
    r.level = 'error'; r.title = '협상된 그룹을 찾지 못했습니다';
    r.reasons.push('ServerHello가 없습니다. 핸드셰이크가 중간에 실패했거나 출력이 잘렸습니다.');
    r.advice.push('연결 자체가 실패했다면 하이브리드 여부를 판정할 수 없습니다. 오류 메시지를 먼저 확인하세요.');
    return r;
  }
  if (!ch.groups.length) r.reasons.push('ClientHello에서 supported_groups 목록을 읽지 못해 클라이언트 유형 판정이 부정확할 수 있습니다.');

  var advPQ = ch.groups.some(isPQ);
  var serverPQFirst = facts.serverGroups && isPQ(facts.serverGroups[0]);
  var serverNoPQ = facts.serverGroups && !facts.serverGroups.some(isPQ);

  if (isPQ(final)) {
    r.level = 'ok'; r.title = '하이브리드 PQ 협상: ' + final;
    r.reasons.push(hrr
      ? '클라이언트가 처음엔 하이브리드 key share를 보내지 않았지만, 서버가 HRR로 요청해 하이브리드를 받았습니다. 논문 표 2의 클라이언트 순서·서버 순서 유형의 동작입니다.'
      : '클라이언트가 보낸 하이브리드 key share로 바로 협상됐습니다(논문 표 2의 C1 결과).');
    return r;
  }

  // 여기부터 최종 그룹이 고전
  if (!advPQ) {
    r.level = 'info'; r.title = 'PQ 미적용: 클라이언트가 하이브리드를 광고하지 않음';
    r.reasons.push('클라이언트 광고 목록에 하이브리드 그룹이 없어, 양쪽이 하이브리드를 쓸 조건 자체가 성립하지 않습니다(논문 §2.1 "PQ 미적용").');
    r.advice.push('OpenSSL 3.5 이상 클라이언트로 다시 시험하세요. 예: -groups X25519MLKEM768:*X25519');
    return r;
  }
  if (serverNoPQ) {
    r.level = 'warn'; r.title = 'PQ 미적용: 서버가 하이브리드를 지원하지 않음';
    r.reasons.push('서버가 보낸 지원 그룹 목록(EncryptedExtensions)에 하이브리드 그룹이 없습니다.');
    r.advice.push('서버 설정과 TLS 라이브러리 버전을 확인하세요. 논문은 배포판 Caddy 2.6.2가 이렇게 X25519만 협상한 사례를 관측했습니다(§6.2).');
    return r;
  }
  if (!isPQ(ch.groups[0])) {
    r.level = serverPQFirst ? 'warn' : 'info';
    r.title = '클라이언트 선호 고전 협상 (C3)';
    r.reasons.push('클라이언트가 고전 그룹(' + ch.groups[0] + ')을 1순위로 광고했습니다. 논문은 이를 PQ 누락이 아닌 정상 협상으로 분류합니다(§2.1).');
    if (serverPQFirst) {
      r.reasons.push('그런데 서버는 하이브리드를 1순위로 둔 목록을 보냈습니다. 서버 순서 유형이었다면 HRR로 하이브리드를 요청했을 것입니다(논문 표 2, 표 7의 S2).');
      r.reasons.push('이 로그만으로는 OpenSSL 단일 tuple(S1, 문서화된 동작)과 CVE-2026-2673(S3, 결함)을 구분할 수 없습니다(논문 §6.5).');
      r.advice.push('아래 "서버 설정 점검"에 서버의 그룹 설정과 버전을 넣어 어느 쪽인지 확인하세요.');
    }
    return r;
  }
  r.level = 'bad';
  if (!ch.shares.some(isPQ)) {
    r.title = 'C2형 PQ 누락: 하이브리드를 원했지만 고전(' + final + ')으로 협상됨';
    r.reasons.push('클라이언트는 하이브리드를 1순위로 광고했지만 초기 key share는 고전만 보냈고(C2), 서버는 HRR 없이 그 고전 key share를 받아들였습니다.');
    r.reasons.push('논문 표 2에서 이렇게 동작한 것은 key share 우선 유형(OpenSSL 단일 tuple, NSS 3.120)과, 표 7의 CVE-2026-2673 영향 버전(OpenSSL 3.5.5 DEFAULT)입니다.');
    if (serverPQFirst) r.reasons.push('서버는 하이브리드를 1순위로 둔 목록을 보냈습니다. 서버의 정책과 실제 선택이 어긋났습니다.');
    r.advice.push('OpenSSL 서버라면 "서버 설정 점검"으로 단일 tuple인지, CVE 영향 버전 + DEFAULT인지 확인하세요.');
    r.advice.push('NSS 서버라면 기본 규칙으로는 하이브리드가 선택되지 않습니다(논문 §6.1, §7.3).');
  } else {
    r.title = 'PQ 누락: 하이브리드 key share를 받고도 고전(' + final + ')을 선택';
    r.reasons.push('클라이언트가 하이브리드를 1순위로 광고하고 하이브리드 key share도 보냈는데 서버가 고전을 골랐습니다.');
    r.reasons.push('논문에서 측정하지 않은 경우입니다. 서버가 고전을 우선하도록 설정됐을 가능성이 큽니다 [추정].');
    r.advice.push('서버의 그룹 우선순위 설정을 확인하세요.');
  }
  return r;
}

// ---- 서버 설정 점검 ----

var OUT = { hy: '하이브리드', hrrHy: 'HRR → 하이브리드', cl: '고전 (HRR 없음)', clC3: '고전 (클라이언트 선호)', clGuess: '고전 [추정·논문 미측정]', clNoPQ: '고전 (PQ 미적용)' };
var TYPES = {
  ksFirst: { name: 'key share 우선', c: [OUT.hy, OUT.cl, OUT.clC3] },
  clientOrder: { name: '클라이언트 순서', c: [OUT.hy, OUT.hrrHy, OUT.clC3] },
  serverOrder: { name: '서버 순서', c: [OUT.hy, OUT.hrrHy, OUT.hrrHy] }
};

// 논문 표 2 (E8) — OpenSSL 외 구현은 설정 문자열과 무관하게 이 행을 보여 준다
var IMPLS = {
  nss: { label: 'NSS', tested: '3.120 selfserv', type: 'ksFirst',
    note: 'NSS는 X25519와 X25519MLKEM768을 같은 256비트 강도로 보고, 받은 X25519 key share를 대체재로 받아들입니다(lib/ssl/tls13con.c, 논문 §6.1).' },
  boringssl: { label: 'BoringSSL', tested: 'commit 7fb4d3d, 697ee71', type: 'clientOrder',
    note: '클라이언트의 supported_groups 순서로 그룹을 정하고, key share가 없으면 HRR을 보냅니다(ssl/extensions.cc, 논문 §6.1).' },
  rustls: { label: 'rustls', tested: '0.23.45', type: 'clientOrder', note: '클라이언트가 광고한 순서를 따릅니다(논문 표 2).' },
  go: { label: 'Go crypto/tls', tested: '1.26', type: 'serverOrder',
    note: 'CurvePreferences 순서는 무시되고 내부 선호(하이브리드 우선)로 고릅니다(논문 §6.1).' }
};

function parseVersion(v) {
  var m = String(v || '').trim().match(/^(?:openssl\s*)?(\d+)\.(\d+)\.(\d+)/i);
  return m ? [+m[1], +m[2], +m[3]] : null;
}

// CVE 레코드 기준 영향 범위: 3.5.0–3.5.5, 3.6.0–3.6.1 (논문 §7.3, 참고문헌 [6])
function cveAffected(v) {
  return v[0] === 3 && ((v[1] === 5 && v[2] <= 5) || (v[1] === 6 && v[2] <= 1));
}

function cveFixVerified(v) {
  return v[0] === 3 && ((v[1] === 5 && v[2] >= 6) || (v[1] === 6 && v[2] >= 2));
}

function cleanGroups(s) {
  return String(s || '').trim()
    .replace(/^(-groups|-curves|groups|curves|ssl_ecdh_curve|ssl_ecdh_curves)\b\s*[=:]?\s*/i, '')
    .replace(/[;"']/g, '').trim();
}

function result(level, title, type, extra) {
  var r = { level: level, title: title, reasons: [], advice: [], type: type ? TYPES[type].name : null,
    predictions: type ? TYPES[type].c.slice() : null };
  for (var k in extra) r[k] = extra[k];
  return r;
}

function analyzeConfig(input) {
  input = input || {};
  var impl = input.impl || 'openssl';
  if (IMPLS[impl]) {
    var d = IMPLS[impl];
    var r = result(d.type === 'ksFirst' ? 'bad' : 'ok', d.label + ': ' + TYPES[d.type].name + ' 유형', d.type);
    r.reasons.push(d.note);
    r.reasons.push('논문이 시험한 버전: ' + d.tested + '. 다른 버전·설정에서는 다를 수 있습니다.');
    if (d.type === 'ksFirst') r.advice.push('key share를 미루는 하이브리드 우선 클라이언트(C2)는 이 서버에서 고전을 받습니다. 그런 클라이언트를 받아야 한다면 서버 순서 유형 구현을 검토하세요.');
    if (impl === 'go') r.reasons.push('서버 순서 유형이라 고전을 1순위로 광고한 C3에도 HRR로 하이브리드를 협상합니다.');
    return r;
  }

  var notes = [];
  var vText = String(input.version || '').trim();
  var v = parseVersion(vText);
  if (vText && !v) notes.push('버전 "' + vText + '"을 읽지 못했습니다. 3.5.5 형식으로 입력하세요.');
  if (v && (v[0] < 3 || (v[0] === 3 && v[1] < 5))) {
    var old = result('info', 'OpenSSL ' + v.join('.') + ': 논문 범위 밖', null);
    old.reasons.push('ML-KEM 기본 지원과 tuple 문법(/)은 OpenSSL 3.5부터입니다. 논문은 3.5·3.6만 시험했습니다.');
    old.advice.push('하이브리드 PQ를 쓰려면 3.5.6 이상 또는 3.6.2 이상으로 올리세요.');
    return old;
  }
  if (v && (v[0] > 3 || (v[0] === 3 && v[1] > 6))) notes.push('논문은 3.5·3.6 계열만 시험했습니다. ' + v.join('.') + '의 판정은 같은 규칙이 유지된다는 가정입니다 [추정].');

  var g = cleanGroups(input.groups);
  var r;
  if (!g) {
    r = result('ok', '설정 생략: 내장 기본 목록 사용 (S4)', 'serverOrder');
    r.reasons.push('내장 기본 목록은 하이브리드를 별도의 첫 tuple로 둡니다. 논문 S4에서 3.5.5·3.5.6 모두 10/10회 HRR 뒤 하이브리드로 협상했습니다.');
  } else {
    var tuples = g.split('/').map(function (t) {
      return t.split(':').map(function (s) { return s.trim(); }).filter(Boolean);
    }).filter(function (t) { return t.length; });
    var name = function (tok) { return tok.replace(/^[*?-]+/, ''); };
    var all = [].concat.apply([], tuples);
    var hasDefault = all.some(function (t) { return name(t).toUpperCase() === 'DEFAULT'; });
    var known = /^(DEFAULT|X25519|X448|secp\d+r1|P-\d+|ffdhe\d+|brainpoolP\d+r1(tls13)?|MLKEM\d+|X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024|curveSM2(MLKEM768)?)$/i;
    var unknown = all.map(name).filter(function (t) { return !known.test(t); });
    if (unknown.length) notes.push('알 수 없는 그룹 이름: ' + unknown.join(', ') + '. 오타라면 서버가 시작되지 않거나 그 그룹을 무시할 수 있습니다.');

    if (hasDefault) {
      if (!v) {
        r = result('warn', 'DEFAULT 사용: 버전을 넣어야 판정할 수 있습니다', null);
        r.reasons.push('CVE-2026-2673은 DEFAULT를 확장할 때 tuple 경계가 사라지는 결함입니다. 결과는 버전에 달려 있습니다.');
        r.advice.push('위에 OpenSSL 버전(openssl version 출력)을 넣으세요.');
      } else if (cveAffected(v)) {
        r = result('bad', 'CVE-2026-2673 영향: DEFAULT가 하이브리드 우선 tuple을 잃습니다', 'ksFirst');
        r.predictions = [OUT.hy, OUT.cl, OUT.cl]; // 표 7: 고전 우선(E5)·C2(E7) 모두 HRR 없이 X25519
        r.reasons.push('OpenSSL ' + v.join('.') + '은 영향 범위(3.5.0–3.5.5, 3.6.0–3.6.1)입니다.');
        r.reasons.push('논문 표 7·8: 영향 버전의 DEFAULT(S3)는 key share를 미루는 클라이언트에게 HRR 0/10회, X25519로 협상했습니다. 수정 버전은 10/10회 HRR 뒤 하이브리드였습니다.');
        r.advice.push('3.5.6 이상 또는 3.6.2 이상으로 업그레이드하세요(권고문 [5]).');
        r.advice.push('당장 올릴 수 없다면 DEFAULT 대신 tuple 경계를 직접 쓰세요. 예: X25519MLKEM768/X25519:secp256r1');
      } else if (!cveFixVerified(v)) {
        r = result('warn', 'OpenSSL ' + v.join('.') + ': DEFAULT 결과는 확인 필요', null);
        r.reasons.push('CVE-2026-2673의 검증 범위는 OpenSSL 3.5·3.6 계열입니다. 이 버전의 DEFAULT tuple 동작은 이 점검기의 근거 자료에 없습니다.');
        r.advice.push('실제 s_client -trace 로그로 HRR 및 최종 협상 그룹을 확인하고, 사용하는 릴리스의 보안 공지를 함께 확인하세요.');
      } else {
        r = result('ok', 'DEFAULT 사용, 수정된 버전', 'serverOrder');
        r.reasons.push('OpenSSL ' + v.join('.') + '은 CVE-2026-2673 수정이 들어간 버전입니다. 논문 표 7에서 3.5.6 S3은 10/10회 HRR 뒤 하이브리드였습니다.');
      }
    } else if (!all.some(function (t) { return isPQ(name(t)); })) {
      r = result('warn', 'PQ 미적용: 설정에 하이브리드 그룹이 없습니다', null);
      r.predictions = [OUT.clNoPQ, OUT.clNoPQ, OUT.clNoPQ];
      r.type = '해당 없음';
      r.advice.push('하이브리드를 쓰려면 별도의 첫 tuple로 넣으세요. 예: X25519MLKEM768/' + g);
    } else {
      var first = tuples[0].map(name);
      var pqFirst = first.filter(isPQ), clFirst = first.filter(function (t) { return !isPQ(t); });
      if (pqFirst.length && clFirst.length) {
        r = result('bad', '단일 tuple (S1): key share 우선 유형', 'ksFirst');
        r.reasons.push('첫 tuple에 하이브리드(' + pqFirst.join(', ') + ')와 고전(' + clFirst.join(', ') + ')이 함께 있습니다. 같은 tuple 안에서는 이미 받은 key share로 바로 협상하므로 HRR을 보내지 않습니다.');
        r.reasons.push('논문 표 2: 이 설정은 C2에게 고전을 주었고, -serverpref를 켜도 같았습니다.');
        var pqTok = tuples[0].filter(function (t) { return isPQ(name(t)); });
        var clTok = tuples[0].filter(function (t) { return !isPQ(name(t)); });
        var fixed = [pqTok.join(':'), clTok.join(':')].concat(tuples.slice(1).map(function (t) { return t.join(':'); })).join('/');
        r.advice.push('하이브리드를 별도의 첫 tuple로 나누세요: ' + fixed);
        r.suggestion = fixed;
      } else if (pqFirst.length) {
        r = result('ok', '하이브리드 단독 첫 tuple (S2): 서버 순서 유형', 'serverOrder');
        r.reasons.push('논문 표 2·표 7: 하이브리드를 별도 첫 tuple로 두면 key share를 미룬 클라이언트에게도 HRR로 하이브리드를 요청했습니다(10/10회).');
      } else {
        r = result('warn', '고전이 첫 tuple: 서버가 고전을 우선합니다', null);
        r.type = '서버가 고전 우선';
        r.predictions = [OUT.clGuess, OUT.clGuess, OUT.clGuess];
        r.reasons.push('첫 tuple(' + first.join(', ') + ')에 하이브리드가 없어, 클라이언트가 그 그룹을 지원하면 고전이 선택될 것입니다. 논문이 시험하지 않은 설정입니다.');
        r.advice.push('하이브리드 그룹을 맨 앞의 별도 tuple로 옮기세요. 예: X25519MLKEM768/X25519:secp256r1');
      }
    }
  }
  r.reasons = notes.concat(r.reasons);
  return r;
}

if (typeof module !== 'undefined') module.exports = { analyzeLog: analyzeLog, analyzeConfig: analyzeConfig, parseTrace: parseTrace };
