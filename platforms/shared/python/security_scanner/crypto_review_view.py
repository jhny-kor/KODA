"""Local dashboard view for certificate files and known HMAC key lengths."""

from __future__ import annotations

import json

from .certificate_review import MAX_CERTIFICATE_BYTES
from .jwt_key_review import HMAC_MINIMUM_BITS


def render_crypto_review_page(language: str) -> str:
    korean = language == "ko"
    title = "인증서와 JWT 키 길이 검토" if korean else "Review certificates and JWT key length"
    certificate = "TLS 인증서 파일" if korean else "TLS certificate file"
    action = "검토" if korean else "Review"
    key_length = "키 길이(비트)" if korean else "Key length in bits"
    return f"""<!doctype html><html lang="{'ko' if korean else 'en'}">
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KODA · {title}</title>
<style>body{{font:16px system-ui;max-width:60rem;margin:2rem auto;padding:0 1rem}}
fieldset{{margin:1rem 0}} label{{margin-right:.5rem}} input,select,button{{font:inherit}}
dt{{font-weight:600}} dd{{margin:0 0 .5rem;overflow-wrap:anywhere}}</style>
<a href="/security-dashboard.html">← KODA</a>
<h1>{title}</h1>
<form id="cert-form"><fieldset><legend>{certificate}</legend>
<label>PEM / DER <input type="file" id="cert-file" accept=".cer,.crt,.pem,.der" required></label>
<button>{action}</button>
<p id="cert-status" role="status"></p><dl id="cert-details"></dl>
</fieldset></form>
<form id="jwt-form"><fieldset><legend>JWT HMAC</legend>
<label>{'서명 알고리즘' if korean else 'Signing algorithm'}
<select id="algorithm">{''.join(f'<option>{name}</option>' for name in HMAC_MINIMUM_BITS)}</select></label>
<label>{key_length}<input type="number" id="bits" min="0" step="1" required></label>
<button>{action}</button>
<p id="jwt-status" role="status"></p>
</fieldset></form>
<script>
const ko = {json.dumps(korean)}, limit = {MAX_CERTIFICATE_BYTES};
const sizes = {json.dumps(HMAC_MINIMUM_BITS)};
const certForm = document.querySelector('#cert-form'), certFile = document.querySelector('#cert-file');
const certStatus = document.querySelector('#cert-status'), details = document.querySelector('#cert-details');
certForm.addEventListener('submit', async event => {{
  event.preventDefault();
  details.replaceChildren();
  const file = certFile.files[0];
  if (!file || file.size === 0 || file.size > limit) {{
    certStatus.textContent = ko ? '파일 크기 한도 내의 인증서 파일을 선택하세요.' : 'Select a certificate within the file size limit.';
    return;
  }}
  const button = certForm.querySelector('button');
  button.disabled = true;
  certStatus.textContent = ko ? '인증서 확인 중…' : 'Reading certificate…';
  try {{
    const health = await fetch('/api/health');
    const response = await fetch('/api/tls-cert-review', {{
      method:'POST', headers:{{'Content-Type':'application/octet-stream',
        'X-KODA-Session':health.headers.get('X-KODA-Session')}}, body:file
    }});
    const data = await response.json();
    if (!response.ok) throw Error(data.error || response.statusText);
    const validity = ko
      ? {{VALID:'유효 기간 내', EXPIRED:'만료됨', NOT_YET_VALID:'유효 시작 전'}}
      : {{VALID:'Within validity period', EXPIRED:'Expired', NOT_YET_VALID:'Not yet valid'}};
    certStatus.textContent = validity[data.validity];
    const rows = [
      [ko ? '유효 시작(UTC)' : 'Valid from (UTC)', data.not_before],
      [ko ? '만료(UTC)' : 'Expires (UTC)', data.not_after],
      [ko ? '서명 알고리즘 OID' : 'Signature algorithm OID', data.signature_oid || '—'],
      ['SHA-256', data.sha256]
    ];
    if (data.weak_signature) {{
      rows.push([ko ? '서명 검토' : 'Signature review', ko ? '약한 해시 알고리즘 관측' : 'Weak hash algorithm detected']);
    }}
    for (const [label, value] of rows) {{
      const term = document.createElement('dt'), description = document.createElement('dd');
      term.textContent = label; description.textContent = value;
      details.append(term, description);
    }}
  }} catch (error) {{
    certStatus.textContent = error.message;
  }} finally {{
    button.disabled = false;
  }}
}});
document.querySelector('#jwt-form').addEventListener('submit', event => {{
  event.preventDefault();
  const algorithm = document.querySelector('#algorithm').value;
  const bits = document.querySelector('#bits').valueAsNumber;
  const status = document.querySelector('#jwt-status');
  if (!Number.isSafeInteger(bits) || bits < 0) {{
    status.textContent = ko ? '0 이상의 정수 비트 길이를 입력하세요.' : 'Enter a nonnegative integer bit length.';
    return;
  }}
  const minimum = sizes[algorithm];
  status.textContent = bits >= minimum
    ? (ko ? `최소 길이 충족 (${{minimum}}비트)` : `Meets minimum length (${{minimum}} bits)`)
    : (ko ? `키가 짧습니다. 최소 ${{minimum}}비트가 필요합니다.` : `Key too short. At least ${{minimum}} bits required.`);
}});
</script></html>"""
