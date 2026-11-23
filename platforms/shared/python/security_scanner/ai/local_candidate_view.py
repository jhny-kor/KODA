"""Loopback desktop candidate review page, independent of exported scan reports."""
from __future__ import annotations

from html import escape
import json


def render(language, windows):
    korean = language == "ko"

    def label(ko, en):
        return escape(ko if korean else en)

    profile = ""
    if windows:
        profile = f"""<label>{label("저장된 연결", "Saved connections")} <select id="profiles"></select></label>
        <button id="save">{label("연결 저장", "Save connection")}</button>
        <button id="remove">{label("연결 삭제", "Delete connection")}</button>"""

    return f"""<!doctype html><html lang="{('ko' if korean else 'en')}"><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>KODA · {label("로컬 AI 수정 후보", "Local AI fix candidate")}</title>
    <style>body{{font:16px system-ui;max-width:62rem;margin:2rem auto;padding:0 1rem}}
    fieldset{{margin:1rem 0;border:1px solid #aaa;padding:1rem}} label,button{{display:inline-block;margin:.3rem}}
    input,button,select{{font:inherit;max-width:100%}} pre{{white-space:pre-wrap;overflow-wrap:anywhere}}
    </style><a href="/security-dashboard.html">← KODA</a><h1>{label("로컬 AI 수정 후보", "Local AI fix candidate")}</h1>
    <fieldset><legend>{label("이 PC의 모델 서버", "Model server on this PC")}</legend>{profile}
    <label>URL <input id="base" value="http://127.0.0.1:1234/v1"></label>
    <label>{label("API 키 (선택)", "API key (optional)")} <input id="key" type="password" autocomplete="off"></label>
    <label>{label("모델", "Model")} <input id="model" list="models"><datalist id="models"></datalist></label>
    <button id="list">{label("모델 목록", "List models")}</button></fieldset>
    <label>{label("검토할 원본 · 12 KiB 이하", "Source to review · up to 12 KiB")}
    <input type="file" id="file" accept=".py,.java,.xml,.js"></label>
    <label>{label("점검 항목", "Finding")} <select id="rules"></select></label>
    <button id="propose" disabled>{label("로컬 모델로 수정 후보 생성", "Generate candidate with local model")}</button>
    <p id="status" role="status"></p><section id="result" hidden>
    <h2>{label("수정 차이", "Source diff")}</h2><pre id="diff"></pre>
    <h2>{label("변경 영향 초안", "Proposed change impact")}</h2><pre id="impact"></pre>
    <h2>{label("테스트 계획 초안", "Proposed test plan")}</h2><pre id="tests"></pre>
    <button id="download">{label("후보 파일 다운로드", "Download candidate")}</button></section>
    <script>const ko={json.dumps(korean)}, windowsProfiles={json.dumps(windows)};
    """ + _SCRIPT + "</script></html>"


_SCRIPT = """
const el = id => document.getElementById(id);
const status = el('status'), form = document.querySelectorAll('button,input,select');
let source = '', name = '', candidate = '';
const token = fetch('/api/health').then(r => r.headers.get('X-KODA-Session'));
async function call(action, fields = {}) {
  const response = await fetch('/api/local-ai', {method:'POST', headers:{
    'Content-Type':'application/json', 'X-KODA-Session':await token}, body:JSON.stringify({
    action, base:el('base').value, model:el('model').value, key:el('key').value,
    language:ko?'ko':'en', ...fields})});
  const data = await response.json();
  if (!response.ok) throw Error(data.error || response.statusText);
  return data;
}
async function run(work) {
  for (const control of form) control.disabled = true;
  status.textContent = ko ? '처리 중…' : 'Working…';
  try { await work(); } catch (error) { status.textContent = error.message; }
  finally {
    for (const control of form) control.disabled = false;
    el('propose').disabled = !el('rules').value;
  }
}
function option(parent, value, label) {
  const entry = document.createElement('option'); entry.value = value; entry.textContent = label;
  parent.append(entry);
}
function resetResult() { candidate = ''; el('result').hidden = true; }
el('rules').onchange = resetResult;
el('file').onchange = () => run(async () => {
  const file = el('file').files[0]; resetResult(); el('rules').replaceChildren(); source=''; name='';
  if (!file) { status.textContent=''; return; }
  if (file.size > 12288) throw Error(ko?'12 KiB 이하 파일을 선택하세요.':'Select a file up to 12 KiB.');
  source = new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer()); name=file.name;
  const data = await call('inspect',{source,name});
  const seen = new Set();
  for (const f of data.findings) if (!seen.has(f.rule)) {
    option(el('rules'), f.rule, f.rule+' · '+f.title); seen.add(f.rule);
  }
  status.textContent = seen.size ? '' : (ko?'수정 가능한 발견이 없습니다.':'No eligible findings.');
});
el('list').onclick = () => run(async () => {
  const data = await call('models'); el('models').replaceChildren();
  for (const id of data.models) option(el('models'),id,id);
  if (!el('model').value && data.models.length) el('model').value=data.models[0];
  status.textContent = data.models.length+' '+(ko?'개 모델':'models');
});
el('propose').onclick = () => run(async () => {
  resetResult(); const data = await call('propose',{source,name,rule:el('rules').value});
  for (const id of ['diff','impact','tests']) el(id).textContent=data[id];
  candidate=data.source; el('result').hidden=false;
  status.textContent=(ko?'검증을 통과한 후보 · 시도 ':'Candidate passed validation · attempts ')+data.attempts;
});
el('download').onclick = () => {
  const url = URL.createObjectURL(new Blob([candidate],{type:'text/plain;charset=utf-8'}));
  const a=document.createElement('a'); a.href=url; a.download='candidate-'+name; a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
};
if (windowsProfiles) {
  const select=el('profiles');
  function display(items) {
    select.replaceChildren(); option(select,'',ko?'연결 선택':'Select connection');
    for (const p of items) option(select,JSON.stringify(p),p.model+' · '+p.base);
  }
  select.onchange=()=>{if(select.value){const p=JSON.parse(select.value);
    el('base').value=p.base; el('model').value=p.model; el('key').value='';}};
  el('base').addEventListener('input',()=>el('key').value='');
  for (const [id,action] of [['save','save-profile'],['remove','delete-profile']])
    el(id).onclick=()=>run(async()=>{display((await call(action)).profiles); el('key').value=''; status.textContent='';});
  run(async()=>{display((await call('profiles')).profiles);status.textContent='';});
}
"""
