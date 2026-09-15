"""Server connection cards and integration-tab behavior for the admin page."""
from .portal_views import esc


def server_admin_section(project_options, connections, mappings):
    options = "<option value=''>서버 선택</option>" + ''.join(
        f"<option value='{esc(c['connection_id'])}'>{esc(c['name'])} · {esc(c['username'])}@{esc(c['host'])}</option>" for c in connections if c.get('enabled', True))
    rows = ''.join(f"<tr><td>{esc(c['name'])}</td><td>{esc(c['host'])}:{esc(c['port'])}</td><td>{esc(c['username'])}</td><td><button type='button' data-server-edit='{esc(c['connection_id'])}'>편집</button> <button type='button' data-server-remove='{esc(c['connection_id'])}'>삭제</button></td></tr>" for c in connections)
    rows = rows or "<tr><td colspan='4' class='empty'>등록된 서버가 없습니다.</td></tr>"
    mapping_rows = ''.join(f"<tr><td>{esc(m['project_name'])}</td><td>{esc(m['name'])}</td><td>{esc(m['username'])}</td><td><button type='button' data-server-unmap='{esc(m['connection_id'])}' data-project='{esc(m['project_id'])}'>연결 해제</button></td></tr>" for m in mappings)
    mapping_rows = mapping_rows or "<tr><td colspan='4' class='empty'>프로젝트에 연결된 서버가 없습니다.</td></tr>"
    return f"""<section class='panel' data-integration-panel='server'><div class='panel-head'><div><h2>서버 연결 설정</h2><p class='muted'>읽기 전용 SSH 서비스 계정을 등록합니다. 키는 worker에 배치한 파일 경로로 참조합니다.</p></div></div>
<div class='panel-body'><form id='server-connection-config' class='gitlab-config-grid'><input type='hidden' name='connection_id'><label>서버 이름<input name='name' required maxlength='255'></label><label>서버 주소<input name='host' required maxlength='255' placeholder='server.example.internal'></label><label>SSH 포트<input name='port' type='number' min='1' max='65535' value='22' required></label><label>읽기 전용 계정<input name='username' required maxlength='128'></label><label>SSH 키 참조<input name='ssh_key_ref' required placeholder='/run/koda/ssh/scan_ed25519'></label><label>검증된 호스트키 파일<input name='known_hosts_file' required placeholder='/run/koda/ssh/known_hosts'></label><div class='toolbar' style='grid-column:1/-1'><button class='primary' type='submit'>서버 연결 저장</button><button type='button' id='server-connection-test'>연결 시험</button><button type='button' id='server-connection-reset'>새 서버</button><span id='server-connection-result' role='status'></span></div></form></div>
<div class='table-wrap'><table id='server-connections-table'><thead><tr><th>서버</th><th>주소</th><th>서비스 계정</th><th>관리</th></tr></thead><tbody>{rows}</tbody></table></div></section>
<section class='panel' data-integration-panel='server'><div class='panel-head'><div><h2>서버 서비스 계정·프로젝트 연결</h2><p class='muted'>KODA 프로젝트에 서버를 연결한 후 서버 스케줄에서 디렉토리와 주기를 설정합니다.</p></div></div><div class='panel-body'><form id='server-project-map' class='gitlab-config-grid'><label>KODA 프로젝트<select name='project_id' required>{project_options}</select></label><label>서버 서비스 계정<select name='connection_id' required>{options}</select></label><div class='toolbar' style='grid-column:1/-1'><button class='primary' type='submit'>프로젝트 연결 저장</button><span id='server-project-result' role='status'></span></div></form></div>
<div class='table-wrap'><table id='server-mappings-table'><thead><tr><th>프로젝트</th><th>서버</th><th>서비스 계정</th><th>관리</th></tr></thead><tbody>{mapping_rows}</tbody></table></div></section>"""


SERVER_ADMIN_SCRIPT = r"""<script>
let integrationKind = location.hash === '#server' ? 'server' : 'gitlab';
const connectionForm=document.querySelector('#server-connection-config');
const serverProjectMap=document.querySelector('#server-project-map'),serverProjectMappings=__SERVER_PROJECT_MAPPINGS__;
const connectionSelect=scheduleForm.elements.server_connection_id;
function syncServerProjectConnection(){{const project=serverProjectMap?.elements.project_id.value,match=serverProjectMappings.find(x=>x.project_id===project);if(match)serverProjectMap.elements.connection_id.value=match.connection_id}}
function refreshScheduleConnections(){
  const selected=connectionSelect.value;
  connectionSelect.replaceChildren(new Option('직접 입력 (기존 설정)',''));
  for(const c of serverConnections.filter(c=>c.enabled && c.project_ids.includes(scheduleForm.elements.project_id.value)))
    connectionSelect.add(new Option(`${c.name} · ${c.username}@${c.host}`,c.connection_id));
  connectionSelect.value=selected;
}
function applyScheduleConnection(){
  const c=serverConnections.find(c=>c.connection_id===connectionSelect.value);
  for(const key of ['host','port','username','ssh_key_ref','known_hosts_file']) {
    const field=scheduleForm.elements[key];
    if(c)field.value=c[key];
    field.readOnly=Boolean(c);
    field.closest('label').hidden=integrationKind!=='server'||Boolean(c);
  }
}
function selectIntegration(kind, reset=true){
  integrationKind=kind;
  if(reset)resetSchedule();
  sourceKind.value=kind;
  for(const option of sourceKind.options)option.disabled=option.value!==kind;
  document.querySelectorAll('[data-integration-tab]').forEach(x=>{x.classList.toggle('active',x.dataset.integrationTab===kind);x.setAttribute('aria-selected',String(x.dataset.integrationTab===kind))});
  document.querySelectorAll('[data-integration-panel]').forEach(x=>x.hidden=x.dataset.integrationPanel!==kind);
  for(const id of ['gitlab-config','gitlab-map'])document.querySelector('#'+id).closest('.panel').hidden=kind!=='gitlab';
  document.querySelector('[data-gitlab-current]').hidden=kind!=='gitlab';
  scheduleForm.closest('.panel').querySelector('h2').textContent=kind==='server'?'서버 스케줄 점검':'GitLab 스케줄 점검';
  document.querySelectorAll('[data-schedule-source]').forEach(x=>x.dataset.filtered=String(x.dataset.scheduleSource!==kind));
  scheduleForm.closest('.panel').querySelector('[data-pager]')._paginate?.();
  toggleScheduleFields();refreshScheduleConnections();applyScheduleConnection();
}
document.querySelectorAll('[data-integration-tab]').forEach(x=>x.addEventListener('click',()=>{location.hash=x.dataset.integrationTab;selectIntegration(x.dataset.integrationTab)}));
scheduleForm.elements.project_id.addEventListener('change',()=>{refreshScheduleConnections();applyScheduleConnection()});
connectionSelect.addEventListener('change',applyScheduleConnection);
document.querySelector('#schedule-reset').addEventListener('click',()=>selectIntegration(integrationKind,false));
scheduleForm.elements.schedule_frequency.addEventListener('change',applyScheduleConnection);
function reloadServer(){location.hash='server';location.reload()}
function storedConnectionPayload(c, project_ids){const p={project_ids};for(const key of ['connection_id','name','host','port','username','ssh_key_ref','known_hosts_file','host_key_fingerprint'])p[key]=c[key];return p}
function connectionPayload(){const p=Object.fromEntries(new FormData(connectionForm));p.port=Number(p.port);const old=serverConnections.find(c=>c.connection_id===p.connection_id);if(old){p.project_ids=old.project_ids;p.host_key_fingerprint=old.host_key_fingerprint;p.enabled=old.enabled;}return p}
connectionForm.addEventListener('submit',async e=>{e.preventDefault();try{await json('/koda/api/v1/admin/server-connections',{method:'POST',body:JSON.stringify(connectionPayload())});reloadServer()}catch(e){document.querySelector('#server-connection-result').textContent=e.message}});
document.querySelector('#server-connection-reset').addEventListener('click',()=>{connectionForm.reset();connectionForm.elements.connection_id.value='';document.querySelector('#server-connection-result').textContent=''});
document.querySelectorAll('[data-server-edit]').forEach(b=>b.addEventListener('click',()=>{const c=serverConnections.find(c=>c.connection_id===b.dataset.serverEdit);for(const key of ['connection_id','name','host','port','username','ssh_key_ref','known_hosts_file'])connectionForm.elements[key].value=c[key];connectionForm.scrollIntoView({block:'start'});}));
document.querySelectorAll('[data-server-remove]').forEach(b=>b.addEventListener('click',async()=>{if(!confirm('이 서버 연결을 삭제할까요? 사용 중인 스케줄이 있으면 먼저 해제해야 합니다.'))return;try{await json('/koda/api/v1/admin/server-connections/'+encodeURIComponent(b.dataset.serverRemove),{method:'DELETE'});reloadServer()}catch(e){alert(e.message)}}));
document.querySelector('#server-project-map').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.currentTarget),c=serverConnections.find(c=>c.connection_id===f.get('connection_id'));try{await json('/koda/api/v1/admin/server-connections',{method:'POST',body:JSON.stringify(storedConnectionPayload(c,[...new Set([...c.project_ids,f.get('project_id')])]))});reloadServer()}catch(e){document.querySelector('#server-project-result').textContent=e.message}});
serverProjectMap?.elements.project_id.addEventListener('change',syncServerProjectConnection);syncServerProjectConnection();
document.querySelectorAll('[data-server-unmap]').forEach(b=>b.addEventListener('click',async()=>{if(!confirm('프로젝트의 서버 연결을 해제할까요?'))return;const c=serverConnections.find(c=>c.connection_id===b.dataset.serverUnmap);try{await json('/koda/api/v1/admin/server-connections',{method:'POST',body:JSON.stringify(storedConnectionPayload(c,c.project_ids.filter(id=>id!==b.dataset.project)))});reloadServer()}catch(e){alert(e.message)}}));
document.querySelector('#server-connection-test').addEventListener('click',async e=>{if(!connectionForm.reportValidity())return;const b=e.currentTarget,status=document.querySelector('#server-connection-result');b.disabled=true;try{await json('/koda/api/v1/admin/schedules/test-connection',{method:'POST',body:JSON.stringify(Object.fromEntries(['host','port','username','ssh_key_ref','known_hosts_file'].map(key=>[key,connectionPayload()[key]]).concat([['remote_directory','/']])))});status.textContent='연결 시험 완료'}catch(e){status.textContent=e.message}finally{b.disabled=false}});
selectIntegration(integrationKind);
</script>"""

SCHEDULE_CHOICES_SCRIPT = r"""<script>
let scheduleStandards=[],scheduleRefRequest=0;
const scheduleRef=scheduleForm.elements.source_gitlab_ref;
const scheduleRefStatus=document.querySelector('#schedule-ref-status');
const branchBase=document.querySelector('#schedule-branch-base');
function renderScheduleCategories(selected='all'){
  const standard=scheduleStandards.find(x=>x.id===scheduleForm.elements.standard.value);
  const categories=(standard?.categories||[]).filter(x=>x.supported&&x.id!=='all');
  const field=scheduleForm.elements.standard_category;
  field.replaceChildren(new Option('전체 (all)','all'));
  for(const c of categories)field.add(new Option(c.labels?.ko||c.labels?.en||c.id,c.id));
  field.value=[...field.options].some(x=>x.value===selected)?selected:'all';
}
function syncScheduleBranchPanel(){
  const hidden=sourceKind.value!=='gitlab'||scheduleForm.elements.source_gitlab_ref_type.value!=='branch';
  document.querySelector('#schedule-new-branch').hidden=hidden;
  document.querySelectorAll('#schedule-new-branch input,#schedule-new-branch select,#schedule-new-branch button').forEach(x=>x.disabled=hidden);
}
async function loadScheduleRefs(selected=''){
  const request=++scheduleRefRequest,project=scheduleForm.elements.project_id.value;
  const mapping=scheduleForm.elements.source_gitlab_mapping_id.value;
  const type=scheduleForm.elements.source_gitlab_ref_type.value;
  syncScheduleBranchPanel();
  scheduleRef.replaceChildren(new Option(type==='branch'?'기본 브랜치':'태그 선택',''));
  scheduleRef.required=sourceKind.value==='gitlab'&&type==='tag';
  branchBase.replaceChildren(new Option('기준 브랜치 선택',''));
  scheduleRefStatus.textContent='';
  if(!mapping||sourceKind.value!=='gitlab')return;
  scheduleRefStatus.textContent='목록 확인 중…';
  try{
    const refs=await json(`/koda/api/v1/projects/${project}/gitlab/repositories/${mapping}/refs?type=${type}`);
    if(request!==scheduleRefRequest)return;
    for(const ref of refs){scheduleRef.add(new Option(ref.name,ref.name));if(type==='branch')branchBase.add(new Option(ref.name,ref.name))}
    if(selected&&!refs.some(x=>x.name===selected))scheduleRef.add(new Option(`${selected} (현재 목록에 없음)`,selected));
    scheduleRef.value=selected;
    scheduleRefStatus.textContent=refs.length?'':'선택 가능한 항목이 없습니다.';
  }catch(e){
    if(request!==scheduleRefRequest)return;
    if(selected){scheduleRef.add(new Option(selected,selected));scheduleRef.value=selected}
    scheduleRefStatus.textContent=e.message;
  }
}
scheduleForm.elements.standard.addEventListener('change',()=>renderScheduleCategories());
for(const key of ['project_id','source_gitlab_mapping_id','source_gitlab_ref_type'])scheduleForm.elements[key].addEventListener('change',()=>loadScheduleRefs());
sourceKind.addEventListener('change',()=>loadScheduleRefs());
document.querySelector('#schedule-reset').addEventListener('click',()=>{renderScheduleCategories();loadScheduleRefs()});
document.querySelectorAll('[data-integration-tab]').forEach(x=>x.addEventListener('click',()=>{renderScheduleCategories();loadScheduleRefs()}));
document.querySelector('#schedule-branch-create').addEventListener('click',async e=>{
  const mapping=scheduleForm.elements.source_gitlab_mapping_id.value;
  const branch=document.querySelector('#schedule-branch-name').value.trim(),ref=branchBase.value;
  if(!mapping||!branch||!ref){scheduleRefStatus.textContent='저장소, 새 브랜치 이름과 생성 기준 브랜치를 선택하세요.';return}
  const button=e.currentTarget;button.disabled=true;
  scheduleRefStatus.textContent='브랜치 생성 중…';
  try{
    await json(`/koda/api/v1/admin/gitlab/mappings/${mapping}/branches`,{method:'POST',body:JSON.stringify({branch,ref})});
    await loadScheduleRefs(branch);
    document.querySelector('#schedule-branch-name').value='';
  }catch(error){scheduleRefStatus.textContent=error.message}
  finally{button.disabled=false}
});
json('/koda/api/v1/standards').then(items=>{scheduleStandards=items;renderScheduleCategories(scheduleForm.elements.standard_category.value)}).catch(e=>{scheduleResult.textContent='기준 분류 조회 실패: '+e.message});
syncScheduleBranchPanel();
</script>"""
