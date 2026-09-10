// Additional interactions in the isolated sample server; no remote probe runs.
async page => {
  const base=await page.evaluate(()=>location.origin),results=[];
  const assert=(ok,msg)=>{if(!ok)throw Error(msg)};
  await page.setViewportSize({width:1440,height:1000});
  await page.goto(base+'/koda/admin/subjects');
  const revoke=page.locator('[data-remove-membership-display="sample.viewer"]');
  await page.evaluate(()=>{window.confirm=()=>true});
  await Promise.all([page.waitForNavigation({waitUntil:'networkidle'}),revoke.click()]);
  assert(await page.locator('[data-remove-membership-display="sample.viewer"]').count()===0,'row revoke persisted');
  await page.locator('#account-toggle').click();
  assert(await page.locator('#account-id').innerText()==='sample.admin','actual login ID');
  assert(await page.locator('.account-details dt').first().evaluate(e=>e.clientHeight<30),'account label single line');
  await page.screenshot({path:'output/playwright/review-account-desktop.png'});
  results.push('row revoke and account login ID');
  await page.goto(base+'/koda/admin/gitlab#server');
  const form=page.locator('#server-connection-config');
  for(const [key,value] of Object.entries({name:'UI 저장 확인 서버',host:'ui-check.example.invalid',username:'readonly',ssh_key_ref:'/run/koda/ssh/ui-key',known_hosts_file:'/run/koda/ssh/known_hosts'}))await form.locator(`[name=${key}]`).fill(value);
  await Promise.all([page.waitForNavigation({waitUntil:'networkidle'}),form.locator('button[type=submit]').click()]);
  const mapping=page.locator('#server-project-map');
  await mapping.locator('[name=connection_id]').selectOption({label:'UI 저장 확인 서버 · readonly@ui-check.example.invalid'});
  await Promise.all([page.waitForNavigation({waitUntil:'networkidle'}),mapping.locator('button[type=submit]').click()]);
  assert((await page.locator('#server-mappings-table').innerText()).includes('UI 저장 확인 서버'),'server/project mapping persisted');
  await page.reload();
  assert((await page.locator('#schedule-target [name=server_connection_id]').innerText()).includes('UI 저장 확인 서버'),'mapped server selectable');
  results.push('server connection and project mapping save/reload');
  await page.goto(base+'/koda/runs');
  await page.locator('[data-source-tab=scheduled_server]').click();
  const detail=await page.locator('main a[href^="/koda/runs/"]:visible').first().getAttribute('href');
  await page.goto(base+detail);
  const gaps=await page.locator('main>.panel+.panel').evaluateAll(es=>es.map(e=>e.getBoundingClientRect().top-e.previousElementSibling.getBoundingClientRect().bottom));
  assert(gaps.length&&gaps.every(x=>x>=19),'card group spacing');
  await page.screenshot({path:'output/playwright/review-detail-desktop.png',fullPage:true});
  for(const path of ['/koda/admin/subjects','/koda/runs',detail]){
    await page.goto(base+path);
    for(const width of [1440,1024,768,390]){
      await page.setViewportSize({width,height:1000});
      assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'page overflow '+path+' '+width);
    }
  }
  await page.screenshot({path:'output/playwright/review-detail-mobile.png',fullPage:true});
  results.push('detail card gaps and account/results widths');
  return results;
}
