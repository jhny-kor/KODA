// Run against isolated schedule_ui_preview.py with playwright-cli run-code.
async page => {
  const base = await page.evaluate(() => location.origin), results=[];
  const assert=(ok,msg)=>{if(!ok)throw Error(msg)};
  await page.goto(base+'/koda/admin/gitlab#server');
  await page.setViewportSize({width:1440,height:1000});
  const f=page.locator('#schedule-worker-settings');
  await f.locator('[name=memory_limit_mb]').fill('3072');
  await f.locator('[name=rate_mb_per_sec]').fill('2.5');
  await f.locator('[name=min_free_mb]').fill('1536');
  const saved=page.waitForResponse(r=>r.url().endsWith('/admin/schedule-settings')&&r.request().method()==='POST');
  await f.locator('button[type=submit]').click();
  const response=await saved, payload=response.request().postDataJSON();
  assert(response.ok()&&payload.memory_limit_bytes===3072*1048576&&payload.rate_bytes_per_sec===2.5*1048576&&payload.min_free_bytes===1536*1048576,'MB conversion/save');
  await page.reload();
  assert(await f.locator('[name=rate_mb_per_sec]').inputValue()==='2.5','MB reload');
  const rows=await f.locator(':scope>label').evaluateAll(es=>es.map(e=>Math.round(e.getBoundingClientRect().top)));
  assert(rows[0]<rows[1]&&rows[1]===rows[2]&&rows[2]===rows[3]&&rows[4]===rows[5]&&rows[5]===rows[6]&&rows[3]<rows[4],'3 by 2 resource layout');
  results.push('MB save/reload and 3×2 resource layout');
  await page.locator('[data-schedule-edit]:visible').first().click();
  assert((await page.locator('#schedule-target [name=target_id]').inputValue()).length>0,'edit target');
  await page.locator('#schedule-reset').click();
  assert(await page.locator('#schedule-target [name=target_id]').inputValue()==='','new target clears ID');
  const target=page.locator('#schedule-target');
  const project='/koda/projects/'+await target.locator('[name=project_id]').inputValue();
  const connectionId=await target.locator('[name=server_connection_id] option').nth(1).getAttribute('value');
  await target.locator('[name=server_connection_id]').selectOption(connectionId);
  assert(!await target.locator('[name=host]').isVisible(),'saved credentials hidden');
  await target.locator('[name=name]').fill('UI 확인 · 서버 계정 연결');
  await target.locator('[name=remote_directory]').fill('/srv/sample');
  const targetSaved=page.waitForResponse(r=>r.url().endsWith('/admin/schedules')&&r.request().method()==='POST');
  await target.locator('button[type=submit]').click();
  const ts=await targetSaved;assert(ts.ok(),"target save status "+ts.status());
  await page.waitForLoadState('networkidle');
  assert((await page.locator('body').innerText()).includes('UI 확인 · 서버 계정 연결'),'bound target persisted');
  results.push('server binding/save and new-target reset');
  for(const kind of ['gitlab','server']) {
    await page.locator(`[data-integration-tab=${kind}]`).click();
    const kinds=await page.locator('[data-schedule-source]:visible').evaluateAll(es=>es.map(e=>e.dataset.scheduleSource));
    assert(kinds.length&&kinds.every(x=>x===kind),'separate target rows');
    for(const width of [1440,1024,768,390]){
      await page.setViewportSize({width,height:1000});
      assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'integration overflow '+width);
    }
    await page.screenshot({path:`output/playwright/review-${kind}-mobile.png`,fullPage:true});
    await page.setViewportSize({width:1440,height:1000});
    await page.screenshot({path:`output/playwright/review-${kind}-desktop.png`,fullPage:true});
  }
  results.push('separate tabs at 1440/1024/768/390');
  await page.goto(base+'/koda/admin/subjects');
  assert(!(await page.locator('th').allTextContents()).includes('UUID'),'UUID headers removed');
  await page.locator('#membership summary').click();
  const users=page.locator('#membership input[name=subject_ids]');
  await users.nth(1).check();await users.nth(2).check();
  await page.locator('#membership select[name=role]').selectOption('viewer');
  await page.locator('#membership button').click();
  await page.waitForLoadState('networkidle');
  results.push('checkbox bulk membership submitted');
  await page.screenshot({path:'output/playwright/review-subjects-desktop.png',fullPage:true});
  await page.goto(base+'/koda/runs');
  assert((await page.locator('main').innerText()).includes('sample.operator'),'executor login ID');
  await page.screenshot({path:'output/playwright/review-runs-desktop.png',fullPage:true});
  await page.goto(base+project);
  assert((await page.locator('main').innerText()).includes('sample.uploader'),'uploader login ID');
  assert((await page.locator('main').innerText()).includes('점검 회차'),'round header');
  await page.screenshot({path:'output/playwright/review-project-desktop.png',fullPage:true});
  await page.goto(base+'/koda/admin/audit');
  await page.locator('#audit-search').fill('sample.operator');
  assert((await page.locator('main').innerText()).includes('sample.operator'),'other user audit');
  results.push('uploader/executor and global audit');
  return results;
}
