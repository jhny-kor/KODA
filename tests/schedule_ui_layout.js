// Run against tests/schedule_ui_preview.py using playwright-cli run-code.
async page => {
  const base = await page.evaluate(() => location.origin);
  const results = [];
  async function check(name) {
    for (const width of [1440, 1024, 768, 390]) {
      await page.setViewportSize({width, height: 1000});
      const result = await page.evaluate(() => ({
        width: innerWidth, scroll: document.documentElement.scrollWidth,
        hiddenVisible: [...document.querySelectorAll('[hidden]')].filter(e => e.getClientRects().length).length,
      }));
      if (result.scroll > width || result.hiddenVisible) throw Error(JSON.stringify({name, ...result}));
      results.push({name, ...result});
    }
    await page.screenshot({path: `output/playwright/${name}-mobile.png`, fullPage: true});
    await page.setViewportSize({width: 1440, height: 1000});
    await page.screenshot({path: `output/playwright/${name}-desktop.png`, fullPage: true});
  }
  await page.goto(`${base}/koda/admin/gitlab`);
  await page.locator('[data-schedule-edit]:visible').first().click();
  await check('schedule-settings');
  const labels = await page.locator('[data-weekly-field] label').evaluateAll(es => es.map(e => {
    const r = e.getBoundingClientRect(); return {x:r.x,y:r.y,right:r.right,bottom:r.bottom};
  }));
  for (let i=0; i<labels.length; i++) for(let j=i+1;j<labels.length;j++) {
    const a=labels[i],b=labels[j];
    if(a.x<b.right && b.x<a.right && a.y<b.bottom && b.y<a.bottom) throw Error('Overlapping weekdays');
  }
  await page.locator('[data-integration-tab=server]').click();
  await page.locator('[data-schedule-edit]:visible').first().click();
  await check('schedule-server-settings');
  await page.goto(`${base}/koda/runs`);
  await page.locator('[data-source-tab=scheduled_server]').click();
  await check('schedule-results');
  const detail = await page.locator('main a').evaluateAll(es => es.map(e=>e.href).find(h=>/\/koda\/runs\/.+/.test(h)));
  if(!detail) throw Error('Missing sample result detail');
  await page.goto(detail);
  await check('schedule-detail');
  return results;
}
