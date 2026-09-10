import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from security_scanner.portal_views import gitlab_admin_page, runs_page


class ScheduleUiRuntimeTests(unittest.TestCase):
    def test_scheduled_failure_without_koda_run_is_visible(self):
        html = runs_page(
            [],
            admin=True,
            schedule_runs=[{
                "schedule_run_id": "sr-1",
                "project_id": "p-1",
                "project_name": "운영 프로젝트",
                "target_id": "target-1",
                "status": "failed",
                "mode": "full",
                "cleanup_status": "failed",
                "cleanup_error": "permission denied",
                "tracker_status": "pending",
                "gitlab_status": "pending",
                "scheduled_for": "2026-09-07",
            }],
        )
        self.assertIn("sr-1", html)
        self.assertIn("운영 프로젝트", html)
        self.assertIn("permission denied", html)
        self.assertIn("스케줄 점검 결과", html)

    def test_schedule_controls_use_display_units_and_explicit_choices(self):
        html = gitlab_admin_page([], [])
        self.assertNotIn("KODA 로컬 기준</option>", html)
        self.assertIn("name='max_mb'", html)
        self.assertNotIn("name='max_bytes'", html)
        self.assertIn("name='memory_limit_mb' type='number' min='256'", html)
        self.assertNotIn("value='4096.0'", html)
        self.assertNotIn("value='5.0'", html)
        self.assertIn("<select name='standard_category'>", html)
        self.assertIn("<select name='source_gitlab_ref'>", html)
        self.assertIn("prefers-reduced-motion:reduce", html)

    @unittest.skipUnless(shutil.which("node"), "requires Node")
    def test_gitlab_buttons_send_requests(self):
        html = gitlab_admin_page([{"project_id": "p-1", "name": "demo"}], [])
        script = next(s for s in re.findall(r"<script(?: [^>]*)?>(.*?)</script>", html, re.S)
                      if "let gitlabProjects=" in s)
        script = script.split("const workerSettingsForm=")[0]
        harness = r"""
const assert=require('node:assert/strict');
const nodes=new Map(), calls=[];
const document={querySelector(id){if(!nodes.has(id))nodes.set(id,{
 value:'',textContent:'',innerHTML:'',handlers:{},elements:{project_id:{value:'p-1'}},
 addEventListener(event,fn){this.handlers[event]=fn},
 querySelectorAll(){return [{dataset:{projectId:'7'}}]}
});return nodes.get(id)},querySelectorAll(){return []}};
const location={reload(){}},confirm=()=>true,alert=()=>{};
const setTimeout=()=>{};
const FormData=class {get(key){return key==='url'?'https://gitlab.example':''}};
async function json(url,opts){calls.push([url,opts]);
 if(url.endsWith('/projects'))return [{id:7,path_with_namespace:'group/repo',default_branch:'main'}];
 return {name:'Account',username:'account',account:{name:'Account',username:'account'}};
}
"""
        checks = r"""
(async()=>{
 for(const [id,event] of [['#gitlab-test','click'],['#gitlab-load','click'],
 ['#gitlab-config','submit'],['#gitlab-map','submit']]){
 const node=document.querySelector(id);
 assert.equal(typeof node.handlers[event],'function',id+' has no handler');
 await node.handlers[event]({preventDefault(){},currentTarget:node});
 }
 assert.deepEqual(calls.map(x=>x[0]),[
 '/koda/api/v1/admin/gitlab/configuration/test','/koda/api/v1/admin/gitlab/status',
 '/koda/api/v1/admin/gitlab/projects','/koda/api/v1/admin/gitlab/configuration',
 '/koda/api/v1/admin/gitlab/mappings']);
 assert.match(document.querySelector('#gitlab-projects').innerHTML,/group\/repo/);
 assert.deepEqual(JSON.parse(calls.at(-1)[1].body),{project_id:'p-1',mappings:[{gitlab_project_id:7}]});
})().catch(e=>{console.error(e);process.exitCode=1});
"""
        result = subprocess.run(['node', '-e', harness + script + checks], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("node"), "JavaScript syntax check requires Node; browser checks run on the host")
    def test_admin_scripts_are_valid_javascript(self):
        html = gitlab_admin_page([{"project_id": "p-1", "name": "demo"}], [], schedule_targets=[])
        scripts = re.findall(r"<script(?: [^>]*)?>(.*?)</script>", html, re.S)
        self.assertGreaterEqual(len(scripts), 2)
        with tempfile.TemporaryDirectory() as tmp:
            for index, script in enumerate(scripts):
                path = Path(tmp) / f"script-{index}.js"
                path.write_text(script, encoding="utf-8")
                result = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
