from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo


SEOUL = ZoneInfo("Asia/Seoul")


def format_portal_time(value: object) -> str:
    """Format stored UTC ISO timestamps for people; leave unknown values readable."""
    if not value:
        return "—"
    try:
        raw = str(value).strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(SEOUL).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return str(value)


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def script_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def page(title: str, body: str, *, admin: bool = False, nav_permissions: set[str] | frozenset[str] | None = None) -> str:
    allowed = nav_permissions
    nav = {
        "dashboard": ("dashboard.view", "<a data-nav='dashboard' title='대시보드' aria-label='대시보드' href='/koda/'><span><svg aria-hidden='true' focusable='false' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M4 3v17h17M8 15v-4m5 4V7m5 8V4'/></svg></span><span class='nav-label'>대시보드</span></a>"),
        "library": ("scan.library.view", "<a data-nav='library' title='라이브러리 취약점' aria-label='라이브러리 취약점' href='/koda/scans/library'><span><svg aria-hidden='true' focusable='false' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='m12 3 9 5v9l-9 5-9-5V8l9-5Zm-9 5 9 5 9-5M12 13v9M7.5 5.5l9 5V14'/></svg></span><span class='nav-label'>라이브러리 취약점</span></a>"),
        "source": ("scan.source.view", "<a data-nav='source' title='소스코드 취약점' aria-label='소스코드 취약점' href='/koda/scans/source'><span><svg aria-hidden='true' focusable='false' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='m6 7-4 5 4 5m12-10 4 5-4 5M12 6v8'/><circle cx='12' cy='18' r='1' fill='currentColor' stroke='none'/></svg></span><span class='nav-label'>소스코드 취약점</span></a>"),
        "runs": ("runs.view", "<a data-nav='runs' title='점검 결과' aria-label='점검 결과' href='/koda/runs'><span><svg aria-hidden='true' focusable='false' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M14 2H4v20h16V8l-6-6Zm0 0v6h6M8 17v-3m4 3v-6m4 6v-4'/></svg></span><span class='nav-label'>점검 결과</span></a>"),
        "compare": ("compare.view", "<a data-nav='compare' title='비교' aria-label='비교' href='/koda/compare'><span>⇄</span><span class='nav-label'>비교</span></a>"),
        "projects": ("projects.view", "<a data-nav='projects' title='프로젝트' aria-label='프로젝트' href='/koda/projects'><span><svg aria-hidden='true' focusable='false' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><rect x='8' y='2' width='8' height='5' rx='1'/><rect x='2' y='17' width='8' height='5' rx='1'/><rect x='14' y='17' width='8' height='5' rx='1'/><path d='M12 7v5H6v5m6-5h6v5'/></svg></span><span class='nav-label'>프로젝트</span></a>"),
    }
    nav_html = "".join(markup for permission, markup in nav.values() if allowed is None or permission in allowed)
    admin_link = "<a data-nav='admin' title='관리자 설정' aria-label='관리자 설정' href='/koda/admin/subjects'><span>⚙</span><span class='nav-label'>관리자 설정</span></a>" if admin else ""
    guide_link = "<a data-nav='guide' title='사용 가이드' aria-label='사용 가이드' href='/koda/guide'><span>?</span><span class='nav-label'>사용 가이드</span></a>"
    return f"""<!doctype html><html lang='ko'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'><link rel='icon' href='/koda/assets/KODA.ico'><title>{esc(title)} · KODA</title>
<style>
:root{{--nav:#081b31;--nav2:#123b5d;--bg:#f3f6fa;--surface:#fff;--surface-soft:#f7fafc;--ink:#14263d;--muted:#687a90;--line:#dbe4ed;--line-strong:#c6d2df;--teal:#008f83;--teal-dark:#00766d;--teal2:#e8f7f4;--red:#c9362b;--orange:#c85b00;--yellow:#9b7300;--blue:#276fbd;--green:#197a3a;--radius-sm:8px;--radius-md:12px;--shadow-sm:0 2px 8px rgba(8,27,49,.05);--shadow-md:0 10px 30px rgba(8,27,49,.08)}}
*{{box-sizing:border-box}}[hidden]{{display:none!important}}html,body{{margin:0;min-height:100%;background:var(--bg);color:var(--ink);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans KR",sans-serif;-webkit-font-smoothing:antialiased}}body{{letter-spacing:-.01em}}button,input,select,textarea{{font:inherit}}a{{color:inherit}}.skip-link{{position:fixed;left:12px;top:12px;z-index:100;transform:translateY(-80px);padding:10px 14px;border-radius:var(--radius-sm);background:#fff;color:var(--ink);font-weight:750}}.skip-link:focus{{transform:none}}
.sidebar{{position:fixed;inset:0 auto 0 0;width:240px;background:var(--nav);color:#dce8f3;display:flex;flex-direction:column;z-index:20;box-shadow:8px 0 24px rgba(8,27,49,.08)}}
.brand{{height:80px;display:flex;align-items:center;gap:12px;padding:0 22px;color:#fff;text-decoration:none;font-size:22px;font-weight:800;letter-spacing:.02em;border-bottom:1px solid rgba(255,255,255,.1)}}.brand img{{width:34px;height:34px;object-fit:contain}}
.side-nav{{display:flex;flex:1;flex-direction:column;padding:18px 12px;gap:6px}}.side-nav a{{display:flex;align-items:center;gap:12px;min-height:44px;color:#cbd9e6;text-decoration:none;padding:10px 14px;border-radius:var(--radius-sm);font-weight:650;transition:background .18s ease,color .18s ease,transform .18s ease}}.side-nav a>span:first-child{{width:22px;text-align:center;color:#92adc4;font-size:17px}}.side-nav a span svg{{display:block;width:18px;height:18px;margin:auto}}.side-nav a:hover{{background:rgba(255,255,255,.08);color:#fff}}.side-nav a.active{{background:var(--nav2);color:#fff;box-shadow:inset 3px 0 var(--teal);transform:translateX(2px)}}.side-nav [data-nav='guide']{{margin-top:auto}}
.workspace{{min-height:100vh;margin-left:240px}}.topbar{{height:64px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:flex-end;padding:0 36px;background:#fff;position:relative;z-index:15}}.sidebar .nav-label,.brand>span{{white-space:nowrap;overflow:hidden;transition:opacity .2s ease,max-width .24s ease;max-width:180px}}.sidebar-collapsed .nav-label,.sidebar-collapsed .brand>span{{opacity:0;max-width:0;pointer-events:none}}.sidebar{{overflow:hidden;transition:width .24s ease}}.workspace{{transition:margin-left .24s ease}}@media(prefers-reduced-motion:reduce){{.sidebar,.workspace,.sidebar .nav-label,.brand>span{{transition:none}}}}@media(min-width:1001px){{.sidebar-collapsed .sidebar{{width:72px}}.sidebar-collapsed .workspace{{margin-left:72px}}.sidebar-collapsed .brand{{padding:0;justify-content:center}}.sidebar-collapsed .side-nav{{padding:18px 8px}}.sidebar-collapsed .side-nav a{{padding:10px 0;justify-content:center;gap:0}}}}.sidebar-toggle{{width:44px;min-height:44px;padding:10px;margin-right:auto;flex-shrink:0;border:0;background:transparent;box-shadow:none}}.sidebar-toggle svg{{width:24px;height:24px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}}.account-menu{{position:relative}}.user-menu{{min-height:44px;border:0;background:transparent;display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:var(--radius-sm);box-shadow:none}}.user-menu:hover,.user-menu[aria-expanded='true']{{border-color:transparent;background:var(--surface-soft)}}.account-icon{{width:28px;height:28px;display:grid;place-items:center;border-radius:50%;background:var(--teal2);color:var(--teal-dark)}}.account-icon svg,.account-chevron{{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}}.account-label{{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.account-chevron{{width:15px;transition:transform .18s ease}}.user-menu[aria-expanded='true'] .account-chevron{{transform:rotate(180deg)}}.account-panel{{position:absolute;top:calc(100% + 8px);right:0;width:300px;padding:16px;border:1px solid var(--line-strong);border-radius:var(--radius-sm);background:#fff;box-shadow:0 12px 28px rgba(8,27,49,.16)}}.account-summary{{display:flex;align-items:center;gap:11px;padding-bottom:14px;border-bottom:1px solid var(--line)}}.account-avatar{{width:36px;height:36px;display:grid;place-items:center;border-radius:50%;background:var(--teal2);color:var(--teal-dark);font-weight:800}}.account-summary strong{{display:block;overflow-wrap:anywhere}}.account-details{{display:grid;gap:9px;margin:14px 0;font-size:12px}}.account-details div{{display:flex;justify-content:space-between;gap:12px}}.account-details dt{{color:var(--muted);white-space:nowrap;flex-shrink:0}}.account-details dd{{min-width:0;margin:0;font-weight:650;text-align:right;overflow-wrap:anywhere}}.account-logout{{width:100%;min-height:44px;border-color:#e2b3b3;background:#fff7f7;color:var(--red)}}.account-logout:hover:not(:disabled){{border-color:#df9b9b;background:#ffeded}}.account-logout:disabled{{cursor:not-allowed;opacity:.55}}main>.panel+.panel,main>.result-layout+.panel{{margin-top:20px}}main{{max-width:1440px;margin:0 auto;padding:28px 36px 64px}}h1{{font-size:30px;line-height:1.2;letter-spacing:-.03em;margin:0 0 26px}}h2{{font-size:19px;line-height:1.35;margin:0;font-weight:750}}h3{{font-size:15px;line-height:1.4;margin:0;font-weight:750}}p{{margin:.45rem 0}}.muted{{color:var(--muted)}}.error{{color:var(--red)}}
.panel{{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius-md);box-shadow:var(--shadow-sm);overflow:hidden}}.panel-head{{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:20px 24px;border-bottom:1px solid var(--line);min-height:72px}}.panel-body{{padding:24px}}
.dashboard-top{{display:grid;grid-template-columns:minmax(max-content,1.08fr) minmax(0,1.92fr);gap:20px;margin-bottom:20px}}.start-panel{{display:flex;align-items:center;gap:14px;padding:18px}}.start-copy{{flex:1;min-width:0}}.start-copy h2{{font-size:21px;margin-bottom:4px}}.start-copy .toolbar{{gap:8px}}.start-copy>.muted{{white-space:nowrap}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr)}}.stat{{min-height:112px;padding:18px;border-right:1px solid var(--line);display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}}.stat:last-child{{border:0}}.stat small{{color:var(--muted);font-weight:650}}.stat strong{{display:block;font-size:30px;line-height:1;margin-top:10px;letter-spacing:-.02em}}.stat.danger strong{{color:var(--red)}}.stat.high strong{{color:var(--orange)}}
.button,button{{min-height:42px;border:1px solid var(--line-strong);border-radius:var(--radius-sm);background:#fff;color:var(--ink);padding:9px 16px;text-decoration:none;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:8px;font-weight:650;line-height:1.2;transition:background .18s ease,border-color .18s ease,color .18s ease,box-shadow .18s ease,transform .18s ease}}.button:hover,button:hover{{border-color:#9eb1c4;background:#f8fafc}}.button:active,button:active{{transform:translateY(1px)}}.button.primary,button.primary{{background:var(--teal);border-color:var(--teal);color:#fff;font-weight:750;box-shadow:0 4px 10px rgba(0,143,131,.18)}}.button.primary:hover,button.primary:hover{{background:var(--teal-dark);border-color:var(--teal-dark)}}.button:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{{outline:3px solid rgba(0,143,131,.22);outline-offset:2px}}
.toolbar{{display:flex;align-items:center;gap:12px;flex-wrap:wrap}}.toolbar-between{{justify-content:space-between}}.toolbar-spaced{{margin-bottom:20px}}.toolbar-submit{{margin-top:18px}}input,select,textarea{{min-height:42px;border:1px solid var(--line-strong);border-radius:var(--radius-sm);background:#fff;color:var(--ink);padding:9px 12px;transition:border-color .18s ease,box-shadow .18s ease}}input:hover,select:hover,textarea:hover{{border-color:#9eb1c4}}input[type=search]{{min-width:260px}}input[type=checkbox]{{min-height:auto;width:18px;height:18px;accent-color:var(--teal)}}label{{display:block;font-weight:650}}label input,label select,label textarea{{display:block;width:100%;margin-top:7px}}.check-label{{display:inline-flex;align-items:center;gap:8px;white-space:nowrap}}.check-label input{{display:inline-block;width:18px;margin:0}}.toolbar label{{display:flex;align-items:center;gap:8px;white-space:nowrap;font-size:13px}}.toolbar label input,.toolbar label select,.toolbar label textarea{{display:inline-block;width:auto;min-width:180px;margin-top:0}}.subject-controls .check-label input{{width:18px;min-width:18px;flex:none}}textarea{{resize:vertical}}
.table-wrap{{overflow:auto}}table{{width:100%;border-collapse:separate;border-spacing:0}}th,td{{padding:14px 16px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap;line-height:1.45}}th{{background:var(--surface-soft);color:#526277;font-size:12px;font-weight:750;letter-spacing:.01em}}tbody tr:last-child td,tbody tr:last-child th{{border-bottom:0}}tbody tr:hover{{background:#f5fbfa}}td.wrap{{white-space:normal;min-width:220px}}code,.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;color:#526277}}.role-head{{text-align:center;min-width:145px}}.role-head strong,.role-head small,.role-head code{{display:block}}.role-head small{{white-space:normal;font-weight:400;margin-top:4px}}.permission-check{{text-align:center;vertical-align:middle}}
.status{{display:inline-flex;align-items:center;gap:7px;min-height:24px;flex:0 0 auto;white-space:nowrap;font-weight:650}}.status:before{{content:"";width:8px;height:8px;flex:0 0 auto;border-radius:50%;background:#7b8794}}.status-completed:before{{background:var(--green)}}.status-running:before,.status-queued:before,.status-preparing:before,.status-scanning:before,.status-finalizing:before{{background:var(--blue)}}.status-failed:before,.status-cancelled:before{{background:var(--red)}}.status-warning:before,.status-cancelling:before{{background:var(--orange)}}.status-skipped:before{{background:var(--muted)}}
.sev{{font-weight:750}}.sev-critical{{color:var(--red)}}.sev-high{{color:var(--orange)}}.sev-medium{{color:var(--yellow)}}.sev-low{{color:var(--blue)}}
.form-grid{{display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:24px}}.steps{{padding:28px}}.step{{padding:0 0 28px;margin-bottom:28px;border-bottom:1px solid var(--line)}}.step:last-child{{border-bottom:0;margin-bottom:0;padding-bottom:0}}.step h2{{margin-bottom:14px}}.drop-zone{{border:1px dashed var(--teal);border-radius:var(--radius-md);background:#fbfefe;padding:28px;text-align:center}}.drop-zone input{{max-width:100%}}.option-row{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}}.choice{{border:1px solid var(--line);border-radius:var(--radius-sm);padding:15px;transition:border-color .18s ease,background .18s ease}}.choice:has(input:checked){{border-color:var(--teal);background:var(--teal2)}}.input-source-switch{{gap:10px;margin-bottom:14px}}.input-source-switch .choice{{min-height:42px;flex:0 0 190px;padding:9px 12px;justify-content:flex-start}}.input-source-switch input[type=radio]{{min-width:0;min-height:0;width:16px;height:16px;margin:0;accent-color:var(--teal)}}.gitlab-repository-row{{display:grid;grid-template-columns:3em minmax(0,1fr);align-items:center;gap:10px}}.gitlab-repository-row select{{width:100%;margin:0}}.gitlab-ref-row{{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:12px;margin-top:12px}}.gitlab-ref-row label{{display:flex;align-items:center;gap:8px;min-width:0;white-space:nowrap}}.gitlab-ref-row label select{{min-width:0;margin:0}}.gitlab-ref-row .gitlab-ref-type-field{{display:grid;grid-template-columns:3em 110px;gap:10px}}.gitlab-ref-type-field select{{flex:0 0 110px;width:110px}}.gitlab-ref-field select{{flex:1;width:auto}}.integration-help{{margin-top:14px}}.integration-help summary{{font-weight:750;cursor:pointer}}.integration-help ol{{margin-bottom:0;padding-left:22px}}.summary-list{{margin:0;padding:0;list-style:none}}.summary-list li{{padding:15px 0;border-bottom:1px solid var(--line)}}.summary-list li:last-child{{border:0}}.summary-list span{{display:block;color:var(--muted);font-size:12px;font-weight:650}}.summary-list strong{{display:block;margin-top:4px;overflow-wrap:anywhere}}
.project-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}}.project-card{{padding:20px;text-decoration:none;transition:border-color .18s ease,box-shadow .18s ease,transform .18s ease}}.project-card h2{{margin-bottom:7px}}.project-card:hover{{border-color:var(--teal);box-shadow:0 8px 22px rgba(0,143,131,.12);transform:translateY(-2px)}}
.compare-layout{{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:24px;margin:0 12px 20px}}.compare-layout .compare-wide{{grid-column:1 / -1}}.severity-bar{{display:flex;height:18px;border-radius:999px;overflow:hidden;background:var(--line)}}.severity-bar span{{min-width:0}}.severity-bar .critical{{background:var(--red)}}.severity-bar .high{{background:var(--orange)}}.severity-bar .medium{{background:var(--yellow)}}.severity-bar .low{{background:var(--blue)}}.pager{{display:flex;align-items:center;justify-content:center;gap:8px;padding:16px;border-top:1px solid var(--line)}}.project-grid>.pager{{grid-column:1 / -1}}.pager button{{min-height:34px;padding:6px 10px}}.pager small{{color:var(--muted)}}
.result-layout{{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(340px,.75fr);gap:20px}}.summary-strip{{display:grid;grid-template-columns:repeat(5,1fr);margin-bottom:20px}}.summary-strip div{{min-height:88px;padding:14px 18px;border-right:1px solid var(--line);display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}}.summary-strip div:last-child{{border:0}}.summary-strip strong{{display:block;font-size:25px;line-height:1.1;margin-top:5px}}#findings td{{overflow:hidden;text-overflow:clip;white-space:nowrap}}.finding-row{{cursor:pointer}}.finding-row.selected{{background:var(--teal2)}}.resizable-table{{table-layout:fixed;min-width:780px}}.resizable-table th{{position:relative}}.column-resizer{{position:absolute;inset:0 -7px 0 auto;width:14px;cursor:col-resize;touch-action:none;z-index:1}}.column-resizer:after{{content:"";position:absolute;top:20%;bottom:20%;left:6px;width:2px;background:transparent}}.column-resizer:hover:after,.column-resizer:focus-visible:after{{background:var(--teal)}}.inspector{{position:sticky;top:92px;align-self:start}}.inspector pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#0c1d2e;color:#e7f0f7;padding:16px;border-radius:var(--radius-sm);max-height:260px;overflow:auto}}.detail-section{{padding:18px 0;border-bottom:1px solid var(--line)}}
.tabs{{display:flex;gap:26px;border-bottom:1px solid var(--line);padding:0 24px;overflow:auto}}.tabs button{{min-height:52px;border:0;border-radius:0;padding:14px 2px;background:transparent;white-space:nowrap;color:var(--muted)}}.tabs button:hover{{background:transparent;color:var(--ink);border-color:transparent}}.tabs button.active{{color:var(--teal);box-shadow:inset 0 -3px var(--teal)}}
.progress{{height:10px;background:#e8edf2;border-radius:999px;overflow:hidden}}.progress span{{display:block;height:100%;background:var(--teal);transition:width .25s}}.progress-panel{{padding:18px 20px;margin-bottom:20px}}.stage-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}}.stage-card{{padding:20px}}.stage-card strong{{display:block;font-size:18px;margin:8px 0}}
#schedule-target [data-weekly-field]{{min-width:0;display:flex;flex-wrap:wrap;gap:8px 12px;border:1px solid var(--line-strong);border-radius:var(--radius-sm)}}#schedule-target [data-weekly-field] .check-label{{display:inline-flex;align-items:center;gap:6px;min-height:32px;margin:0}}#schedule-target [data-weekly-field] input{{margin:0;flex-shrink:0}}
.subject-picker{{margin:0;min-width:200px}}.subject-picker-options{{display:grid;gap:8px;max-height:240px;overflow:auto;padding-bottom:12px}}.subject-picker-options label{{margin:0!important;width:auto!important}}.subject-picker-options input{{flex:none!important;min-width:0!important}}
.admin-content,.project-content{{display:grid;gap:20px}}.gitlab-config-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}}.gitlab-config-grid>label:first-child{{grid-column:1 / -1}}.admin-subnav{{display:flex;gap:0;margin-bottom:20px;flex-wrap:wrap;border-bottom:1px solid var(--line)}}.admin-subnav .button{{border:0;border-radius:0;background:transparent;color:var(--muted);border-bottom:3px solid transparent}}.admin-subnav .button:hover,.admin-subnav .button[aria-current='page']{{background:var(--teal2);color:var(--teal-dark);border-bottom-color:var(--teal)}}details{{margin-top:18px;border:1px solid var(--line);border-radius:var(--radius-sm);padding:0 16px;background:var(--surface)}}details summary{{cursor:pointer;padding:14px 0;font-weight:700}}[data-rule-group]+[data-rule-group]{{margin-top:12px}}[data-rule-card]+[data-rule-card]{{margin-top:10px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}.empty{{padding:48px;text-align:center;color:var(--muted)}}
.guide-hero{{margin-bottom:20px}}.guide-eyebrow{{color:var(--teal-dark);font-size:12px;font-weight:800;letter-spacing:.08em}}.guide-search{{max-width:560px}}.guide-search input{{width:100%}}.guide-grid,.glossary-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin:16px 0 24px}}.guide-card{{padding:20px}}.guide-card h3{{margin-bottom:8px;font-size:17px}}.glossary-grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}.guide-term{{margin:0;padding:18px;border:1px solid var(--line);border-radius:var(--radius-md);background:var(--surface)}}.guide-term dt{{font-size:17px;font-weight:800;color:var(--teal-dark)}}.guide-term dd{{margin:7px 0 0;color:#42556b}}.guide-standards{{padding-top:6px}}.guide-standard summary{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}.guide-standard summary strong{{margin-right:auto}}.guide-badge{{padding:3px 9px;border-radius:999px;font-size:12px;font-weight:750;background:var(--surface-soft);color:#526277}}.guide-badge-local{{background:var(--teal2);color:var(--teal-dark)}}.guide-badge-external{{background:#edf4ff;color:var(--blue)}}.guide-badge-evidence{{background:#fff6dc;color:#7b5c00}}.guide-standard-body{{padding:0 0 18px}}.guide-meta{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:14px 0}}.guide-meta div{{padding:12px;border-radius:var(--radius-sm);background:var(--surface-soft)}}.guide-meta dt{{color:var(--muted);font-size:12px;font-weight:700}}.guide-meta dd{{margin:4px 0 0;font-weight:650;overflow-wrap:anywhere}}.guide-categories{{overflow-wrap:anywhere}}
@media(max-width:1100px){{.start-copy>.muted{{white-space:normal}}.dashboard-top,.form-grid,.result-layout{{grid-template-columns:1fr}}.inspector{{position:static}}}}
@media(max-width:1000px){{.sidebar{{position:static;width:auto;min-height:auto}}.brand{{height:64px}}.side-nav{{flex:0 0 auto;flex-direction:row;overflow:auto}}.side-nav a{{white-space:nowrap}}.side-nav [data-nav='guide']{{margin-top:0}}.workspace{{margin-left:0}}.topbar{{padding:0 24px}}main{{padding:28px 24px 48px}}.stats{{grid-template-columns:repeat(2,1fr)}}.guide-grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}}}
@media(max-width:700px){{.subject-picker{{width:100%}}.gitlab-config-grid{{grid-template-columns:1fr}}main{{padding:24px 16px 40px}}h1{{font-size:26px;margin-bottom:20px}}.panel-head{{align-items:flex-start;flex-direction:column;padding:18px}}.panel-head>.toolbar{{width:100%}}.toolbar label{{width:100%}}.toolbar label input,.toolbar label select,.toolbar label textarea{{flex:1;min-width:0}}input[type=search]{{min-width:0;width:100%}}.start-panel{{align-items:flex-start;flex-direction:column;padding:22px}}.stage-grid{{grid-template-columns:1fr}}.summary-strip{{grid-template-columns:repeat(2,1fr)}}.summary-strip div:nth-child(2n){{border-right:0}}.summary-strip div:last-child{{grid-column:1 / -1;border-top:1px solid var(--line)}}.option-row{{grid-template-columns:1fr}}.steps,.panel-body{{padding:20px}}.table-wrap{{margin:0 -1px}}th,td{{padding:12px}}.project-grid,.compare-layout,.guide-grid,.glossary-grid,.guide-meta{{grid-template-columns:1fr;margin-left:0;margin-right:0}}.compare-layout .compare-wide{{grid-column:auto}}.guide-standard summary strong{{width:100%}}}}
</style><script>const json=async(url,options={{}})=>{{const r=await fetch(url,{{credentials:'include',...options,headers:{{'Content-Type':'application/json',...(options.headers||{{}})}}}});if(!r.ok)throw new Error((await r.json().catch(()=>({{}}))).detail||`HTTP ${{r.status}}`);return r.status===204?null:r.json()}};</script></head><body>
<a class='skip-link' href='#main-content'>본문으로 건너뛰기</a><aside class='sidebar' id='sidebar'><a class='brand' aria-label='KODA' href='/koda/'><img src='/koda/assets/KODA.ico' alt=''><span>KODA</span></a><nav class='side-nav'>{nav_html}{admin_link}{guide_link}</nav></aside><div class='workspace'><header class='topbar'><button class='sidebar-toggle' id='sidebar-toggle' type='button' aria-controls='sidebar' aria-expanded='true' aria-label='사이드바 닫기' title='사이드바 닫기'><svg viewBox='0 0 24 24' aria-hidden='true' focusable='false'><path d='M4 6h16M4 12h16M4 18h16'></path></svg></button><div class='account-menu' id='account-menu'><button class='user-menu' id='account-toggle' type='button' aria-controls='account-panel' aria-expanded='false' aria-haspopup='true' title='계정 메뉴'><span class='account-icon' aria-hidden='true'><svg viewBox='0 0 24 24'><circle cx='12' cy='8' r='4'></circle><path d='M4 21a8 8 0 0 1 16 0'></path></svg></span><span class='account-label' id='account-label'>사용자</span><svg class='account-chevron' viewBox='0 0 24 24' aria-hidden='true'><path d='m6 9 6 6 6-6'></path></svg></button><div class='account-panel' id='account-panel' aria-label='계정 메뉴' hidden><div class='account-summary'><span class='account-avatar' id='account-avatar' aria-hidden='true'>사</span><div><strong id='account-display'>사용자</strong></div></div><dl class='account-details'><div><dt>아이디</dt><dd id='account-id'>-</dd></div><div><dt>역할</dt><dd id='account-role'>-</dd></div></dl><button class='account-logout' id='account-logout' type='button'>로그아웃</button></div></div></header><main id='main-content'><h1>{esc(title)}</h1>{body}</main></div>
<script>
const sidebarToggle=document.querySelector('#sidebar-toggle');
function setSidebarOpen(open){{document.body.classList.toggle('sidebar-collapsed',!open);sidebarToggle.setAttribute('aria-expanded',String(open));sidebarToggle.setAttribute('aria-label',open?'사이드바 닫기':'사이드바 열기');sidebarToggle.title=open?'사이드바 닫기':'사이드바 열기';document.querySelector('.brand').setAttribute('aria-label',open?'KODA':'사이드바 열기')}}
try{{setSidebarOpen(sessionStorage.getItem('koda-sidebar-collapsed')!=='true')}}catch{{}}
sidebarToggle.addEventListener('click',()=>{{setSidebarOpen(sidebarToggle.getAttribute('aria-expanded')!=='true');try{{sessionStorage.setItem('koda-sidebar-collapsed',String(document.body.classList.contains('sidebar-collapsed')))}}catch{{}}}});
document.querySelector('.brand').addEventListener('click',e=>{{if(document.body.classList.contains('sidebar-collapsed')){{e.preventDefault();sidebarToggle.click()}}}});
function setupPagination(root,selector='[data-page-item]'){{const items=[...root.querySelectorAll(selector)],size=Number(root.dataset.pageSize||10);let current=1,max=1;const controls=document.createElement('div');controls.className='pager';controls.innerHTML='<button type="button" data-prev>이전</button><small data-label></small><button type="button" data-next>다음</button>';root.append(controls);function draw(){{const visible=items.filter(x=>x.dataset.filtered!=='true'&&!x.dataset.removed);max=Math.max(1,Math.ceil(visible.length/size));current=Math.min(current,max);items.forEach(x=>x.hidden=true);visible.slice((current-1)*size,current*size).forEach(x=>x.hidden=false);controls.querySelector('[data-label]').textContent=`${{current}} / ${{max}}`;controls.querySelector('[data-prev]').disabled=current<=1;controls.querySelector('[data-next]').disabled=current>=max}}controls.querySelector('[data-prev]').onclick=()=>{{if(current>1){{current--;draw()}}}};controls.querySelector('[data-next]').onclick=()=>{{if(current<max){{current++;draw()}}}};root._paginate=(reset=true)=>{{if(reset)current=1;draw()}};draw()}}
const path=location.pathname;let key=path==='/koda/'||path==='/koda'?'dashboard':path.startsWith('/koda/scans/library')?'library':path.startsWith('/koda/scans/source')?'source':path.startsWith('/koda/runs')?'runs':path.startsWith('/koda/compare')?'compare':path.startsWith('/koda/projects')?'projects':path.startsWith('/koda/admin')?'admin':path.startsWith('/koda/guide')?'guide':'',activeNav=document.querySelector(`[data-nav="${{key}}"]`);activeNav?.classList.add('active');if(matchMedia('(max-width:1000px)').matches)activeNav?.scrollIntoView({{block:'nearest',inline:'center'}});
document.querySelectorAll('[data-pager]').forEach(x=>setupPagination(x));
const accountMenu=document.querySelector('#account-menu'),accountToggle=document.querySelector('#account-toggle'),accountPanel=document.querySelector('#account-panel');function setAccountOpen(open){{accountPanel.hidden=!open;accountToggle.setAttribute('aria-expanded',String(open))}}accountToggle.addEventListener('click',()=>setAccountOpen(accountPanel.hidden));document.addEventListener('pointerdown',event=>{{if(!accountMenu.contains(event.target))setAccountOpen(false)}});document.addEventListener('keydown',event=>{{if(event.key==='Escape'&&!accountPanel.hidden){{setAccountOpen(false);accountToggle.focus()}}}});json('/koda/api/v1/me').then(user=>{{const display=user.display||'사용자';document.querySelector('#account-label').textContent=display;document.querySelector('#account-display').textContent=display;document.querySelector('#account-avatar').textContent=display.trim().slice(0,1)||'사';document.querySelector('#account-id').textContent=user.username||user.display||'-';document.querySelector('#account-role').textContent=user.system_admin?'시스템 관리자':'일반 사용자'}}).catch(()=>{{document.querySelector('#account-label').textContent='사용자 정보를 확인할 수 없음'}});document.querySelector('#account-logout').addEventListener('click',async event=>{{const button=event.currentTarget;button.disabled=true;try{{const r=await fetch('/api/v1/auth/logout-current',{{method:'POST',credentials:'include',headers:{{'X-KODA-Logout':'current-browser'}}}});if(!r.ok)throw new Error(`HTTP ${{r.status}}`);location='/koda/login'}}catch(e){{button.disabled=false;alert('로그아웃하지 못했습니다: '+e.message)}}}});
</script></body></html>"""


def guide_page(*, admin: bool = False, nav_permissions=None) -> str:
    from .standards import standards_payload

    def localized(value: object) -> str:
        if isinstance(value, dict):
            return str(value.get("ko") or value.get("en") or "")
        return str(value or "")

    features = (
        ("대시보드", "접근 가능한 프로젝트의 최신 점검 상태와 심각도 분포를 프로젝트별로 확인합니다."),
        ("프로젝트와 입력", "점검 대상을 프로젝트 단위로 관리합니다. 업로드한 원본은 점검 종료 후 자동 삭제되며 결과와 실행 메타데이터는 남습니다."),
        ("라이브러리 취약점 점검", "SBOM, manifest, lockfile, JAR/WAR 등에서 구성요소를 식별하고 오프라인 Grype DB와 연결된 CVE 결과만 보여줍니다."),
        ("소스코드 취약점 점검", "전체 통합 기준 또는 OWASP·CWE·소프트웨어 개발보안 기준을 선택해 파일 기반 정적 점검을 실행합니다."),
        ("점검 결과와 보고서", "심각도와 분류별 결과, 항목별 근거와 조치 방법을 보고 HTML·PDF·Excel·JSON·Markdown 및 SBOM 형식으로 내보냅니다."),
        ("회차 비교", "같은 프로젝트의 완료된 두 회차를 비교해 신규·해결·유지 항목을 확인합니다."),
    )
    terms = (
        ("CVE", "공개된 개별 보안 취약점에 부여되는 고유 식별자입니다. 예: CVE-2025-12345."),
        ("CVSS", "취약점의 기술적 심각도를 0.0~10.0 점수로 표현하는 체계입니다. 실제 업무 위험도는 노출 범위와 악용 가능성을 함께 판단해야 합니다."),
        ("CWE", "소프트웨어 결함의 원인과 유형을 분류한 약점 목록입니다. CVE가 개별 취약점이라면 CWE는 그 취약점이 속한 문제 유형입니다."),
        ("KEV", "실제 악용이 확인된 취약점을 모은 CISA 카탈로그입니다. KEV 등재 항목은 우선 조치 대상으로 보는 것이 좋습니다."),
        ("SBOM", "소프트웨어를 구성하는 라이브러리·패키지·버전 등의 목록입니다. 의존성 취약점 확인과 공급망 관리에 사용합니다."),
        ("SAST", "프로그램을 실행하지 않고 소스코드나 정적 산출물을 분석해 보안 문제를 찾는 방식입니다."),
        ("DAST", "실행 중인 애플리케이션에 요청을 보내 동작과 응답을 분석하는 방식입니다. KODA의 파일 기반 정적 점검과는 역할이 다릅니다."),
        ("의존성 취약점", "프로젝트가 사용하는 외부 라이브러리나 패키지 버전에 알려진 CVE가 연결된 상태입니다."),
        ("시크릿", "API 키, 토큰, 비밀번호, 개인키처럼 외부에 노출되면 안 되는 인증·기밀 값입니다."),
        ("심각도", "KODA는 심각·높음·보통·낮음으로 우선순위를 표시합니다. 결과의 맥락과 실제 노출 여부를 함께 검토해야 합니다."),
        ("오탐", "도구가 문제로 표시했지만 실제 환경에서는 취약하지 않은 결과입니다. 근거와 코드 흐름을 검토해 판정합니다."),
        ("수정 버전", "해당 취약점이 해결된 것으로 공급자나 데이터베이스에 기록된 라이브러리 버전입니다."),
        ("OWASP", "웹·API·모바일·개발보안 지침을 제공하는 공개 보안 커뮤니티입니다. Top 10, ASVS, WSTG 등의 기준을 발행합니다."),
        ("소프트웨어 개발보안 49", "국내 소프트웨어 개발 단계에서 점검하는 보안약점 49개 항목 체계입니다. KODA는 정적 근거를 만들 수 있는 항목을 룰에 매핑합니다."),
    )
    feature_cards = "".join(
        f"<article class='panel guide-card' data-guide-item><h3>{esc(title)}</h3><p>{esc(description)}</p></article>"
        for title, description in features
    )
    term_cards = "".join(
        f"<div class='guide-term' data-guide-item><dt>{esc(term)}</dt><dd>{esc(description)}</dd></div>"
        for term, description in terms
    )
    coverage_labels = {"local": "KODA 자동 점검", "external": "외부 도구 연동", "evidence": "증거·수동 검토"}
    standard_cards = []
    standards = [standard for standard in standards_payload() if standard.get("id") != "local"]
    for standard in standards:
        categories = standard.get("categories") if isinstance(standard.get("categories"), list) else []
        category_names = [localized(category.get("labels")) for category in categories if isinstance(category, dict)]
        supported = sum(bool(category.get("supported")) for category in categories if isinstance(category, dict))
        level = str(standard.get("coverage_level") or "evidence")
        edition = " · ".join(value for value in (str(standard.get("version") or ""), str(standard.get("published_on") or "")) if value) or "—"
        standard_cards.append(
            f"<details class='guide-standard' data-guide-item><summary><strong>{esc(localized(standard.get('labels')))}</strong>"
            f"<code>{esc(standard.get('id'))}</code><span class='guide-badge guide-badge-{esc(level)}'>{esc(coverage_labels.get(level, level))}</span></summary>"
            f"<div class='guide-standard-body'><p>{esc(localized(standard.get('description')))}</p><p class='muted'>{esc(localized(standard.get('coverage')))}</p>"
            f"<dl class='guide-meta'><div><dt>발행 기관</dt><dd>{esc(localized(standard.get('issuer')) or '—')}</dd></div>"
            f"<div><dt>버전·발행일</dt><dd>{esc(edition)}</dd></div><div><dt>KODA 지원 분류</dt><dd>{supported} / {len(categories)}</dd></div></dl>"
            f"<p class='guide-categories'><strong>분류</strong><br>{esc(', '.join(category_names) or '등록된 분류 없음')}</p></div></details>"
        )
    body = f"""<section class='panel guide-hero'><div class='panel-body'><p class='guide-eyebrow'>KODA USER GUIDE</p><h2>KODA를 처음 사용하는 분을 위한 안내</h2><p>KODA는 프로젝트의 라이브러리와 소스코드를 로컬 환경에서 점검하고, 결과를 회차별로 관리하는 보안 점검 포털입니다.</p><label class='guide-search'>가이드 검색<input id='guide-search' type='search' placeholder='예: CVE, OWASP, 회차 비교'></label><p id='guide-search-status' class='muted' aria-live='polite'></p></div></section>
<section id='guide-features'><h2>KODA 기능</h2><div class='guide-grid'>{feature_cards}</div></section>
<section id='guide-terms'><h2>보안 용어</h2><dl class='glossary-grid'>{term_cards}</dl></section>
<section id='guide-standards' class='panel'><div class='panel-head'><div><h2>지원 기준</h2><p class='muted'>현재 KODA 카탈로그에 등록된 {len(standards)}개 기준입니다. 자동 점검 범위는 공식 인증이나 전체 준수 판정을 의미하지 않습니다.</p></div></div><div class='panel-body guide-standards'>{''.join(standard_cards)}</div></section>
<script>const guideItems=[...document.querySelectorAll('[data-guide-item]')],guideSearch=document.querySelector('#guide-search'),guideStatus=document.querySelector('#guide-search-status');function filterGuide(){{const query=guideSearch.value.trim().toLowerCase();let visible=0;guideItems.forEach(item=>{{const show=!query||item.textContent.toLowerCase().includes(query);item.hidden=!show;if(show)visible++}});guideStatus.textContent=query?`${{visible}}개 항목 표시`:`전체 ${{guideItems.length}}개 항목`}}guideSearch.addEventListener('input',filterGuide);filterGuide()</script>"""
    return page("KODA 사용 가이드", body, admin=admin, nav_permissions=nav_permissions)


def login_page(next_path: str = "/koda/") -> str:
    return f"""<!doctype html><html lang='ko'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><link rel='icon' href='/koda/assets/KODA.ico'><title>KODA 로그인</title>
<style>:root{{--nav:#081b31;--bg:#f3f6fa;--surface:#fff;--ink:#14263d;--muted:#687a90;--line:#dbe4ed;--line-strong:#c6d2df;--teal:#008f83;--teal-dark:#00766d;--red:#c9362b;--radius:14px;--shadow:0 18px 44px rgba(8,27,49,.12)}}*{{box-sizing:border-box}}body{{font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans KR",sans-serif;background:linear-gradient(145deg,#edf4f8 0%,var(--bg) 55%,#e8f4f2 100%);margin:0;min-height:100vh;color:var(--ink);display:grid;place-items:center;padding:24px;-webkit-font-smoothing:antialiased}}main{{width:min(100%,440px);background:var(--surface);padding:40px;border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}}.brand{{display:flex;align-items:center;gap:13px;margin-bottom:26px}}.brand img{{width:46px;height:46px;object-fit:contain}}h1{{margin:0;font-size:28px;letter-spacing:-.03em}}p{{margin:.5rem 0}}label{{display:block;margin:18px 0;font-weight:650}}input:not([type=checkbox]),button{{width:100%;min-height:44px;padding:10px 12px;box-sizing:border-box;border:1px solid var(--line-strong);border-radius:8px;font:inherit}}input:not([type=checkbox]){{display:block;margin-top:8px}}input:focus-visible{{outline:3px solid rgba(0,143,131,.22);outline-offset:2px;border-color:var(--teal)}}input[type=checkbox]{{width:18px;height:18px;accent-color:var(--teal);vertical-align:-4px;margin-right:6px}}button{{background:var(--teal);color:white;border-color:var(--teal);font-weight:750;cursor:pointer;transition:background .18s ease,transform .18s ease}}button:hover{{background:var(--teal-dark);border-color:var(--teal-dark)}}button:active{{transform:translateY(1px)}}button:focus-visible{{outline:3px solid rgba(0,143,131,.22);outline-offset:2px}}button.secondary{{margin-top:10px;background:white;color:var(--ink);border-color:var(--line-strong)}}button.secondary:hover{{background:#f7fafc;border-color:#9eb1c4}}.error{{color:var(--red)}}.notice{{color:#006b63}}[hidden]{{display:none!important}}@media(max-width:480px){{body{{padding:16px}}main{{padding:28px 22px}}}}</style></head><body><main><div class='brand'><img src='/koda/assets/KODA.ico' alt=''><h1>KODA</h1></div><p>공유 계정으로 로그인합니다.</p>
<form id='login'><label>계정<input name='username' autocomplete='username' required></label><label>비밀번호<input name='password' type='password' autocomplete='current-password' required></label><label><input name='useLdap' type='checkbox'> LDAP 계정</label><button>로그인</button><button id='show-register' class='secondary' type='button'>회원가입</button><p id='message' class='error' role='alert'></p></form>
<form id='register' hidden><label>계정<input name='username' autocomplete='username' pattern='[A-Za-z0-9][A-Za-z0-9._-]{{2,63}}' required></label><label>비밀번호<input name='password' type='password' autocomplete='new-password' minlength='12' required></label><label>비밀번호 확인<input name='passwordConfirm' type='password' autocomplete='new-password' minlength='12' required></label><button>가입 신청</button><button id='show-login' class='secondary' type='button'>로그인으로 돌아가기</button><p id='register-message' class='error' role='alert'></p></form>
<script>
const login=document.querySelector('#login'),register=document.querySelector('#register'),message=document.querySelector('#message');
document.querySelector('#show-register').onclick=()=>{{login.hidden=true;register.hidden=false}};document.querySelector('#show-login').onclick=()=>{{register.hidden=true;login.hidden=false}};
login.addEventListener('submit',async e=>{{e.preventDefault();const f=new FormData(e.currentTarget);message.className='error';message.textContent='';const r=await fetch('/api/v1/auth/login',{{method:'POST',credentials:'include',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{username:f.get('username'),password:f.get('password'),useLdap:f.get('useLdap')==='on'}})}});if(r.ok)location={script_json(next_path)};else{{const x=await r.json().catch(()=>({{}}));message.textContent=x.detail||'로그인하지 못했습니다.'}}}});
register.addEventListener('submit',async e=>{{e.preventDefault();const f=new FormData(e.currentTarget),m=document.querySelector('#register-message');m.textContent='';const r=await fetch('/api/v1/auth/register',{{method:'POST',credentials:'include',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{username:f.get('username'),password:f.get('password'),passwordConfirm:f.get('passwordConfirm')}})}}),x=await r.json().catch(()=>({{}}));if(r.ok){{register.hidden=true;login.hidden=false;message.className='notice';message.textContent=x.detail}}else m.textContent=x.detail||'가입 신청을 처리하지 못했습니다.'}});
</script></main></body></html>"""


def _severity_counts(runs: list[dict]) -> dict[str, int]:
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for run in runs:
        result = run.get("result") if isinstance(run.get("result"), dict) else {}
        for finding in result.get("findings", []):
            key = str(finding.get("severity", "info")).lower()
            counts[key if key in counts else "info"] += 1
    return counts


def _finding_group(category: object) -> str:
    category = str(category).lower()
    if category == "dependencies":
        return "library"
    if category in {"quality", "screen_quality"}:
        return "quality"
    return "source"


_CATEGORY_LABELS = {
    "dependencies": "라이브러리",
    "code": "소스코드",
    "secrets": "비밀정보",
    "configuration": "보안설정",
    "prevention": "예방통제",
    "screen_quality": "화면품질",
    "quality": "품질",
    "host": "호스트",
    "security": "소스코드",
}

ROLE_LABELS = {
    "admin": "프로젝트 관리자",
    "manager": "점검 운영자",
    "analyst": "분석 담당자",
    "uploader": "입력·점검 담당자",
    "viewer": "조회 전용",
}

ROLE_DESCRIPTIONS = {
    "admin": "프로젝트 내 입력·점검을 모두 관리합니다.",
    "manager": "입력을 등록하고 점검을 운영합니다.",
    "analyst": "점검을 실행하고 결과를 조회합니다.",
    "uploader": "입력을 등록하고 점검을 실행합니다.",
    "viewer": "프로젝트와 점검 결과만 조회합니다.",
}

PERMISSION_METADATA = {
    "dashboard.view": ("대시보드", "화면 접근", "프로젝트별 최신 점검 현황을 조회합니다."),
    "scan.library.view": ("라이브러리 점검", "화면 접근", "CVE 기반 라이브러리 점검 화면에 접근합니다."),
    "scan.source.view": ("소스코드 점검", "화면 접근", "소스코드 점검 화면에 접근합니다."),
    "runs.view": ("점검 결과", "화면 접근", "회차 목록·상세·보고서를 조회합니다."),
    "compare.view": ("회차 비교", "화면 접근", "두 완료 회차를 비교하고 내보냅니다."),
    "projects.view": ("프로젝트", "화면 접근", "프로젝트와 입력·회차 목록을 조회합니다."),
    "project.manage": ("프로젝트", "관리", "프로젝트를 생성하고 기본 정보를 관리합니다."),
    "input.manage": ("입력 파일", "등록", "SBOM·소스코드 입력 파일을 등록합니다."),
    "scan.create": ("보안 점검", "실행", "라이브러리·소스코드 점검을 실행하고 진행 중인 점검을 취소합니다."),
}

_SCAN_SCOPE_LABELS = {
    "all": "전체 점검",
    "library": "라이브러리 취약점",
    "source": "소스코드 취약점",
}


def _scan_scope(run: dict) -> str:
    snapshot = run.get("snapshot") if isinstance(run.get("snapshot"), dict) else {}
    return str(run.get("scan_scope") or snapshot.get("scan_scope") or "all")


def _scan_label(run: dict) -> str:
    scope = _scan_scope(run)
    if scope == "library":
        return "CVE 점검"
    if scope in {"all", "source"} and str(run.get("standard", "")) == "local" and str(run.get("standard_category", "")) == "all":
        return "전체/전체"
    return _SCAN_SCOPE_LABELS.get(scope, scope)


def _standard_label(run: dict) -> str:
    label = _scan_label(run)
    if label in {"CVE 점검", "전체/전체"}:
        return label
    return f"{run.get('standard', '')} / {run.get('standard_category', '')}"


def dashboard(identity, projects: list[dict], project_runs: list[tuple[dict, list[dict]]], *, admin: bool, nav_permissions=None) -> str:
    all_runs = [(project, run) for project, runs in project_runs for run in runs]
    all_runs.sort(key=lambda item: item[1].get("created_at", ""), reverse=True)
    completed = [run for _, run in all_runs if run.get("status") == "completed"]
    counts = _severity_counts(completed)
    cards = []
    for project, runs in project_runs:
        if not runs:
            continue
        latest = sorted(runs, key=lambda x: x.get("created_at", ""), reverse=True)[0]
        done = next((r for r in sorted(runs, key=lambda x: x.get("created_at", ""), reverse=True) if r.get("status") == "completed"), None)
        counts_done = _severity_counts([done]) if done else {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total = sum(counts_done[key] for key in ("critical", "high", "medium", "low")) or 1
        bar = "".join(f"<span class='{key}' style='flex:{counts_done[key] / total}' title='{label} {counts_done[key]}건'></span>" for key, label in (("critical", "심각"), ("high", "높음"), ("medium", "보통"), ("low", "낮음")))
        result = f"<div class='severity-bar' aria-label='심각도별 완료 결과'>{bar}</div><small class='muted'>심각 {counts_done['critical']} · 높음 {counts_done['high']} · 보통 {counts_done['medium']} · 낮음 {counts_done['low']}</small>" if done else "<p class='muted'>완료된 결과 없음</p>"
        cards.append(f"<a data-page-item class='panel project-card' href='/koda/runs/{esc(latest['run_id'])}'><h2>{esc(project['name'])}</h2><p><span class='status status-{esc(latest.get('status',''))}'>{esc(latest.get('status',''))}</span> · {esc(_scan_label(latest))}</p><p class='muted'>{esc(format_portal_time(latest.get('created_at')))}</p>{result}</a>")
    cards_html = "".join(cards) or "<div class='panel empty'>아직 점검 결과가 없습니다.</div>"
    body = f"""
<div class='dashboard-top'><section class='panel start-panel'><div class='start-copy'><h2>보안취약점 점검</h2><p class='muted'>점검 유형을 선택하여 점검 및 점검결과를 관리합니다.</p><p class='toolbar'><a class='button primary' href='/koda/scans/library'>라이브러리 점검</a><a class='button' href='/koda/scans/source'>소스코드 점검</a></p></div></section>
<section class='panel stats'><div class='stat'><small>전체 점검</small><strong>{len(all_runs)}</strong></div><div class='stat'><small>완료</small><strong>{len(completed)}</strong></div><div class='stat danger'><small>심각</small><strong>{counts['critical']}</strong></div><div class='stat high'><small>높음</small><strong>{counts['high']}</strong></div></section></div>
<section class='panel'><div class='panel-head'><div><h2>프로젝트별 최신 점검</h2><p class='muted'>{esc(identity.display)} 계정이 접근할 수 있는 프로젝트 기준</p></div><a class='button' href='/koda/runs'>전체 결과</a></div><div class='panel-body project-grid' data-pager data-page-size='10'>{cards_html}</div></section>"""
    return page("대시보드", body, admin=admin, nav_permissions=nav_permissions)


def new_scan_page(projects: list[dict], *, admin: bool, scan_scope: str = "all", nav_permissions=None) -> str:
    available = [p for p in projects if p.get("can_scan")]
    project_options = "".join(f"<option value='{esc(p['project_id'])}'>{esc(p['name'])}</option>" for p in available)
    scope_labels = {"all": "새 점검", "library": "라이브러리 보안취약점 점검", "source": "소스코드 보안취약점 점검"}
    scope_categories = {
        "all": ["secrets", "dependencies", "configuration", "code", "prevention"],
        "library": ["dependencies"],
        "source": ["secrets", "configuration", "code", "prevention"],
    }.get(scan_scope, [])
    title = scope_labels.get(scan_scope, scope_labels["all"])
    input_help = "SBOM, manifest, lockfile, JAR/WAR 또는 의존성 파일" if scan_scope == "library" else "소스 폴더·압축파일 또는 소스가 포함된 입력"
    intro = "라이브러리 구성요소와 오프라인 취약점 DB를 점검합니다." if scan_scope == "library" else "코드, 비밀정보, 보안설정, 예방통제를 점검합니다." if scan_scope == "source" else "점검 유형과 검사 기준을 선택합니다."
    library = scan_scope == "library"
    criteria = "<p class='choice'><strong>CVE 점검</strong><br><small class='muted'>CVE가 연결된 Grype 결과만 표시합니다.</small></p>" if library else "<label>검사 기준<select id='standards'></select></label><label>범위(카테고리)<select id='category'></select></label>"
    body = f"""<div class='form-grid'><section class='panel steps'><div class='step'><h2>1. 프로젝트 선택</h2><p class='muted'>{esc(intro)}</p><select id='project'>{project_options}</select></div>
<div class='step'><h2>2. 입력 선택</h2><div class='toolbar input-source-switch'><label class='choice'><input type='radio' name='input-source' value='file' checked> 파일 업로드</label><label class='choice'><input type='radio' name='input-source' value='gitlab'> GitLab 저장소</label></div><div id='file-source'><div class='drop-zone'><p><strong>{esc(input_help)}</strong></p><input id='file' type='file'><p id='file-note' class='muted'>최대 2 GiB</p><div class='progress' aria-label='업로드 진행률'><span id='upload-progress' style='width:0'></span></div><p id='upload-state' class='muted'></p><button id='upload' type='button'>선택 파일 등록</button></div><input id='input' type='hidden'><small class='muted'>점검이 끝난 입력은 자동 삭제되고, 현재 화면에서만 점검 대상으로 유지됩니다.</small></div><div id='gitlab-source' hidden><div class='gitlab-repository-row'><label for='gitlab-repository'>저장소</label><select id='gitlab-repository'></select></div><div class='gitlab-ref-row'><label class='gitlab-ref-type-field' for='gitlab-ref-type'>유형<select id='gitlab-ref-type'><option value='branch'>브랜치</option><option value='tag'>태그</option></select></label><label class='gitlab-ref-field' for='gitlab-ref'>브랜치/태그<select id='gitlab-ref'></select></label></div><p id='gitlab-state' class='muted'></p></div></div>
<div class='step'><h2>3. 검사 기준 선택</h2>{criteria}</div>
<div class='step'><h2>4. 점검 실행</h2><p class='muted'>사용자는 검사 기준과 범위만 선택합니다. 세부 규칙 활성화 여부는 관리자가 설정합니다.</p><button id='scan' class='primary' type='button'>▶ {esc(title)} 실행</button></div></section>
<aside class='panel inspector'><div class='panel-head'><h2>실행 전 확인</h2></div><div class='panel-body'><ul class='summary-list'><li><span>점검 유형</span><strong>{esc(title)}</strong></li><li><span>프로젝트</span><strong id='sum-project'>—</strong></li><li><span>입력</span><strong id='sum-input'>—</strong></li><li><span>검사 기준</span><strong id='sum-standard'>—</strong></li><li><span>범위</span><strong id='sum-category'>—</strong></li><li><span>오프라인 취약점 DB</span><strong id='vuln-db'>확인 중…</strong><small id='vuln-db-detail' class='muted'></small></li><li><span>정책</span><strong>관리자 설정 최신 버전</strong></li></ul></div></aside></div>
<script>
const projects={script_json(available)},scope={script_json(scan_scope)},scopeCategories={script_json(scope_categories)},project=document.querySelector('#project'),input=document.querySelector('#input'),standardBox=document.querySelector('#standards'),category=document.querySelector('#category'),repository=document.querySelector('#gitlab-repository'),refType=document.querySelector('#gitlab-ref-type'),refBox=document.querySelector('#gitlab-ref'),html=v=>String(v??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));let standards=[],currentInput='',repositories=[];
function activeProject(){{return projects.find(x=>x.project_id===project.value)}}function inputSource(){{return document.querySelector('[name="input-source"]:checked').value}}async function loadRepositories(){{repositories=[];repository.innerHTML='';refBox.innerHTML='';if(!project.value)return;document.querySelector('#gitlab-state').textContent='저장소 확인 중…';try{{repositories=await json(`/koda/api/v1/projects/${{project.value}}/gitlab/repositories`);repository.innerHTML=repositories.map(x=>`<option value="${{html(x.mapping_id)}}">${{html(x.path_with_namespace)}}</option>`).join('');document.querySelector('#gitlab-state').textContent=repositories.length?'':'연결된 GitLab 저장소가 없습니다.';await loadRefs()}}catch(e){{document.querySelector('#gitlab-state').textContent=e.message}}}}async function loadRefs(){{refBox.innerHTML='';if(!repository.value)return;document.querySelector('#gitlab-state').textContent='브랜치·태그 확인 중…';try{{const refs=await json(`/koda/api/v1/projects/${{project.value}}/gitlab/repositories/${{repository.value}}/refs?type=${{refType.value}}`);refBox.innerHTML=refs.map(x=>`<option value="${{html(x.name)}}">${{html(x.name)}}</option>`).join('');document.querySelector('#gitlab-state').textContent=refs.length?'':'선택 가능한 항목이 없습니다.';syncSummary()}}catch(e){{document.querySelector('#gitlab-state').textContent=e.message}}}}function renderInputs(){{currentInput='';input.value='';const p=activeProject();document.querySelector('#sum-project').textContent=p?.name||'—';if(inputSource()==='gitlab')loadRepositories();syncSummary()}}
function compatibleCategory(x){{return x.supported&&(x.scanner_categories||[]).some(v=>scopeCategories.includes(v))}}function compatibleStandard(x){{return (x.categories||[]).some(compatibleCategory)}}function activeStandard(){{return standardBox&&standards.find(x=>x.id===standardBox.value)}}function renderCategories(){{if(!category)return;if(scope==='source'&&standardBox.value==='local'){{category.innerHTML='<option value="all">전체</option>';syncSummary();return}}const s=activeStandard();category.innerHTML=(s?.categories||[]).filter(compatibleCategory).map(x=>`<option value="${{x.id}}">${{x.labels.ko||x.labels.en||x.id}}</option>`).join('');syncSummary()}}
function syncSummary(){{const repo=repositories.find(x=>x.mapping_id===repository.value);document.querySelector('#sum-input').textContent=inputSource()==='gitlab'?(repo&&refBox.value?`${{repo.path_with_namespace}} · ${{refBox.value}}`:'저장소와 브랜치/태그를 선택하세요'):(currentInput?'현재 업로드한 입력':'입력을 등록하세요');const s=activeStandard();document.querySelector('#sum-standard').textContent=scope==='library'?'CVE 점검':s?.labels.ko||s?.labels.en||'—';document.querySelector('#sum-category').textContent=scope==='library'?'CVE':category?.selectedOptions[0]?.textContent||'—'}}
project?.addEventListener('change',renderInputs);input?.addEventListener('change',syncSummary);standardBox?.addEventListener('change',renderCategories);category?.addEventListener('change',syncSummary);
document.querySelectorAll('[name="input-source"]').forEach(x=>x.addEventListener('change',()=>{{document.querySelector('#file-source').hidden=inputSource()!=='file';document.querySelector('#gitlab-source').hidden=inputSource()!=='gitlab';if(inputSource()==='gitlab')loadRepositories();syncSummary()}}));repository.addEventListener('change',loadRefs);refType.addEventListener('change',loadRefs);refBox.addEventListener('change',syncSummary);
if(standardBox)json('/koda/api/v1/standards').then(x=>{{standards=x.filter(compatibleStandard);standardBox.innerHTML=(scope==='source'?'<option value="local">전체</option>':'')+standards.filter(v=>scope!=='source'||v.id!=='local').map(v=>`<option value="${{v.id}}">${{v.labels.ko||v.labels.en||v.id}}</option>`).join('');renderCategories()}});
if(scope==='library')json('/koda/api/v1/vulnerability-db').then(x=>{{document.querySelector('#vuln-db').textContent=x.available?'점검 가능':'점검 불가';document.querySelector('#vuln-db-detail').textContent=[x.version,x.database?.built,x.warning].filter(Boolean).join(' · ')}}).catch(()=>document.querySelector('#vuln-db').textContent='상태 확인 실패');else document.querySelector('#vuln-db').textContent='해당 없음';renderInputs();
document.querySelector('#file')?.addEventListener('change',e=>{{const f=e.target.files[0];document.querySelector('#file-note').textContent=f?`${{f.name}} · ${{(f.size/1048576).toFixed(2)}} MiB`:'최대 2 GiB'}});
function uploadInput(url,file){{return new Promise((resolve,reject)=>{{const x=new XMLHttpRequest();x.open('POST',url);x.withCredentials=true;x.setRequestHeader('Content-Type','application/octet-stream');x.upload.onprogress=e=>{{if(e.lengthComputable){{const n=Math.round(e.loaded/e.total*100);document.querySelector('#upload-progress').style.width=n+'%';document.querySelector('#upload-state').textContent=`업로드 중 ${{n}}%`}}}};x.onload=()=>x.status<300?resolve(JSON.parse(x.responseText)):reject(new Error(JSON.parse(x.responseText||'{{}}').detail||`HTTP ${{x.status}}`));x.onerror=()=>reject(new Error('업로드 연결에 실패했습니다.'));x.send(file)}})}}
document.querySelector('#upload')?.addEventListener('click',async()=>{{const f=document.querySelector('#file').files[0],p=activeProject();if(!f||!p)return alert('프로젝트와 파일을 선택하세요.');if(f.size>2*1024*1024*1024)return alert('파일은 2 GiB 이하여야 합니다.');try{{const uploaded=await uploadInput(`/koda/api/v1/projects/${{p.project_id}}/inputs?name=${{encodeURIComponent(f.name)}}`,f);currentInput=uploaded.input_id||uploaded.id||'';input.value=currentInput;document.querySelector('#upload-state').textContent='등록 완료';syncSummary()}}catch(e){{document.querySelector('#upload-state').textContent='등록 실패';alert(e.message)}}}});
document.querySelector('#scan')?.addEventListener('click',async()=>{{const p=activeProject(),s=activeStandard(),standard=scope==='library'?'local':standardBox?.value||s?.id,standardCategory=scope==='library'?'all':category?.value,payload={{project_id:p?.project_id,standard,standard_category:standardCategory,scan_scope:scope}};if(inputSource()==='gitlab')Object.assign(payload,{{gitlab_repository_id:repository.value,ref_type:refType.value,ref_name:refBox.value}});else payload.input_id=input.value;if(!p||!standard||!standardCategory||(inputSource()==='gitlab'?(!repository.value||!refBox.value):!input.value))return alert('프로젝트, 입력, 검사 기준을 확인하세요.');try{{const r=await json('/koda/api/v1/scans',{{method:'POST',body:JSON.stringify(payload)}});location=`/koda/runs/${{r.run_id}}`}}catch(e){{alert(e.message)}}}});
</script>"""
    if available:
        content = body
    elif admin:
        content = "<section class='panel empty'><h2>점검할 프로젝트가 없습니다.</h2><p>먼저 프로젝트를 생성한 뒤 입력 파일을 등록하세요.</p><p><a class='button primary' href='/koda/projects'>프로젝트 생성으로 이동</a></p></section>"
    else:
        content = "<section class='panel empty'><h2>점검 권한이 있는 프로젝트가 없습니다.</h2><p>Tracker 계정 승인만으로는 KODA 프로젝트 권한이 부여되지 않습니다.</p><p>KODA 관리자에게 프로젝트 생성 및 <code>scan.create</code> 역할 배정을 요청하세요.</p><p><a class='button' href='/koda/projects'>프로젝트 권한 확인</a></p></section>"
    return page(title, content, admin=admin, nav_permissions=nav_permissions)


def projects_page(projects: list[dict], *, admin: bool, nav_permissions=None) -> str:
    create = "<form id='create' class='toolbar'><input name='name' placeholder='새 프로젝트 이름' required maxlength='128'><button class='primary'>프로젝트 생성</button></form>" if admin else ""
    if projects:
        cards = "".join(f"<a data-page-item class='panel project-card' href='/koda/projects/{esc(p['project_id'])}'><h2>{esc(p['name'])}</h2><p class='muted'>입력 {len(p.get('inputs', []))}개 · 점검 {len(p.get('runs', []))}회</p></a>" for p in projects)
    elif admin:
        cards = "<div class='panel empty'>프로젝트를 생성하면 새 점검과 회차별 결과를 관리할 수 있습니다.</div>"
    else:
        cards = "<div class='panel empty'>접근 가능한 프로젝트가 없습니다.<br>Tracker 승인 후에도 KODA 관리자가 프로젝트 역할을 배정해야 합니다.</div>"
    script = "<script>document.querySelector('#create')?.addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.currentTarget);try{await json('/koda/api/v1/projects',{method:'POST',body:JSON.stringify({name:f.get('name')})});location.reload()}catch(x){alert(x.message)}})</script>" if admin else ""
    return page("프로젝트", f"<section class='panel'><div class='panel-head'><div><h2>점검 대상 관리</h2><p class='muted'>입력 파일과 회차별 결과를 프로젝트 단위로 보관합니다.</p></div>{create}</div><div class='panel-body project-grid' data-pager data-page-size='10'>{cards}</div></section>{script}", admin=admin, nav_permissions=nav_permissions)


def project_page(project: dict, inputs: list[dict], runs: list[dict], *, can_upload: bool, can_scan: bool, admin: bool, nav_permissions=None) -> str:
    input_rows = ""
    for item in inputs:
        rounds = " · ".join(f"<a href='/koda/runs/{esc(run['run_id'])}'>#{run['round_number']}</a>" for run in item.get('runs', [])) or "미실행"
        input_rows += f"<tr data-page-item><td>{esc(item['name'])}</td><td>{esc(item.get('registered_by_id') or '기록 없음')}</td><td>{rounds}</td><td>{esc(format_portal_time(item.get('created_at')))}</td><td>{'원본 보관 중' if item.get('available', True) else '원본 삭제됨 · 재업로드 필요'}</td></tr>"
    input_rows = input_rows or "<tr><td colspan='5' class='empty'>등록된 입력이 없습니다.</td></tr>"
    run_rows = "".join(f"<tr data-page-item><td><a href='/koda/runs/{esc(r['run_id'])}'>#{r['round_number']}</a></td><td>{esc(_scan_label(r))}</td><td>{esc(_standard_label(r))}</td><td><span class='status status-{esc(r['status'])}'>{esc(r['status'])}</span></td><td>{esc(format_portal_time(r.get('created_at')))}</td></tr>" for r in runs) or "<tr><td colspan='5' class='empty'>점검 회차가 없습니다.</td></tr>"
    action = "<a class='button primary' href='/koda/scans/library'>라이브러리 점검</a><a class='button' href='/koda/scans/source'>소스코드 점검</a>" if can_scan else ""
    return page(str(project['name']), f"<div class='toolbar toolbar-spaced'>{action}</div><div class='project-content'><section class='panel'><div class='panel-head'><h2>등록된 입력</h2><p class='muted'>점검 완료 후 원본 파일은 삭제되고 결과 회차만 보관됩니다.</p></div><div class='table-wrap' data-pager data-page-size='10'><table><tr><th>이름</th><th>등록자 ID</th><th>점검 회차</th><th>등록일</th><th>보관 상태</th></tr>{input_rows}</table></div></section><section class='panel'><div class='panel-head'><h2>점검 회차</h2></div><div class='table-wrap' data-pager data-page-size='10'><table><tr><th>회차</th><th>점검 유형</th><th>기준</th><th>상태</th><th>요청일</th></tr>{run_rows}</table></div></section></div>", admin=admin, nav_permissions=nav_permissions)


def runs_page(projects: list[tuple[dict, list[dict]]], *, admin: bool, schedule_runs: list[dict] | None = None, nav_permissions=None) -> str:
    project_options = "".join(f"<option>{esc(project['name'])}</option>" for project, _ in projects)
    def delete_cell(run):
        if not admin:
            return ""
        disabled = " disabled" if run['status'] not in {'completed', 'failed', 'cancelled'} else ""
        return f"<td><button type='button' class='danger' data-delete-run='{esc(run['run_id'])}' data-round='{esc(run['round_number'])}' aria-label='{esc(run['round_number'])}회차 삭제'{disabled}>삭제</button></td>"

    manual_rows = "".join(
        f"<tr data-page-item data-source='manual' data-project='{esc(project['name'])}' data-scope='{esc(_scan_scope(run))}' data-status='{esc(run['status'])}'><td><a href='/koda/runs/{esc(run['run_id'])}'>#{run['round_number']}</a></td><td>{esc(project['name'])}</td><td>수동/API</td><td>{esc(run.get('requested_by_id') or '기록 없음')}</td><td>{esc(_scan_label(run))}</td><td>{esc(_standard_label(run))}</td><td><span class='status status-{esc(run['status'])}'>{esc(run['status'])}</span></td><td>{esc(format_portal_time(run.get('created_at')))}</td>{delete_cell(run)}</tr>"
        for project, runs in projects for run in runs if run.get('source') != 'scheduled_server'
    )
    def schedule_row(row):
        project = row.get('project_name') or row.get('project_id') or '—'
        status = row.get('status') or 'failed'
        scope = row.get('scan_scope') or row.get('mode') or 'all'
        changed = int(row.get('changed_files') or 0)
        change_label = '변경 없음' if not changed else f'변경 파일 {changed}개'
        run_ref = row.get('schedule_run_id') or '—'
        run_cell = f"<a href='/koda/runs/{esc(row['run_id'])}'>#{esc(row.get('round_number') or run_ref)}</a>" if row.get('run_id') else esc(run_ref)
        control = (f"<td><button type='button' data-cancel-schedule='{esc(run_ref)}'>취소</button></td>"
                   if admin and status in {'queued', 'running'} and not row.get('run_id') else '<td></td>' if admin else '')
        cleanup_error = f"<br><small class='error'>{esc(row['cleanup_error'])}</small>" if row.get('cleanup_error') else ''
        return (
            f"<tr data-page-item data-source='scheduled_server' data-project='{esc(project)}' data-scope='{esc(scope)}' data-status='{esc(status)}'>"
            f"<td>{run_cell}</td><td>{esc(project)}</td><td>스케줄</td><td>schedule-worker</td><td>{esc(scope)} · {esc(change_label)}</td>"
            f"<td>{esc(row.get('standard') or '—')}</td><td><span class='status status-{esc(status)}'>{esc(status)}</span><br>"
            f"<small class='muted'>정리 {esc(row.get('cleanup_status') or 'pending')} · Tracker {esc('전송 대상 아님' if row.get('tracker_status') == 'skipped' else row.get('tracker_status') or 'pending')} · GitLab {esc(row.get('gitlab_status') or 'pending')}</small>{cleanup_error}</td>"
            f"<td>{esc(format_portal_time(row.get('created_at') or row.get('started_at') or row.get('scheduled_for')))}</td>{control}</tr>"
        )
    scheduled_rows = "".join(schedule_row(row) for row in (schedule_runs or []))
    rows = manual_rows + scheduled_rows or f"<tr><td colspan='{9 if admin else 8}' class='empty'>점검 결과가 없습니다.</td></tr>"
    body = f"""<section class='panel'>
<div class='tabs' role='tablist' aria-label='점검 결과 출처'><button class='active' type='button' role='tab' aria-selected='true' data-source-tab='manual'>수동 점검 결과</button><button type='button' role='tab' aria-selected='false' data-source-tab='scheduled_server'>스케줄 점검 결과</button></div>
<div class='panel-head'><div><h2 id='runs-heading'>수동·API 점검 결과</h2></div><div class='toolbar'><label>프로젝트<select id='run-project'><option value=''>전체</option>{project_options}</select></label><label>점검 유형<select id='run-scope'><option value=''>전체</option><option value='library'>라이브러리</option><option value='source'>소스코드</option><option value='all'>전체</option></select></label><label>상태<select id='run-status'><option value=''>전체</option><option value='queued'>대기</option><option value='running'>진행 중</option><option value='cancelling'>취소 중</option><option value='completed'>완료</option><option value='failed'>실패</option><option value='cancelled'>취소됨</option></select></label><button id='run-query' type='button'>조회</button></div></div>
<div class='table-wrap' data-pager data-page-size='10'><table id='runs-table'><thead><tr><th>회차</th><th>프로젝트</th><th>출처</th><th>점검실행자 ID</th><th>점검 유형</th><th>점검 기준</th><th>상태</th><th>실행일</th>{'<th>관리</th>' if admin else ''}</tr></thead><tbody>{rows}</tbody></table></div></section>
<script>let runSource='manual';function filterRuns(){{const p=document.querySelector('#run-project').value,s=document.querySelector('#run-scope').value,t=document.querySelector('#run-status').value;document.querySelectorAll('#runs-table tbody tr[data-page-item]').forEach(r=>r.dataset.filtered=String((r.dataset.source!==runSource)||(p&&r.dataset.project!==p)||(s&&r.dataset.scope!==s)||(t&&r.dataset.status!==t)));document.querySelector('#runs-table').closest('[data-pager]')._paginate?.()}}document.querySelector('#run-query').addEventListener('click',filterRuns);document.querySelectorAll('[data-source-tab]').forEach(tab=>tab.addEventListener('click',()=>{{runSource=tab.dataset.sourceTab;document.querySelectorAll('[data-source-tab]').forEach(x=>{{x.classList.toggle('active',x===tab);x.setAttribute('aria-selected',x===tab)}});document.querySelector('#runs-heading').textContent=runSource==='scheduled_server'?'스케줄 점검 결과':'수동·API 점검 결과';filterRuns()}}));filterRuns()</script>"""
    if admin:
        body += "<script>document.querySelectorAll('[data-cancel-schedule]').forEach(b=>b.addEventListener('click',async()=>{b.disabled=true;try{await json('/koda/api/v1/admin/schedule-runs/'+encodeURIComponent(b.dataset.cancelSchedule)+'/cancel',{method:'POST',body:'{}'});location.reload()}catch(e){alert(e.message);b.disabled=false}}))</script>"
        body += "<script>document.querySelectorAll('[data-delete-run]').forEach(button=>button.addEventListener('click',async()=>{if(!confirm(`${button.dataset.round}회차 점검 결과를 삭제하시겠습니까? KODA의 결과와 보고서를 더 이상 조회할 수 없습니다. Tracker·GitLab에 전송된 결과는 유지됩니다.`))return;button.disabled=true;try{await json('/koda/api/v1/runs/'+encodeURIComponent(button.dataset.deleteRun),{method:'DELETE'});const row=button.closest('[data-page-item]'),pager=row?.closest('[data-pager]');if(row){row.dataset.removed='true';row.remove()}pager?._paginate(false)}catch(e){alert(e.message);button.disabled=false}}))</script>"
    return page("점검 결과", body, admin=admin, nav_permissions=nav_permissions)
def run_page(run: dict, *, admin: bool, project_name: str | None = None, tracker: dict | None = None, gitlab_issues: dict | None = None, schedule_run: dict | None = None, nav_permissions=None) -> str:
    result = run.get("result") if isinstance(run.get("result"), dict) else {}
    findings = result.get("findings", []) if isinstance(result.get("findings"), list) else []
    snapshot = run.get("snapshot") or {}
    is_gitlab = bool(snapshot.get("gitlab_project_id"))
    issue_items = {
        int(item["finding_index"]): item for item in (gitlab_issues or {}).get("items", [])
        if isinstance(item, dict) and str(item.get("finding_index", "")).isdigit()
    }
    scan_scope = _scan_scope(run)
    scope_label = _scan_label(run)
    type_label = _SCAN_SCOPE_LABELS.get(scan_scope, scan_scope)
    counts = _severity_counts([run])
    groups = [_finding_group(f.get("category")) for f in findings]
    group_counts = {group: 0 for group in ("library", "source", "quality")}
    for group in groups:
        group_counts[group] += 1
    def issue_cell(index, finding):
        if not is_gitlab:
            return ""
        item = issue_items.get(index)
        is_dependency = groups[index] == "library" or str(finding.get("category") or "").lower() == "dependencies"
        if is_dependency:
            summary_urls = [str(url) for url in (tracker or {}).get("gitlab_issue_urls", []) if str(url).startswith("https://")]
            links = " ".join(f"<a href='{esc(url)}' target='_blank' rel='noopener noreferrer'>요약 이슈 {n}</a>" for n, url in enumerate(summary_urls, 1))
            return f"<td><span class='muted'>요약 이슈에 포함</span>{(' · ' + links) if links else ''}</td>"
        eligible = str(finding.get("category") or "").lower() in {"dependencies", "secrets", "configuration", "code", "prevention"} and finding.get("verification_status") == "confirmed"
        if not item:
            return "<td><span class='muted'>대기</span></td>" if eligible else "<td><span class='muted'>대상 아님</span></td>"
        labels = {"pending": "대기", "creating": "등록 중", "created": "생성", "reused": "재사용", "failed": "실패"}
        label, url = labels.get(item.get("status"), item.get("status") or "대기"), str(item.get("issue_url") or "")
        content = f"<a href='{esc(url)}' target='_blank' rel='noopener noreferrer'>{esc(label)}</a>" if url.startswith("https://") else f"<span class='status status-{esc(item.get('status') or 'pending')}'>{esc(label)}</span>"
        return f"<td>{content}</td>"

    column_count = 7 if is_gitlab else 6
    rows = "".join(
        f"<tr data-page-item class='finding-row' data-index='{i}' data-group='{groups[i]}'><td class='sev sev-{esc(f.get('severity','info'))}'>{esc(f.get('severity',''))}</td><td><code>{esc(f.get('rule_id',''))}</code></td><td>{esc(_CATEGORY_LABELS.get(str(f.get('category','')).lower(), f.get('category','')))}</td><td>{esc(f.get('path',''))}</td><td>{esc(f.get('line',''))}</td><td class='wrap'>{esc(f.get('title',''))}</td>{issue_cell(i, f)}</tr>"
        for i, f in enumerate(findings)
    ) or f"<tr><td colspan='{column_count}' class='empty'>발견된 항목이 없습니다.</td></tr>"
    filtered_empty = f"<tr id='filtered-empty' hidden><td colspan='{column_count}' class='empty'>선택한 분류에 발견된 항목이 없습니다.</td></tr>" if findings else ""
    exports = ""
    if run.get("status") == "completed":
        base = f"/koda/api/v1/runs/{esc(run['run_id'])}/report"
        sbom = f"/koda/api/v1/runs/{esc(run['run_id'])}/sbom"
        report_label = "라이브러리 취약점 보고서" if scan_scope == "library" else "보고서 보기"
        exports = f"<a class='button primary' href='{base}.html' target='_blank'>{report_label}</a><a class='button' href='{base}?format=html'>HTML</a><a class='button' href='{base}?format=pdf'>PDF</a><a class='button' href='{base}?format=xlsx'>Excel</a><a class='button' href='{base}?format=json'>JSON</a><a class='button' href='{base}?format=markdown'>Markdown</a><a class='button' href='{sbom}?format=cyclonedx'>CycloneDX 1.6</a><a class='button' href='{sbom}?format=nis-sbom'>국정원 NIS-SBOM 1.0 (CSV)</a>"
    stages = result.get("analysis_stages", {}) if isinstance(result.get("analysis_stages"), dict) else {}
    legacy_stage_note = "<p class='muted'>이전 회차에는 단계별 상태 메타데이터가 없습니다.</p>" if run.get("status") == "completed" and not stages else ""
    stage_cards = []
    for key, label in (("source", "소스코드"), ("library", "라이브러리"), ("quality", "품질")):
        stage = stages.get(key, {})
        stage_status = stage.get("status", "completed" if run.get("status") == "completed" else run.get("status", "queued"))
        detail = ""
        if key == "library" and stage:
            detail = f"<small class='muted'>Grype {esc(stage.get('version') or '확인 불가')} · 조회 {esc(stage.get('queried_components', 0))}개</small><p class='error'>{esc(stage.get('warning') or '')}</p>"
        stage_cards.append(f"<section class='panel stage-card'><span>{label}</span><strong class='status status-{esc(stage_status)}'>{esc(stage_status)}</strong><p>{esc(stage.get('finding_count', 0))}건</p>{detail}</section>")
    terminal = run.get("status") in {"completed", "failed", "cancelled"}
    run_action = "<button id='cancel' type='button'>취소</button>" if not terminal else ""
    schedule_panel = ""
    if snapshot.get("source_type") == "scheduled_server":
        schedule_run = schedule_run or {}
        cleanup_status = schedule_run.get("cleanup_status") or (snapshot.get("cleanupStatus") or "pending")
        # The delivery tables are updated by retry/recovery paths; prefer them
        # over the scheduler's launch snapshot so the page reflects live state.
        tracker_status = (tracker or {}).get("status") or schedule_run.get("tracker_status") or "pending"
        gitlab_status = (tracker or {}).get("gitlab_result_status") or schedule_run.get("gitlab_status") or "pending"
        changed_count = len(snapshot.get("changed_files") or [])
        change_label = "변경 없음" if changed_count == 0 else f"변경 파일 {changed_count}개"
        schedule_panel = (
            "<section class='panel'><div class='panel-head'><div><h2>스케줄 점검 실행</h2>"
            "<p class='muted'>원격 서버 파일을 읽기 전용으로 수집하고, 분석 후 임시 원본을 정리한 실행입니다.</p></div>"
            f"<span class='status status-{esc(schedule_run.get('status') or run.get('status') or 'pending')}'>{esc(schedule_run.get('status') or run.get('status') or 'pending')}</span></div>"
            "<div class='panel-body'><ul class='summary-list'>"
            f"<li><span>대상 ID</span><strong class='mono'>{esc(snapshot.get('schedule_target_id') or '—')}</strong></li>"
            f"<li><span>서버·디렉토리</span><strong>{esc(snapshot.get('remote_server') or '—')} / {esc(snapshot.get('remote_directory') or '—')}</strong></li>"
            f"<li><span>점검 방식</span><strong>{esc(snapshot.get('scan_mode') or '—')} · {esc(change_label)}</strong></li>"
            f"<li><span>원본 정리</span><strong class='status status-{esc(cleanup_status)}'>{esc(cleanup_status)}</strong></li>"
            f"<li><span>Tracker 전송</span><strong class='status status-{esc(tracker_status)}'>{esc('전송 대상 아님' if tracker_status == 'skipped' else tracker_status)}</strong></li>"
            f"<li><span>GitLab 게시</span><strong class='status status-{esc(gitlab_status)}'>{esc(gitlab_status)}</strong></li>"
            f"<li><span>정리 오류</span><strong class='error'>{esc(schedule_run.get('cleanup_error') or '없음')}</strong></li>"
            "</ul></div></section>"
        )
    gitlab_source = ""
    if snapshot.get("gitlab_project_id"):
        if snapshot.get("source_type") == "scheduled_server":
            scheduled_result_branch = snapshot.get("gitlab_result_branch") or f"koda/scheduled/{snapshot.get('schedule_target_id')}/{snapshot.get('schedule_run_id')}"
            gitlab_source = (
                "<section class='panel'><div class='panel-head'><h2>GitLab 실행 원본</h2></div><div class='panel-body'><ul class='summary-list'>"
                f"<li><span>저장소</span><strong>{esc(snapshot.get('gitlab_path_with_namespace', ''))}</strong></li>"
                f"<li><span>결과 브랜치</span><strong class='mono'>{esc(scheduled_result_branch)}</strong></li>"
                f"<li><span>서버·디렉토리</span><strong>{esc(snapshot.get('remote_server') or '—')} / {esc(snapshot.get('remote_directory') or '—')}</strong></li>"
                "</ul></div></section>"
            )
        else:
            gitlab_source = (
                "<section class='panel'><div class='panel-head'><h2>GitLab 실행 원본</h2></div><div class='panel-body'><ul class='summary-list'>"
                f"<li><span>저장소</span><strong>{esc(snapshot.get('gitlab_path_with_namespace', ''))}</strong></li>"
                f"<li><span>브랜치/태그</span><strong>{esc(snapshot.get('gitlab_ref_name', ''))}</strong></li>"
                f"<li><span>Commit SHA</span><strong class='mono'>{esc(snapshot.get('gitlab_commit_sha', ''))}</strong></li>"
                "</ul></div></section>"
            )
        state = tracker or {"status": "pending"}
        retry = "<button id='tracker-retry' type='button'>Tracker 전송 재시도</button>" if state.get("status") == "failed" else ""
        tracker_run_url = str(state.get("tracker_run_url") or "")
        tracker_link = f"<a href='{esc(tracker_run_url)}' target='_blank' rel='noopener noreferrer'>Tracker 실행 화면</a>" if tracker_run_url.startswith(("http://", "https://")) else ""
        merge_request_url = str(state.get("gitlab_merge_request_url") or "")
        merge_request = f"<p><a class='button' href='{esc(merge_request_url)}' target='_blank' rel='noopener noreferrer'>GitLab 결과 MR 보기</a></p>" if merge_request_url.startswith("https://") else ""
        issue_links = "".join(
            f"<a href='{esc(url)}' target='_blank' rel='noopener noreferrer'>Tracker 집계 이슈 {index}</a>"
            for index, url in enumerate(state.get("gitlab_issue_urls") or [], 1)
            if str(url).startswith("https://")
        )
        issues = f"<p class='toolbar'>{issue_links}</p>" if issue_links else ""
        gitlab_source += (
            "<section class='panel'><div class='panel-head'><h2>KODA-SBOM-Tracker 전송</h2></div><div class='panel-body'>"
            f"<p><span class='status status-{esc(state.get('status', 'pending'))}'>{esc('전송 대상 아님 (소스코드 전용)' if state.get('status') == 'skipped' else state.get('status', 'pending'))}</span></p>"
            f"<p class='muted'>Tracker 실행 ID: {esc(state.get('tracker_run_id') or '—')} {tracker_link}</p>"
            f"<p class='error'>{esc(state.get('last_error') or '')}</p>{retry}</div></section>"
        )
        result_status = str(state.get("gitlab_result_status") or ("completed" if merge_request_url else "pending"))
        result_retry = "<button id='gitlab-result-retry' type='button'>GitLab 결과 등록 재시도</button>" if admin and result_status == "failed" else ""
        gitlab_source += (
            "<section class='panel'><div class='panel-head'><h2>GitLab 결과 등록</h2></div><div class='panel-body'>"
            f"<p><span class='status status-{esc(result_status)}'>{esc(result_status)}</span></p>"
            f"<p class='muted'>소스코드 결과는 GitLab에 직접 게시하며, 라이브러리 점검은 Tracker 분석 결과를 함께 게시합니다.</p>"
            f"{merge_request}{issues}<p class='error'>{esc(state.get('gitlab_result_last_error') or '')}</p>{result_retry}</div></section>"
        )
        issue_state = gitlab_issues or {"status": "pending", "created_count": 0, "reused_count": 0, "failed_count": 0, "total_count": 0}
        issue_retry = "<button id='gitlab-issues-retry' type='button'>실패 항목 재시도</button>" if admin and issue_state.get("status") in {"partial", "failed"} else ""
        gitlab_source += (
            "<section class='panel'><div class='panel-head'><h2>GitLab 취약점 이슈 등록</h2></div><div class='panel-body'>"
            f"<p><span class='status status-{esc(issue_state.get('status', 'pending'))}'>{esc(issue_state.get('status', 'pending'))}</span></p>"
            f"<p>대상 {esc(issue_state.get('total_count', 0))}건 · 생성 {esc(issue_state.get('created_count', 0))}건 · 재사용 {esc(issue_state.get('reused_count', 0))}건 · 실패 {esc(issue_state.get('failed_count', 0))}건</p>"
            f"<p class='error'>{esc(issue_state.get('last_error') or '')}</p>{issue_retry}</div></section>"
        )
    tracker_retry_script = "document.querySelector('#tracker-retry')?.addEventListener('click',async()=>{try{await json(`/koda/api/v1/runs/${runId}/tracker/retry`,{method:'POST',body:'{}'});location.reload()}catch(e){alert(e.message)}});" if snapshot.get("gitlab_project_id") else ""
    result_retry_script = "document.querySelector('#gitlab-result-retry')?.addEventListener('click',async()=>{try{await json(`/koda/api/v1/runs/${runId}/gitlab/result/retry`,{method:'POST',body:'{}'});location.reload()}catch(e){alert(e.message)}});" if snapshot.get("gitlab_project_id") else ""
    issue_retry_script = "document.querySelector('#gitlab-issues-retry')?.addEventListener('click',async()=>{try{await json(`/koda/api/v1/runs/${runId}/gitlab/issues/retry`,{method:'POST',body:'{}'});location.reload()}catch(e){alert(e.message)}});" if snapshot.get("gitlab_project_id") else ""
    columns = (("심각도", "96px"), ("규칙 ID", "150px"), ("구분", "120px"), ("파일", "180px"), ("위치", "86px"), ("제목", "260px"))
    if is_gitlab:
        columns += (("GitLab 이슈", "130px"),)
    colgroup = "<colgroup>" + "".join(f"<col style='width:{width}'>" for _, width in columns) + "</colgroup>"
    headers = "".join(f"<th>{label}<span class='column-resizer' role='separator' aria-orientation='vertical' tabindex='0' aria-label='{label} 열 너비 조정' data-column-index='{index}'></span></th>" for index, (label, _) in enumerate(columns))
    body = f"""<div class='toolbar toolbar-between toolbar-spaced'><div><strong>{esc(project_name or run.get('project_name') or '')}</strong> · <strong>{esc(type_label)}</strong> · <span id='run-status' class='status status-{esc(run['status'])}'>{esc(run['status'])}</span> · {esc(_standard_label(run))} · {esc(format_portal_time(run.get('created_at')))}</div><div class='toolbar'>{run_action}{exports}</div></div>
<section class='panel progress-panel'><div class='toolbar toolbar-between'><strong id='run-stage'>{esc(run.get('stage', run.get('status', 'queued')))}</strong><span id='run-progress-text'>{esc(run.get('progress', 0))}%</span></div><div class='progress'><span id='run-progress' style='width:{esc(run.get('progress', 0))}%'></span></div></section>
{legacy_stage_note}<div class='stage-grid'>{''.join(stage_cards)}</div>
<section class='panel summary-strip'><div><small>심각</small><strong class='sev-critical'>{counts['critical']}</strong></div><div><small>높음</small><strong class='sev-high'>{counts['high']}</strong></div><div><small>보통</small><strong>{counts['medium']}</strong></div><div><small>낮음</small><strong>{counts['low']}</strong></div><div><small>전체</small><strong>{len(findings)}</strong></div></section>
<div class='result-layout'><section class='panel'><div class='tabs' role='tablist' aria-label='점검 결과 분류'><button class='active' type='button' role='tab' aria-selected='true' data-tab=''>전체 {len(findings)}</button><button type='button' role='tab' aria-selected='false' data-tab='library'>라이브러리 취약점 {group_counts['library']}</button><button type='button' role='tab' aria-selected='false' data-tab='source'>소스코드 취약점 {group_counts['source']}</button><button type='button' role='tab' aria-selected='false' data-tab='quality'>품질 점검 {group_counts['quality']}</button></div><div class='panel-head'><div class='toolbar'><input id='finding-search' type='search' placeholder='제목, 규칙 ID, 파일 검색'><select id='severity'><option value=''>모든 심각도</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></div></div><div class='table-wrap' data-pager data-page-size='10'><table id='findings' class='resizable-table'>{colgroup}<thead><tr>{headers}</tr></thead><tbody>{rows}{filtered_empty}</tbody></table></div></section>
<aside class='panel inspector'><div class='panel-head'><h2 id='detail-title'>점검 항목 상세</h2></div><div class='panel-body' id='detail'><p class='muted'>왼쪽 목록에서 항목을 선택하세요.</p></div><div class='panel-body'><h3>실행 정보 (변경 불가)</h3><ul class='summary-list'><li><span>정책 버전</span><strong>{esc(run['policy_version'])}</strong></li><li><span>요청 계정</span><strong class='mono'>{esc(run['snapshot'].get('requested_by',''))}</strong></li><li><span>스캐너 버전</span><strong>{esc(run['snapshot'].get('scanner_version',''))}</strong></li></ul></div></aside></div>
{schedule_panel}{gitlab_source}<details><summary>불변 실행 스냅샷</summary><pre>{esc(json.dumps(run['snapshot'], ensure_ascii=False, indent=2))}</pre></details><p class='error'>{esc(run.get('error') or '')}</p>
<script>function resizeFindingColumn(handle,width){{const col=document.querySelectorAll('#findings col')[Number(handle.dataset.columnIndex)];if(col)col.style.width=Math.max(72,width)+'px'}}document.querySelectorAll('.column-resizer').forEach(handle=>{{handle.addEventListener('pointerdown',e=>{{e.preventDefault();const col=document.querySelectorAll('#findings col')[Number(handle.dataset.columnIndex)],start=e.clientX,width=col.getBoundingClientRect().width;handle.setPointerCapture(e.pointerId);handle.onpointermove=x=>resizeFindingColumn(handle,width+x.clientX-start);handle.onpointerup=()=>handle.onpointermove=null}});handle.addEventListener('keydown',e=>{{if(e.key==='ArrowLeft'||e.key==='ArrowRight'){{e.preventDefault();const col=document.querySelectorAll('#findings col')[Number(handle.dataset.columnIndex)];resizeFindingColumn(handle,col.getBoundingClientRect().width+(e.key==='ArrowRight'?16:-16))}}}})}})</script>
<script>const runId={script_json(run['run_id'])},terminal={str(terminal).lower()},findings={script_json(findings)},h=v=>String(v??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));let tab='',selectedSeverity='';function show(i){{const f=findings[i];if(!f)return;const sev=['critical','high','medium','low','info'].includes(f.severity)?f.severity:'info';document.querySelectorAll('.finding-row').forEach(x=>x.classList.toggle('selected',x.dataset.index==i));document.querySelector('#detail-title').textContent=f.title||'점검 항목 상세';document.querySelector('#detail').innerHTML=`<div class="detail-section"><span class="sev sev-${{sev}}">${{h(f.severity)}}</span> · <code>${{h(f.rule_id)}}</code><p>${{h(f.description||'설명이 없습니다.')}}</p></div><div class="detail-section"><h3>위치</h3><p><code>${{h(f.path||'—')}}${{f.line?':'+h(f.line):''}}</code></p><pre>${{h(f.evidence||f.target||'표시할 증거가 없습니다.')}}</pre></div><div class="detail-section"><h3>조치 방법</h3><p>${{h(f.recommendation||'권장 조치가 없습니다.')}}</p></div>`}}function filter(){{const q=document.querySelector('#finding-search').value.toLowerCase();let visible=0;document.querySelectorAll('.finding-row').forEach(r=>{{const f=findings[Number(r.dataset.index)],filtered=(q&&!r.textContent.toLowerCase().includes(q))||(selectedSeverity&&f.severity!==selectedSeverity)||(tab&&r.dataset.group!==tab);r.dataset.filtered=String(filtered);if(!filtered)visible++}});document.querySelector('#findings').closest('[data-pager]')?._paginate();const empty=document.querySelector('#filtered-empty');if(empty)empty.hidden=visible>0}}document.querySelectorAll('.finding-row').forEach(r=>r.addEventListener('click',()=>show(r.dataset.index)));document.querySelector('#finding-search').addEventListener('input',filter);document.querySelector('#severity').addEventListener('change',e=>{{selectedSeverity=e.target.value;filter()}});document.querySelectorAll('[data-tab]').forEach(b=>b.addEventListener('click',()=>{{document.querySelectorAll('[data-tab]').forEach(x=>{{x.classList.toggle('active',x===b);x.setAttribute('aria-selected',x===b)}});tab=b.dataset.tab;filter()}}));document.querySelector('#cancel')?.addEventListener('click',async()=>{{if(confirm('이 점검을 취소할까요?')){{await json(`/koda/api/v1/runs/${{runId}}/cancel`,{{method:'POST',body:'{{}}'}});location.reload()}}}});{tracker_retry_script}{result_retry_script}{issue_retry_script}if(!terminal)setInterval(async()=>{{try{{const r=await json(`/koda/api/v1/runs/${{runId}}`),status=document.querySelector('#run-status');status.textContent=r.status;status.className='status status-'+r.status;document.querySelector('#run-stage').textContent=r.stage;document.querySelector('#run-progress').style.width=r.progress+'%';document.querySelector('#run-progress-text').textContent=r.progress+'%';if(['completed','failed','cancelled'].includes(r.status))location.reload()}}catch(e){{console.warn(e)}}}},2000);if(findings.length)show(0)</script>"""
    return page(f"{scope_label} 결과 #{run['round_number']}", body, admin=admin, nav_permissions=nav_permissions)


def gitlab_admin_page(projects: list[dict], mappings: list[dict], *, configuration: dict | None = None, schedule_targets: list[dict] | None = None, worker_settings: dict | None = None, server_connections: list[dict] | None = None, server_mappings: list[dict] | None = None, nav_permissions=None) -> str:
    configuration = configuration or {"configured": False, "write_configured": False, "locked": False, "source": "web", "url": "", "ca_configured": False}
    locked, configured = bool(configuration.get("locked")), bool(configuration.get("configured"))
    disabled = " disabled" if locked else ""
    source_label = "서버 환경변수" if locked else "KODA 웹 설정"
    status_label = "읽기·결과 저장 설정됨" if configured and configuration.get("write_configured") else ("읽기만 설정됨" if configured else "미설정")
    read_required = "" if configured else " required"
    write_required = "" if configuration.get("write_configured") else " required"
    read_placeholder = "비워 두면 기존 PAT 유지" if configured else "저장할 읽기 PAT"
    write_placeholder = "비워 두면 기존 PAT 유지" if configuration.get("write_configured") else "저장할 API PAT"
    project_options = "".join(
        f"<option value='{esc(project['project_id'])}'>{esc(project['name'])}</option>" for project in projects
    )
    rows = "".join(
        f"<tr data-page-item><td>{esc(row['project_name'])}</td><td>{esc(row['path_with_namespace'])}</td>"
        f"<td>{esc(row['tracker_service_id'])}<br><small>{esc(row['tracker_environment_id'])}</small></td>"
        f"<td><button type='button' data-remove='{esc(row['mapping_id'])}'>연결 해제</button></td></tr>"
        for row in mappings if row.get("enabled")
    ) or "<tr><td colspan='4' class='empty'>연결된 저장소가 없습니다.</td></tr>"
    schedule_targets = schedule_targets or []
    worker_settings = worker_settings or {
        "enabled": False, "cpu_limit": 1, "memory_limit_bytes": 4 * 1024**3,
        "rate_bytes_per_sec": 5 * 1024**2, "gap_seconds": 30,
        "min_free_bytes": 1024**3, "concurrency": 1,
    }
    worker_settings_section = f"""
<section class='panel'><div class='panel-head'><div><h2>스케줄 worker 자원 설정</h2><p class='muted'>새벽 순차 점검의 전역 실행 조건입니다. 메모리·전송 속도·디스크 값은 MB(1MB=1,048,576 bytes)로 입력하며 저장할 때 bytes로 변환됩니다.</p></div></div>
<div class='panel-body'><form id='schedule-worker-settings' class='worker-settings-grid'><label style='grid-column:1/-1' class='check-label'><input name='enabled' type='checkbox' {'checked' if worker_settings.get('enabled') else ''}> 스케줄 점검 활성화</label><label>CPU 제한(코어)<input name='cpu_limit' type='number' min='1' max='32' value='{int(worker_settings.get('cpu_limit', 1))}' required></label><label>분석 메모리 제한(MB)<input name='memory_limit_mb' type='number' min='256' max='{64 * 1024}' step='any' value='{worker_settings.get('memory_limit_bytes', 4 * 1024**3) / 1024**2:g}' required></label><label>전송 속도(MB/s)<input name='rate_mb_per_sec' type='number' min='0.0625' max='1024' step='any' value='{worker_settings.get('rate_bytes_per_sec', 5 * 1024**2) / 1024**2:g}' required></label><label>작업 간 대기(초)<input name='gap_seconds' type='number' min='0' max='3600' value='{int(worker_settings.get('gap_seconds', 30))}' required></label><label>최소 여유 디스크(MB)<input name='min_free_mb' type='number' min='0' max='{1024 * 1024}' step='any' value='{worker_settings.get('min_free_bytes', 1024**3) / 1024**2:g}' required></label><label>동시 작업<input name='concurrency' type='number' value='1' readonly></label><div style='grid-column:1/-1;display:flex;align-items:center;gap:12px'><button class='primary' type='submit'>저장</button><span id='schedule-worker-settings-result' class='muted'></span></div></form></div></section>
"""
    def schedule_label(target):
        frequency = target.get("schedule_frequency", "daily")
        if frequency == "weekly":
            repeat = "매주 " + "·".join("월화수목금토일"[day] for day in target.get("schedule_weekdays", []))
        elif frequency == "hourly":
            repeat = str(target.get("schedule_interval_hours", 24)) + "시간마다"
        else:
            repeat = "매일"
        return repeat + " · " + target.get("schedule_time", "01:00") + " (한국시간)"

    mapping_names = {row["mapping_id"]: row["path_with_namespace"] for row in mappings}
    schedule_rows = "".join(
        f"<tr data-page-item data-schedule-source='{esc(target.get("source_kind") or "server")}'><td>{esc(target['name'])}</td><td>{esc(target['project_name'])}</td><td>{'GitLab' if target.get('source_kind') == 'gitlab' else '서버'}<br><code>{esc((mapping_names.get(target.get('source_gitlab_mapping_id'), '연결 해제') + ' · ' + target.get('source_gitlab_ref', '')) if target.get('source_kind') == 'gitlab' else target.get('host', ''))}</code><br>{esc((target.get('source_gitlab_directory') if target.get('source_kind') == 'gitlab' else target.get('remote_directory')) or '/')}</td><td>{esc(schedule_label(target))}<br>{'활성' if target.get('enabled') else '일시정지'}</td><td>{esc(target.get('scan_scope') or 'all')} · {esc(target.get('config_version') or 1)}</td><td><button type='button' data-schedule-edit='{esc(target['target_id'])}'>편집</button> <button type='button' data-schedule-disable='{esc(target['target_id'])}'>일시정지</button></td></tr>"
        for target in schedule_targets
    ) or "<tr><td colspan='6' class='empty'>등록된 스케줄 대상이 없습니다.</td></tr>"
    mapping_options = "".join(
        f"<option value='{esc(row['mapping_id'])}'>{esc(row['project_name'])} · {esc(row['path_with_namespace'])}</option>"
        for row in mappings if row.get("enabled")
    )
    from .portal_server_views import server_admin_section, SERVER_ADMIN_SCRIPT, SCHEDULE_CHOICES_SCRIPT
    server_section = server_admin_section(project_options, server_connections or [], server_mappings or [])
    schedule_section = worker_settings_section + f"""
<section class='panel'><div class='panel-head'><div><h2>서버·GitLab 스케줄 점검</h2><p class='muted'>한국시간 기준 실행 시간과 주기를 대상별로 설정합니다. 원격 서버는 SSH로 읽기 전용 수집하며, GitLab은 연결 저장소의 브랜치·태그와 하위 디렉토리를 사용합니다. 기본값은 서버 매일 01:00, 비활성입니다.</p></div></div>
<div class='panel-body'><form id='schedule-target' class='form-grid'><input type='hidden' name='target_id'><label class='check-label schedule-wide'><input name='enabled' type='checkbox'> 활성화</label><label class='schedule-wide'>점검 대상<select name='source_kind' id='schedule-source-kind'><option value='server'>다른 서버 디렉토리</option><option value='gitlab'>GitLab 저장소 디렉토리</option></select></label><label class='schedule-wide'>연결 KODA 프로젝트<select name='project_id' required>{project_options}</select></label><label data-server-field>연결 서버 서비스 계정<select name='server_connection_id'><option value=''>직접 입력 (기존 설정)</option></select></label><label>대상 이름<input name='name' required maxlength='255' placeholder='운영 서버 / 저장소'></label><label data-server-field class='server-credentials'>서버 주소<input name='host' placeholder='server.example.internal'></label><label data-server-field class='server-credentials'>SSH 포트<input name='port' type='number' min='1' max='65535' value='22'></label><label data-server-field class='server-credentials'>읽기 전용 계정<input name='username'></label><label data-server-field class='server-credentials'>SSH 키 파일 참조<input name='ssh_key_ref' placeholder='/run/koda/ssh/scan_ed25519'></label><label data-server-field class='server-credentials'>검증된 호스트키 파일<input name='known_hosts_file' placeholder='/run/koda/ssh/known_hosts'></label><label data-server-field>서버 디렉토리<input name='remote_directory' placeholder='/srv/application'></label><label data-gitlab-field>GitLab 저장소<select name='source_gitlab_mapping_id'><option value=''>선택</option>{mapping_options}</select></label><label data-gitlab-field>GitLab 참조 종류<select name='source_gitlab_ref_type'><option value='branch'>브랜치</option><option value='tag'>태그</option></select></label><label data-gitlab-field>브랜치·태그 선택<select name='source_gitlab_ref'><option value=''>기본 브랜치</option></select><span id='schedule-ref-status' role='status' class='muted'></span></label><fieldset data-gitlab-field id='schedule-new-branch' class='schedule-wide'><legend>신규 브랜치</legend><div class='schedule-branch-grid'><label>새 브랜치 이름<input id='schedule-branch-name' maxlength='255' placeholder='예: release/security-scan'></label><label>생성 기준 브랜치<select id='schedule-branch-base'><option value=''>브랜치를 선택하세요</option></select></label></div><button type='button' id='schedule-branch-create'>브랜치 생성</button></fieldset><label data-gitlab-field>저장소 하위 디렉토리<input name='source_gitlab_directory' placeholder='/ 또는 /src'></label><label>실행 주기<select name='schedule_frequency'><option value='daily'>매일</option><option value='weekly'>매주</option><option value='hourly'>N시간마다</option></select></label><label>실행 시각(KST)<input name='schedule_time' type='time' value='01:00' required></label><fieldset data-weekly-field><legend>실행 요일</legend><label class='check-label'><input type='checkbox' name='schedule_weekdays' value='0' checked>월</label><label class='check-label'><input type='checkbox' name='schedule_weekdays' value='1' checked>화</label><label class='check-label'><input type='checkbox' name='schedule_weekdays' value='2' checked>수</label><label class='check-label'><input type='checkbox' name='schedule_weekdays' value='3' checked>목</label><label class='check-label'><input type='checkbox' name='schedule_weekdays' value='4' checked>금</label><label class='check-label'><input type='checkbox' name='schedule_weekdays' value='5' checked>토</label><label class='check-label'><input type='checkbox' name='schedule_weekdays' value='6' checked>일</label></fieldset><label data-hourly-field>반복 간격<select name='schedule_interval_hours'><option value='1'>1시간</option><option value='2'>2시간</option><option value='3'>3시간</option><option value='4'>4시간</option><option value='6'>6시간</option><option value='8'>8시간</option><option value='12'>12시간</option><option value='24' selected>24시간</option></select></label><label>점검 유형<select name='scan_scope'><option value='all'>소스 + 라이브러리</option><option value='source'>소스코드</option><option value='library'>라이브러리</option></select></label><label>점검 기준<select name='standard'><option value='owasp-top-10-2025'>OWASP Top 10 2025</option><option value='sw-dev-security-49'>SW 개발보안 49</option></select></label><label>기준 분류<select name='standard_category'><option value='all'>전체 (all)</option></select></label><label>결과 GitLab 매핑<select name='gitlab_mapping_id'><option value=''>게시 안 함</option>{mapping_options}</select></label><label>결과 대상 브랜치<input name='gitlab_target_branch' placeholder='비우면 매핑 기본 브랜치'></label><label>실행 순서<input name='order_index' type='number' value='0' min='0'></label><label>최대 파일 수<input name='max_files' type='number' value='200000' min='1' max='200000'></label><label>최대 수집 용량(MB)<input name='max_mb' type='number' value='2048' min='1' max='4096' step='1'></label><label>디렉토리 제한(초)<input name='timeout_seconds' type='number' value='21600' min='60' max='86400'></label><label>제외 경로(줄바꿈 구분)<textarea name='exclude_paths' rows='3' placeholder='node_modules/\n.git/\nlogs'></textarea></label><label>비활성 규칙(JSON 배열)<textarea name='disabled_rules' rows='3' placeholder='[]'></textarea></label><div class='toolbar'><button class='primary' type='submit'>저장</button><button type='button' id='schedule-connection-test' data-server-field>연결 시험</button><button type='button' id='schedule-access-test' data-server-field>접근 시험</button><button type='button' id='schedule-reset'>새 대상</button><span id='schedule-result' class='muted'></span></div></form></div>
<div class='table-wrap' data-pager data-page-size='10'><table><thead><tr><th>대상</th><th>프로젝트</th><th>서버·디렉토리</th><th>상태</th><th>범위·설정 버전</th><th></th></tr></thead><tbody>{schedule_rows}</tbody></table></div></section>
"""
    body = f"""<section class='panel'><div class='panel-head'><div><h2>GitLab 연결 설정</h2><p class='muted'>저장소 조회용 <code>read_api</code> PAT와 결과 브랜치·MR·비공개 취약점 이슈 저장용 <code>api</code> PAT를 분리해 저장합니다. 저장한 PAT는 다시 표시되지 않습니다.</p></div><span class='status status-{'completed' if configured and configuration.get('write_configured') else 'failed'}'>{status_label}</span></div><form id='gitlab-config' class='panel-body'><div class='gitlab-config-grid'><label>GitLab URL<input name='url' type='url' value='{esc(configuration.get('url') or '')}' placeholder='https://gitlab.example.internal' required{disabled}></label><label>저장소 조회 PAT (<code>read_api</code>)<input name='token' type='password' autocomplete='new-password' placeholder='{read_placeholder}'{read_required}{disabled}></label><label>결과 저장 PAT (<code>api</code>)<input name='write_token' type='password' autocomplete='new-password' placeholder='{write_placeholder}'{write_required}{disabled}></label></div><details class='integration-help'><summary>사설 CA 인증서 (선택)</summary><label>PEM 인증서<textarea name='ca_pem' rows='5' placeholder='-----BEGIN CERTIFICATE-----'{disabled}></textarea></label><p class='muted'>현재 CA 설정: {'있음' if configuration.get('ca_configured') else '없음'}. 입력하지 않으면 기존 CA를 유지합니다.</p></details><p class='muted'>결과 저장 계정에는 대상 저장소 Developer 이상 권한이 필요합니다. 취약점 이슈는 비공개(Confidential)로 생성합니다.</p><p class='muted'>설정 출처: {source_label}. 환경변수 설정은 웹 설정보다 우선하며 웹에서 변경할 수 없습니다.</p><div class='toolbar toolbar-spaced'><button id='gitlab-test' type='button'{disabled}>연결·권한 테스트</button><button class='primary' type='submit'{disabled}>저장</button><button id='gitlab-config-remove' type='button'{disabled}>연결정보 삭제</button><span id='gitlab-config-result' class='muted'></span></div></form></section>
<section class='panel'><div class='panel-head'><div><h2>GitLab 서비스 계정</h2><p class='muted'>연결된 계정이 Developer 이상으로 접근할 수 있는 저장소를 불러옵니다. Tracker 서비스·환경·전송 토큰은 연결 시 자동 생성·재사용됩니다.</p></div><button id='gitlab-load' class='primary' type='button'{' disabled' if not configured or not configuration.get('write_configured') else ''}>저장소 불러오기</button></div><div class='panel-body'><p id='gitlab-account' class='muted'>연결 상태를 확인하세요.</p><label>저장소 검색<input id='gitlab-search' type='search' placeholder='그룹 또는 저장소명'></label><form id='gitlab-map'><label>KODA 프로젝트<select name='project_id' required>{project_options}</select></label><div id='gitlab-projects' class='table-wrap'></div><button class='primary toolbar-submit'>선택 저장소 연결</button></form></div></section>
<section class='panel' data-gitlab-current><div class='panel-head'><h2>현재 연결</h2></div><div class='table-wrap' data-pager data-page-size='10'><table><thead><tr><th>KODA 프로젝트</th><th>GitLab 저장소</th><th>Tracker 서비스·환경</th><th></th></tr></thead><tbody>{rows}</tbody></table></div></section>
{schedule_section}
<script>
let gitlabProjects=[];const gitlabExistingByProject={script_json({project: [str(row.get('gitlab_project_id')) for row in mappings if row.get('enabled') and str(row.get('project_id') or '') == project] for project in {str(row.get('project_id') or '') for row in mappings if row.get('enabled')}})},gitlabProjectSelect=document.querySelector('#gitlab-map select[name=project_id]');let gitlabSelected=new Set(gitlabExistingByProject[gitlabProjectSelect?.value]||[]);const box=document.querySelector('#gitlab-projects'),safe=v=>String(v??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
function renderGitLab(){{const q=document.querySelector('#gitlab-search').value.toLowerCase(),items=gitlabProjects.filter(x=>(x.path_with_namespace||'').toLowerCase().includes(q));box.innerHTML=`<table><thead><tr><th><label class="check-label"><input id="gitlab-select-all" type="checkbox">전체 선택</label></th><th>저장소</th><th>기본 브랜치</th><th>Tracker 준비</th></tr></thead><tbody>${{items.map(x=>`<tr><td><input type="checkbox" data-project-id="${{x.id}}" ${{gitlabSelected.has(String(x.id))?'checked':''}}></td><td>${{safe(x.path_with_namespace)}}</td><td>${{safe(x.default_branch||'—')}}</td><td>연결 시 자동 생성·재사용</td></tr>`).join('')}}</tbody></table>`;const checks=[...box.querySelectorAll('[data-project-id]')],all=box.querySelector('#gitlab-select-all');checks.forEach(x=>x.addEventListener('change',()=>{{x.checked?gitlabSelected.add(x.dataset.projectId):gitlabSelected.delete(x.dataset.projectId);syncGitlabSelectAll()}}));function syncGitlabSelectAll(){{const n=checks.filter(x=>x.checked).length;all.checked=checks.length>0&&n===checks.length;all.indeterminate=n>0&&n<checks.length}}all.addEventListener('change',()=>{{checks.forEach(x=>{{x.checked=all.checked;x.checked?gitlabSelected.add(x.dataset.projectId):gitlabSelected.delete(x.dataset.projectId)}});syncGitlabSelectAll()}});syncGitlabSelectAll()}}
const configForm=document.querySelector('#gitlab-config'),configResult=document.querySelector('#gitlab-config-result');function gitlabConfigPayload(){{const data=new FormData(configForm);return{{url:data.get('url'),token:data.get('token'),write_token:data.get('write_token'),ca_pem:data.get('ca_pem')}}}}document.querySelector('#gitlab-test')?.addEventListener('click',async()=>{{configResult.textContent='확인 중…';try{{const result=await json('/koda/api/v1/admin/gitlab/configuration/test',{{method:'POST',body:JSON.stringify(gitlabConfigPayload())}});configResult.textContent=`연결됨: ${{result.account.name||result.account.username}} (@${{result.account.username}}) · api 범위 확인`}}catch(e){{configResult.textContent=e.message}}}});configForm?.addEventListener('submit',async e=>{{e.preventDefault();configResult.textContent='저장 중…';try{{const result=await json('/koda/api/v1/admin/gitlab/configuration',{{method:'POST',body:JSON.stringify(gitlabConfigPayload())}});configResult.textContent=`저장됨: ${{result.account.name||result.account.username}} (@${{result.account.username}})`;setTimeout(()=>location.reload(),500)}}catch(x){{configResult.textContent=x.message}}}});document.querySelector('#gitlab-config-remove')?.addEventListener('click',async()=>{{if(!confirm('저장한 GitLab 연결정보를 삭제할까요? 저장소 매핑과 기존 점검 결과는 유지됩니다.'))return;try{{await json('/koda/api/v1/admin/gitlab/configuration',{{method:'DELETE'}});location.reload()}}catch(e){{configResult.textContent=e.message}}}});
document.querySelector('#gitlab-load').addEventListener('click',async()=>{{try{{const account=await json('/koda/api/v1/admin/gitlab/status');document.querySelector('#gitlab-account').textContent=`${{account.name||account.username}} (@${{account.username}})`;gitlabProjects=await json('/koda/api/v1/admin/gitlab/projects');const existing=gitlabExistingByProject[gitlabProjectSelect?.value]||[];gitlabSelected=new Set(existing.length?existing:gitlabProjects.map(x=>String(x.id)));renderGitLab()}}catch(e){{document.querySelector('#gitlab-account').textContent=e.message}}}});gitlabProjectSelect?.addEventListener('change',()=>{{const existing=gitlabExistingByProject[gitlabProjectSelect.value]||[];gitlabSelected=new Set(existing.length?existing:gitlabProjects.map(x=>String(x.id)));renderGitLab()}});document.querySelector('#gitlab-search').addEventListener('input',renderGitLab);
document.querySelector('#gitlab-map').addEventListener('submit',async e=>{{e.preventDefault();const mappings=gitlabProjects.filter(x=>gitlabSelected.has(String(x.id))).map(x=>({{gitlab_project_id:Number(x.id)}}));if(!mappings.length)return alert('연결할 저장소를 선택하세요.');try{{await json('/koda/api/v1/admin/gitlab/mappings',{{method:'POST',body:JSON.stringify({{project_id:e.currentTarget.elements.project_id.value,mappings}})}});location.reload()}}catch(x){{alert(x.message)}}}});document.querySelectorAll('[data-remove]').forEach(x=>x.addEventListener('click',async()=>{{if(!confirm('이 저장소 연결을 해제할까요?'))return;await json(`/koda/api/v1/admin/gitlab/mappings/${{x.dataset.remove}}`,{{method:'DELETE'}});location.reload()}}));
const workerSettingsForm=document.querySelector('#schedule-worker-settings');workerSettingsForm.addEventListener('submit',async e=>{{e.preventDefault();const f=new FormData(workerSettingsForm),payload=Object.fromEntries(f.entries());payload.enabled=f.get('enabled')==='on';for(const key of ['cpu_limit','gap_seconds','concurrency'])payload[key]=Number(payload[key]);for(const [field,key] of [['memory_limit_mb','memory_limit_bytes'],['rate_mb_per_sec','rate_bytes_per_sec'],['min_free_mb','min_free_bytes']]){{payload[key]=Math.round(Number(payload[field])*1048576);delete payload[field]}}try{{await json('/koda/api/v1/admin/schedule-settings',{{method:'POST',body:JSON.stringify(payload)}});document.querySelector('#schedule-worker-settings-result').textContent='저장되었습니다.'}}catch(x){{document.querySelector('#schedule-worker-settings-result').textContent=x.message}}}});
const scheduleTargets={script_json(schedule_targets)},scheduleForm=document.querySelector('#schedule-target'),scheduleResult=document.querySelector('#schedule-result'),sourceKind=document.querySelector('#schedule-source-kind');function toggleScheduleFields(){{const gitlab=sourceKind?.value==='gitlab';document.querySelectorAll('[data-server-field],[data-gitlab-field]').forEach(x=>{{x.hidden=x.hasAttribute('data-server-field')?gitlab:!gitlab;x.querySelectorAll('input,select').forEach(f=>f.disabled=x.hidden)}});scheduleForm.elements.source_gitlab_mapping_id.required=gitlab;const frequency=scheduleForm?.elements.schedule_frequency?.value||'daily';document.querySelectorAll('[data-weekly-field]').forEach(x=>x.hidden=frequency!=='weekly');document.querySelectorAll('[data-hourly-field]').forEach(x=>x.hidden=frequency!=='hourly');if(typeof syncScheduleBranchPanel==='function')syncScheduleBranchPanel()}}function resetSchedule(){{scheduleForm.reset();scheduleForm.elements.target_id.value='';scheduleForm.elements.port.value='22';scheduleForm.elements.max_files.value='200000';scheduleForm.elements.max_mb.value='2048';scheduleForm.elements.timeout_seconds.value='21600';scheduleForm.elements.schedule_time.value='01:00';scheduleForm.querySelectorAll('[name=schedule_weekdays]').forEach(x=>x.checked=true);scheduleForm.elements.schedule_interval_hours.value='24';scheduleResult.textContent='';toggleScheduleFields()}}function editSchedule(id){{const target=scheduleTargets.find(x=>x.target_id===id);if(!target)return;scheduleForm.elements.project_id.value=target.project_id;refreshScheduleConnections();for(const key of ['target_id','project_id','name','source_kind','server_connection_id','host','port','username','ssh_key_ref','known_hosts_file','remote_directory','source_gitlab_mapping_id','source_gitlab_ref','source_gitlab_ref_type','source_gitlab_directory','schedule_frequency','schedule_time','schedule_interval_hours','standard','standard_category','scan_scope','gitlab_mapping_id','gitlab_target_branch','order_index','max_files','timeout_seconds'])if(scheduleForm.elements[key])scheduleForm.elements[key].value=target[key]??'';scheduleForm.querySelectorAll('[name=schedule_weekdays]').forEach(x=>x.checked=(target.schedule_weekdays||[0,1,2,3,4,5,6]).includes(Number(x.value)));scheduleForm.elements.enabled.checked=Boolean(target.enabled);scheduleForm.elements.exclude_paths.value=(target.exclude_paths||[]).join('\\n');scheduleForm.elements.disabled_rules.value=JSON.stringify(target.disabled_rules||[]);scheduleForm.elements.max_mb.value=String(target.max_bytes/1048576);if(target.standard==='local')scheduleForm.elements.standard.value='owasp-top-10-2025';renderScheduleCategories(target.standard_category);loadScheduleRefs(target.source_gitlab_ref||'');scheduleResult.textContent=`${{target.name}} 편집 중`+(target.standard==='local'?' · 저장 시 OWASP 기준으로 변경됩니다.':'');toggleScheduleFields();applyScheduleConnection()}}document.querySelector('#schedule-reset')?.addEventListener('click',resetSchedule);sourceKind?.addEventListener('change',toggleScheduleFields);scheduleForm?.elements.schedule_frequency?.addEventListener('change',toggleScheduleFields);toggleScheduleFields();document.querySelectorAll('[data-schedule-edit]').forEach(x=>x.addEventListener('click',()=>editSchedule(x.dataset.scheduleEdit)));document.querySelectorAll('[data-schedule-disable]').forEach(x=>x.addEventListener('click',async()=>{{if(!confirm('이 스케줄 대상을 일시정지할까요?'))return;try{{await json(`/koda/api/v1/admin/schedules/${{x.dataset.scheduleDisable}}`,{{method:'DELETE'}});location.reload()}}catch(e){{scheduleResult.textContent=e.message}}}}));scheduleForm?.addEventListener('submit',async e=>{{e.preventDefault();const f=new FormData(e.currentTarget);let disabledRules=[];try{{disabledRules=JSON.parse(f.get('disabled_rules')||'[]');if(!Array.isArray(disabledRules))throw new Error('비활성 규칙은 JSON 배열이어야 합니다')}}catch(x){{return scheduleResult.textContent=x.message}}const payload=Object.fromEntries(f.entries());payload.max_bytes=Math.round(Number(payload.max_mb)*1048576);delete payload.max_mb;payload.enabled=f.get('enabled')==='on';payload.schedule_weekdays=payload.schedule_frequency==='weekly'?f.getAll('schedule_weekdays').map(Number):[0,1,2,3,4,5,6];payload.schedule_interval_hours=Number(payload.schedule_interval_hours||24);payload.exclude_paths=String(f.get('exclude_paths')||'').split(/\\r?\\n/).map(x=>x.trim()).filter(Boolean);payload.disabled_rules=disabledRules;try{{await json('/koda/api/v1/admin/schedules',{{method:'POST',body:JSON.stringify(payload)}});location.reload()}}catch(x){{scheduleResult.textContent=x.message}}}});
const scheduleProbePayload=()=>{{const data=new FormData(scheduleForm);return {{host:data.get('host'),port:Number(data.get('port')||22),username:data.get('username'),ssh_key_ref:data.get('ssh_key_ref'),known_hosts_file:data.get('known_hosts_file'),remote_directory:data.get('remote_directory'),exclude_paths:String(data.get('exclude_paths')||'').split(/\\r?\\n/).map(x=>x.trim()).filter(Boolean),max_files:Number(data.get('max_files')||200000),max_bytes:Math.round(Number(data.get('max_mb')||2048)*1048576),timeout_seconds:Math.min(Number(data.get('timeout_seconds')||60),86400)}}}};async function probeSchedule(endpoint,label,button){{if(!scheduleForm.reportValidity())return;button.disabled=true;scheduleResult.textContent=label+' 확인 중…';try{{const result=await json(endpoint,{{method:'POST',body:JSON.stringify(scheduleProbePayload())}});scheduleResult.textContent=result.fileCount===undefined?label+' 완료':`${{label}} 완료: ${{result.fileCount}}개 · ${{result.totalBytes}} bytes`}}catch(error){{scheduleResult.textContent=error.message}}finally{{button.disabled=false}}}}document.querySelector('#schedule-connection-test')?.addEventListener('click',e=>probeSchedule('/koda/api/v1/admin/schedules/test-connection','연결',e.currentTarget));document.querySelector('#schedule-access-test')?.addEventListener('click',e=>probeSchedule('/koda/api/v1/admin/schedules/test-access','접근',e.currentTarget));
</script>"""
    body = "<nav class='tabs integration-tabs' role='tablist' aria-label='연동 설정 종류'><button type='button' class='active' role='tab' data-integration-tab='gitlab' aria-selected='true'>GitLab 연동</button><button type='button' role='tab' data-integration-tab='server' aria-selected='false'>서버 연동</button></nav>" + body
    body = body.replace(schedule_section, server_section + schedule_section)
    body += "<style>.worker-settings-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:20px}.worker-settings-grid>label{min-width:0}#schedule-target{grid-template-columns:repeat(2,minmax(0,1fr))}#schedule-target>label,#schedule-target>fieldset{min-width:0}#schedule-target input:not([type=checkbox]),#schedule-target select{width:100%;min-width:0}#schedule-target .schedule-wide{grid-column:1/-1}.schedule-branch-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}#schedule-target fieldset{margin:0}#schedule-target .toolbar{grid-column:1/-1}@media(max-width:700px){#schedule-target,.schedule-branch-grid{grid-template-columns:1fr}}.integration-tabs{border-bottom:1px solid var(--line)}@media(max-width:700px){.worker-settings-grid{grid-template-columns:1fr}.subject-picker{width:100%}}</style>"
    body += "<script>const serverConnections=" + script_json(server_connections or []) + ";</script>"
    body += SERVER_ADMIN_SCRIPT.replace('__SERVER_PROJECT_MAPPINGS__', script_json(server_mappings or []))
    body += SCHEDULE_CHOICES_SCRIPT
    return admin_page("연동 설정", body, active="gitlab", nav_permissions=nav_permissions)
def admin_page(title: str, body: str, *, active: str = "", nav_permissions=None) -> str:
    tabs = (("subjects", "KODA 접근", "/koda/admin/subjects"), ("roles", "권한관리", "/koda/admin/roles"), ("rules", "점검 설정", "/koda/admin/rules"), ("gitlab", "연동 설정", "/koda/admin/gitlab"), ("vulnerability-db", "취약점 DB", "/koda/admin/vulnerability-db"), ("audit", "감사 로그", "/koda/admin/audit"))
    subnav = "<nav class='admin-subnav' aria-label='관리자 설정'>" + "".join(f"<a class='button' href='{url}'" + (" aria-current='page'" if active == key else "") + f">{label}</a>" for key, label, url in tabs) + "</nav>"
    return page(title, subnav + "<div class='admin-content'>" + body + "</div>", admin=True, nav_permissions=nav_permissions)
