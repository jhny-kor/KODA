"""Inventory TCP listeners reported by the local OS, without opening a connection."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass

from .checks.host.common import current_platform
from .checks.host.runner import powershell, run_command

_LSOF = "/usr/sbin/lsof"
_NETSTAT = "/usr/sbin/netstat"
_WINDOWS_QUERY = (
    "$rows = @(Get-NetTCPConnection -ErrorAction Stop | "
    "Where-Object State -eq Listen | Select-Object LocalAddress, LocalPort); "
    "ConvertTo-Json -InputObject $rows -Compress"
)
_MAC_WILDCARDS = {
    "IPv4": "0.0.0.0",
    "IPv6": "::",
}
_NETSTAT_WILDCARDS = {"tcp4": ("0.0.0.0",), "tcp6": ("::",), "tcp46": ("0.0.0.0", "::")}


@dataclass(frozen=True)
class LocalListener:
    address: str
    port: int
    family: str
    binding: str


def _listener(address: str, port: int) -> LocalListener:
    parsed = ipaddress.ip_address(address)
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    classification = parsed
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        classification = parsed.ipv4_mapped
    if classification.is_unspecified:
        binding = "all-interfaces"
    elif classification.is_loopback:
        binding = "loopback"
    else:
        binding = "specific-interface"
    return LocalListener(str(parsed), port, f"IPv{parsed.version}", binding)


def _macos_rows(stdout: str) -> tuple[set[LocalListener], int]:
    listeners: set[LocalListener] = set()
    invalid = 0
    family = ""
    for line in stdout.splitlines():
        field, data = line[:1], line[1:]
        if field in ("p", "f"):
            family = ""
        elif field == "t":
            family = data
        elif field == "n":
            try:
                address, port = data.rsplit(":", 1)
                address = _MAC_WILDCARDS[family] if address == "*" else address.removeprefix("[").removesuffix("]")
                listeners.add(_listener(address, int(port)))
            except (KeyError, ValueError):
                invalid += 1
        elif field:
            invalid += 1
    return listeners, invalid


def _windows_rows(stdout: str) -> tuple[set[LocalListener], int]:
    rows = json.loads(stdout.lstrip("\ufeff"))
    if not isinstance(rows, list):
        raise ValueError("invalid local TCP inventory")
    listeners: set[LocalListener] = set()
    invalid = 0
    for row in rows:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("LocalAddress"), str)
            or type(row.get("LocalPort")) is not int
        ):
            invalid += 1
            continue
        try:
            listeners.add(_listener(row["LocalAddress"], row["LocalPort"]))
        except ValueError:
            invalid += 1
    return listeners, invalid


def _netstat_rows(stdout: str) -> tuple[set[LocalListener], int]:
    if not stdout.startswith("Active Internet connections"):
        raise ValueError("OS socket inventory is missing")
    listeners: set[LocalListener] = set()
    invalid = 0
    for line in stdout.splitlines():
        fields = line.split()
        if not fields or fields[-1] != "LISTEN":
            continue
        try:
            address, port = fields[3].rsplit(".", 1)
            addresses = _NETSTAT_WILDCARDS[fields[0]] if address == "*" else (address,)
            listeners.update(_listener(value, int(port)) for value in addresses)
        except (IndexError, KeyError, ValueError):
            invalid += 1
    return listeners, invalid


def collect_local_listeners() -> dict[str, object]:
    """Return local TCP bind addresses and ports in a platform-neutral report."""
    platform = current_platform()
    status = "unavailable"
    warnings: list[str] = []
    listeners: set[LocalListener] = set()
    empty_inventory = False
    if platform == "macos":
        result = run_command([_LSOF, "-nP", "-a", "-iTCP", "-sTCP:LISTEN", "-Fftn"], allow=frozenset({"lsof"}))
        parse = _macos_rows
        # lsof exits 1 without output when no sockets match. netstat reads the
        # numeric socket table and can work when per-process inspection is restricted.
        empty_inventory = result.returncode == 1 and not (result.stdout or result.stderr or result.error)
        if not (result.ok or empty_inventory):
            result = run_command([_NETSTAT, "-an", "-p", "tcp"], allow=frozenset({"netstat"}))
            parse = _netstat_rows
    elif platform == "windows":
        result = powershell(_WINDOWS_QUERY)
        parse = _windows_rows
    else:
        result = None
        warnings.append("Local TCP listeners can be collected on macOS and Windows.")
    if result is not None:
        if not (result.ok or empty_inventory):
            warnings.append(result.error or f"The OS TCP inventory command failed (exit {result.returncode}).")
        else:
            try:
                listeners, invalid = parse(result.stdout)
            except ValueError:
                warnings.append("The OS TCP inventory output could not be read.")
            else:
                status = "completed"
                if invalid:
                    status = "partial"
                    warnings.append(f"{invalid} TCP listener row(s) could not be read.")
                if result.stderr.strip():
                    status = "partial"
                    warnings.append("The OS TCP inventory command reported a warning.")
    return {
        "format": "koda-local-listeners-v1",
        "platform": platform,
        "status": status,
        "listeners": [
            asdict(item) for item in sorted(listeners, key=lambda item: (item.port, item.family, item.address))
        ],
        "warnings": warnings,
    }


def render_local_listeners_markdown(report: dict, language: str = "ko") -> str:
    korean = language == "ko"
    title = "이 기기의 TCP 수신 포트" if korean else "Local TCP listeners"
    summary = {
        "completed": ("수집 완료", "Collected"),
        "partial": ("일부 수집", "Partially collected"),
        "unavailable": ("수집 불가", "Unavailable"),
    }[report["status"]][0 if korean else 1]
    bindings = {
        "all-interfaces": "모든 인터페이스",
        "loopback": "이 기기에서만",
        "specific-interface": "특정 주소",
    }
    detail = (
        "현재 사용자에게 표시되는 수신 소켓입니다. 외부에서 접속할 수 있는지는 방화벽과 네트워크 설정에 따라 달라집니다."
        if korean else
        "These listening sockets are visible to the current user. Reachability depends on the firewall and network configuration."
    )
    lines = [f"# {title}", "", f"{report['platform']} · {summary}", "", detail]
    if report["listeners"]:
        header = "| 포트 | 주소 | IP 버전 | 바인딩 |" if korean else "| Port | Address | IP version | Binding |"
        lines.extend(("", header, "|---:|---|---|---|"))
        for item in report["listeners"]:
            binding = item["binding"]
            label = bindings[binding] if korean else binding.replace("-", " ")
            lines.append(f"| {item['port']} | `{item['address']}` | {item['family']} | {label} |")
    lines.extend(f"\n- {warning}" for warning in report["warnings"])
    return "\n".join(lines) + "\n"


def render_listeners_page(language: str) -> str:
    korean = language == "ko"
    title = "이 PC의 TCP 수신 포트" if korean else "Local TCP listeners"
    detail = (
        "현재 사용자에게 표시되는 수신 소켓을 조회합니다. 외부 접속 가능 여부는 방화벽과 네트워크 설정에 따라 달라집니다."
        if korean else "List sockets visible to the current user. Reachability depends on the firewall and network settings."
    )
    cols = ("포트", "주소", "IP 버전", "바인딩") if korean else ("Port", "Address", "IP version", "Binding")
    return f"""<!doctype html><html lang="{'ko' if korean else 'en'}">
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KODA · {title}</title>
<style>body{{font:16px system-ui;max-width:56rem;margin:2rem auto;padding:0 1rem}}
button{{font:inherit}}table{{border-collapse:collapse;width:100%}}
th,td{{padding:.5rem;text-align:left;border-bottom:1px solid #9995;overflow-wrap:anywhere}}</style>
<a href="/security-dashboard.html">← KODA</a>
<h1>{title}</h1><p>{detail}</p>
<button id="refresh">{'조회' if korean else 'List listeners'}</button>
<p id="status" role="status"></p><ul id="warnings"></ul>
<table hidden><thead><tr>{''.join(f'<th scope="col">{column}</th>' for column in cols)}</tr></thead><tbody></tbody></table>
<script>
const ko = {json.dumps(korean)};
const refresh = document.querySelector('#refresh'), status = document.querySelector('#status');
const warnings = document.querySelector('#warnings'), table = document.querySelector('table');
const body = table.tBodies[0];
const bindings = ko
  ? {{loopback:'이 PC에서만', 'all-interfaces':'모든 인터페이스', 'specific-interface':'특정 주소'}}
  : {{loopback:'Loopback', 'all-interfaces':'All interfaces', 'specific-interface':'Specific address'}};
refresh.addEventListener('click', async () => {{
  refresh.disabled = true;
  body.replaceChildren(); warnings.replaceChildren(); table.hidden = true;
  status.textContent = ko ? '조회 중…' : 'Loading…';
  try {{
    const health = await fetch('/api/health');
    const response = await fetch('/api/local-listeners', {{
      method:'POST', headers:{{'X-KODA-Session':health.headers.get('X-KODA-Session')}}
    }});
    const data = await response.json();
    if (!response.ok) throw Error(data.error || response.statusText);
    const summary = ko
      ? {{completed:'수집 완료', partial:'일부 수집', unavailable:'수집 불가'}}
      : {{completed:'Collected', partial:'Partially collected', unavailable:'Unavailable'}};
    status.textContent = summary[data.status] + ' · ' + data.listeners.length;
    for (const warning of data.warnings) {{
      const item = document.createElement('li');
      item.textContent = warning;
      warnings.append(item);
    }}
    for (const listener of data.listeners) {{
      const row = body.insertRow();
      for (const column of [listener.port, listener.address, listener.family, bindings[listener.binding]]) {{
        row.insertCell().textContent = column;
      }}
    }}
    table.hidden = !data.listeners.length;
  }} catch (error) {{
    status.textContent = error.message;
  }} finally {{
    refresh.disabled = false;
  }}
}});
</script></html>"""
