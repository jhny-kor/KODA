"""Generate and rescan a separate source candidate using a loopback model."""
from __future__ import annotations

import ast
from collections import Counter
import difflib
import http.client
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
import ntpath
from urllib.parse import urlsplit

from ..checks import code_patterns, configuration, secrets
from ..models import TargetConfig
from ..xml_safe import parse_xml

SOURCE_LIMIT = 12288
SUFFIXES = {".py", ".xml", ".js", ".java"}


def _endpoint(value):
    url = urlsplit(value)
    if (url.port == 0 or url.scheme not in {"http", "https"} or url.hostname not in {"localhost", "127.0.0.1", "::1"}
            or url.username is not None or url.password is not None or url.fragment or url.query
            or url.path.rstrip("/") not in {"", "/v1"}):
        raise ValueError("이 PC의 OpenAI 호환 주소를 입력하세요 (예: http://127.0.0.1:1234/v1).")
    return url


def local_request(base, key, route, payload=None):
    """Connect directly to loopback. Neither proxy settings nor redirects are used."""
    url = _endpoint(base)
    connection = (http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection)(
        url.hostname, url.port, timeout=90)
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    try:
        connection.request("POST" if payload else "GET", "/v1/" + route,
                           json.dumps(payload).encode() if payload else None, headers)
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"로컬 모델 서버 응답 HTTP {response.status}")
        raw = response.read(262145)
        if len(raw) > 262144:
            raise ValueError("모델 응답이 너무 큽니다.")
        return json.loads(raw)
    except http.client.HTTPException as exc:
        raise ValueError("로컬 모델 서버의 HTTP 응답을 읽을 수 없습니다.") from exc
    finally:
        connection.close()


def _python_api(source):
    tree = compile(source, "<candidate>", "exec", ast.PyCF_ONLY_AST)
    compile(tree, "<candidate>", "exec")
    api = set()

    def visit(body, prefix=""):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                signature = ast.dump(node.args) if hasattr(node, "args") else tuple(ast.dump(b) for b in node.bases)
                api.add((prefix + node.name, type(node).__name__, signature, tuple(ast.dump(d) for d in node.decorator_list)))
                if isinstance(node, ast.ClassDef):
                    visit(node.body, prefix + node.name + ".")

    visit(tree.body)
    return api


def _xml_shape(source):
    root = parse_xml(source)
    return (root.tag, Counter(el.tag for el in root.iter()),
            Counter((el.tag, key, value) for el in root.iter() for key, value in el.attrib.items()
                    if key.rsplit("}", 1)[-1] in {"id", "name"}))


def _javascript_api(source):
    # Keep only declarations outside strings, template literals and comments.
    trivia = r"""//[^\n]*|/\*[\s\S]*?\*/|'(?:\\[\s\S]|[^'\\])*'|"(?:\\[\s\S]|[^"\\])*"|`(?:\\[\s\S]|[^`\\])*`"""
    masked = re.sub(trivia, lambda match: re.sub(r"[^\n]", " ", match[0]), source)
    symbol = r"[a-zA-Z_$][\w$]*"
    declarations = re.findall(r"^\s*(?:(?:export|default|async)\s+)*(?:class|function)\s+(" + symbol + ")", masked, re.M)
    api = {"declaration:" + name for name in declarations}
    for name in re.findall(r"\bexport\s+(?:(?:default|async)\s+)*(?:function|class|const|let|var)\s+(" + symbol + ")", masked):
        api.add("esm:" + name)
    for group in re.findall(r"\bexport\s*\{([^}]*)\}", masked):
        for item in group.split(","):
            if item.strip():
                api.add("esm:" + item.split()[-1])
    if re.search(r"\bexport\s+default\b", masked):
        api.add("esm:default")
    for name in re.findall(r"\b(?:module\.)?exports\.(" + symbol + r")\s*=", masked):
        api.add("cjs:" + name)
    if re.search(r"\bmodule\.exports\s*=", masked):
        api.add("cjs:module.exports")
    return api


def _check_syntax(path, source):
    if path.suffix.lower() == ".py":
        return _python_api(source)
    if path.suffix.lower() == ".xml":
        return _xml_shape(source)
    if path.suffix.lower() == ".js":
        node = shutil.which("node")
        if not node:
            raise ValueError("JavaScript 구문 검사에는 Node.js가 필요합니다.")
        modes = set()
        for mode in ("module", "commonjs"):
            if subprocess.run([node, "--check", "--input-type=" + mode], input=source.encode(), cwd=path.parent,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode == 0:
                modes.add(mode)
        if not modes:
            raise ValueError("JavaScript 구문을 확인하세요.")
        return modes | _javascript_api(source)
    javac, javap = shutil.which("javac"), shutil.which("javap")
    if not javac or not javap:
        raise ValueError("Java 검사에는 javac와 javap가 있는 JDK가 필요합니다.")
    with tempfile.TemporaryDirectory() as output:
        # No project classpath, annotation processors or model-generated code execution.
        if subprocess.run([javac, "-proc:none", "-encoding", "UTF-8", "-d", output, "-classpath", output,
                           "-sourcepath", output, str(path)], cwd=output, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=15).returncode:
            raise ValueError("단일 Java 파일을 컴파일할 수 없습니다. 구문과 외부 의존성을 확인하세요.")
        classes = sorted(Path(output).rglob("*.class"))
        if not 0 < len(classes) <= 32:
            raise ValueError("단일 파일에서 검증할 수 있는 Java 클래스는 1~32개입니다.")
        declarations = subprocess.check_output([javap, "-private", *map(str, classes)], cwd=output,
                                                stderr=subprocess.DEVNULL, timeout=15).decode(errors="replace")
        api = set()
        owner = ""
        for line in declarations.splitlines():
            line = line.strip()
            if line.endswith("{"):
                owner = line
            if owner:
                api.add((owner, line))
            if line == "}":
                owner = ""
        return api


def _scan(path, source):
    path.write_text(source, encoding="utf-8")
    target = TargetConfig(name="candidate", path=path.parent)
    if secrets.check_file(path, target):
        raise ValueError("소스에 비밀정보가 발견되었습니다.")
    return code_patterns.check_file(path, target) + configuration.check_file(path, target)


def _reserved_name(name):
    if hasattr(ntpath, "isreserved"):
        return ntpath.isreserved(name)
    from pathlib import PureWindowsPath
    return PureWindowsPath(name).is_reserved()


def process(data, request=local_request):
    action = data.get("action")
    base, key = str(data.get("base", "")), str(data.get("key", ""))
    if action == "models":
        result = request(base, key, "models")
        return {"models": [item["id"] for item in result.get("data", []) if isinstance(item, dict)
                           and isinstance(item.get("id"), str)]}
    name, source = data.get("name"), data.get("source")
    if (not isinstance(name, str) or not re.fullmatch(r"[\w. -]{1,128}", name) or name.startswith(".")
            or _reserved_name(name) or Path(name).suffix.lower() not in SUFFIXES):
        raise ValueError("Python·Java·XML·JavaScript 소스 파일을 선택하세요.")
    if not isinstance(source, str) or not 0 < len(source.encode()) <= SOURCE_LIMIT or "\0" in source:
        raise ValueError("12 KiB 이하의 UTF-8 소스 파일을 선택하세요.")
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / name
        findings = _scan(path, source)
        if action == "inspect":
            return {"findings": [{"rule": f.rule_id, "line": f.line, "title": f.title} for f in findings]}
        if action != "propose":
            raise ValueError("지원하지 않는 작업입니다.")
        rule, model = data.get("rule"), data.get("model")
        finding = next((f for f in findings if f.rule_id == rule), None)
        if finding is None or not isinstance(model, str) or not model.strip():
            raise ValueError("현재 파일에서 확인한 점검 항목과 모델을 선택하세요.")
        before = _check_syntax(path, source)
        baseline = Counter(f.rule_id for f in findings)
        instruction = ("Fix the reported finding with the smallest behavior-preserving edit. Return a JSON "
                       "object with source (complete source), impact (change impact), and tests (test plan, "
                       "not results). Write the impact and tests in the user's language.")
        prompt = json.dumps({"rule": rule, "title": finding.title, "line": finding.line, "source": source,
                             "language": data.get("language", "ko")}, ensure_ascii=False)
        reason = ""
        seen = set()
        for attempt in range(1, 4):
            messages = [{"role": "system", "content": instruction}, {"role": "user", "content": prompt}]
            if reason:
                messages.append({"role": "user", "content": "Previous proposal failed validation: " + reason})
            reply = request(base, key, "chat/completions", {"model": model, "messages": messages, "temperature": 0.1})
            try:
                proposal = json.loads(reply["choices"][0]["message"]["content"])
                candidate = proposal["source"]
                if not isinstance(candidate, str) or not candidate.strip() or len(candidate.encode()) > 2 * SOURCE_LIMIT:
                    raise ValueError("수정본 크기 또는 내용이 유효하지 않습니다.")
                if candidate in seen:
                    raise RuntimeError("모델이 같은 후보를 반복해 중단했습니다.")
                seen.add(candidate)
                if candidate == source:
                    raise ValueError("원본과 동일한 후보입니다.")
                findings_after = _scan(path, candidate)
                after = _check_syntax(path, candidate)
                preserved = before.issubset(after) if isinstance(before, set) else before == after
                if not preserved:
                    raise ValueError("기존 소스 인터페이스가 변경되었습니다.")
                remaining = Counter(f.rule_id for f in findings_after)
                if remaining[rule] or remaining - baseline:
                    raise ValueError("대상 규칙이 남거나 다른 점검 항목이 늘었습니다.")
                impact, tests = proposal["impact"], proposal["tests"]
                if not all(isinstance(v, str) and v.strip() for v in (impact, tests)):
                    raise ValueError("변경 영향과 테스트 계획이 필요합니다.")
                return {"source": candidate, "diff": "".join(difflib.unified_diff(source.splitlines(True),
                        candidate.splitlines(True), fromfile=name, tofile="candidate/" + name)),
                        "impact": impact, "tests": tests, "attempts": attempt}
            except (KeyError, IndexError, TypeError, ValueError, SyntaxError, RecursionError) as exc:
                reason = str(exc)[:240] if isinstance(exc, ValueError) else type(exc).__name__
        raise ValueError(f"후보 3개가 검증을 통과하지 못했습니다. {reason}")
