"""Parser-based source-to-sink analysis for Python (standard library ``ast``).

The line-oriented pass in ``code_patterns`` cannot see sanitizers, allow-list
guards, or values returned by helper functions. This module parses a Python
file and judges every security sink call with a three-valued result:

- ``TAINTED``: the argument derives from request input with no sanitizer on the
  path to the sink.
- ``CLEAN``: positively proven safe — only constants, a recognized sanitizer or
  numeric cast, an allow-list / ``re.fullmatch`` guard, or a request value that
  was overwritten by a constant before the sink.
- ``UNKNOWN``: depends on names whose provenance is not visible here (function
  parameters, globals, attributes, unknown calls).

``code_patterns`` drops a line-pattern finding only when the sink is proven
``CLEAN`` and adds or confirms one only when it is proven ``TAINTED``; an
``UNKNOWN`` sink keeps the existing judgement. A gap in this model therefore can
never hide a finding the line pass already reported.

ponytail: intra-file only — taint through function *parameters* (e.g. FastAPI
route arguments), object attributes, or other modules is UNKNOWN, not tracked.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass, field

TAINTED = "tainted"
CLEAN = "clean"
UNKNOWN = "unknown"

RULE_FOR_CLASS = {
    "cmd": "code.command-injection",
    "sql": "code.sql-dynamic-query",
    "eval": "code.eval-user-input",
    "deser": "code.unsafe-deserialization",
    "path": "code.path-traversal",
    "ssrf": "code.ssrf-user-url",
}
CLASSES = tuple(RULE_FOR_CLASS)
HANDLED_RULES = frozenset(RULE_FOR_CLASS.values())

# Untrusted input roots: Flask / Django / Starlette request objects.
_SOURCE_ROOTS = frozenset({"request"})

# A numeric value cannot carry an injection payload for any sink class.
_CASTS = frozenset({"int", "float", "bool", "len", "abs", "round", "ord", "hash"})
_SANITIZERS = {
    "cmd": frozenset({"shlex.quote", "pipes.quote"}),
    "path": frozenset({
        "os.path.basename", "posixpath.basename", "ntpath.basename",
        "werkzeug.utils.secure_filename", "werkzeug.secure_filename",
    }),
    "sql": frozenset(),
    "eval": frozenset(),
    "deser": frozenset(),
    "ssrf": frozenset(),
}
# Module functions that propagate (but never introduce) taint.
_PURE = frozenset({
    "str", "repr", "format", "os.path.join", "posixpath.join", "ntpath.join",
    "os.path.normpath", "os.path.abspath", "urllib.parse.urljoin",
})
_STR_METHODS = frozenset({
    "strip", "lstrip", "rstrip", "lower", "upper", "replace", "format", "join",
    "encode", "decode", "split", "title", "capitalize", "casefold",
    "removeprefix", "removesuffix", "zfill", "center", "ljust", "rjust",
})
_EXIT_CALLS = frozenset({"abort", "flask.abort", "sys.exit", "exit", "quit", "os._exit"})
_GUARD_MATCHERS = frozenset({"re.fullmatch", "re.match", "fullmatch"})

_CMD_ALWAYS = frozenset({
    "os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4",
    "commands.getoutput", "commands.getstatusoutput",
    "subprocess.getoutput", "subprocess.getstatusoutput",
})
_CMD_SHELL = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
})
_EVAL = frozenset({"eval", "exec", "compile"})
_DESER = frozenset({
    "pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "_pickle.loads",
    "marshal.loads", "marshal.load", "dill.loads", "dill.load",
    "jsonpickle.decode", "yaml.unsafe_load", "yaml.unsafe_load_all",
})
_YAML_LOAD = frozenset({"yaml.load", "yaml.load_all"})
_SAFE_YAML_LOADERS = frozenset({"SafeLoader", "CSafeLoader", "BaseLoader"})
_PATH = frozenset({"open", "io.open", "codecs.open", "os.open", "flask.send_file"})
_SSRF = frozenset(
    f"{lib}.{verb}"
    for lib in ("requests", "httpx")
    for verb in ("get", "post", "put", "delete", "head", "patch", "options")
) | frozenset({"urllib.request.urlopen", "urllib2.urlopen", "urllib.urlopen"})
_SSRF_REQUEST = frozenset({"requests.request", "httpx.request"})
_SQL_METHODS = frozenset({"execute", "executemany", "executescript"})


@dataclass
class PythonTaintResult:
    """Per-sink verdicts keyed by ``(rule_id, line)``."""

    vulnerable: dict[tuple[str, int], str] = field(default_factory=dict)
    safe: set[tuple[str, int]] = field(default_factory=set)


def analyze_python(
    source: str, *, extra_sanitizer: Callable[[str], bool] | None = None
) -> PythonTaintResult | None:
    """Return sink verdicts for a Python file, or None if it does not parse.

    ``extra_sanitizer`` lets the caller share its own sanitizer vocabulary (the
    line engine's validate*/escape*/secure_filename names) so both engines agree
    on what neutralizes taint; it receives the call's resolved dotted name.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    try:
        return _Analyzer(tree, extra_sanitizer).run()
    except (RecursionError, AttributeError, TypeError, ValueError, KeyError, IndexError):
        # Fail safe: an unfamiliar construct falls back to the line engine alone
        # rather than aborting the scan of this file.
        return None


@dataclass
class _Env:
    tainted: set[str] = field(default_factory=set)
    clean: set[str] = field(default_factory=set)

    def copy(self) -> _Env:
        return _Env(set(self.tainted), set(self.clean))

    def assign(self, name: str, state: str) -> None:
        self.tainted.discard(name)
        self.clean.discard(name)
        if state == TAINTED:
            self.tainted.add(name)
        elif state == CLEAN:
            self.clean.add(name)


def _combine(states) -> str:
    states = list(states)
    if TAINTED in states:
        return TAINTED
    if UNKNOWN in states:
        return UNKNOWN
    return CLEAN


def _union(a: dict[str, _Env], b: dict[str, _Env]) -> dict[str, _Env]:
    merged = {}
    for cls in CLASSES:
        tainted = a[cls].tainted | b[cls].tainted
        merged[cls] = _Env(tainted, (a[cls].clean & b[cls].clean) - tainted)
    return merged


def _copy(env: dict[str, _Env]) -> dict[str, _Env]:
    return {cls: e.copy() for cls, e in env.items()}


def _root_name(node: ast.AST) -> str | None:
    while True:
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        else:
            break
    return node.id if isinstance(node, ast.Name) else None


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for elt in target.elts for name in _target_names(elt)]
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []  # attribute / subscript targets are not tracked


class _Analyzer:
    def __init__(self, tree: ast.Module, extra_sanitizer: Callable[[str], bool] | None = None) -> None:
        self.tree = tree
        self.extra_sanitizer = extra_sanitizer
        self.imports: dict[str, str] = {}
        self.func_returns: dict[str, dict[str, str]] = {cls: {} for cls in CLASSES}
        self.result = PythonTaintResult()
        self._collect_imports()

    # -- setup -------------------------------------------------------------
    def _collect_imports(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.imports[alias.asname] = alias.name
                    else:
                        root = alias.name.split(".")[0]
                        self.imports.setdefault(root, root)
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    self.imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def _dotted(self, node: ast.AST) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return ""
        parts.append(self.imports.get(node.id, node.id))
        return ".".join(reversed(parts))

    def _functions(self) -> dict[str, ast.AST]:
        funcs: dict[str, ast.AST] = {}
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.setdefault(node.name, node)
        return funcs

    def _module_constants(self) -> dict[str, _Env]:
        env = {cls: _Env() for cls in CLASSES}
        for stmt in self.tree.body:
            if isinstance(stmt, ast.Assign) and self._is_literal(stmt.value):
                for target in stmt.targets:
                    for name in _target_names(target):
                        for cls in CLASSES:
                            env[cls].assign(name, CLEAN)
        return env

    def _is_literal(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self._is_literal(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            return all(k is None or self._is_literal(k) for k in node.keys) and all(
                self._is_literal(v) for v in node.values
            )
        return False

    # -- driver ------------------------------------------------------------
    def run(self) -> PythonTaintResult:
        constants = self._module_constants()
        funcs = self._functions()
        # Fixpoint: a helper returns taint if any of its returns does.
        for _ in range(6):
            changed = False
            for name, fn in funcs.items():
                returns: dict[str, list[str]] = {cls: [] for cls in CLASSES}
                self._block(fn.body, _copy(constants), record=False, returns=returns)
                for cls in CLASSES:
                    state = _combine(returns[cls]) if returns[cls] else CLEAN
                    if self.func_returns[cls].get(name) != state:
                        self.func_returns[cls][name] = state
                        changed = True
            if not changed:
                break
        self._block(self.tree.body, _copy(constants), record=True)
        for fn in funcs.values():
            self._block(fn.body, _copy(constants), record=True)
        return self.result

    # -- statements --------------------------------------------------------
    def _block(self, stmts, env, *, record: bool, returns=None) -> dict[str, _Env]:
        for stmt in stmts:
            env = self._stmt(stmt, env, record=record, returns=returns)
        return env

    def _stmt(self, stmt, env, *, record: bool, returns) -> dict[str, _Env]:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return env  # analyzed as their own scopes
        if isinstance(stmt, ast.Assign):
            self._scan(stmt.value, env, record)
            for cls in CLASSES:
                state = self._eval(stmt.value, env, cls)
                for target in stmt.targets:
                    for name in _target_names(target):
                        env[cls].assign(name, state)
            return env
        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._scan(stmt.value, env, record)
                for cls in CLASSES:
                    state = self._eval(stmt.value, env, cls)
                    for name in _target_names(stmt.target):
                        env[cls].assign(name, state)
            return env
        if isinstance(stmt, ast.AugAssign):
            self._scan(stmt.value, env, record)
            for cls in CLASSES:
                state = _combine([self._eval(stmt.target, env, cls), self._eval(stmt.value, env, cls)])
                for name in _target_names(stmt.target):
                    env[cls].assign(name, state)
            return env
        if isinstance(stmt, ast.Return):
            if stmt.value is not None:
                self._scan(stmt.value, env, record)
            if returns is not None:
                for cls in CLASSES:
                    returns[cls].append(self._eval(stmt.value, env, cls) if stmt.value is not None else CLEAN)
            return env
        if isinstance(stmt, ast.If):
            return self._if(stmt, env, record=record, returns=returns)
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self._scan(stmt.iter, env, record)
            body_env = _copy(env)
            for cls in CLASSES:
                state = self._eval(stmt.iter, env, cls)
                for name in _target_names(stmt.target):
                    body_env[cls].assign(name, state)
            body_env = self._block(stmt.body, body_env, record=record, returns=returns)
            merged = _union(env, body_env)
            if stmt.orelse:
                merged = self._block(stmt.orelse, merged, record=record, returns=returns)
            return merged
        if isinstance(stmt, ast.While):
            self._scan(stmt.test, env, record)
            body_env = self._block(stmt.body, _copy(env), record=record, returns=returns)
            merged = _union(env, body_env)
            if stmt.orelse:
                merged = self._block(stmt.orelse, merged, record=record, returns=returns)
            return merged
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                self._scan(item.context_expr, env, record)
                if item.optional_vars is not None:
                    for cls in CLASSES:
                        state = self._eval(item.context_expr, env, cls)
                        for name in _target_names(item.optional_vars):
                            env[cls].assign(name, state)
            return self._block(stmt.body, env, record=record, returns=returns)
        if isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
            env = self._block(stmt.body, env, record=record, returns=returns)
            merged = env
            for handler in stmt.handlers:
                handler_env = self._block(handler.body, _copy(env), record=record, returns=returns)
                merged = _union(merged, handler_env)
            if stmt.orelse:
                merged = self._block(stmt.orelse, merged, record=record, returns=returns)
            if stmt.finalbody:
                merged = self._block(stmt.finalbody, merged, record=record, returns=returns)
            return merged
        if type(stmt).__name__ == "Match":
            self._scan(stmt.subject, env, record)
            merged = env
            for case in stmt.cases:
                merged = _union(merged, self._block(case.body, _copy(env), record=record, returns=returns))
            return merged
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.expr):
                self._scan(child, env, record)
        return env

    def _if(self, stmt: ast.If, env, *, record: bool, returns) -> dict[str, _Env]:
        self._scan(stmt.test, env, record)
        guard = self._guard(stmt.test)
        body_env = _copy(env)
        if guard and guard[1] == "pos":
            for cls in CLASSES:
                body_env[cls].assign(guard[0], CLEAN)
        body_env = self._block(stmt.body, body_env, record=record, returns=returns)
        else_env = self._block(stmt.orelse, _copy(env), record=record, returns=returns)
        if guard and guard[1] == "neg" and self._exits(stmt.body):
            # Code after the `if` only runs when the value passed the guard.
            for cls in CLASSES:
                else_env[cls].assign(guard[0], CLEAN)
            return else_env
        return _union(body_env, else_env)

    def _guard(self, test: ast.AST) -> tuple[str, str] | None:
        negated = False
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            negated, test = True, test.operand
        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.left, ast.Name)
            and isinstance(test.ops[0], (ast.In, ast.NotIn))
        ):
            positive = isinstance(test.ops[0], ast.In) != negated
            return test.left.id, "pos" if positive else "neg"
        if (
            isinstance(test, ast.Call)
            and self._dotted(test.func) in _GUARD_MATCHERS
            and len(test.args) >= 2
            and isinstance(test.args[1], ast.Name)
        ):
            return test.args[1].id, "neg" if negated else "pos"
        return None

    def _exits(self, body: list[ast.stmt]) -> bool:
        if not body:
            return False
        last = body[-1]
        if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        return (
            isinstance(last, ast.Expr)
            and isinstance(last.value, ast.Call)
            and self._dotted(last.value.func) in _EXIT_CALLS
        )

    # -- expressions -------------------------------------------------------
    def _eval(self, node, env, cls: str) -> str:
        if node is None or isinstance(node, ast.Constant):
            return CLEAN
        if isinstance(node, ast.Name):
            if node.id in _SOURCE_ROOTS:
                return TAINTED
            if node.id in env[cls].tainted:
                return TAINTED
            if node.id in env[cls].clean:
                return CLEAN
            return UNKNOWN
        if isinstance(node, ast.Call):
            return self._eval_call(node, env, cls)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            if _root_name(node) in _SOURCE_ROOTS:
                return TAINTED
            return TAINTED if self._eval(node.value, env, cls) == TAINTED else UNKNOWN
        if isinstance(node, ast.JoinedStr):
            return _combine(self._eval(v, env, cls) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._eval(node.value, env, cls)
        if isinstance(node, ast.BinOp):
            return _combine([self._eval(node.left, env, cls), self._eval(node.right, env, cls)])
        if isinstance(node, ast.BoolOp):
            return _combine(self._eval(v, env, cls) for v in node.values)
        if isinstance(node, ast.IfExp):
            return _combine([self._eval(node.body, env, cls), self._eval(node.orelse, env, cls)])
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return _combine(self._eval(e, env, cls) for e in node.elts)
        if isinstance(node, ast.Dict):
            return _combine(
                [self._eval(k, env, cls) for k in node.keys if k is not None]
                + [self._eval(v, env, cls) for v in node.values]
            )
        if isinstance(node, (ast.Await, ast.Starred)):
            return self._eval(node.value, env, cls)
        return UNKNOWN

    def _eval_call(self, node: ast.Call, env, cls: str) -> str:
        dotted = self._dotted(node.func)
        if dotted in _CASTS or dotted in _SANITIZERS[cls]:
            return CLEAN
        if dotted and self.extra_sanitizer is not None and self.extra_sanitizer(dotted):
            return CLEAN
        if isinstance(node.func, ast.Name) and node.func.id in self.func_returns[cls]:
            return self.func_returns[cls][node.func.id]
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in {"self", "cls"}
            and node.func.attr in self.func_returns[cls]
        ):
            return self.func_returns[cls][node.func.attr]
        if _root_name(node) in _SOURCE_ROOTS:
            return TAINTED
        args = _combine(
            [self._eval(a, env, cls) for a in node.args]
            + [self._eval(k.value, env, cls) for k in node.keywords]
        )
        if dotted in _PURE:
            return args
        if isinstance(node.func, ast.Attribute):
            receiver = self._eval(node.func.value, env, cls)
            if TAINTED in (receiver, args):
                return TAINTED
            if node.func.attr in _STR_METHODS and receiver == CLEAN and args == CLEAN:
                return CLEAN
            return UNKNOWN
        return TAINTED if args == TAINTED else UNKNOWN

    # -- sinks -------------------------------------------------------------
    def _sinks(self, call: ast.Call) -> list[tuple[str, ast.AST | None, str]]:
        dotted = self._dotted(call.func)
        first = call.args[0] if call.args else None
        keyword = {k.arg: k.value for k in call.keywords if k.arg}
        if dotted in _CMD_ALWAYS and first is not None:
            return [("cmd", first, dotted)]
        if dotted in _CMD_SHELL and first is not None:
            shell = keyword.get("shell")
            if isinstance(shell, ast.Constant) and shell.value is True:
                return [("cmd", first, dotted)]
            return []
        if dotted in _EVAL and first is not None:
            return [("eval", first, dotted)]
        if dotted in _DESER and first is not None:
            return [("deser", first, dotted)]
        if dotted in _YAML_LOAD and first is not None:
            loader = keyword.get("Loader") or (call.args[1] if len(call.args) > 1 else None)
            loader_name = self._dotted(loader).rsplit(".", 1)[-1] if loader is not None else ""
            return [("deser", None if loader_name in _SAFE_YAML_LOADERS else first, dotted)]
        if dotted in _PATH and first is not None:
            return [("path", first, dotted)]
        if dotted in _SSRF:
            url = keyword.get("url", first)
            return [("ssrf", url, dotted)] if url is not None else []
        if dotted in _SSRF_REQUEST:
            url = keyword.get("url", call.args[1] if len(call.args) > 1 else None)
            return [("ssrf", url, dotted)] if url is not None else []
        if isinstance(call.func, ast.Attribute) and call.func.attr in _SQL_METHODS and first is not None:
            return [("sql", first, call.func.attr)]
        return []

    def _scan(self, node: ast.AST, env, record: bool) -> None:
        if not record or node is None:
            return
        stack = [node]
        while stack:
            current = stack.pop()
            if isinstance(current, ast.Lambda):
                continue
            if isinstance(current, ast.Call):
                for cls, arg, name in self._sinks(current):
                    self._record(cls, arg, name, current.lineno, env)
            stack.extend(ast.iter_child_nodes(current))

    def _record(self, cls: str, arg, sink: str, line: int, env) -> None:
        key = (RULE_FOR_CLASS[cls], line)
        state = CLEAN if arg is None else self._eval(arg, env, cls)
        if state == TAINTED:
            via = f" via `{arg.id}`" if isinstance(arg, ast.Name) else ""
            self.result.vulnerable[key] = f"AST: request-derived value reaches {sink}(){via} with no recognized sanitizer."
        elif state == CLEAN:
            self.result.safe.add(key)
