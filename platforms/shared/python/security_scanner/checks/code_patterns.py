from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import replace as _replace_finding
from pathlib import Path

from ..models import Finding, TargetConfig
from .common import is_text_candidate, read_text_lines
from .python_taint import HANDLED_RULES as _PY_TAINT_RULES
from .python_taint import analyze_python


CODE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".conf",
    ".config",
    ".cs",
    ".cxx",
    ".go",
    ".h",
    ".hpp",
    ".htm",
    ".html",
    ".java",
    ".jsp",
    ".js",
    ".cjs",
    ".jsx",
    ".kt",
    ".php",
    ".properties",
    ".py",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
    ".vue",
    ".xml",
    ".md",
    ".mjs",
    ".txt",
}

CODE_FILENAMES = {
    ".htaccess",
}


@dataclass(frozen=True)
class CodePatternRule:
    rule_id: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    description: str
    recommendation: str
    extensions: frozenset[str] = frozenset(CODE_EXTENSIONS)


# Remote, attacker-supplied input. `ctx` needs a request-shaped member: a bare
# `ctx.` also matches a canvas 2D context, a crypto context, and most other
# graphics or codec handles.
REMOTE_SOURCE = (
    r"\b(?:req|request)\s*(?:\.|\[)|"
    r"\bctx\s*(?:\.\s*(?:request|req|query|params|body|headers|cookies)\b|\[)|"
    r"\$_(?:GET|POST|REQUEST|FILES)\b|"
    r"\blocation\.(?:hash|search|href)\b"
)
# Operator-supplied input. Reading the file named on your own command line is
# what a CLI is for, so these raise review candidates but never confirm a flow.
LOCAL_SOURCE = r"\binput\s*\(|\bsys\.argv\b|\bARGV\b"
UNTRUSTED_SOURCE = rf"(?:{REMOTE_SOURCE}|{LOCAL_SOURCE})"
LOGGING_API = (
    r"(console\.(log|debug|info|warn|error)|logger\.(debug|info|warning|warn|error|exception)|"
    r"logging\.(debug|info|warning|warn|error|exception)|print|System\.out\.println|NSLog|Log\.(d|i|w|e))"
)
# Bounded so `passed`, `bypass`, `tokenize` and `cache_token` are not secrets,
# while the compound names that really do carry credentials still match.
SENSITIVE_NAME = (
    r"\b(?:pass" r"(?:word)?|passwd|pwd|secret|credentials?|authorization|"
    r"(?:access|refresh|auth|id|bearer|csrf|xsrf|session)[_-]?tokens?|tokens?|"
    r"api[_-]?keys?|secret[_-]?keys?|private[_-]?keys?|session[_-]?ids?|sessions?|cookies?)\b"
)
COOKIE_SENSITIVE_NAME = (
    r"\b(?:pass(?:word)?|passwd|pwd|secret|credentials?|authorization|jwt|"
    r"(?:access|refresh|auth|id|bearer|csrf|xsrf|session)[_-]?tokens?|tokens?|"
    r"api[_-]?keys?|secret[_-]?keys?|private[_-]?keys?|session[_-]?ids?|sessions?)\b"
)
XML_PARSER_API = (
    r"(Document" r"BuilderFactory|SAX" r"ParserFactory|Xml" r"ReaderSettings|Xml" r"Document)"
)

_SQL_CALL_NAMES = (
    r"execute|executemany|executescript|executeQuery|executeUpdate|executeLargeUpdate|executeBatch|addBatch|"
    r"query|raw|prepareStatement|createQuery|createNativeQuery|createSQLQuery|batchUpdate|"
    r"SqlCommand|ExecuteReader|ExecuteScalar|ExecuteNonQuery|ExecuteReaderAsync|ExecuteScalarAsync|ExecuteNonQueryAsync|"
    r"ExecuteSqlRaw|ExecuteSqlRawAsync|ExecuteSqlCommand|FromSqlRaw|FromSqlRawAsync|SqlQueryRaw|"
    r"mysqli_query|mysqli_real_query|mysqli_multi_query|mysqli_prepare|mysqli_execute_query|"
    r"mysqli_stmt_execute|pg_query|pg_send_query|pg_query_params"
)
_SQL_CALL_SINK = (
    rf"(?:\b(?:{_SQL_CALL_NAMES})\b|(?:->|::)\s*(?:query|exec|prepare|execute)\b|"
    r"\b(?:jdbcTemplate|namedParameterJdbcTemplate)\s*\.\s*update\b)"
)
_SQL_CONTEXT_SINK = re.compile(
    rf"(?:{_SQL_CALL_SINK}(?=\s*\()|\.\s*CommandText\b(?=\s*(?:\+?=)))",
    re.IGNORECASE,
)
_SQL_SINK_TOKENS = ("execute", "query", "raw", "prepare", "commandtext", "sqlcommand", "batch", "jdbc")

CODE_PATTERN_RULES = (
    CodePatternRule(
        "code.xss-dom-sink",
        "Potential XSS through unsafe HTML sink",
        "high",
        re.compile(
            rf"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML)\b.*{UNTRUSTED_SOURCE}",
            re.IGNORECASE,
        ),
        "Untrusted input appears to flow into an HTML-rendering sink.",
        "Use safe text rendering, contextual output encoding, or a vetted sanitizer before rendering user-controlled HTML.",
        frozenset({".html", ".js", ".jsx", ".ts", ".tsx", ".vue"}),
    ),
    CodePatternRule(
        "code.sql-dynamic-query",
        "Potential SQL injection through dynamic query",
        "high",
        re.compile(
            rf"(?:{_SQL_CALL_SINK}\s*\(|\.\s*CommandText\s*(?:\+?=))"
            r"[^#\n;]*(SELECT|INSERT|UPDATE|DELETE|MERGE|WHERE)[^#\n;]*(\+|%\s|\{|\$\{|\.format\(|\.\s*\$)",
            re.IGNORECASE,
        ),
        "SQL text appears to be assembled dynamically before execution.",
        "Use parameterized queries or ORM binding APIs instead of string-built SQL.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.command-injection",
        "Potential command injection",
        "high",
        re.compile(
            rf"\b(os\.system|os\.popen|subprocess\.(run|call|Popen|check_output)|child_process\.(exec|execSync)|"
            rf"shell_exec|passthru|Runtime\.getRuntime\(\)\.exec)\s*\([^#\n]*({UNTRUSTED_SOURCE}|shell\s*=\s*True|\+)",
            re.IGNORECASE,
        ),
        "A shell or process execution API appears to receive dynamic or user-controlled input.",
        "Avoid shell execution for user input; pass fixed argument arrays and validate allowlisted values.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.path-traversal",
        "Potential path traversal",
        "medium",
        re.compile(
            rf"(?:(?<![.\w])open|\b(?:os|io|codecs|shutil|aiofiles)\.open|"
            rf"\b(?:send_file|FileResponse|readFile|readFileSync|createReadStream|writeFile|writeFileSync))\s*"
            rf"\([^#\n]*({UNTRUSTED_SOURCE}|path\.join\([^)]*(req|request|params|query)|\.\.)",
            re.IGNORECASE,
        ),
        "A filesystem API appears to use user-controlled path data.",
        "Resolve paths against an allowlisted base directory and reject traversal before opening files.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.csrf-disabled",
        "CSRF protection appears disabled",
        "medium",
        re.compile(
            r"(@cs" r"rf_exempt|cs" r"rf\s*:\s*false|cs" r"rf\.disable|verify_cs" r"rf_token.*false|"
            r"skip_before_action\s+:verify_authenticity_token|protect_from_forgery\s+except:)",
            re.IGNORECASE,
        ),
        "The code appears to disable CSRF protection for a route or application.",
        "Keep CSRF protection enabled for browser-authenticated state-changing requests, or document a compensating control.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.auth-disabled-endpoint",
        "Authentication or authorization appears disabled",
        "medium",
        re.compile(
            r"(@Allow" r"Anonymous|@Public\(\)|permit" r"All\(\)|auth\s*:\s*false|Allow" r"Any|"
            r"permission_classes\s*=\s*\[\s*\]|skip_before_action\s+:authenticate)",
            re.IGNORECASE,
        ),
        "An endpoint or handler appears to explicitly bypass authentication or authorization.",
        "Confirm the endpoint is intentionally public and enforce authorization checks on sensitive operations.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.eval-user-input",
        "Potential code injection through eval-like API",
        "high",
        re.compile(
            # setTimeout/setInterval only execute code when their first argument
            # is a string; a callback that merely mentions `request` is normal.
            # `Function` stays case-sensitive: the JS `function` keyword is not a sink.
            rf"(?:\b(?:eval|exec|(?-i:Function)|instance_eval|class_eval)\s*\([^#\n]*{UNTRUSTED_SOURCE}"
            rf"|\b(?:setTimeout|setInterval)\s*\(\s*[\"'`][^#\n]*{UNTRUSTED_SOURCE})",
            re.IGNORECASE,
        ),
        "User-controlled input appears to reach an eval-like code execution API.",
        "Remove dynamic code execution or replace it with a fixed dispatch table over allowlisted operations.",
        frozenset({".html", ".js", ".jsx", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.unsafe-deserialization",
        "Unsafe deserialization API",
        "high",
        re.compile(
            r"\b(pick" r"le\.loads?|ya" r"ml\.load\s*\(|Object" r"InputStream|Binary" r"Formatter|"
            r"unser" r"ialize\s*\(|Marshal\.load|readObject\s*\()",
            re.IGNORECASE,
        ),
        "A dangerous deserialization API appears in code.",
        "Use safe parsers for untrusted data and restrict deserialization to signed, trusted inputs only.",
        frozenset({".cs", ".java", ".php", ".py", ".rb"}),
    ),
    CodePatternRule(
        "code.ssrf-user-url",
        "Potential SSRF through user-controlled URL fetch",
        "high",
        re.compile(
            rf"\b(requests|httpx|urllib\.request|axios|fetch|http\.get|https\.get|RestTemplate|WebClient)"
            rf"[^#\n]*(get|post|open|request|\()[^#\n]*{UNTRUSTED_SOURCE}",
            re.IGNORECASE,
        ),
        "A server-side HTTP client appears to fetch a URL derived from user input.",
        "Fetch only allowlisted hosts, block private network ranges, and avoid forwarding arbitrary user-provided URLs.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.unrestricted-file-upload",
        "Potential unrestricted file upload",
        "medium",
        re.compile(
            r"(move_uploaded_file\s*\(\s*\$_FILES|\.save\s*\([^#\n]*(filename|originalname|req\.file)|"
            r"multer\s*\(\s*\{\s*dest\s*:)",
            re.IGNORECASE,
        ),
        "Uploaded file data appears to be saved using client-controlled filename or permissive storage.",
        "Validate content type and extension, generate server-side filenames, and store uploads outside executable paths.",
        frozenset({".js", ".jsx", ".php", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.dangerous-c-buffer-api",
        "Dangerous C/C++ buffer API",
        "medium",
        re.compile(r"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(", re.IGNORECASE),
        "The code uses legacy C/C++ APIs commonly associated with buffer overflows.",
        "Use bounded alternatives and verify destination buffer sizes before copying or formatting data.",
        frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}),
    ),
    CodePatternRule(
        "code.unbounded-request-body",
        "Request body parsing without an obvious size limit",
        "low",
        re.compile(r"\b(express\.json|bodyParser\.json|express\.urlencoded|bodyParser\.urlencoded)\s*\(\s*\)", re.IGNORECASE),
        "Request body parsing appears to be enabled without an explicit size limit.",
        "Set conservative request body limits and reject oversized requests early.",
        frozenset({".js", ".jsx", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.logging-sensitive-data",
        "Sensitive data may be written to logs",
        "medium",
        re.compile(rf"\b{LOGGING_API}\s*\([^#\n]*{SENSITIVE_NAME}", re.IGNORECASE),
        "A logging or console output call appears to include credential, token, session, or cookie data.",
        "Remove sensitive values from logs and record only redacted identifiers or security-safe event metadata.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.empty-exception-handler",
        "Exception appears to be silently ignored",
        "low",
        re.compile(r"(\bexcept\b[^:\n]*:\s*pass\b|\bcatch\s*(\([^)]*\))?\s*\{\s*\})", re.IGNORECASE),
        "An exception handler appears to swallow errors without logging, recovery, or a clear security decision.",
        "Handle expected exceptions explicitly and log security-relevant failures with sanitized context.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.broad-exception-handler",
        "Overly broad exception handler",
        "low",
        re.compile(
            r"(?:\bexcept\s*(?::|(?:Exception|BaseException)\b[^:]*:)|"
            r"\bcatch\s*\(\s*(?:final\s+)?(?:Exception|Throwable|System\.Exception)\b|"
            r"\brescue\s+Exception\b)",
            re.IGNORECASE,
        ),
        "A handler catches the broadest exception type, which can hide unexpected security-relevant failures.",
        "Catch expected exception types and fail closed or rethrow unexpected failures at the application boundary.",
        frozenset({".cs", ".java", ".kt", ".py", ".rb"}),
    ),
    CodePatternRule(
        "code.stack-trace-exposure",
        "Stack trace output may expose internals",
        "low",
        re.compile(r"\b(printStackTrace|traceback\.print_exc|console\.trace)\s*\(", re.IGNORECASE),
        "A stack trace output API appears in application code and may expose internals if enabled in user-facing flows.",
        "Route exceptions through centralized error handling and avoid returning or printing raw stack traces outside local debugging.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.unversioned-api-route",
        "API route appears to be unversioned",
        "low",
        re.compile(
            r"(?:@\w+\.route|(?:app|router|routes|server)\.(?:get|post|put|patch|delete|use)|Route|path)"
            r"\s*\([^#\n]*[\"']/api/(?!v\d+(?:/|$))[^\"']+[\"']",
            re.IGNORECASE,
        ),
        "A public-looking API route is declared without an obvious version segment.",
        "Inventory public APIs and prefer explicit versioned routes such as /api/v1/... for lifecycle management.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.insecure-temp-file",
        "Temporary file use may be predictable or race-prone",
        "medium",
        re.compile(
            r"(\b(tempfile\.mktemp|mktemp|tmpnam)\s*\(|\b(open|writeFile|readFile|fopen)\s*\([^#\n]*[\"']/tmp/[^\"']+[\"'])",
            re.IGNORECASE,
        ),
        "The code appears to use a predictable temporary filename or a direct /tmp path in a file operation.",
        "Use secure temporary file APIs that create files atomically and avoid predictable shared paths.",
        frozenset({".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.wildcard-cors",
        "CORS appears to allow every origin",
        "medium",
        re.compile(
            r"(Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*|allow_origins\s*=\s*\[\s*[\"']\*|"
            r"origins?\s*[:=]\s*[\"']\*|allowedOrigins\s*\(\s*[\"']\*)",
            re.IGNORECASE,
        ),
        "CORS configuration appears to allow requests from any origin.",
        "Restrict allowed origins to trusted application domains and avoid combining wildcard origins with credentials.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.public-bind-all-interfaces",
        "Service appears to bind all network interfaces",
        "low",
        re.compile(
            r"(\b(app\.run|uvicorn\.run|server\.listen|listen|http\.ListenAndServe)\s*\([^#\n]*[\"']0\.0\.0\.0[\"']|"
            r"\b(host|bind_address|listen_address)\s*[:=]\s*[\"']0\.0\.0\.0[\"']|--host\s+0\.0\.0\.0)",
            re.IGNORECASE,
        ),
        "A service binding appears to listen on all interfaces, which can expose local services more broadly than intended.",
        "Bind development services to localhost by default and require explicit configuration for public exposure.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.insecure-cookie-settings",
        "Session cookie settings appear insecure",
        "medium",
        re.compile(
            r"(SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False|"
            r"(secure|httpOnly|httponly)\s*[:=]\s*false|"
            r"sameSite\s*[:=]\s*[\"']none[\"'][^#\n]*(secure\s*[:=]\s*false)?)",
            re.IGNORECASE,
        ),
        "Cookie or session settings appear to disable Secure or HttpOnly protections.",
        "Set Secure, HttpOnly, and appropriate SameSite attributes for session cookies and avoid weakening them outside local-only development.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.persistent-sensitive-cookie",
        "Sensitive value stored in a persistent cookie",
        "medium",
        re.compile(
            rf"(?=.*\b(?:cookie|set-cookie)\b)(?=.*{COOKIE_SENSITIVE_NAME})"
            r"(?=.*\b(?:max[_-]?age|expires?)\b).+",
            re.IGNORECASE,
        ),
        "A credential, session, or token value appears to be stored in a cookie with persistent expiry.",
        "Keep sensitive cookies session-scoped where possible and store only opaque, revocable identifiers.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.jwt-verification-disabled",
        "JWT signature verification appears disabled",
        "high",
        re.compile(
            r"(verify_signature\s*[:=]\s*False|verify\s*[:=]\s*false|jwt\.decode\s*\([^#\n]*(verify\s*=\s*False|options\s*=\s*\{[^}]*verify_signature[^}]*False))",
            re.IGNORECASE,
        ),
        "JWT decoding appears to disable signature verification or token validation.",
        "Require signature, issuer, audience, expiry, and algorithm validation for every trusted JWT.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.jwt-none-algorithm",
        "JWT none algorithm appears allowed",
        "high",
        re.compile(r"(algorithms?\s*[:=]\s*\[[^\]]*[\"']none[\"']|alg\s*[:=]\s*[\"']none[\"'])", re.IGNORECASE),
        "JWT configuration appears to allow the none algorithm.",
        "Use an explicit allowlist of approved signing algorithms and reject unsigned tokens.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.session-long-expiry",
        "Session or token expiry appears excessive",
        "low",
        re.compile(
            r"(SESSION_COOKIE_AGE\s*=\s*(?:[7-9]\d{5,}|[1-9]\d{6,})|maxAge\s*[:=]\s*(?:[7-9]\d{8,}|[1-9]\d{9,})|expiresIn\s*[:=]\s*[\"'](?:365d|[2-9]\d{2,}d|[1-9]\d+y)[\"'])",
            re.IGNORECASE,
        ),
        "Session or token lifetime appears very long for an application credential.",
        "Use short-lived access tokens, rotate refresh tokens, and document any long-lived session exception.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.api-route-missing-auth",
        "Sensitive API route appears to lack an auth guard",
        "medium",
        re.compile(
            r"((app|router|server)\.(get|post|put|patch|delete)\s*\([\"'][^\"']*/api/[^\"']*(admin|user|account|payment|order|profile|secret|token)[^\"']*[\"'][^#\n]*\(?\s*(req|request|ctx)\s*\)?\s*=>)",
            re.IGNORECASE,
        ),
        "A sensitive-looking API route is declared inline without an obvious authentication or authorization guard nearby.",
        "Require explicit route-level authentication and object/function authorization checks before sensitive API handlers run.",
        frozenset({".js", ".jsx", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.api-mass-assignment",
        "API handler appears to mass-assign request body data",
        "medium",
        re.compile(
            r"(\b(create|update|assign|save|insert|merge)\s*\([^#\n]*(req\.body|request\.body|body|params)|\.\.\.\s*(req\.body|request\.body|body))",
            re.IGNORECASE,
        ),
        "Request body data appears to be assigned directly to a model or persistence call.",
        "Map only allowed fields explicitly and reject unexpected object properties before persistence.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.api-missing-rate-limit",
        "API server appears to lack rate limiting",
        "low",
        re.compile(r"(express\s*\(\)|FastAPI\s*\(|new\s+Koa\s*\(|SpringApplication\.run)", re.IGNORECASE),
        "An API framework bootstrap was found; KODA did not see route-level rate limiting from this line.",
        "Add rate limits, request quotas, and abuse controls for login, signup, password reset, and high-cost API routes.",
        frozenset({".java", ".js", ".jsx", ".kt", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.auth-attempt-protection-missing",
        "Authentication flow may lack repeated-attempt protection",
        "medium",
        re.compile(r"(?!)"),
        "A login or authentication flow was found without visible throttling, lockout, CAPTCHA, or step-up authentication.",
        "Apply authentication-specific throttling and failed-attempt controls, with lockout or step-up verification where appropriate.",
        frozenset({".cs", ".java", ".js", ".jsx", ".kt", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.external-api-no-timeout",
        "External API call appears to omit a timeout",
        "low",
        re.compile(
            r"\b(requests\.(get|post|put|patch|delete)|httpx\.(get|post|put|patch|delete)|axios\.(get|post|put|patch|delete)|fetch)\s*\([^#\n]*(https?://|url|endpoint)(?![^#\n]*(timeout|signal|AbortController))",
            re.IGNORECASE,
        ),
        "An outbound API call appears to be made without an explicit timeout or abort signal.",
        "Set conservative timeouts, retries with backoff, and allowlisted destinations for outbound API integrations.",
        frozenset({".js", ".jsx", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.pii-logging",
        "Personal data may be written to logs",
        "medium",
        re.compile(
            rf"\b{LOGGING_API}\s*\([^#\n]*(email|phone|mobile|address|birth|dob|ssn|resident|rrn|jumin|주민|전화|주소|생년|card[_-]?number)",
            re.IGNORECASE,
        ),
        "A logging or console output call appears to include personal or regulated data fields.",
        "Redact personal data in logs, use event IDs instead of raw identifiers, and document retention limits.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.directory-listing-enabled",
        "Web directory listing appears enabled",
        "medium",
        re.compile(
            r"(Options\s+(\+?Indexes|.*\bIndexes\b)|autoindex\s+on|DirectoryBrowse\s+On)",
            re.IGNORECASE,
        ),
        "Web server configuration appears to expose directory listings.",
        "Disable directory listing and serve only explicitly intended files through controlled routes or static asset configuration.",
        frozenset({".conf", ".config", ".htaccess", ".properties", ".xml"}),
    ),
    CodePatternRule(
        "code.webdav-enabled",
        "WebDAV appears enabled",
        "medium",
        re.compile(r"(\bDAV\s+On\b|mod_dav|webdav|httpPutEnabled\s*=\s*[\"']?true)", re.IGNORECASE),
        "WebDAV or HTTP PUT-style publishing support appears enabled.",
        "Disable WebDAV unless explicitly required, and restrict authoring methods with authentication and network controls.",
        frozenset({".conf", ".config", ".htaccess", ".properties", ".xml"}),
    ),
    CodePatternRule(
        "code.legacy-board-software",
        "Legacy bulletin board software marker",
        "medium",
        re.compile(r"\b(tech" r"note|zero" r"board)\b", re.IGNORECASE),
        "The project contains markers of legacy bulletin board software historically associated with recurring web compromise.",
        "Confirm the component is still used, update or remove it, and isolate legacy upload/download functionality behind compensating controls.",
        frozenset({".html", ".inc", ".js", ".php"}),
    ),
    CodePatternRule(
        "code.weak-hash",
        "Weak hash algorithm appears in security-sensitive code",
        "medium",
        re.compile(r"\b(md" r"5|sha" r"1)\s*\(", re.IGNORECASE),
        "The code appears to use MD5 or SHA-1, which are unsuitable for passwords, signatures, and collision-resistant integrity checks.",
        "Use modern password hashing for credentials and SHA-256 or stronger approved algorithms for integrity where appropriate.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.xml-external-entity",
        "XML parser may allow external entity processing",
        "high",
        re.compile(
            rf"(resolve_entities\s*=\s*True|load_dtd\s*=\s*True|{XML_PARSER_API}[^#\n]*(parse|load|newInstance|\())",
            re.IGNORECASE,
        ),
        "XML parsing appears to use APIs that can be unsafe when external entity processing is not disabled.",
        "Disable DTD and external entity resolution, or use hardened XML parser configurations for untrusted XML.",
        frozenset({".cs", ".java", ".kt", ".py", ".xml"}),
    ),
    CodePatternRule(
        "code.llm-prompt-user-concat",
        "LLM prompt appears to concatenate user input",
        "medium",
        re.compile(
            rf"(system|developer|prompt|messages?)\s*[:=][^#\n]*(\+|f[\"']|`\$\{{)[^#\n]*{UNTRUSTED_SOURCE}",
            re.IGNORECASE,
        ),
        "User-controlled input appears to be concatenated into a privileged prompt or message.",
        "Keep system/developer instructions fixed, place user content in separate message fields, and add prompt-injection tests.",
        frozenset({".js", ".jsx", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.llm-tool-unrestricted",
        "LLM tool or function call appears unrestricted",
        "high",
        re.compile(
            r"(tool_choice\s*[:=]\s*[\"']auto|function_call\s*[:=]\s*[\"']auto|tools\s*[:=]\s*\[[^\]]*(exec|shell|browser|http|file|database))",
            re.IGNORECASE,
        ),
        "The model appears able to call broad tools without an obvious allowlist or confirmation boundary.",
        "Constrain tools by task, validate tool arguments, require confirmation for side effects, and log tool decisions.",
        frozenset({".js", ".jsx", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.open-redirect-user-input",
        "Potential open redirect from user input",
        "medium",
        re.compile(
            rf"(\bsendRedirect\s*\([^#\n]*request\.getParameter|"
            rf"\b(res|response|ctx)\.redirect\s*\([^#\n]*{UNTRUSTED_SOURCE}|"
            rf"\bredirect\s*\(\s*[^#\n)]*{UNTRUSTED_SOURCE})",
            re.IGNORECASE,
        ),
        "A redirect target appears to be built from user-controlled input without an allowlist.",
        "Redirect only to allowlisted internal paths, or map user input to fixed destinations instead of raw URLs.",
        frozenset({".java", ".jsp", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.xml-injection",
        "Potential XML injection through string assembly",
        "medium",
        re.compile(
            rf"([\"'`][^\"'`\n]*<[A-Za-z][\w:-]*>[^\"'`\n]*[\"'`]\s*(\+|%)\s*[^#\n]*{UNTRUSTED_SOURCE}|"
            rf"f[\"'][^\"'\n]*<[A-Za-z][\w:-]*>[^\"'\n]*\{{[^}}\n]*(req|request|params|query|body|input))",
            re.IGNORECASE,
        ),
        "User-controlled input appears to be concatenated into an XML document body without escaping.",
        "Build XML with a serializer or escape user input for XML content instead of concatenating strings.",
        frozenset({".java", ".js", ".jsx", ".kt", ".php", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.ldap-injection",
        "Potential LDAP injection through filter assembly",
        "high",
        re.compile(
            r"([\"']\(*[&|]?\(*(uid|cn|sAMAccountName|mail|memberOf|objectClass)=[^\"'\n]*[\"']\s*(\+|%|\.format\()|"
            r"\b(LdapTemplate|DirContext|InitialDirContext|InitialLdapContext)\b[^#\n]*\bsearch\b[^#\n]*(\+|\.format\(|f[\"'])|"
            r"\bldap\w*[^#\n]*\bsearch(_s|_ext)?\s*\([^#\n]*(%s|\+|\.format\(|f[\"']))",
            re.IGNORECASE,
        ),
        "An LDAP filter appears to be assembled from dynamic input without escaping.",
        "Escape LDAP filter metacharacters or use parameterized LDAP query APIs for user-supplied values.",
        frozenset({".java", ".kt", ".py"}),
    ),
    CodePatternRule(
        "code.http-response-splitting",
        "Potential HTTP response splitting via header value",
        "medium",
        re.compile(
            rf"\b(setHeader|addHeader|set_header|writeHead)\s*\([^#\n]*{UNTRUSTED_SOURCE}",
            re.IGNORECASE,
        ),
        "User-controlled input appears to flow into an HTTP response header without CR/LF filtering.",
        "Strip or reject CR/LF characters and validate user input before writing it into response headers.",
        frozenset({".cs", ".go", ".java", ".jsp", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.format-string-user-input",
        "Format string may be attacker-controlled",
        "high",
        re.compile(
            r"(\b(printf|vprintf|syslog)\s*\(\s*[a-zA-Z_][\w>.\-\[\]]*\s*\)|"
            r"\bf?printf\s*\(\s*(stderr|stdout)\s*,\s*[a-zA-Z_][\w>.\-\[\]]*\s*\)|"
            r"\bString\.format\s*\(\s*(?!Locale\b)[a-zA-Z_][\w.\[\]]*\s*[,)])",
            re.IGNORECASE,
        ),
        "A variable is used directly as a format string, which allows format specifier injection.",
        "Pass a constant format string and supply dynamic data as arguments (e.g. printf(\"%s\", value)).",
        frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".java", ".kt"}),
    ),
    CodePatternRule(
        "code.insufficient-key-length",
        "Cryptographic key length appears insufficient",
        "medium",
        re.compile(
            r"(\bRSA\b[^#\n]{0,60}\b(512|768|1024)\b|\b(512|768|1024)\b[^#\n]{0,30}\bRSA\b|"
            r"\bKeyPairGenerator\b[^#\n]*initialize\s*\(\s*(512|768|1024)\b|"
            r"\b(DSA|DiffieHellman|DH)\b[^#\n]{0,40}\b(512|768|1024)\b)",
            re.IGNORECASE,
        ),
        "An asymmetric key appears to be generated with fewer than 2048 bits.",
        "Use RSA/DSA/DH keys of at least 2048 bits (or modern elliptic-curve algorithms) for new keys.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.insecure-random-security-use",
        "Non-cryptographic randomness used in a security context",
        "medium",
        re.compile(
            r"\b(token|otp|nonce|salt|session[_-]?id|secret|password|api[_-]?key|auth[_-]?code|verification[_-]?code|reset[_-]?code)\w*\s*[:=]"
            r"[^#\n]*(Math\.random|java\.util\.Random|new\s+Random\s*\(|\brandom\.(random|randint|choice|choices|randrange|getrandbits)\s*\(|\brand\s*\(\s*\))",
            re.IGNORECASE,
        ),
        "A security-purpose value appears to be generated with a non-cryptographic random API.",
        "Use a CSPRNG (secrets, SecureRandom, crypto.randomBytes/getRandomValues) for tokens, codes, keys, and salts.",
        frozenset({".cs", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.tls-certificate-verification-disabled",
        "TLS certificate verification appears disabled",
        "high",
        re.compile(
            r"(\bverify\s*=\s*False\b|rejectUnauthorized\s*[:=]\s*false|InsecureSkipVerify\s*:\s*true|"
            r"NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*[:=]\s*[\"']?0|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|"
            r"setHostnameVerifier\s*\([^)#\n]*->\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)|"
            r"check_hostname\s*=\s*False|ssl\.CERT_NONE)",
            re.IGNORECASE,
        ),
        "TLS certificate or hostname verification appears to be turned off for an outbound connection.",
        "Keep certificate and hostname verification enabled; pin or provision proper trust anchors instead of disabling checks.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.password-hash-without-salt",
        "Password appears hashed without a salt or KDF",
        "medium",
        re.compile(
            r"(\b(password|passwd|pwd|pin|credential)\w*\b[^#\n]*\b(hashlib\.(md5|sha1|sha256)|MessageDigest\.getInstance|DigestUtils\.(md5|sha1|sha256)\w*|crypto\.createHash)\b|"
            r"\b(hashlib\.(md5|sha1|sha256)|crypto\.createHash)\b[^#\n]*\b(password|passwd|pwd|pin)\b)",
            re.IGNORECASE,
        ),
        "A credential appears to be hashed directly with a fast hash instead of a salted password KDF.",
        "Hash passwords with a dedicated KDF (bcrypt, scrypt, Argon2, PBKDF2) that applies a unique salt per credential.",
        frozenset({".cs", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.null-pointer-dereference",
        "Potential null pointer dereference",
        "medium",
        # Java/Kotlin nullability needs state tracking, so the real detector is
        # `_java_null_pointer_findings` rather than a line-only expression.
        re.compile(r"(?!)"),
        "A value that is null or returned by a known nullable lookup appears to be dereferenced.",
        "Check for null before dereferencing, return a non-null type, or use a fail-closed wrapper such as Objects.requireNonNull or Optional.orElseThrow.",
        frozenset({".java", ".kt"}),
    ),
    CodePatternRule("code.improper-resource-release", "Potential resource leak", "medium", re.compile(r"(?!)"), "A resource appears to be acquired without an obvious same-scope release.", "Close or release acquired resources on every path.", frozenset({".java", ".kt"})),
    CodePatternRule("code.use-after-free", "Potential use after free", "high", re.compile(r"(?!)"), "A C/C++ variable appears to be used after free without reset or reassignment.", "Do not use a pointer after free; set it to NULL or reassign before use.", frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"})),
    CodePatternRule("code.uninitialized-variable", "Potential uninitialized variable use", "high", re.compile(r"(?!)"), "A local C/C++ variable appears to be read before initialization.", "Initialize local variables before any read on every control-flow path.", frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"})),
    CodePatternRule("code.dns-security-decision", "DNS result used in security decision", "medium", re.compile(r"(?!)"), "A DNS lookup result appears to flow directly into an authentication, authorization, or trust decision.", "Do not use DNS identity alone for security decisions; use authenticated identity and certificate validation.", frozenset({".py", ".java", ".kt", ".js", ".ts", ".go", ".cs", ".rb", ".php"})),
    CodePatternRule("code.integer-overflow-user-input", "Unbounded external integer used in allocation or indexing", "high", re.compile(r"(?!)"), "An integer parsed from external input appears to be used as an array index or allocation size without a visible range check.", "Validate lower and upper bounds before using externally supplied integers in arithmetic, allocation, or indexing.", frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".java", ".kt", ".cs"})),
    CodePatternRule("code.security-decision-user-input", "External input used in a security or business decision", "high", re.compile(r"(?!)"), "A security-sensitive decision value appears to come directly from request-controlled input.", "Derive authorization, price, role, and permission decisions from trusted server-side state and validate any external input.", frozenset({".java", ".kt", ".cs", ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb"})),
    CodePatternRule("code.authorization-check-missing", "Sensitive operation lacks a visible authorization check", "high", re.compile(r"(?!)"), "A sensitive endpoint or method appears to perform an operation without a nearby role, ownership, or permission check.", "Enforce function- and object-level authorization before the sensitive operation.", frozenset({".java", ".kt", ".cs", ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb"})),
    CodePatternRule("code.insecure-resource-permissions", "Critical resource receives permissive permissions", "high", re.compile(r"(?!)"), "Code explicitly grants broad write or full-control permissions to a resource.", "Grant only the owner or required service identity the minimum read and write permissions.", frozenset({".java", ".kt", ".cs", ".py", ".js", ".jsx", ".ts", ".tsx", ".c", ".cc", ".cpp", ".cxx"})),
    CodePatternRule("code.weak-password-policy", "Weak password length policy", "medium", re.compile(r"(?!)"), "An explicit password policy accepts passwords shorter than eight characters.", "Require an appropriate minimum length and apply the organization's password composition and breached-password controls.", frozenset({".java", ".kt", ".cs", ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb"})),
    CodePatternRule("code.uncontrolled-loop", "Loop or recursion lacks a visible termination path", "medium", re.compile(r"(?!)"), "A literal infinite loop or direct recursion appears without a visible exit or base case.", "Add a bounded condition, explicit exit, timeout, or recursive base case.", frozenset({".java", ".kt", ".cs", ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb", ".go", ".c", ".cc", ".cpp", ".cxx"})),
    CodePatternRule("code.session-shared-state", "Request or session data stored in shared mutable state", "high", re.compile(r"(?!)"), "Per-user request or session data appears to be stored in module or instance state shared across requests.", "Keep per-user data in request/session scope and avoid mutable servlet or controller instance fields.", frozenset({".java", ".kt", ".cs", ".py"})),
    CodePatternRule("code.private-array-return", "Private array returned directly by a public method", "medium", re.compile(r"(?!)"), "A public method appears to return a private array or mutable collection reference directly.", "Return a clone, immutable view, or defensive copy.", frozenset({".java", ".kt", ".cs"})),
    CodePatternRule("code.private-array-assignment", "Public array assigned directly to a private field", "medium", re.compile(r"(?!)"), "A public method appears to assign a caller-owned array or mutable collection directly to a private field.", "Clone or defensively copy mutable input before storing it in private state.", frozenset({".java", ".kt", ".cs"})),
    CodePatternRule("code.dangerous-managed-api", "Dangerous Java/J2EE or C# API", "high", re.compile(r"(?!)"), "Code uses a runtime API identified by the guide as unsafe in a managed application context.", "Use managed connection APIs and graceful lifecycle handling instead of direct sockets or forced process exit.", frozenset({".java", ".kt", ".cs"})),
    CodePatternRule(
        "code.llm-sensitive-data-in-prompt",
        "Sensitive data may be sent to an LLM prompt",
        "medium",
        re.compile(rf"(openai|anthropic|chat\.completions|responses\.create|generateContent)[^#\n]*{SENSITIVE_NAME}", re.IGNORECASE),
        "A prompt or LLM request appears to include credential, session, cookie, or other sensitive fields.",
        "Redact sensitive values before LLM calls and document whether prompts may leave the local trust boundary.",
        frozenset({".js", ".jsx", ".py", ".ts", ".tsx"}),
    ),
)


_JAVA_XML_FACTORY = re.compile(
    r"\b(?:DocumentBuilderFactory\s+)?([A-Za-z_$][\w$]*)\s*=\s*DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)",
)
_JAVA_XML_UNTRUSTED_INPUT = re.compile(
    r"\b(request|req|body|payload|input|stream|reader|upload|xml)\w*\b|getInputStream\s*\(|getReader\s*\(",
    re.IGNORECASE,
)

_JAVA_ASSIGNMENT = re.compile(
    r"^\s*(?:(?:final|var|val)\s+)?(?:[A-Za-z_$][\w$<>\[\].,?]*\s+)?"
    r"([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?\s*$"
)
_JAVA_NULL_GUARD = re.compile(
    r"\bif\s*\(\s*([A-Za-z_$][\w$]*)\s*==\s*null\s*\)|"
    r"\bif\s*\(\s*null\s*==\s*([A-Za-z_$][\w$]*)\s*\)"
)
_JAVA_NONNULL_GUARD = re.compile(
    r"\bif\s*\(\s*([A-Za-z_$][\w$]*)\s*!=\s*null\s*\)|"
    r"\bif\s*\(\s*null\s*!=\s*([A-Za-z_$][\w$]*)\s*\)"
)
_JAVA_MAP_DECLARATION = re.compile(
    r"\b(?:Map|HashMap|ConcurrentHashMap|SortedMap|NavigableMap)\s*<[^;=]+>\s*([A-Za-z_$][\w$]*)"
)
_JAVA_KNOWN_NULLABLE_CALL = re.compile(
    r"(?:\brequest\s*\.\s*getParameter|\bSystem\s*\.\s*(?:getenv|getProperty)|"
    r"\b(?:[A-Za-z_$][\w$]*(?:Map|Cache|Repository|Repo|Dao)|map|cache|users|items|records)"
    r"\s*\.\s*(?:get|findBy\w*|lookup\w*))\s*\([^;]*?\)",
    re.IGNORECASE,
)
_JAVA_NULL_SAFE_CHAIN = re.compile(
    r"\.(?:orElseThrow|orElseGet|orElse|ifPresent|isPresent)\s*\(|"
    r"\bObjects\s*\.\s*requireNonNull\s*\(",
    re.IGNORECASE,
)


def _java_guard_exits(lines: list[str], start: int) -> bool:
    """Return true when a small null-guard block exits before fall-through."""
    if "{" not in lines[start]:
        return bool(re.search(r"\b(?:return|throw)\b", lines[start]))
    depth = 0
    saw_block = False
    for index in range(start, min(len(lines), start + 7)):
        line = lines[index]
        if "{" in line:
            saw_block = True
        depth += line.count("{") - line.count("}")
        if re.search(r"\b(?:return|throw)\b", line):
            return True
        if saw_block and index > start and depth <= 0:
            break
    return False


def _java_null_pointer_findings(path: Path, lines: list[str], analysis_lines: list[str]) -> list[Finding]:
    """Conservative intra-file Java/Kotlin null-state analysis.

    Definite ``x = null; x.member`` paths are confirmed. Dereferences of a
    small allowlist of APIs whose contracts permit null are review candidates.
    Arbitrary method returns are deliberately not inferred.
    """
    rule = _RULE_BY_ID["code.null-pointer-dereference"]
    definitely_null: set[str] = set()
    possibly_null: set[str] = set()
    nullable_receivers: set[str] = set()
    nonnull_scopes: list[tuple[str, int]] = []
    nonnull_next_statement: dict[str, int] = {}
    brace_depth = 0
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for index, line in enumerate(analysis_lines):
        stripped = line.strip()
        if not stripped:
            continue

        nonnull_next_statement = {
            name: statement_index
            for name, statement_index in nonnull_next_statement.items()
            if statement_index >= index
        }
        if re.search(r"\belse\b", stripped):
            # A fact established by the positive branch is not valid in else.
            nonnull_scopes.clear()
        nonnull_scopes = [(name, depth) for name, depth in nonnull_scopes if brace_depth >= depth]
        map_declaration = _JAVA_MAP_DECLARATION.search(stripped)
        if map_declaration:
            nullable_receivers.add(map_declaration.group(1))

        nonnull_guard = _JAVA_NONNULL_GUARD.search(stripped)
        nonnull_on_line: str | None = None
        if nonnull_guard:
            name = nonnull_guard.group(1) or nonnull_guard.group(2)
            if "{" in stripped:
                nonnull_scopes.append((name, brace_depth + 1))
            elif stripped[nonnull_guard.end():].strip():
                nonnull_on_line = name
            else:
                next_statement = next(
                    (candidate for candidate in range(index + 1, len(analysis_lines)) if analysis_lines[candidate].strip()),
                    index,
                )
                if next_statement == index:
                    nonnull_on_line = name
                else:
                    nonnull_next_statement[name] = next_statement

        required_nonnull = re.search(
            r"\bObjects\s*\.\s*requireNonNull\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*;",
            stripped,
        )
        if required_nonnull:
            name = required_nonnull.group(1)
            definitely_null.discard(name)
            possibly_null.discard(name)

        guard = _JAVA_NULL_GUARD.search(stripped)
        if guard and _java_guard_exits(analysis_lines, index):
            name = guard.group(1) or guard.group(2)
            definitely_null.discard(name)
            possibly_null.discard(name)
            continue

        for name in sorted(definitely_null | possibly_null):
            if not re.search(rf"\b{re.escape(name)}\s*\.(?!\s*class\b)", stripped):
                continue
            if (
                name == nonnull_on_line
                or nonnull_next_statement.get(name) == index
                or any(scope_name == name for scope_name, _ in nonnull_scopes)
            ):
                continue
            if _JAVA_NULL_SAFE_CHAIN.search(stripped):
                continue
            line_number = index + 1
            if line_number in seen_lines:
                continue
            confirmed = name in definitely_null
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category="code",
                    severity=rule.severity,
                    title=rule.title,
                    path=path,
                    line=line_number,
                    evidence=_trim_evidence(lines[index].strip()),
                    description=rule.description,
                    recommendation=rule.recommendation,
                    verification_status="confirmed" if confirmed else "needs_review",
                    verification_note=(
                        "동일 파일에서 null 대입 후 방어 없이 멤버를 참조하는 흐름을 확인했습니다."
                        if confirmed
                        else "null을 반환할 수 있는 API 결과를 즉시 참조합니다. API 계약과 입력 조건을 검토해야 합니다."
                    ),
                )
            )
            seen_lines.add(line_number)

        typed_map_chain = any(
            re.search(rf"\b{re.escape(receiver)}\s*\.\s*get\s*\([^;]*?\)\s*\.\s*[A-Za-z_$]", stripped)
            for receiver in nullable_receivers
        )
        if (_JAVA_KNOWN_NULLABLE_CALL.search(stripped) or typed_map_chain) and re.search(r"\)\s*\.\s*[A-Za-z_$]", stripped):
            if not _JAVA_NULL_SAFE_CHAIN.search(stripped):
                line_number = index + 1
                if line_number not in seen_lines:
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            category="code",
                            severity=rule.severity,
                            title=rule.title,
                            path=path,
                            line=line_number,
                            evidence=_trim_evidence(lines[index].strip()),
                            description=rule.description,
                            recommendation=rule.recommendation,
                            verification_status="needs_review",
                            verification_note="null을 반환할 수 있는 조회 API의 결과를 즉시 참조합니다. 조회 실패 경로를 확인해야 합니다.",
                        )
                    )
                    seen_lines.add(line_number)

        assignment = _JAVA_ASSIGNMENT.match(stripped)
        if assignment:
            name, expression = assignment.groups()
            normalized_expression = expression.rstrip(";").strip()
            typed_map_lookup = any(
                re.search(rf"\b{re.escape(receiver)}\s*\.\s*get\s*\(", expression)
                for receiver in nullable_receivers
            )
            if normalized_expression == "null" or normalized_expression in definitely_null:
                definitely_null.add(name)
                possibly_null.discard(name)
            elif normalized_expression in possibly_null or (
                (_JAVA_KNOWN_NULLABLE_CALL.search(expression) or typed_map_lookup)
                and not _JAVA_NULL_SAFE_CHAIN.search(expression)
            ):
                definitely_null.discard(name)
                possibly_null.add(name)
            else:
                definitely_null.discard(name)
                possibly_null.discard(name)

        brace_depth += stripped.count("{") - stripped.count("}")

    # Bound report noise without allowing early review candidates to hide a
    # later definite dereference.
    return sorted(
        findings,
        key=lambda finding: (finding.verification_status != "confirmed", finding.line or 0),
    )[:5]


def _java_document_builder_xxe_findings(path: Path, lines: list[str], analysis_lines: list[str]) -> list[Finding]:
    """Find DocumentBuilder XXE paths only when an unsafe builder reaches untrusted XML."""
    findings: list[Finding] = []

    for factory_index, raw_line in enumerate(analysis_lines):
        factory_match = _JAVA_XML_FACTORY.search(raw_line)
        if not factory_match:
            continue

        factory = factory_match.group(1)
        factory_ref = re.escape(factory)
        next_factory_index = next(
            (
                index
                for index in range(factory_index + 1, len(analysis_lines))
                if _JAVA_XML_FACTORY.search(analysis_lines[index])
            ),
            len(analysis_lines),
        )
        builder_pattern = re.compile(
            rf"\b(?:DocumentBuilder\s+)?([A-Za-z_$][\w$]*)\s*=\s*{factory_ref}\s*\.\s*newDocumentBuilder\s*\(\s*\)",
        )
        builder_match: re.Match[str] | None = None
        builder_index: int | None = None
        for index in range(factory_index + 1, next_factory_index):
            builder_match = builder_pattern.search(analysis_lines[index])
            if builder_match:
                builder_index = index
                break

        if builder_match is None or builder_index is None:
            continue

        builder = builder_match.group(1)
        parse_pattern = re.compile(rf"\b{re.escape(builder)}\s*\.\s*parse\s*\((.*)", re.IGNORECASE)
        parse_match: re.Match[str] | None = None
        parse_index: int | None = None
        for index in range(builder_index + 1, next_factory_index):
            candidate = parse_pattern.search(analysis_lines[index])
            if candidate and _JAVA_XML_UNTRUSTED_INPUT.search(candidate.group(1)):
                parse_match = candidate
                parse_index = index
                break

        if parse_match is None or parse_index is None:
            continue

        configuration_lines = analysis_lines[factory_index + 1 : builder_index]
        if _java_xml_factory_is_hardened(factory, configuration_lines):
            continue

        evidence = lines[parse_index].strip()
        findings.append(
            Finding(
                rule_id="code.xml-external-entity",
                category="code",
                severity="high",
                title="XML parser may allow external entity processing",
                path=path,
                line=parse_index + 1,
                evidence=_trim_evidence(evidence),
                description=(
                    "Potentially untrusted XML reaches DocumentBuilder.parse() before safe DTD or external entity "
                    "configuration is confirmed."
                ),
                recommendation=(
                    "Disable DOCTYPE declarations, or disable external general entities, external parameter entities, "
                    "external DTD loading, XInclude, and entity expansion before newDocumentBuilder()."
                ),
            )
        )
        if len(findings) >= 5:
            break

    return findings


_SLASH_COMMENT_SUFFIXES = frozenset(
    {
        ".c", ".cc", ".cpp", ".cs", ".cxx", ".go", ".h", ".hpp", ".java", ".js",
        ".jsx", ".kt", ".php", ".rs", ".swift", ".ts", ".tsx", ".vue",
    }
)
_HASH_COMMENT_SUFFIXES = frozenset({".conf", ".config", ".php", ".properties", ".py", ".rb"})
_HTML_COMMENT_SUFFIXES = frozenset({".html", ".jsp", ".vue", ".xml"})
_TRIPLE_QUOTE_SUFFIXES = frozenset({".py"})
_BACKTICK_STRING_SUFFIXES = frozenset({".go", ".js", ".jsx", ".ts", ".tsx", ".vue"})


def _code_view(lines: list[str], suffix: str) -> list[str]:
    """Return the file with comments removed, keeping line numbers aligned.

    Every rule runs against this view instead of the raw line so that
    commented-out code, block comments, and multi-line docstrings are never
    reported as live findings. String *contents* are preserved because rules
    such as dynamic-SQL detection need the literal text; only multi-line
    string bodies (Python docstrings) are dropped, since a rule cannot tell
    prose from code inside them.
    """
    line_tokens: tuple[str, ...] = ()
    if suffix in _SLASH_COMMENT_SUFFIXES:
        line_tokens += ("//",)
    if suffix in _HASH_COMMENT_SUFFIXES:
        line_tokens += ("#",)
    block_open, block_close = ("/*", "*/") if suffix in _SLASH_COMMENT_SUFFIXES else ("", "")
    html_comments = suffix in _HTML_COMMENT_SUFFIXES
    triples = ('"""', "'''") if suffix in _TRIPLE_QUOTE_SUFFIXES else ()
    quotes = {'"', "'"} | ({"`"} if suffix in _BACKTICK_STRING_SUFFIXES else set())

    if not line_tokens and not block_open and not html_comments:
        return lines

    stripped: list[str] = []
    open_block: str | None = None
    open_triple: str | None = None

    for raw_line in lines:
        output: list[str] = []
        # Single-quote strings never span lines in these languages, so quote
        # state must reset per line or one stray apostrophe blinds the rest.
        quote: str | None = None
        escaped = False
        index = 0
        # Indexed scanning, never slicing: a minified line is a single very long
        # line, and `raw_line[index:]` per character makes that quadratic.
        while index < len(raw_line):
            if open_triple is not None:
                end = raw_line.find(open_triple, index)
                if end < 0:
                    break
                index = end + len(open_triple)
                open_triple = None
                continue
            if open_block is not None:
                end = raw_line.find(open_block, index)
                if end < 0:
                    break
                index = end + len(open_block)
                open_block = None
                continue
            current = raw_line[index]
            if quote:
                output.append(current)
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    quote = None
                index += 1
                continue
            triple = next(
                (token for token in triples if raw_line.startswith(token, index)),
                None,
            ) if triples and current in {'"', "'"} else None
            if triple is not None:
                end = raw_line.find(triple, index + len(triple))
                if end < 0:
                    open_triple = triple
                    break
                # Opened and closed on one line: a normal string literal.
                output.append(raw_line[index : end + len(triple)])
                index = end + len(triple)
                continue
            if line_tokens and raw_line.startswith(line_tokens, index):
                break
            if block_open and current == block_open[0] and raw_line.startswith(block_open, index):
                end = raw_line.find(block_close, index + len(block_open))
                if end < 0:
                    open_block = block_close
                    break
                index = end + len(block_close)
                continue
            if html_comments and current == "<" and raw_line.startswith("<!--", index):
                end = raw_line.find("-->", index + 4)
                if end < 0:
                    open_block = "-->"
                    break
                index = end + 3
                continue
            if current in quotes:
                quote = current
                output.append(current)
                index += 1
                continue
            output.append(current)
            index += 1
        stripped.append("".join(output))
    return stripped


def _last_java_boolean_call(factory_ref: str, method: str, configuration: str) -> bool | None:
    matches = list(
        re.finditer(
            rf"\b{factory_ref}\s*\.\s*{method}\s*\(\s*(true|false)\s*\)",
            configuration,
            re.IGNORECASE,
        )
    )
    return matches[-1].group(1).lower() == "true" if matches else None


def _java_xml_factory_is_hardened(factory: str, configuration_lines: list[str]) -> bool:
    configuration = "\n".join(configuration_lines)
    factory_ref = re.escape(factory)

    # A swallowed parser-configuration failure makes the control fail open.
    for catch in re.finditer(
        r"catch\s*\([^)]*(?:ParserConfigurationException|SAXNotRecognizedException|SAXNotSupportedException)[^)]*\)\s*\{([^}]*)\}",
        configuration,
        re.IGNORECASE | re.DOTALL,
    ):
        if not re.search(r"\b(throw|return)\b", catch.group(1)):
            return False

    feature_states: dict[str, bool] = {}
    feature_pattern = re.compile(
        rf"\b{factory_ref}\s*\.\s*setFeature\s*\(\s*[\"']([^\"']+)[\"']\s*,\s*(true|false)\s*\)",
        re.IGNORECASE,
    )
    for feature in feature_pattern.finditer(configuration):
        feature_states[feature.group(1).lower()] = feature.group(2).lower() == "true"

    if feature_states.get("http://apache.org/xml/features/disallow-doctype-decl") is True:
        return True

    external_entities_disabled = all(
        feature_states.get(feature) is False
        for feature in (
            "http://xml.org/sax/features/external-general-entities",
            "http://xml.org/sax/features/external-parameter-entities",
            "http://apache.org/xml/features/nonvalidating/load-external-dtd",
        )
    )
    xinclude_disabled = _last_java_boolean_call(factory_ref, "setXIncludeAware", configuration) is False
    entity_expansion_disabled = (
        _last_java_boolean_call(factory_ref, "setExpandEntityReferences", configuration) is False
    )
    if external_entities_disabled and xinclude_disabled and entity_expansion_disabled:
        return True

    return False


_RULE_BY_ID = {rule.rule_id: rule for rule in CODE_PATTERN_RULES}
_LINE_RULES = {
    extension: tuple(
        rule
        for rule in CODE_PATTERN_RULES
        if extension in rule.extensions and rule.pattern.pattern != r"(?!)"
    )
    for extension in CODE_EXTENSIONS | CODE_FILENAMES
}
_COOKIE_MARKER = re.compile(r"cookie", re.IGNORECASE)
_ASSIGNMENT = re.compile(
    r"^\s*(?:(?:const|let|var|final)\s+)?"
    r"(?:(?:[A-Za-z_$][\w$<>\[\].,?]*\s+))?"
    r"([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(.+)$"
)
# The confirming dataflow pass only follows remote input; a local CLI argument
# is not enough evidence to call a flow proven.
_UNTRUSTED = re.compile(rf"(?:{REMOTE_SOURCE})", re.IGNORECASE)
# Mass assignment is about binding a whole request body onto a model, not about
# any call that happens to mention the request.
_REQUEST_BODY = re.compile(
    r"\b(?:req|request)\s*\.\s*(?:body|data|json|POST|form|params|query|values)\b",
    re.IGNORECASE,
)
_SANITIZERS = re.compile(
    r"\b(DOMPurify\.sanitize|sanitizeHtml|escapeHtml|html\.escape|encodeForHTML|"
    r"secure_filename|Path\.GetFileName|basename|realpath|canonicalPath|"
    r"allowlist|allowed_hosts?|validate(?:Url|Path|Host|Redirect|Input)|"
    r"escapeLdap|encodeForLDAP|stripCrLf|sanitizeHeader)\b",
    re.IGNORECASE,
)

_CONTEXT_SINKS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("code.sql-dynamic-query", _SQL_CONTEXT_SINK),
    ("code.xss-dom-sink", re.compile(r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML)\b", re.IGNORECASE)),
    ("code.command-injection", re.compile(r"\b(os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output)|child_process\.(?:exec|execSync)|shell_exec|passthru|Runtime\.getRuntime\(\)\.exec)\s*\(", re.IGNORECASE)),
    # Bare `open(` or an explicit filesystem module only: `self.parent.open()`
    # in a URL opener is not a file API.
    ("code.path-traversal", re.compile(r"(?<![.\w])open\s*\(|\b(?:os|io|codecs|shutil|aiofiles)\.open\s*\(|\b(send_file|FileResponse|readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\(", re.IGNORECASE)),
    ("code.eval-user-input", re.compile(r"\b(eval|exec|(?-i:Function)|instance_eval|class_eval)\s*\(", re.IGNORECASE)),
    ("code.eval-user-input", re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*[\"'`]", re.IGNORECASE)),
    ("code.ssrf-user-url", re.compile(r"\b(requests\.(?:get|post|put|patch|delete|request)|httpx\.(?:get|post|put|patch|delete|request)|urllib\.request\.urlopen|axios\.(?:get|post|put|patch|delete)|fetch|http\.get|https\.get|RestTemplate|WebClient)\b", re.IGNORECASE)),
    ("code.open-redirect-user-input", re.compile(r"\b(sendRedirect|redirect|(?:res|response|ctx)\.redirect)\s*\(", re.IGNORECASE)),
    (
        "code.ldap-injection",
        re.compile(
            r"\b(?:ldap(?:[_-]?(?:client|connection|template))?|dirContext)\s*\.\s*(?:search|search_s|search_ext)\s*\(",
            re.IGNORECASE,
        ),
    ),
    ("code.http-response-splitting", re.compile(r"\b(setHeader|addHeader|set_header|writeHead)\s*\(", re.IGNORECASE)),
    ("code.unsafe-deserialization", re.compile(r"\b(pickle\.loads?|yaml\.load|ObjectInputStream|BinaryFormatter|unserialize|Marshal\.load|readObject)\b", re.IGNORECASE)),
    ("code.unrestricted-file-upload", re.compile(r"\b(move_uploaded_file|save|writeFile|writeFileSync)\s*\(", re.IGNORECASE)),
    ("code.api-mass-assignment", re.compile(r"\b(create|update|assign|save|insert|merge)\s*\(", re.IGNORECASE)),
    ("code.format-string-user-input", re.compile(r"\b(printf|vprintf|syslog|fprintf|String\.format)\s*\(", re.IGNORECASE)),
    ("code.xml-injection", re.compile(r"(?:<[A-Za-z][\w:-]*>|XML|Document)\b.*(?:\+|%|\.format\(|\$\{)", re.IGNORECASE)),
    ("code.llm-prompt-user-concat", re.compile(r"\b(system|developer|prompt|messages?)\b.*(?:\+|f[\"']|`\$\{)", re.IGNORECASE)),
)


# Rules that match a sensitive *word*. Plain English inside a string literal
# ("session established") is prose, not data being logged, so these rules are
# re-checked against the line with literal prose removed.
_PROSE_SENSITIVE_RULES = frozenset(
    {"code.logging-sensitive-data", "code.pii-logging", "code.llm-sensitive-data-in-prompt"}
)
_STRING_LITERAL = re.compile(r"(['\"`])(?:\\.|(?!\1).)*?\1")
# Only interpolated expressions stay. A bare label inside a literal is prose:
# `"shlex: token="` is a debug caption, not a credential reaching the log.
_LITERAL_KEEP = re.compile(r"\$\{[^}]*\}|\{[^{}]*\}")
_PHP_LITERAL_VARIABLE = re.compile(r"(?<!\\)\$[A-Za-z_]\w*")


def _mask_literal_prose(line: str, *, keep_php_variables: bool = False) -> str:
    def replace(match: re.Match[str]) -> str:
        literal = match.group(0)
        kept_items = [item.group(0) for item in _LITERAL_KEEP.finditer(literal)]
        if keep_php_variables and match.group(1) != "'":
            kept_items.extend(item.group(0) for item in _PHP_LITERAL_VARIABLE.finditer(literal))
        kept = " ".join(kept_items)
        return f'"{kept}"'

    return _STRING_LITERAL.sub(replace, line)


def _contains_name(expression: str, names: set[str]) -> bool:
    return any(
        re.search(
            rf"(?<![\w$]){re.escape(name)}(?![\w$])" if name.startswith("$") else rf"\b{re.escape(name)}\b",
            expression,
        )
        for name in names
    )


def _without_sanitizer_calls(expression: str) -> str:
    """Remove balanced sanitizer-call expressions before checking remaining taint.

    This keeps `sanitize(trusted) + tainted` unsafe while treating
    `sanitize(tainted)` as a guarded value. It is deliberately parser-light and
    falls back to the original text when a call is incomplete.
    """
    output = expression
    offset = 0
    for match in list(_SANITIZERS.finditer(expression)):
        start = match.start() + offset
        cursor = match.end() + offset
        while cursor < len(output) and output[cursor].isspace():
            cursor += 1
        if cursor >= len(output) or output[cursor] != "(":
            continue
        depth = 0
        quote: str | None = None
        escaped = False
        end = cursor
        while end < len(output):
            char = output[end]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in {'"', "'"}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    end += 1
                    break
            end += 1
        if depth != 0:
            continue
        output = output[:start] + (" " * (end - start)) + output[end:]
        offset = len(output) - len(expression)
    return output


def _has_unsanitized_taint(
    expression: str,
    tainted: set[str],
    *,
    keep_php_variables: bool = False,
) -> bool:
    remaining = _without_sanitizer_calls(expression)
    untrusted = _UNTRUSTED.search(remaining)
    if not (untrusted or _contains_name(remaining, tainted)):
        return False
    literal_starts = [index for quote in ('"', "'", "`") if (index := remaining.find(quote)) >= 0]
    first_literal = min(literal_starts, default=-1)
    if first_literal < 0 or (untrusted and untrusted.start() < first_literal):
        return True
    masked = _mask_literal_prose(remaining, keep_php_variables=keep_php_variables)
    return bool(_UNTRUSTED.search(masked) or _contains_name(masked, tainted))


def _safe_command_arguments(line: str) -> bool:
    return bool(
        re.search(r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\(\s*\[", line, re.IGNORECASE)
        and not re.search(r"shell\s*=\s*True", line, re.IGNORECASE)
    )


def _safe_sql_binding(line: str) -> bool:
    return bool(
        re.search(
            rf"{_SQL_CALL_SINK}\s*\(\s*[furb]*[\"'][^\"']*(?:\?|%s|:\w+|@\w+|\$\d+)[^\"']*[\"']\s*,",
            line,
            re.IGNORECASE,
        )
        or re.search(
            r"\bmysqli_execute_query\s*\(\s*[^,]+,\s*[\"'][^\"']*\?[^\"']*[\"']\s*,",
            line,
            re.IGNORECASE,
        )
        or re.search(
            r"\bpg_query_params\s*\(\s*[^,]+,\s*[\"'][^\"']*\$\d+[^\"']*[\"']\s*,",
            line,
            re.IGNORECASE,
        )
    )


def _safe_prepared_assignment(expression: str, tainted: set[str]) -> bool:
    prepare = re.search(
        r"(?:\b(?:prepareStatement|mysqli_prepare)\b|(?:->|::)\s*prepare\b)\s*\(",
        expression,
        re.IGNORECASE,
    )
    if not prepare:
        return False
    arguments = _call_arguments(expression, prepare.end() - 1)
    if arguments is None or _has_unsanitized_taint(arguments, tainted, keep_php_variables=True):
        return False
    return bool(re.search(r"[\"'][^\"']*(?:\?|%s|:\w+|@\w+|\$\d+)[^\"']*[\"']", arguments))


def _executes_safe_prepared_statement(line: str, safe_statements: set[str]) -> bool:
    receiver = re.search(
        r"(?P<name>\$?[A-Za-z_][\w$]*)\s*(?:->|\.)\s*"
        r"(?:execute|executeQuery|executeUpdate|executeLargeUpdate|executeBatch|"
        r"ExecuteReader|ExecuteScalar|ExecuteNonQuery|ExecuteReaderAsync|ExecuteScalarAsync|ExecuteNonQueryAsync)\s*\(",
        line,
        re.IGNORECASE,
    )
    if receiver and receiver.group("name") in safe_statements:
        return True
    function_receiver = re.search(
        r"\bmysqli_stmt_execute\s*\(\s*(?P<name>\$?[A-Za-z_][\w$]*)",
        line,
        re.IGNORECASE,
    )
    return bool(function_receiver and function_receiver.group("name") in safe_statements)


def _dateutil_format_variable_is_safe(
    name: str,
    document: str,
    lines: list[str] | None,
    line_number: int | None,
) -> bool:
    if (
        lines is None
        or line_number is None
        or not re.search(r"\bimport\s+devonframe\.util\.DateUtil\s*;?", document)
    ):
        return False

    safe: set[str] = set()
    assignment = re.compile(
        r"^\s*(?:final\s+)?(?:String\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*$"
    )
    write = re.compile(
        r"(?<![\w$])([A-Za-z_$][\w$]*)\s*(?:(?:<<|>>|[+\-*/%&|^])?=(?!=))"
    )
    for source_line in lines[: max(0, line_number - 1)]:
        if _starts_function_scope(source_line, ".java"):
            safe.clear()
        for statement in source_line.split(";"):
            statement = statement.strip()
            if not statement:
                continue
            written = write.search(statement)
            if written:
                safe.discard(written.group(1))

            match = assignment.match(statement)
            if not match:
                continue
            variable, expression = match.groups()
            direct = re.fullmatch(r"DateUtil\.getDate\(\s*[\"']([^\"']*)[\"']\s*\)", expression)
            if direct and "%" not in direct.group(1):
                safe.add(variable)
                continue

            derived = re.match(
                r"DateUtil\.(?:getNextMonthDate|getPrevDate)\(\s*([A-Za-z_$][\w$]*)\s*,",
                expression,
            )
            if derived:
                safe.add(variable)

    return name in safe


def _candidate_is_suppressed(
    rule_id: str,
    line: str,
    document: str,
    lines: list[str] | None = None,
    line_number: int | None = None,
) -> bool:
    if lines is not None and line_number is not None:
        start = max(0, line_number - 6)
        end = min(len(lines), line_number + 5)
        nearby = "\n".join(lines[start:end])
    else:
        nearby = line
    if rule_id == "code.api-missing-rate-limit" and re.search(
        r"\b(express-rate-limit|rateLimit\s*\(|RateLimiter|SlowAPIMiddleware|@\w*limiter\.limit|Bucket4j|resilience4j[^\n]*ratelimit)",
        document,
        re.IGNORECASE,
    ):
        return True
    if rule_id == "code.api-route-missing-auth" and re.search(
        r"\b(app|router|server)\.use\s*\([^\n]*(?:authenticate|authorize|requireAuth|requireAdmin)|"
        r"\b(?:SecurityFilterChain|OncePerRequestFilter|AuthMiddleware|AuthorizationMiddleware)\b",
        document,
        re.IGNORECASE,
    ):
        return True
    if rule_id == "code.unsafe-deserialization" and re.search(
        r"yaml\.load\s*\([^\n]*(?:Loader\s*=\s*yaml\.SafeLoader|SafeLoader)", line, re.IGNORECASE
    ):
        return True
    if rule_id == "code.command-injection" and _safe_command_arguments(line):
        return True
    if rule_id == "code.sql-dynamic-query" and _safe_sql_binding(line):
        return True
    if rule_id == "code.broad-exception-handler" and re.search(
        r"\b(?:throw|raise)\b",
        nearby,
        re.IGNORECASE,
    ):
        return True
    if rule_id == "code.eval-user-input" and re.search(r"\.\s*exec\s*\(", line, re.IGNORECASE) and not re.search(
        r"(?<![.\w])(?:eval|exec|(?-i:Function)|instance_eval|class_eval)\s*\(",
        line,
        re.IGNORECASE,
    ):
        return True
    if rule_id == "code.format-string-user-input":
        format_variable = re.search(r"\bString\.format\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]", line)
        if format_variable:
            name = format_variable.group(1)
            if re.search(
                rf"\b(?:static\s+)?final\s+String\s+{re.escape(name)}\s*=\s*[\"']",
                document,
            ) or _dateutil_format_variable_is_safe(name, document, lines, line_number):
                return True
    if rule_id in {
        "code.xss-dom-sink",
        "code.path-traversal",
        "code.ssrf-user-url",
        "code.open-redirect-user-input",
        "code.ldap-injection",
        "code.http-response-splitting",
    } and _SANITIZERS.search(line):
        return True
    if rule_id == "code.api-route-missing-auth" and re.search(
        r"\b(requireAuth|requireAdmin|authenticate|authorize|isAuthenticated|checkPermission)\b", line, re.IGNORECASE
    ):
        return True
    # `usedforsecurity=False` is the caller declaring this hash is not a
    # security control; `\b` would miss `file_checksum`, because `_` is itself
    # a word character.
    if rule_id == "code.weak-hash" and (
        re.search(r"usedforsecurity\s*=\s*False", line, re.IGNORECASE)
        or re.search(
            r"\w*(?:checksum|etag|cache[_-]?key|content[_-]?hash|file[_-]?hash)\w*", nearby, re.IGNORECASE
        )
    ):
        return True
    if rule_id in _PROSE_SENSITIVE_RULES and not _RULE_BY_ID[rule_id].pattern.search(_mask_literal_prose(line)):
        return True
    if rule_id == "code.external-api-no-timeout" and re.search(
        r"\b(timeout|signal|AbortController)\s*[:=]", nearby, re.IGNORECASE
    ):
        return True
    if rule_id == "code.stack-trace-exposure" and re.search(
        r"\b(?:if|guard)\b[^\n]*(?:DEBUG|development|isDev|devMode)", nearby, re.IGNORECASE
    ):
        return True
    return False


_MAX_CONTINUATION_LINES = 4


def _open_depth(text: str) -> int:
    depth = 0
    quote: str | None = None
    escaped = False
    for char in text:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'", "`"}:
            quote = char
        elif char in {"(", "["}:
            depth += 1
        elif char in {")", "]"}:
            depth -= 1
    return depth


def _logical_lines(code_lines: list[str]) -> list[str]:
    """Join argument lists that continue onto following lines.

    A statement split over several lines is still one statement, and matching
    each fragment alone is exactly the single-line reading this scanner avoids.
    A line ending in ``{`` opens a block rather than an argument list, so a
    route handler is never merged into its own declaration.
    """
    joined: list[str] = []
    for index, line in enumerate(code_lines):
        text = line
        if not line.rstrip().endswith("{"):
            cursor = index
            while (
                _open_depth(text) > 0
                and cursor + 1 < len(code_lines)
                and cursor - index < _MAX_CONTINUATION_LINES
            ):
                cursor += 1
                text = f"{text} {code_lines[cursor].strip()}"
        joined.append(text)
    return joined


def _starts_function_scope(line: str, suffix: str) -> bool:
    """Return whether a source line starts a new callable body.

    The SW49 stateful checks are intentionally intraprocedural. A lightweight
    boundary is enough to prevent a variable named in one function from
    affecting a different function without pretending to build a full parser.
    """
    stripped = line.strip()
    if not stripped:
        return False
    if suffix == ".py":
        return bool(re.match(r"(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(", stripped))
    if suffix == ".rb":
        return bool(re.match(r"def\s+(?:self\.)?[A-Za-z_]\w*[!?=]?", stripped))
    if suffix == ".go":
        return bool(re.match(r"func\s+(?:\([^)]*\)\s*)?[A-Za-z_]\w*\s*\(", stripped))
    if suffix == ".swift":
        return bool(re.match(r"(?:[\w@]+\s+)*func\s+[A-Za-z_]\w*\s*\(", stripped))
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return bool(
            re.match(r"(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(", stripped)
            or re.match(r"(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=.*=>\s*\{", stripped)
            or re.match(r"(?:async\s+)?[A-Za-z_$][\w$]*\s*\([^;{}]*\)\s*\{", stripped)
        )
    if suffix == ".php":
        return bool(re.match(r"(?:public\s+|protected\s+|private\s+|static\s+)*function\s+\w+\s*\(", stripped, re.I))
    if suffix in {".java", ".kt", ".cs", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
        match = re.match(
            r"(?:(?:public|private|protected|internal|static|final|abstract|synchronized|native|default|open|override|virtual|inline|constexpr|extern|friend)\s+)*"
            r"(?:<[^>]+>\s+)?(?:[\w$:.<>,?\[\]*&]+\s+)?([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[^\{]+)?\{",
            stripped,
        )
        return bool(match and match.group(1) not in {"if", "for", "while", "switch", "catch", "try", "synchronized"})
    return False


def _call_arguments(line: str, call_end: int) -> str | None:
    """Return the argument text of a call whose name ends at ``call_end``.

    Returns ``None`` when the sink is not a call (for example an ``innerHTML``
    assignment) so the caller can fall back to line scope.
    """
    cursor = call_end
    while cursor < len(line) and line[cursor].isspace():
        cursor += 1
    if cursor >= len(line) or line[cursor] != "(":
        return None
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(cursor, len(line)):
        char = line[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'", "`"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return line[cursor + 1 : index]
    # Unbalanced (call continues on the next line): treat the remainder as args.
    return line[cursor + 1 :]


def _contextual_dataflow_findings(path: Path, lines: list[str], code_lines: list[str]) -> list[Finding]:
    """Confirm simple intra-file source-to-sink flows and sanitizer boundaries.

    This intentionally stays conservative: aliases and direct assignments are
    followed, while unresolved inter-procedural or project-wide context remains
    a review candidate instead of being promoted to a violation.
    """
    findings: list[Finding] = []
    suffix = path.suffix.lower()
    tainted: set[str] = set()
    sanitized: set[str] = set()
    safe_prepared_statements: set[str] = set()

    for line_number, code_line in enumerate(code_lines, start=1):
        line = code_line.strip()
        if not line or _is_comment(line):
            continue
        assignment = _ASSIGNMENT.match(line)
        if assignment:
            name, expression = assignment.groups()
            if suffix == ".php":
                if "prepare" in expression.lower() and _safe_prepared_assignment(expression, tainted):
                    safe_prepared_statements.add(name)
                else:
                    safe_prepared_statements.discard(name)
            if _has_unsanitized_taint(expression, tainted, keep_php_variables=suffix == ".php"):
                tainted.add(name)
                sanitized.discard(name)
            elif _SANITIZERS.search(expression):
                tainted.discard(name)
                sanitized.add(name)
            else:
                tainted.discard(name)
                sanitized.discard(name)

        reaches_sink = _has_unsanitized_taint(line, tainted, keep_php_variables=suffix == ".php")
        if not reaches_sink:
            continue

        lowered_line = line.lower()
        for rule_id, sink in _CONTEXT_SINKS:
            if rule_id == "code.sql-dynamic-query" and not any(
                token in lowered_line for token in _SQL_SINK_TOKENS
            ):
                continue
            match = sink.search(line)
            if not match:
                continue
            if (
                rule_id == "code.eval-user-input"
                and match.lastindex
                and match.group(1).lower() == "exec"
                and line[: match.start(1)].rstrip().endswith(".")
            ):
                continue
            # Taint anywhere on the line is not enough for a call sink: the
            # untrusted value has to be an argument of that call, otherwise
            # `ctx.save()` next to unrelated request handling reads as a flow.
            arguments = _call_arguments(line, match.end())
            if arguments is not None and not _has_unsanitized_taint(
                arguments,
                tainted,
                keep_php_variables=suffix == ".php",
            ):
                continue
            if rule_id == "code.command-injection" and _safe_command_arguments(line):
                continue
            if rule_id == "code.sql-dynamic-query":
                if _safe_sql_binding(line) or _executes_safe_prepared_statement(line, safe_prepared_statements):
                    continue
            if rule_id == "code.api-mass-assignment" and not _REQUEST_BODY.search(arguments or line):
                continue
            rule = _RULE_BY_ID[rule_id]
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category="code",
                    severity=rule.severity,
                    title=rule.title,
                    path=path,
                    line=line_number,
                    evidence=_trim_evidence(lines[line_number - 1].strip()),
                    description=rule.description,
                    recommendation=rule.recommendation,
                    verification_status="confirmed",
                    verification_note="동일 파일에서 외부 입력이 방어 처리 없이 위험 동작까지 전달되는 흐름을 확인했습니다.",
                )
            )
            break
        if len(findings) >= 45:
            break
    return findings


def _mybatis_sql_findings(path: Path, lines: list[str], code_lines: list[str]) -> list[Finding]:
    """Find raw MyBatis substitutions only inside executable mapper SQL."""
    if path.suffix.lower() != ".xml" or not re.search(r"<\s*mapper\b", "\n".join(code_lines), re.IGNORECASE):
        return []

    rule = _RULE_BY_ID["code.sql-dynamic-query"]
    findings: list[Finding] = []
    in_statement = False
    for index, line in enumerate(code_lines):
        if re.search(r"<\s*(?:select|insert|update|delete)\b", line, re.IGNORECASE):
            in_statement = True
        if in_statement and re.search(r"\$\{\s*[A-Za-z_$][\w$.-]*\s*\}", line):
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category="code",
                    severity=rule.severity,
                    title=rule.title,
                    path=path,
                    line=index + 1,
                    evidence=_trim_evidence(lines[index].strip()),
                    description=rule.description,
                    recommendation=rule.recommendation,
                    verification_status="needs_review",
                    verification_note=(
                        "MyBatis ${...} 치환이 SQL 원문에 삽입됩니다. 값의 서버측 고정 allowlist 여부를 확인해야 합니다."
                    ),
                )
            )
            if len(findings) >= 5:
                break
        if re.search(r"<\s*/\s*(?:select|insert|update|delete)\s*>", line, re.IGNORECASE):
            in_statement = False
    return findings


_JSP_CONTEXT_ENCODER = re.compile(
    r"(?:Encode\.(?:forHtml|forHtmlAttribute|forJavaScript)|ESAPI\.encoder\(\)\.encodeFor|"
    r"fn:escapeXml|escapeXml|StringEscapeUtils\.escape)",
    re.IGNORECASE,
)


def _jsp_xss_findings(path: Path, lines: list[str], code_lines: list[str]) -> list[Finding]:
    """Find JSP output only when the source or a dangerous browser sink is visible."""
    if path.suffix.lower() != ".jsp":
        return []

    rule = _RULE_BY_ID["code.xss-dom-sink"]
    findings: list[Finding] = []
    seen: set[int] = set()

    def add(index: int, status: str, note: str) -> None:
        if index in seen or len(findings) >= 5:
            return
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                category="code",
                severity=rule.severity,
                title=rule.title,
                path=path,
                line=index + 1,
                evidence=_trim_evidence(lines[index].strip()),
                description=rule.description,
                recommendation=rule.recommendation,
                verification_status=status,
                verification_note=note,
            )
        )
        seen.add(index)

    for index, line in enumerate(code_lines):
        if _JSP_CONTEXT_ENCODER.search(line):
            continue
        if re.search(r"<%=\s*(?:request\s*\.\s*getParameter|param\b)", line, re.IGNORECASE):
            add(index, "confirmed", "요청값이 JSP 출력식에서 문맥 인코딩 없이 응답에 기록됩니다.")
            continue
        if "<c:out" not in line and re.search(r"\$\{\s*param(?:Values)?\.", line, re.IGNORECASE):
            add(index, "confirmed", "JSP EL 요청값이 출력 인코딩 없이 HTML 응답에 기록됩니다.")
            continue

        assignment = re.search(
            r"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=.*<%=\s*([^%]+?)\s*%>",
            line,
            re.IGNORECASE,
        )
        if not assignment:
            continue
        variable = assignment.group(1)
        following = "\n".join(code_lines[index + 1 : index + 13])
        if re.search(rf"\bdocument\s*\.\s*write(?:ln)?\s*\(\s*{re.escape(variable)}\b", following, re.IGNORECASE):
            add(
                index,
                "needs_review",
                "JSP 출력식이 JavaScript 문자열을 거쳐 document.write에 전달됩니다. 서버 변수의 입력 출처를 확인해야 합니다.",
            )
    return findings


def _sw49_semantic_findings(path: Path, lines: list[str], statements: list[str]) -> list[Finding]:
    suffix = path.suffix.lower()
    out: list[Finding] = []
    def add(rule_id: str, i: int, note: str) -> None:
        rule = _RULE_BY_ID[rule_id]
        out.append(Finding(rule_id=rule_id, category="code", severity=rule.severity, title=rule.title,
            path=path, line=i + 1, evidence=_trim_evidence(lines[i].strip()), description=rule.description,
            recommendation=rule.recommendation, verification_status="needs_review", verification_note=note))
    if suffix in {".java", ".kt"}:
        acquired: dict[str, int] = {}
        released: dict[str, int] = {}
        delegated: dict[str, str] = {}
        scope_start = 0

        def report_unreleased(scope_end: int) -> None:
            for name, acquired_at in acquired.items():
                if name in delegated:
                    continue
                try_with_resources = any(
                    "try (" in candidate and re.search(rf"\b{name}\b", candidate)
                    for candidate in statements[max(scope_start, acquired_at - 1):acquired_at + 2]
                )
                if try_with_resources:
                    continue
                release_at = released.get(name)
                if release_at is None:
                    add("code.improper-resource-release", acquired_at, "자원 취득 후 모든 경로의 close/release/disconnect를 확인하지 못했습니다.")
                    continue
                catch_after_release = any(
                    re.search(r"\bcatch\s*\(", candidate)
                    for candidate in statements[release_at + 1:scope_end]
                )
                release_in_finally = any(
                    re.search(r"\bfinally\b", candidate)
                    for candidate in statements[acquired_at:release_at + 1]
                )
                if catch_after_release and not release_in_finally:
                    add("code.improper-resource-release", acquired_at, "예외 발생 시 close/release 전에 catch로 이동할 수 있어 자원 해제가 보장되지 않습니다.")

        acquisition = re.compile(
            r"\b([A-Za-z_$][\w$]*)\s*=\s*[^;]*(?:getConnection|prepareStatement|createStatement|"
            r"new\s+(?:FileInputStream|FileOutputStream|FileReader|FileWriter|BufferedReader|BufferedWriter|"
            r"Scanner|PrintWriter|ZipFile|JarFile)|Files\.newInputStream|Files\.newOutputStream)",
            re.IGNORECASE,
        )
        http_connection = re.compile(
            r"\b(?:HttpURLConnection\s+)?([A-Za-z_$][\w$]*)\s*=\s*[^;]*\bHttpURLConnection\b[^;]*\.openConnection\s*\(",
            re.IGNORECASE,
        )
        for i, line in enumerate(statements):
            if _starts_function_scope(line, suffix):
                report_unreleased(i)
                acquired.clear(); released.clear(); delegated.clear()
                scope_start = i
            m = acquisition.search(line) or http_connection.search(line)
            if m:
                name = m.group(1)
                if not (re.search(r"\bnew\s+Scanner\s*\(\s*System\.in\b", line) and name):
                    acquired[name] = i
                    released.pop(name, None)
                wrapper = re.search(
                    rf"\b{name}\s*=\s*new\s+(?:PrintWriter|BufferedReader|BufferedWriter)\s*\(\s*([A-Za-z_$][\w$]*)",
                    line,
                    re.IGNORECASE,
                )
                if wrapper and wrapper.group(1) in acquired:
                    delegated[wrapper.group(1)] = name
            for name in acquired:
                if re.search(rf"\b{name}\s*\.\s*(?:close|release|disconnect)\s*\(", line):
                    released[name] = i
        report_unreleased(len(statements))
    if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
        freed: dict[str, int] = {}
        uninit: set[str] = set()
        for i, line in enumerate(statements):
            if _starts_function_scope(line, suffix):
                freed.clear(); uninit.clear()
            dm = re.search(r"\b(?:int|char|float|double|long|short|size_t)\s+([A-Za-z_]\w*)\s*;", line)
            if dm: uninit.add(dm.group(1)); continue
            fm = re.search(r"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)\s*;", line)
            if fm: freed[fm.group(1)] = i; continue
            for name in list(uninit):
                if re.search(rf"\b{name}\s*=", line): uninit.remove(name)
                elif re.search(rf"\b(?:return|printf|fprintf|assert)\b[^;]*\b{name}\b|\b{name}\b\s*[+\-*/;,)\]]", line):
                    add("code.uninitialized-variable", i, "명시적 초기화 없는 지역 변수가 읽히는 후보입니다."); uninit.remove(name)
            for name in list(freed):
                if re.search(rf"\b{name}\s*=", line): del freed[name]
                elif re.search(rf"\b{name}\b", line):
                    add("code.use-after-free", i, "free(var) 이후 재할당/초기화 없이 같은 변수를 사용했습니다."); del freed[name]
    dns_names: set[str] = set()
    for i, line in enumerate(statements):
        if _starts_function_scope(line, suffix):
            dns_names.clear()
        written = re.search(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*(?:(?:<<|>>|[+\-*/%&|^])?=(?!=))", line)
        m = re.search(r"\b([A-Za-z_]\w*)\s*=\s*[^;]*(?:gethostbyname|getaddrinfo|gethostbyaddr|getnameinfo|socket\.gethost|dns\.lookup|InetAddress\.getByName)", line, re.I)
        if written:
            dns_names.discard(written.group(1))
        if m:
            dns_names.add(m.group(1))
        if dns_names and re.search(r"\b(?:auth|authoriz|allow|permit|trust|trusted|is_internal|role|admin|principal)\w*\b", line, re.I) and re.search(r"(?:==|!=|\bin\b|\.equals\s*\(|\.contains\s*\()", line, re.I) and any(re.search(rf"\b{name}\b", line) for name in dns_names):
            add("code.dns-security-decision", i, "DNS 조회 결과가 인증/인가/신뢰 비교에 직접 사용됩니다.")

    document = "\n".join(statements)
    auth_entry = re.search(
        r"(?im)(?:@(?:\w+\.)?(?:post|route)\s*\([^\n]*(?:login|sign[_-]?in|authenticate|token)|"
        r"\b(?:app|router|server)\.(?:post|use)\s*\([^\n]*(?:login|sign[_-]?in|authenticate|token)|"
        r"\b(?:def|function|public|private|protected)\s+\w*(?:login|signin|authenticate|issueToken)\w*)",
        document,
    )
    auth_sink = re.search(
        r"(?i)\b(?:authenticate|verifyPassword|check_password|issueToken|create_access_token|"
        r"authenticationManager\.authenticate)\s*\(",
        document,
    )
    protection = re.search(
        r"(?i)\b(?:express-rate-limit|rateLimit|RateLimiter|SlowAPIMiddleware|limiter\.limit|"
        r"Bucket4j|failedAttempts?|loginAttempts?|lockAccount|lockedUntil|accountLocked|"
        r"captcha|mfa|2fa|otp|webauthn)\b",
        document,
    )
    if auth_entry and auth_sink and not protection:
        line_index = document[:auth_entry.start()].count("\n")
        add("code.auth-attempt-protection-missing", line_index, "인증 흐름에서 반복 시도 제한, 잠금 또는 추가 인증 통제를 확인하지 못했습니다.")

    integer_inputs: dict[str, int] = {}
    guarded_integers: set[str] = set()
    for i, line in enumerate(statements):
        if _starts_function_scope(line, suffix):
            integer_inputs.clear()
            guarded_integers.clear()
        assignment = re.search(r"\b([A-Za-z_$][\w$]*)\s*=\s*([^;]+)", line)
        if assignment and re.search(
            r"\b(?:atoi|atol|strtol|Integer\.parseInt|Long\.parseLong|Int32\.Parse|Convert\.ToInt32)\s*\("
            r"[^)]*(?:argv|args|request|params?|getParameter|query|input)",
            assignment.group(2),
            re.I,
        ):
            integer_inputs[assignment.group(1)] = i
        for name in tuple(integer_inputs):
            if re.search(rf"\b{name}\b\s*(?:<=|>=|<|>)|(?:<=|>=|<|>)\s*\b{name}\b", line):
                guarded_integers.add(name)
            if name not in guarded_integers and (
                re.search(rf"\[\s*{re.escape(name)}\s*\]", line)
                or re.search(rf"\b(?:malloc|calloc|realloc)\s*\([^;]*\b{re.escape(name)}\b", line)
                or re.search(rf"\bnew\s+[\w$.<>\[\]]+\s*\[\s*{re.escape(name)}\s*\]", line)
            ):
                add("code.integer-overflow-user-input", i, "외부 입력에서 파싱한 정수가 범위 확인 없이 인덱스 또는 할당 크기에 사용됩니다.")
                del integer_inputs[name]
                guarded_integers.discard(name)

    decision_inputs: set[str] = set()
    for i, line in enumerate(statements):
        if _starts_function_scope(line, suffix):
            decision_inputs.clear()
        assignment = re.search(r"\b([A-Za-z_$][\w$]*)\s*=\s*([^;]+)", line)
        if assignment:
            name, expression = assignment.groups()
            if (
                re.search(r"(?:request|req|params?|query|cookies?|headers?|getParameter|process\.env|os\.environ)", expression, re.I)
                and re.search(r"(?:role|admin|authoriz|permit|permission|price|amount|discount|limit|trusted|privilege)", name, re.I)
            ):
                decision_inputs.add(name)
        for name in tuple(decision_inputs):
            if re.search(rf"\b(?:validate|verify|allowlist|lookup|loadTrusted)\w*\s*\([^;]*\b{re.escape(name)}\b", line, re.I):
                decision_inputs.discard(name)
            elif re.search(rf"\b{re.escape(name)}\b", line) and (
                re.search(r"\b(?:if|return|authorize|permit|allow|total|price|amount|discount)\b", line, re.I)
                or re.search(r"[+\-*/]|==|!=", line)
            ) and not (assignment and assignment.group(1) == name):
                add("code.security-decision-user-input", i, "요청에서 받은 보안·업무 결정값이 서버측 기준 조회 없이 사용됩니다.")
                decision_inputs.discard(name)

    authorization_guard = re.compile(
        r"(?i)@PreAuthorize|@Secured|@RolesAllowed|hasRole|hasAuthority|checkPermission|"
        r"authorize|isOwner|isAdmin|requireRole|permissionService|SecurityContext|getPrincipal",
    )
    endpoint_annotation = re.compile(r"@(?:Delete|Put|Patch|Post|Request)Mapping\b", re.IGNORECASE)
    sensitive_action = re.compile(r"(?:delete|remove|update|approve|grant|revoke|export|reset)", re.IGNORECASE)
    sensitive_resource = re.compile(r"(?:admin|users?|accounts?|payments?|orders?|roles?|permissions?)", re.IGNORECASE)
    mutation_sink = re.compile(
        r"\b(?:[A-Za-z_$][\w$]*(?:Dao|Repository|Mapper|Service)|dao|repository|mapper|service)\s*\.\s*"
        r"(?:delete|remove|update|save|insert|merge|approve|grant|revoke)\w*\s*\(",
        re.IGNORECASE,
    )
    external_endpoint_input = re.compile(
        r"@RequestBody|@PathVariable|@RequestParam|HttpServletRequest|HttpSession|\b(?:request|params?)\b",
        re.IGNORECASE,
    )
    for annotation_index, annotation in enumerate(statements):
        if not endpoint_annotation.search(annotation):
            continue
        method_index = next(
            (
                index
                for index in range(annotation_index + 1, min(len(statements), annotation_index + 9))
                if _starts_function_scope(statements[index], suffix)
            ),
            None,
        )
        if method_index is None:
            continue
        signature = statements[method_index]
        method_name = re.search(r"\b([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[^{}]+)?\{", signature)
        if method_name is None:
            continue

        body_lines: list[str] = []
        depth = 0
        started = False
        for body_index in range(method_index, min(len(statements), method_index + 180)):
            body_line = statements[body_index]
            body_lines.append(body_line)
            if "{" in body_line:
                started = True
            depth += body_line.count("{") - body_line.count("}")
            if started and body_index > method_index and depth <= 0:
                break
        body = "\n".join(body_lines)
        descriptor = f"{annotation}\n{method_name.group(1)}"
        if not (sensitive_action.search(descriptor) or sensitive_resource.search(descriptor)):
            continue
        has_endpoint_input = bool(
            external_endpoint_input.search(f"{signature}\n{body}")
            or re.search(r"\(\s*[^)]", signature)
        )
        if not has_endpoint_input or not mutation_sink.search(body):
            continue
        guarded_scope = "\n".join(statements[max(0, annotation_index - 3):method_index] + body_lines)
        if authorization_guard.search(guarded_scope):
            continue
        add(
            "code.authorization-check-missing",
            method_index,
            "외부 입력을 받는 상태 변경 엔드포인트에서 민감 저장 동작 전 인가 검사를 확인하지 못했습니다. 전역 보안 설정은 추가 검토해야 합니다.",
        )

    for i, line in enumerate(statements):
        if re.search(
            r"(?i)\bos\.chmod\s*\([^,]+,\s*(?:0o?777|0o?666|0x1ff)\b|"
            r"\bchmod\s*\([^,]+,\s*0?777\b|"
            r"\.setWritable\s*\(\s*true\s*,\s*false\s*\)|"
            r"PosixFilePermissions\.fromString\s*\(\s*[\"']rwxrwxrwx[\"']\s*\)|"
            r"FileSystemRights\.FullControl[^\n]*(?:WorldSid|Everyone)",
            line,
        ):
            add("code.insecure-resource-permissions", i, "모든 사용자에게 쓰기 또는 전체 제어를 허용하는 권한 설정입니다.")

        password_length = re.search(
            r"(?i)(?:min(?:imum)?[_-]?password[_-]?length|password[_-]?min(?:imum)?[_-]?length)\s*[:=]\s*(\d+)",
            line,
        )
        annotation_length = re.search(r"(?i)@Size\s*\(\s*min\s*=\s*(\d+)", line)
        length = int((password_length or annotation_length).group(1)) if password_length or annotation_length else None
        if length is not None and length < 8 and (password_length or "password" in "\n".join(statements[max(0, i - 2):i + 3]).lower()):
            add("code.weak-password-policy", i, "명시된 비밀번호 최소 길이가 8자보다 짧습니다.")

    for i, line in enumerate(statements):
        if suffix == ".py" and re.match(r"^\s*while\s+(?:True|1)\s*:", line):
            indent = len(line) - len(line.lstrip())
            body: list[str] = []
            for following in statements[i + 1:i + 26]:
                if following.strip() and len(following) - len(following.lstrip()) <= indent:
                    break
                body.append(following)
            if not re.search(r"(?m)^\s*(?:break|return|raise)\b", "\n".join(body)):
                add("code.uncontrolled-loop", i, "상수 조건 반복문 본문에서 종료 경로를 확인하지 못했습니다.")
        elif suffix != ".py" and re.search(r"\bwhile\s*\(\s*(?:true|1)\s*\)|\bfor\s*\(\s*;\s*;\s*\)", line, re.I):
            nearby = "\n".join(statements[i:i + 25])
            if not re.search(r"\b(?:break|return|throw|goto)\b", nearby):
                add("code.uncontrolled-loop", i, "상수 조건 반복문 주변에서 종료 경로를 확인하지 못했습니다.")

    if suffix == ".py":
        for match in re.finditer(r"(?m)^(\s*)def\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*:", document):
            indent, name = len(match.group(1)), match.group(2)
            start = document[:match.start()].count("\n")
            body_lines: list[str] = []
            for following in statements[start + 1:]:
                if following.strip() and len(following) - len(following.lstrip()) <= indent:
                    break
                body_lines.append(following)
            body = "\n".join(body_lines)
            call = re.search(rf"(?<![.\w]){re.escape(name)}\s*\(", body)
            if call and not re.search(r"(?s)\bif\b.*?\b(?:return|raise)\b", body):
                add("code.uncontrolled-loop", start + 1 + body[:call.start()].count("\n"), "직접 재귀 호출 전에 종료 기저 조건을 확인하지 못했습니다.")

    if suffix == ".py":
        shared_names = {
            match.group(1)
            for match in re.finditer(
                r"(?m)^([A-Za-z_]\w*(?:user|session|account|profile|token)\w*)\s*=",
                document,
                re.I,
            )
        }
        global_shared_names = {
            name
            for name in shared_names
            if re.search(rf"\bglobal\s+{re.escape(name)}\b", document, re.I)
        }
        for i, line in enumerate(statements):
            for name in global_shared_names:
                if re.search(
                    rf"\b{re.escape(name)}\s*=\s*[^;]*(?:session|request)",
                    line,
                    re.I,
                ):
                    add("code.session-shared-state", i, "요청별 사용자 정보가 모듈 전역 상태에 저장됩니다.")
    elif suffix in {".java", ".kt", ".cs"} and re.search(
        r"(?i)extends\s+HttpServlet|HttpServletRequest|@WebServlet|@Controller|@RestController",
        document,
    ):
        fields = {
            match.group(1)
            for match in re.finditer(
                r"(?im)^\s*(?:private|protected|public)\s+(?:static\s+)?[\w$.<>\[\]?]+\s+"
                r"([A-Za-z_$][\w$]*(?:user|session|account|profile|token)\w*)\s*(?:[;=])",
                document,
            )
        }
        for i, line in enumerate(statements):
            for name in fields:
                if re.search(rf"\b(?:this\.)?{re.escape(name)}\s*=\s*[^;]*(?:request|session|getParameter|getAttribute)", line, re.I):
                    add("code.session-shared-state", i, "요청별 사용자 정보가 서블릿·컨트롤러의 공유 인스턴스 필드에 저장됩니다.")

    if suffix in {".java", ".kt", ".cs"}:
        private_arrays = {
            match.group(1)
            for match in re.finditer(
                r"(?im)^\s*private\s+(?:static\s+)?(?:[\w$.<>?]+\s*\[\]|"
                r"(?:List|Collection|ArrayList|IList|ICollection)<[^>]+>)\s+([A-Za-z_$][\w$]*)",
                document,
            )
        }
        for name in private_arrays:
            direct_return = re.search(
                rf"(?is)\bpublic\b[^;{{}}]*\([^;{{}}]*\)\s*\{{[^{{}}]*\breturn\s+(?:this\.)?{re.escape(name)}\s*;",
                document,
            )
            if direct_return:
                i = document[:direct_return.start()].count("\n")
                add("code.private-array-return", i, "public 메소드가 private 배열·컬렉션 참조를 복사 없이 반환합니다.")
            for method in re.finditer(r"(?is)\bpublic\b[^;{}]*\(([^)]*)\)\s*\{([^{}]*)\}", document):
                parameters, body = method.groups()
                for parameter in re.finditer(
                    r"(?:[\w$.<>?]+\s*\[\]|(?:List|Collection|ArrayList|IList|ICollection)<[^>]+>)\s+([A-Za-z_$][\w$]*)",
                    parameters,
                ):
                    value = parameter.group(1)
                    assignment = re.search(
                        rf"\b(?:this\.)?{re.escape(name)}\s*=\s*{re.escape(value)}\s*;",
                        body,
                    )
                    if assignment:
                        i = document[:method.start()].count("\n") + body[:assignment.start()].count("\n")
                        add("code.private-array-assignment", i, "public 메소드 인자의 배열·컬렉션 참조를 private 필드에 복사 없이 저장합니다.")

    if suffix in {".java", ".kt"} and re.search(
        r"(?i)extends\s+HttpServlet|HttpServletRequest|ServletException|@WebServlet",
        document,
    ):
        for i, line in enumerate(statements):
            if re.search(r"\bnew\s+(?:java\.net\.)?Socket\s*\(|\bSystem\.exit\s*\(", line):
                add("code.dangerous-managed-api", i, "J2EE 실행 문맥에서 직접 Socket 또는 System.exit API를 사용합니다.")
    elif suffix == ".cs":
        for i, line in enumerate(statements):
            if re.search(r"\bApplication\.Exit\s*\(", line):
                add("code.dangerous-managed-api", i, "Application.Exit은 일부 종료 이벤트 처리를 건너뛸 수 있습니다.")
    return out


def check_file(path: Path, target: TargetConfig) -> list[Finding]:
    if not is_text_candidate(path) or (path.suffix.lower() not in CODE_EXTENSIONS and path.name not in CODE_FILENAMES):
        return []

    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    # Recognized dependency sources are inventory input, not meaningful
    # application source for line-regex analysis. A banner alone is insufficient:
    # first-party bundles often include a library banner before application code.
    if path.suffix.lower() in {".js", ".mjs", ".cjs"}:
        parts = {part.lower().replace("-", "_") for part in path.parts}
        is_pdfjs_bundle = (
            any(part in {"pdfjs", "pdf.js"} or part.startswith("pdfjs_") for part in parts)
            and path.name.lower() in {
                "viewer.js", "viewer.mjs", "pdf.js", "pdf.min.js",
                "pdf.worker.js", "pdf.worker.min.js", "pdf.worker.mjs",
            }
        )
        if is_pdfjs_bundle:
            return []
        banner = "\n".join(lines[:5])[:2000]
        is_dependency_path = bool(parts.intersection({"node_modules", "vendor", "vendors", "thirdparty", "third_party"}))
        has_library_banner = bool(re.search(
            r"(?i)\b(jquery|jsrender|datepicker|lodash|bootstrap|angular|react|vue|moment)\b[^\n]{0,100}\bv?\d+(?:\.\d+)+",
            banner,
        ))
        versioned_library_file = re.match(
            r"(?i)^(jquery|jsrender|datepicker|lodash|bootstrap|angular|react(?:\.production)?|vue(?:\.runtime)?|moment)"
            r"[._-]?v?\d+(?:\.\d+)*(?:\.min)?\.(?:js|mjs|cjs)$",
            path.name,
        )
        named_library_file = re.match(
            r"(?i)^(jquery|jsrender|datepicker|lodash|bootstrap|angular|react(?:\.production)?|vue(?:\.runtime)?|moment)"
            r"(?:\.min)?\.(?:js|mjs|cjs)$",
            path.name,
        )
        if versioned_library_file or (named_library_file and (is_dependency_path or has_library_banner)):
            return []

    suffix = path.suffix.lower()
    # Every rule below reads the whole-file code view, not the raw line, so a
    # single line is never judged out of its file context.
    code_lines = _code_view(lines, suffix)
    statements = _logical_lines(code_lines)
    findings = _java_document_builder_xxe_findings(path, lines, code_lines) if suffix in {".java", ".kt"} else []
    findings.extend(_mybatis_sql_findings(path, lines, code_lines))
    findings.extend(_jsp_xss_findings(path, lines, code_lines))
    findings.extend(_sw49_semantic_findings(path, lines, statements))
    if suffix in {".java", ".kt"}:
        findings.extend(_java_null_pointer_findings(path, lines, code_lines))
    findings.extend(_contextual_dataflow_findings(path, lines, statements))
    per_rule_counts: dict[str, int] = {}
    seen_locations: set[tuple[str, int | None]] = set()
    for finding in findings:
        per_rule_counts[finding.rule_id] = per_rule_counts.get(finding.rule_id, 0) + 1
        seen_locations.add((finding.rule_id, finding.line))
    document = "\n".join(code_lines)
    filename = path.name
    line_rules = _LINE_RULES.get(filename if filename in CODE_FILENAMES else suffix, ())
    for line_number, code_line in enumerate(statements, start=1):
        line = code_line.strip()
        if not line or _is_comment(line):
            continue
        for rule in line_rules:
            if rule.rule_id == "code.persistent-sensitive-cookie" and not _COOKIE_MARKER.search(line):
                continue
            if (
                rule.rule_id == "code.xml-external-entity"
                and suffix in {".java", ".kt"}
                and "DocumentBuilderFactory" in line
            ):
                continue
            if per_rule_counts.get(rule.rule_id, 0) >= 5:
                continue
            if rule.pattern.search(line):
                if (rule.rule_id, line_number) in seen_locations:
                    continue
                if _candidate_is_suppressed(rule.rule_id, line, document, code_lines, line_number):
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category="code",
                        severity=rule.severity,
                        title=rule.title,
                        path=path,
                        line=line_number,
                        evidence=_trim_evidence(lines[line_number - 1].strip()),
                        description=rule.description,
                        recommendation=rule.recommendation,
                        verification_status="needs_review",
                        verification_note=(
                            "소스 파일 전체의 설정과 방어 패턴을 함께 확인했지만 위험 흐름을 확정할 "
                            "충분한 근거가 없습니다. 함수 간 호출과 업무 중요도를 추가 검토해야 합니다."
                        ),
                    )
                )
                per_rule_counts[rule.rule_id] = per_rule_counts.get(rule.rule_id, 0) + 1
    if suffix == ".py":
        findings = _apply_python_taint(path, lines, findings)
    return findings


_AST_CONFIRMED_NOTE = (
    "파이썬 구문 분석(AST)으로 외부 입력이 방어 처리 없이 위험 동작까지 전달되는 흐름을 확인했습니다."
)


def _apply_python_taint(path: Path, lines: list[str], findings: list[Finding]) -> list[Finding]:
    """Reconcile line-pattern findings with the parser-based verdicts.

    A finding is dropped only when the AST proves its sink argument clean
    (sanitizer, numeric cast, allow-list guard, constant); it is confirmed — or
    added — only when the AST proves a request-to-sink flow. Sinks the AST cannot
    judge keep their existing verdict.
    """
    # Share the line engine's sanitizer vocabulary so the AST never re-flags a
    # value this scanner already treats as neutralized (validateUrl, escapeLdap...).
    result = analyze_python("\n".join(lines), extra_sanitizer=lambda name: bool(_SANITIZERS.search(name)))
    if result is None:
        return findings
    kept: list[Finding] = []
    confirmed: set[tuple[str, int | None]] = set()
    for finding in findings:
        key = (finding.rule_id, finding.line)
        if finding.rule_id in _PY_TAINT_RULES and key in result.safe and key not in result.vulnerable:
            continue
        if key in result.vulnerable:
            if finding.verification_status != "confirmed":
                finding = _replace_finding(
                    finding,
                    verification_status="confirmed",
                    verification_note=f"{_AST_CONFIRMED_NOTE} {result.vulnerable[key]}",
                )
            confirmed.add(key)
        kept.append(finding)
    for (rule_id, line), trace in sorted(result.vulnerable.items()):
        if (rule_id, line) in confirmed or rule_id not in _RULE_BY_ID or not 0 < line <= len(lines):
            continue
        rule = _RULE_BY_ID[rule_id]
        kept.append(
            Finding(
                rule_id=rule.rule_id,
                category="code",
                severity=rule.severity,
                title=rule.title,
                path=path,
                line=line,
                evidence=_trim_evidence(lines[line - 1].strip()),
                description=rule.description,
                recommendation=rule.recommendation,
                verification_status="confirmed",
                verification_note=f"{_AST_CONFIRMED_NOTE} {trace}",
            )
        )
    return kept


def _is_comment(line: str) -> bool:
    return line.startswith(("#", "//", "/*", "*", "<!--"))


def _trim_evidence(line: str) -> str:
    return line if len(line) <= 240 else f"{line[:237]}..."
