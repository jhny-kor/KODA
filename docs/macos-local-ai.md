# macOS Local AI Development Guide

> As of **2026-10-11**, this guide describes the implementation inspected in the
> local working tree. Its AI source, development script, and tests are unpublished
> working files. Publishing these docs alone does not make the commands available
> in a GitHub checkout or establish availability in the Mac App Store app.
> Store distribution, notarization, and inclusion in a release are separate checks.

The native macOS app uses an OpenAI-compatible local server's `/models` and
`/chat/completions` endpoints without an additional AI SDK. Python candidate
validation requires an executable Python 3 on this Mac. This is separate from the
shared Python engine's `--ai-triage` implementation.

## Run the development app

Use this command only in a checkout containing `script/build_and_run.sh` and the
local AI development files. `--verify` builds, launches, and checks that the app
process exists; it does not run the full feature test suite.

```bash
./script/build_and_run.sh --verify
```

The bundle is `.build/macos-local-ai/Build/Products/Debug/KODA.app`. Its identifier,
`com.jhnykor.koda.localai`, separates settings and Keychain items from the installed
release. The script uses ad-hoc signing (`CODE_SIGN_IDENTITY=-`) and excludes the
Java scanner bundle (`KODA_INCLUDE_JAVA_SCANNER=0`). This is not Store distribution signing.

## Configure a connection

1. Run an OpenAI-compatible chat model server on this Mac.
2. Open **Settings → Local AI** and enter, for example, `http://127.0.0.1:1234/v1`.
3. Supply a key only if required. Fetch the model list and select a chat model. An embedding-only model is not suitable for chat responses.
4. Enter a name and save the connection. UserDefaults stores name, address, and model; macOS Keychain stores the key per server address. Saving an empty key deletes that server's key.
5. Use **Test response** to establish actual chat inference. Add another model on the same server through **New connection**.
6. Select saved connections from Settings or a finding's AI panel. The selection persists across launches.

Legacy single-server settings migrate when first opened. Deleting a connection
leaves its server's Keychain key intact. A successful model listing does not prove
inference. Requests occur on button presses and can be cancelled while waiting or
by closing the panel.

## Data sent and meaning of results

Native AI requests accept only HTTP(S) addresses on `localhost`, `127.0.0.1`, and
`::1`; LAN and cloud addresses are rejected. Redirects are blocked, and the session
disables proxies, cookies, and caching. Check the local server's own external
connections separately. Saved connection records contain no API keys.

| Feature | Data sent to the model | Limits of the result |
|---|---|---|
| AI explanation | Rule ID, title, original severity, recommendation | Advisory explanation without file contents or paths |
| Risk / false-positive review | At most 11 lines (4 KiB) around the finding after rechecking, filename/line number and finding metadata | Likely risk, possible false positive, or uncertain; original finding and severity retained |
| Revised source | Full selected file, filename/line number, rule ID, title, recommendation | Original unchanged; validated candidate preview and separate save |
| Regression test draft | Before/after source, rule and recommendation | Natural-language plan marked **Not run**, without executable tests or proof of passing |
| Change impact | At most 30 declaration names and search counts | Python textual reference candidates; model receives no paths or source; not a complete call graph |
| AI supplemental report | Rule ID, category, severity and verification status for the first 12 findings | Original counts, severity and risk score retained; separate Markdown with unverified suggestions |

Risk review reads context from files up to 512 KiB. Risk review and candidate
generation reject detected secrets, stale findings, and
incomplete rescans. Secret detection is not a guarantee that all sensitive content
is recognized. The supplemental report sends no source, paths, evidence, or
warnings and directs readers to the original report for findings beyond the first
12. Explanations, reviews, and supplemental reports do not change the original verdict.

## Validate and save a candidate

Open **View all → Remediation guide → Local AI explanation → Generate revised
source** for `.py`, `.java`, `.xml`, or `.js`. Input is limited to 12 KiB and a
candidate to 24 KiB. Host, secret, and dependency findings are excluded.

KODA confirms the finding still exists in the current source, rejects an unchanged
candidate, and validates syntax and basic interfaces. It rescans a separate
temporary file to require removal of the selected finding without new findings.
It stops if the original changes during generation.

| Language | Tool and validation boundary |
|---|---|
| Python | Executable Homebrew/Xcode/Command Line Tools Python 3; AST syntax and existing function/class interfaces |
| Java | JDK 11+ syntax parser and main declarations; no dependency compilation, project build, or generated-code execution |
| XML | Parser with external entities disabled; root, namespace, element counts, name/ID attributes |
| JavaScript | JavaScriptCore syntax and main declarations; unsupported syntax such as ES modules falls back to accessible Node.js `--check` |

Missing or inaccessible tools stop validation. App Sandbox can prevent access even
when a tool is installed. The validator finds directly executable Python paths
instead of the usual `/usr/bin/python3` launcher. Generated code is not executed.

**Auto-repair and rescan (up to 3 attempts)** sends syntax/interface/rescan failures
back to the same local model. The previous candidate is resent only if at most
4 KiB. Repeated candidates, three failed attempts, changed originals, secrets,
incomplete scans, and connection/output-limit errors stop the loop.

Only an accepted candidate is shown for comparison and **Save revised source as
separate file**. Saving over the original is rejected. Regression drafts support
all candidate languages; impact analysis supports Python only. Impact search is
bounded to 400 Python files, 5,000 visited entries, 4 MiB total source, and 80
reference candidates, with warnings for omitted scope.

**Syntax, interface, and KODA rescan checks do not prove functional equivalence.**
Run project behavior and security tests against the separately saved candidate
before deciding to apply it.

## Response limits and troubleshooting

Chat requests use SSE streaming, retaining only final assistant content rather
than reasoning fragments. They require `[DONE]` and a normal `stop` finish reason;
truncated, empty, or incompletely terminated output is rejected. Limits are 16 MiB
for the stream, 128 KiB per event line, and 64 KiB of final content. Nonstreaming
responses, including model lists, are limited to 1 MiB.

Ordinary candidate, risk review, regression plan, and supplemental report requests
allow up to 10 minutes waiting for response data and 25 minutes total. Connection
tests and impact analysis allow up to 10 minutes; automatic repair allows 5 minutes
per request and at most three attempts. There is no separate 15-minute timer for
the complete retry loop, and local validation also takes time. Requests can be cancelled.

For timeouts or reasoning-only output, inspect outstanding server generations and
try a smaller file or faster chat model. Lowering the server's reasoning setting,
where supported, may help latency; it does not guarantee correction quality or
preserved behavior.

## Verification commands and historical records

These tests require the unpublished development files. **On 2026-10-11, all ten
macOS validation scripts passed, including the seven local AI fixtures below.**
The Java-enabled arm64/x86_64 Release build and static analysis succeeded. Actual
ARM execution checked the app window and the headless Java scan. This does not
establish complete local AI UI interaction or freshly validated real-model
inference. Intel execution, Store distribution, and notarization remain unverified.
See the [current validation record](verification-2026-10-11.md).

```bash
python3 platforms/macos/tests/test_local_ai_client.py
python3 platforms/macos/tests/test_local_ai_profiles.py
python3 platforms/macos/tests/test_native_local_ai_fix.py
python3 platforms/macos/tests/test_native_local_ai_triage_review.py
python3 platforms/macos/tests/test_native_local_ai_test_plan.py
python3 platforms/macos/tests/test_native_local_ai_impact.py
python3 platforms/macos/tests/test_native_ai_report.py
```

The current ten-script set adds native archive, Java process, and Java asset
packaging checks to those seven fixtures. It covers valid empty ZIP/GZIP files,
invalid compressed data, concurrent process output/timeout behavior, and rejection
of a helper with the wrong architecture. Fixture responses do not establish
real-model analysis accuracy.

The 2026-10-02 `python3 -m unittest discover -s platforms/macos/tests -q` result
(seven local AI fixtures and five archive tests at the time) is a historical
regression record for the earlier implementation.

Earlier development records from 2026-09-28–29 describe the following. They are not
current-environment passing evidence.

- September 28 recorded LM Studio model listing, chat/explanation, streaming risk review, and fixture-server UI checks for candidate comparison, separate save, regression plans, references, and supplemental reports.
- A small Python candidate from `qwen3.8-27b-mlx` appeared after about five minutes. Its changed command allowlist was not proven to preserve existing behavior.
- September 29 recorded fixture checks for second-attempt success, repeated-candidate rejection and three-attempt limits, plus first-attempt acceptance for a small Python example with `koda-qwen3.8-no-think`. A real-model second attempt still needed validation.
- XML and ordinary JavaScript candidate previews were recorded after the language extension. Java's success path lacked a JDK, and ES modules lacked sandbox access to Node.js. Recheck current tool availability before relying on those environment observations.

- [한국어 로컬 AI 가이드](macos-local-ai.ko.md)
- [macOS installation](install/macos.md)
