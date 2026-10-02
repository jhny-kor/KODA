# KODA AI Augmentation and CI/CD Roadmap

As of **2026-10-02**, this is a source-based status summary of the local working
tree, including uncommitted development changes. The [Korean roadmap](roadmap-ai-augmentation.md)
preserves the original **2026-06-14** benchmarking, decisions, gap analysis, and
unchecked plans. Those checkboxes are historical, not today's unimplemented list.
Publishing documentation does not establish a feature release or Store update.

## Current implementation and remaining boundaries

| Area | Present in inspected source | Not established by this status |
|---|---|---|
| Shared Python AI triage | `--ai-triage --llm`; Ollama, Anthropic and OpenAI providers; added triage metadata preserves original severity | Accurate AI verdicts or exploit confirmation; local-only egress with a customized Ollama base |
| Deterministic fixes | Default dry-run diff for `fix --target ...`; explicit `--apply`; default `.bak` backup and Python syntax checks | Interactive approval, required clean Git state, arbitrary LLM patches, automatic PR creation/merge |
| Reachability | Python AST and JS/TS import searches label dependency CVEs `reachable`, `unreachable`, or `unknown` | Runtime reachability or a complete call graph; default deletion or severity downgrading |
| Changed-file CI | `--changed-only --base`; repository composite action and SARIF upload step; full-scan fallback when diff cannot be determined | Changed-line filtering, inline PR comments, Marketplace publication or verified live uploads |
| Native macOS local AI | Loopback OpenAI-compatible connections, explanation, risk review, candidate preview, up to three attempts, regression plans, Python impact search, separate AI reports | Currently unpublished development files; Store inclusion, functional equivalence, executed regression drafts |

KODA keeps the default scan offline-first and read-only. Optional network and
write paths require explicit selection. The shared Python Ollama provider defaults
to `http://localhost:11434`, but `KODA_LLM_API_BASE` also accepts other HTTP(S)
hosts; operators must check where that configured server sends data. This differs
from the native macOS AI client's loopback-only restriction. Native AI candidates
are saved separately without automatic original-source changes, whereas the
shared CLI's explicit `fix --apply` writes original files.

Use the [CLI guide](usage.md) for current commands and the [native local AI guide](macos-local-ai.md)
for development requirements and validation limits. Historical proposals such as
`--ai-provider`, interactive approval, and clean-Git gates are not current support
contracts.

- [English documentation index](README.en.md)
- [Korean AI augmentation roadmap](roadmap-ai-augmentation.md)
- [English implementation specification](spec-beyond-static-scanner.en.md)
