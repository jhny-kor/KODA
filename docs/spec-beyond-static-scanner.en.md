# KODA Beyond-Static-Scanner Specification

Reviewed: 2026-10-02. Historical implementation and test counts in the Korean
specification are dated records. Use the [current status](current-status.en.md)
for fresh verification and publication scope, and the [local macOS AI guide](macos-local-ai.md)
for the separate development implementation. Shared Python and native Swift
checks do not establish functional equivalence. The shared Ollama API base can
be remote HTTP(S); `koda[ai]` is not a declared extra in the current pyproject.


This is the English entry point for the implementation specification behind AI
triage, reachability, deterministic auto-fix, and changed-file CI. The design
keeps discovery separate from deterministic validation, makes writes dry-run by
default, and keeps cloud transfer explicitly opt-in.

The source specification contains module boundaries, CLI/config contracts, and
the historical implementation record. Current behavior is defined by the
[English CLI guide](usage.md), while planning detail remains in the [Korean
specification](spec-beyond-static-scanner.md).

- [English documentation index](README.en.md)
- [Korean implementation specification](spec-beyond-static-scanner.md)
