# Agent instructions

This project's agent operating rules live in **`CLAUDE.md`** (see the "Engineering rules (MUST)"
section). Read it before doing any work.

The **authoritative** engineering principles are in the project constitution:
**`.specify/memory/constitution.md`**.

Summary of the non-negotiables (full text + rationale in the constitution):

- **DRY** — single authoritative source for logic/constants/config; no duplication.
- **Always Root-Cause Analysis** — fix causes, not symptoms; record the RCA in the PR.
- **No opportunistic edits** — keep changes scoped; track unrelated issues separately.
- **Test-first, ≥95% unit coverage** — tests fail first; contract-tested against the real
  Cleverbase surface; signatures checked against a reference validator.
- **Production-grade & complete** — no half-features; demos are only usage examples.
