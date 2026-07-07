<!-- SPECKIT START -->
For additional context about technologies to be used, project structure,
shell commands, and other important information, read the current plan
at specs/004-attestation-and-verification/plan.md
<!-- SPECKIT END -->

## Engineering rules (MUST)

Authoritative source: `.specify/memory/constitution.md`. These apply to every change in this
repository:

- **DRY** — one authoritative source for logic, constants, config, and protocol/crypto
  definitions. No copy-paste or parallel re-implementations; extract and reuse. (Constitution
  Principles III and VIII.)
- **Always do Root-Cause Analysis (RCA)** — fix the underlying cause, never the symptom. No
  band-aids, no retries wrapped around a defect, no swallowed errors. Record the RCA (what
  failed, why, why it wasn't caught) in the PR. (Principle VIII.)
- **No opportunistic edits/fixes** — keep each change scoped to its task. No drive-by refactors
  or unrelated "while I'm here" edits; track unrelated issues separately. (Principle VIII.)
- **Test-first, ≥95% unit coverage** — write tests before implementation; they must fail first.
  Unit-test coverage MUST stay ≥95% (per crate/package). Contract tests run against the real
  Cleverbase surface; produced signatures are checked against a reference validator.
  (Principle VI.)
- **Production-grade & complete** — no half-features; demos are only usage examples, never a
  reason to reduce scope. (Principle I.)
- **Do not stop mid-implementation** — the ONLY reason to halt is a genuine obstacle that requires
  an actual human decision (e.g. a missing credential/secret only the user can supply, or a real
  product fork with no sensible default). Choosing order between items that all must be done ("do A
  or B first?" when the goal is A+B) is NOT a reason to stop — just do A then B. "I finished a small
  fraction, shall I continue?" is NOT a reason to stop. Keep going until the task is fully complete
  or you are genuinely blocked.

The constitution is authoritative and broader than this summary — read it before non-trivial
work.
