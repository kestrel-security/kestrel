# ADR-0002: Legacy policy DSL implementation approach

## Status

**Superseded** by [ADR-0009: Python policies via RestrictedPython](0009-python-policies.md)
on 2026-07-30. The DSL, its grammar, parser, and compiler were removed from
the repository. This record is kept so the reasoning behind the original
choice, and the reasons it was abandoned, stay reviewable.

## Context (as of 2026-07-21)

Kestrel's first policy language was a custom DSL. It had to be readable by a
security engineer who is not a programmer, support graph traversal and
attribute filtering, parse into a stable AST, be statically validatable, and
run against real data with a fixture-based test framework. Four
implementation strategies were considered:

1. **A hand-rolled recursive-descent parser.** Full control and no dependencies, but it grows messy as the grammar adds aggregation, time conditions, and traversal syntax.
2. **A parser generator (Lark).** A formal grammar file that is easy to read, diff, and version, with a clean separation between grammar and AST construction via a `Transformer`.
3. **Embedding a subset of an existing configuration language (HCL, CUE).** Would have meant fighting someone else's grammar to add graph-traversal semantics, and CUE had no mature Python binding.
4. **A Python DSL with restricted evaluation.** Powerful, but at the time it read as "policies are Python" rather than "policies are readable by a security engineer", and a restricted `eval` was judged a standing liability.

## Decision (superseded)

Lark with the Earley parser was chosen. The pipeline was grammar file →
`Transformer` into typed AST dataclasses → schema-aware validator → compiler
into a Python predicate plus an evidence extractor → evaluator over rows loaded
by `dataload.py` → fixture test runner. The compiler deliberately did not push
filters down to SQL: every candidate row for an org was loaded through the
ORM and filtered client-side, which was simple to implement correctly and fast
enough at single-org scale, with SQL pushdown noted as an additive follow-up.

The v0 grammar covered object selection, attribute filtering and comparison
operators, `contains`, null checks, boolean composition, `evidence {}`,
`remediation`, `compliance {}`, `exists(...)` correlated subqueries, graph
traversal via `through(...)`, and `aggregate { group_by ... having ... }`.

## Why it was superseded

Option 4 turned out to be right once its security concern was addressed
properly. RestrictedPython compilation plus subprocess isolation gave a
reviewable, deterministic runtime; fixture-testable Python modules matched how
detection engineers already work (the Panther model); and AI-assisted
drafting was far more reliable for Python than for a bespoke grammar. The
custom DSL's readability advantage did not outweigh maintaining a grammar,
validator, and compiler that every new data shape had to be threaded through.
ADR-0009 records the replacement. The `dataload.py` row-loading approach
survived the transition and is still how policies see data.
