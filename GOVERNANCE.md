# Governance

Kestrel is a maintainer-led project. The maintainers are listed in
[`MAINTAINERS.md`](MAINTAINERS.md).

## Making decisions

Most decisions are made in pull requests and issues by **lazy consensus**: a
proposal that has been open for review for a reasonable time (at least three
working days for anything significant) and draws no objection from a
maintainer is accepted. Silence is consent; an objection should come with a
reason and, where possible, an alternative.

When consensus cannot be reached, the maintainers decide by simple majority.

## Recording decisions

Decisions that shape the project -- architecture, scope, licensing, process --
are recorded in [`docs/decisions.md`](docs/decisions.md), with an ADR under
`docs/adr/` for architectural ones. Changing an accepted decision starts with an
issue proposing the change, not with a pull request that changes the behaviour.

## What needs explicit maintainer approval

- Adding or removing a maintainer ([`MAINTAINERS.md`](MAINTAINERS.md)).
- Changes to this document, the license, or the
  [Code of Conduct](CODE_OF_CONDUCT.md).
- Irreversible database migrations.
- Cutting a release ([`docs/operations/release-process.md`](docs/operations/release-process.md)).

## Code of Conduct

Everyone taking part in the project follows the
[Code of Conduct](CODE_OF_CONDUCT.md).
