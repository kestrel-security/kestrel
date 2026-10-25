# Getting help with Kestrel

Kestrel is a personal open-source project, maintained in spare time. There is
no paid support channel; the places below are watched by the maintainer and the
community, and answers may take a few days.

| You want to... | Go to |
|----------------|-------|
| Ask how to do something, or discuss an idea | [GitHub Discussions](https://github.com/kestrel-security/kestrel/discussions) |
| Report a bug | [Open an issue](https://github.com/kestrel-security/kestrel/issues/new/choose) using the bug template |
| Request a feature | [Open an issue](https://github.com/kestrel-security/kestrel/issues/new/choose) using the feature template; for anything large, start a discussion first |
| Report a security vulnerability | **Not** an issue or a discussion. Follow [`SECURITY.md`](SECURITY.md) |
| Report a Code of Conduct concern | [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md#enforcement) |
| Contribute a change | [`CONTRIBUTING.md`](CONTRIBUTING.md) |

## Before you ask

- Read [`docs/getting-started.md`](docs/getting-started.md) and
  [`docs/deployment.md`](docs/deployment.md); most setup questions are answered
  there. Every page is indexed in [`docs/README.md`](docs/README.md).
- Search existing issues and discussions, including closed ones.

## What to include

The Kestrel version (`GET /healthz` reports it), how you run it (Docker Compose,
your own images, from source), what you did, what you expected, and what happened instead,
with logs. Remove tokens, tenant names, and any other data you would not post
publicly before you paste anything.
