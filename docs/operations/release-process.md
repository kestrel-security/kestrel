# Release process

Label: **implemented**.

A release is a tag. Pushing `vX.Y.Z` re-runs CI, dependency and secret scans,
system tests, and all three container scans before creating a GitHub Release.
Kestrel publishes no container images:
operators check out the tag and build the images from `deployments/docker/`
(`docker compose -f deployments/compose/docker-compose.yml up -d --build` does
it) — see [`../deployment.md`](../deployment.md#building-the-images).

## Cutting a release

```bash
make release VERSION=0.5.0 PUSH=1
```

That is the whole of the manual part. `scripts/release.sh`:

1. Refuses a dirty tree, a branch that is not `main`, a `main` behind
   `origin/main`, a version the tree already carries without `--prepared`, and a tag that already
   exists locally or on the remote.
2. Bumps the version in every file that records it (below).
3. Moves the `## Unreleased` entries in `CHANGELOG.md` under
   `## v0.5.0 — <today>`, leaving a fresh empty `## Unreleased`. An empty
   `Unreleased` is a hard error — a release nobody can read is not a release.
4. Runs `uv lock` so the lockfile records the new workspace versions too, then
   proves both: `scripts/check-versions.sh 0.5.0` for the files, and
   `uv sync --locked` for the lockfile.
5. Commits, creates a signed tag (annotated when no signing key is configured),
   and with `PUSH=1` pushes `main` and then the tag. In that order, always: the
   tag must be an ancestor of `origin/main`.

Anything that fails between step 2 and the commit reverts the bump, so a
failed attempt leaves the tree exactly as it was.

Without `PUSH=1` it stops after the tag and prints the push commands, so you can
read `git show --stat HEAD` first.

### An already-prepared release (including the first v0.4.0)

Prepare version, lockfile and release-note changes in a pull request and merge
it after the required checks pass. From the resulting clean `main`, run:

```bash
make release VERSION=0.4.0 PREPARED=1 PUSH=1
```

`--prepared` verifies that all versions match, the lockfile is current, and the
changelog has a nonempty dated section for that version with no pending
Unreleased entries. It tags the existing commit without bumping versions or
creating a commit. The tag must not already exist. This is also the release
path for anyone who cannot push to `main` directly: merge the preparation
first, then tag it.

Both pushes rely on the repository rulesets (see
[Repository settings](#repository-settings)): only a repository administrator
can push to `main` without a pull request, and only a repository administrator
can create, move or delete a `v*` tag. GitHub reports each as a bypassed rule
violation on push; that is expected.

Before tagging, run CI, Security scan and Nightly on the exact candidate. All
three workflows support manual dispatch. The release workflow reruns all three
against the tagged commit and requires every gate before publishing notes.

### One version, several files

A release is identified by a single git tag `vX.Y.Z`. Every place that records a
version must agree with it, or the tag stops meaning anything:

| File | Field |
|------|-------|
| `kestrel/pyproject.toml` | `[project] version` |
| `apps/api/pyproject.toml` | `[project] version` |
| `apps/worker/pyproject.toml` | `[project] version` |
| `apps/web/package.json` | `version` |
| `uv.lock` | the pinned version of each workspace member |

`uv.lock` is the one that bites. It pins every workspace member, so a pyproject
bumped without relocking leaves the two disagreeing, and `uv sync --locked`
refuses — which is every Python CI job and both Python image builds, discovered
after the tag is already pushed. `pnpm-lock.yaml` does not record the importer's
own version, so the web bump needs no equivalent.

Connectors are versioned independently (a connector can ship a fix without a
product release), but each connector's `pyproject.toml` version must match its
`manifest.yaml` version.

`scripts/check-versions.sh` enforces both rules and runs in CI, in
`scripts/release.sh`, and again in the release workflow against the tag. At
runtime `kestrel.version.get_version()` returns the `KESTREL_VERSION`
environment variable when a build stamps one, otherwise the installed `kestrel`
package's version (which the bump above sets, so an image built from a tag
reports that tag), and `dev` only when neither is available. `GET /healthz`
and `GET /readyz` report it, so a post-deploy check can confirm the version
serving matches the tag. Set `KESTREL_VERSION` on the api and worker
containers when a downstream pipeline builds from a commit rather than a tag
and wants the SHA reported instead.

## What the tag sets off

Pushing `vX.Y.Z` runs `.github/workflows/release.yaml`. The release needs the
gate, so a tag that fails it releases nothing:

```
push v0.5.0
  ci ................ the full pull-request gate (ci.yaml) on the tagged commit
  security .......... Python/Node dependency audits and gitleaks
  nightly ........... system tests and api/worker/web Trivy scans
  github-release .... scripts/check-versions.sh 0.5.0, then a GitHub Release
                      whose notes are CHANGELOG.md's `## v0.5.0` section
  docs .............. docs.kestrelsecurity.io rebuilt from the tag (docs.yaml)
```

- The GitHub Release is created only when its CHANGELOG section exists and is
  not empty. It is the only job with write access to the repository; the docs
  job writes a GitHub Pages deployment and nothing else.
- Images are built for scanning and are never pushed. The nightly workflow
  (`nightly.yaml`) builds all three images from the tagged commit during a
  release, and from `main` on its daily schedule, then scans them with Trivy
  (CRITICAL/HIGH with a released fix fails), so a Dockerfile or base image that
  has gone stale shows up within a day. Accepted exceptions go in
  `.trivyignore`, each with a reason.

## The documentation site

docs.kestrelsecurity.io is `docs/` rendered by `mkdocs.yml`, and it always shows
the latest release. The release workflow's `docs` job calls
`.github/workflows/docs.yaml`, which checks out the tag, runs `mkdocs build
--strict`, and deploys the result to GitHub Pages with the Pages OIDC token —
there is no stored secret. Links that leave `docs/` (`../SECURITY.md`,
`../examples/custom-connector/`) are rewritten by `docs-site/hooks.py` to the
same path on GitHub at that tag.

- A pre-release (`v0.6.0-rc.1`) does not replace the site.
- The CI `docs-site` job builds the site the same way on every pull request, so
  a page missing from `mkdocs.yml`'s `nav`, a broken link, or a missing anchor
  fails the pull request, not the release.
- To redeploy a tag (a failed deploy, or a fix to the site's styling), run
  **Docs site** from the Actions tab with that tag. Only a tag that contains
  `mkdocs.yml` can be published.
- Preview locally with `make docs-serve`; `make docs-build` is the CI build.

The Pages settings this needs, once: **Settings → Pages → Source: GitHub
Actions**, custom domain `docs.kestrelsecurity.io` with **Enforce HTTPS**, and the
`github-pages` environment's deployment rule allowing `v*` tags.

## Rolling back

Rolling back is checking out the previous tag and rebuilding:

```bash
git checkout v0.4.0
docker compose -f deployments/compose/docker-compose.yml up -d --build
```

Migrations are **not** reversed by a rollback: the database stays at the newer
schema. Kestrel's migrations are additive by policy, so an older application
normally runs against a newer schema; when a release notes otherwise, restore the
database backup taken before the upgrade.

## When it goes wrong

**A tag failed before it published anything.** Cut the next patch version
anyway. Deleting and re-pushing a tag to reuse the number saves nothing and
costs you the one guarantee a tag is for — that it means the same thing to
everyone who has already fetched it. A tag that failed CI is honest history.

**The nightly scan fails on an OS package with a fix available.** Every image
starts with `apt-get upgrade`, so a build without cache (`docker compose build
--no-cache`) picks up the distribution's fix; otherwise bump the base image. If
the fix is not yet published upstream, wait for it or record a reasoned
exception in `.trivyignore`.

**Green does not prove the encryption key is right.** `/readyz` does not
verify that `KESTREL_MASTER_KEY` decrypts existing rows. API startup rejects
malformed and short configured keys; a valid-length wrong key reports ready and fails on the first
sync with `InvalidTag:`. After a key or database change, run **Test connection**
on a live connector.

## Repository settings

`scripts/configure-github-security.py` records the repository's security
settings and checks them against GitHub:

```bash
python3 scripts/configure-github-security.py          # verify only
python3 scripts/configure-github-security.py --apply  # enable, then verify
```

It covers GitHub Actions, fork pull request approval (required for every
outside contributor), private vulnerability reporting, secret scanning and push
protection, dependency alerts, and three repository rulesets:

| Ruleset | Applies to | Rules | Bypass |
|---------|------------|-------|--------|
| `main` | default branch | no deletion, no force push | nobody, administrators included |
| `main-pr` | default branch | pull request with a code-owner approval, squash merges only, the required CI/security/DCO checks (pinned to GitHub Actions) | repository administrators |
| `release-tags` | `refs/tags/v*` | no creation, update or deletion | repository administrators |

The administrator bypass is what lets the maintainer push to `main` and merge
without a second reviewer; nothing else (other users, bots, apps, tokens,
Actions) can change `main` except through a pull request the maintainer
approves. Keep the maintainer the only repository administrator. Merging a
pull request as the maintainer means ticking **bypass rules** on the merge
button, since there is no other code owner to approve it.

`--apply` creates or updates each ruleset by name, writing `main-pr` before
narrowing `main`. The script fails if `main` also has classic branch
protection: with "include administrators" set, it would block the direct pushes
the rulesets allow, so remove it rather than layering the two. It never
changes visibility, and refuses to run while the repository is private. Also
check the reporting link in `SECURITY.md` from a non-maintainer account.

Around a release, merge necessary security fixes with green checks;
defer unrelated dependency changes and major upgrades. Python updates use uv
0.12.18, matching the CI/Docker pins and the version supported by Dependabot.
