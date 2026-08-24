# Releasing nanoidp (maintainers)

Everything a release needs is automated by two tag-triggered workflows, but
every step can be run and verified by hand. This document is the manual:
what happens, in which order, with the exact commands, and how to verify
that what was published is what you meant to publish.

Two hard-won rules first:

1. **Workflows run from the tagged commit.** Fixing a workflow on `main`
   does nothing for a tag that already exists; re-running the run uses the
   old definition. A broken cut is fixed by a re-cut with a new tag, never
   by re-tagging the same name onto a different commit.
2. **A green workflow does not mean every job ran.** A skipped job shows a
   green run. Always list the jobs (step 6) and confirm none were skipped.

## Version and tag naming

| Where | Pre-release | Final |
|---|---|---|
| `pyproject.toml` | `2.7.0rc5` (PEP 440, no hyphen) | `2.7.0` |
| git tag | `v2.7.0-rc5` (hyphen) | `v2.7.0` |

The hyphen in the git tag is load-bearing: `docker.yml` publishes `:latest`
only when the tag name contains no hyphen (`enable=${{ !contains(github.ref_name, '-') }}`,
with `flavor: latest=false` so the metadata-action's `latest=auto` default
cannot add it through a second path). `publish.yml` pushes every `v*` tag to
TestPyPI and PyPI; pip's own resolver keeps plain `pip install nanoidp` on
the last final because PEP 440 pre-releases need `--pre` or an exact pin.

## CHANGELOG policy

Pre-releases get **no** CHANGELOG section: everything stays under
`[Unreleased]` until the final, which becomes `[X.Y.Z] - date` with the
compare link updated at the bottom of the file. The rc's content is
described in its GitHub pre-release notes instead, which is where rc
installers look. Only the net change belongs in the CHANGELOG: something
added in rc1 and removed before the final must not appear. One exception:
if a later rc breaks something relative to an earlier rc, say so in the
newer rc's release notes.

## Step by step

### 0. Pre-flight

```bash
git checkout main && git pull
git status                      # clean tree, no stray commits
gh pr list                      # nothing you meant to include is still open
python -m pytest -q             # green locally, not just in CI
ruff check . && mypy src && lint-imports
nanoidp validate-config --config ./config
```

For a final release also: consolidate the CHANGELOG (`[Unreleased]` ->
`[X.Y.Z] - YYYY-MM-DD`, compare links at the bottom) in the bump PR.

### 1. Bump the version (through a PR, like any change)

```bash
git checkout -b chore/bump-2.7.0rc5
sed -i 's/^version = ".*"/version = "2.7.0rc5"/' pyproject.toml
git add pyproject.toml && git commit -m "chore: bump to 2.7.0rc5"
git push -u origin chore/bump-2.7.0rc5
gh pr create --title "chore: bump to 2.7.0rc5" --body "..." --milestone 2.7.0
# wait for CI, review, merge
```

### 2. Tag the merged commit

```bash
git checkout main && git pull
git log --oneline -1            # this IS the commit the workflows will run from
git tag v2.7.0-rc5
git push origin v2.7.0-rc5
```

### 3. Create the GitHub release

```bash
gh release create v2.7.0-rc5 --prerelease --title "v2.7.0-rc5" --notes-file notes.md
# final: drop --prerelease; the notes can point at the CHANGELOG section
```

Pre-release notes should state the install commands (`pip install --pre
nanoidp==2.7.0rc5`, the GHCR tag), what changed since the previous rc, and
that plain `pip install nanoidp` keeps resolving the last final.

### 4. What the tag triggers

- `publish.yml` (`Publish to PyPI`): `test` -> `build` -> `wheel-smoke` ->
  `publish-testpypi` -> `publish-pypi`. The smoke job installs the **built
  wheel** in a clean venv and exercises it as a user would: import +
  version, `nanoidp --help`, the `nanoidp-mcp` entry point exists,
  `nanoidp init`, a real server start, `/api/health` and OIDC discovery.
- `docker.yml` (`Publish to GHCR`): multi-arch build (amd64+arm64), tags
  `v2.7.0-rc5` always, `latest` only for hyphen-less tags.

### 5. Watch the runs

```bash
gh run list --limit 4
gh run watch <run-id>           # or poll gh run list until completed
```

### 6. Verify EVERY job ran (skips look green)

```bash
for id in $(gh run list --limit 4 --json databaseId,headBranch \
    --jq '.[] | select(.headBranch=="v2.7.0-rc5") | .databaseId'); do
  gh run view "$id" --json jobs --jq '.jobs[] | "\(.name): \(.conclusion)"'
done
# expect: test, build, wheel-smoke, publish-testpypi, publish-pypi, publish-ghcr
# all "success"; a "skipped" anywhere means the artifact did NOT go out
```

### 7. Verify the published artifacts, not the repo

PyPI, in a throwaway venv (the index can lag a minute; retry):

```bash
python3 -m venv /tmp/rcvenv
/tmp/rcvenv/bin/pip install --pre nanoidp==2.7.0rc5
/tmp/rcvenv/bin/python -c "import nanoidp; print(nanoidp.__version__)"
/tmp/rcvenv/bin/nanoidp validate-config --config ./config   # a real command from the wheel

# plain install must keep resolving the last FINAL release:
python3 -m venv /tmp/plainvenv
/tmp/plainvenv/bin/pip install nanoidp
/tmp/plainvenv/bin/python -c "import nanoidp; print(nanoidp.__version__)"
```

GHCR digests (no docker needed; works with a plain `gh` token for pulls):

```bash
TOK=$(curl -s -u USER:$(gh auth token) \
  "https://ghcr.io/token?scope=repository:cdelmonte-zg/nanoidp:pull" | jq -r .token)
for t in v2.7.0-rc5 v2.6.0 latest; do
  curl -sI -H "Authorization: Bearer $TOK" \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
    "https://ghcr.io/v2/cdelmonte-zg/nanoidp/manifests/$t" \
    | grep -i docker-content-digest | sed "s/^/$t /"
done
```

Checks: the new tag exists with its own digest; **for a pre-release,
`latest` is byte-identical to the last final's digest**; for a final,
`latest` equals the new tag. Optionally run the image:

```bash
docker run --rm -p 8000:8000 ghcr.io/cdelmonte-zg/nanoidp:v2.7.0-rc5 &
curl -sf http://127.0.0.1:8000/api/health
```

## When a cut goes wrong

- **Minutes old, nothing installed by anyone**: delete release and tag,
  fix, re-cut under a NEW name if anything might have been pulled:

  ```bash
  gh release delete v2.7.0-rc5 --yes --cleanup-tag
  ```

  Never re-tag the same name onto a different commit: caches, mirrors and
  anyone who fetched in between now disagree with you.
- **`:latest` moved onto a pre-release** (the rc1 incident): repoint it via
  the registry API by PUTting the good tag's manifest bytes verbatim onto
  `latest` (GET with the OCI-index Accept headers, PUT the identical body
  with the same Content-Type). Requires a token with `write:packages`
  (`gh auth refresh -h github.com -s write:packages`); a plain gh token
  403s on the PUT even though `docker login` appears to succeed.
- **A workflow bug in the tagged commit**: fix on main through a PR, then
  re-cut (rule 1 above). Re-running the failed run re-runs the old broken
  definition.

## Final-release extras

1. CHANGELOG consolidated in the bump PR (see policy above), including the
   compare links at the bottom of the file.
2. `gh release create vX.Y.Z --title "vX.Y.Z" --notes ...` without
   `--prerelease`.
3. Verify `latest` moved to the new digest (step 7) and that the docs site
   redeployed (it does automatically on merges touching book/ or docs/).
4. If a security advisory ships with the release, cross-link the GHSA and
   the release notes both ways, and update it once a CVE id is assigned.
