# sbom2repo

`sbom2repo` reads Package URLs (PURLs) from a CycloneDX JSON SBOM and resolves
them to repositories with `purl2repo`.

It is intentionally small: SBOM parsing stays limited to CycloneDX `components`,
and repository resolution is delegated to `purl2repo` 2.x.

## Install

Install the released dependency set:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

When developing against a local checkout of `purl2repo`, install it into this
virtual environment in editable mode:

```bash
.venv/bin/python -m pip install -e ../purl2repo
```

Confirm the installed resolver supports the bulk settings used by `--fast` and
the first-class repository validation fields added in `purl2repo` 2.0.2:

```bash
.venv/bin/python -c "import inspect; from purl2repo import Resolver; print(inspect.signature(Resolver))"
```

The output should include `validate_repositories`,
`use_deps_dev_fallback`, and `use_scraper_fallback`. The JSON model should
include `repository_validated` when resolving with `purl2repo` 2.0.2 or newer;
older local installs still work through a compatibility fallback that inspects
evidence strings.

## Usage

Human-readable output:

```bash
.venv/bin/python sbom2repo.py path/to/sbom.json
```

Fast repository-only inventory:

```bash
.venv/bin/python sbom2repo.py path/to/sbom.json --repo-only
```

Fast first-party-only inventory:

```bash
.venv/bin/python sbom2repo.py path/to/sbom.json --fast
```

`--fast` is a convenience preset for large SBOM inventory runs. It resolves
repositories only, skips repository URL validation, skips deps.dev, skips
fallback scraping, and uses a default timeout of `3.0` seconds unless
`--timeout` is supplied.

Tune resolver fallbacks independently:

```bash
.venv/bin/python sbom2repo.py path/to/sbom.json \
  --repo-only \
  --no-deps-dev-fallback \
  --no-scraper-fallback
```

Conservative automation output:

```bash
.venv/bin/python sbom2repo.py path/to/sbom.json \
  --repo-only \
  --min-confidence medium \
  --require-validated
```

JSON output:

```bash
.venv/bin/python sbom2repo.py path/to/sbom.json --json --pretty
```

Offline/direct-host resolution:

```bash
.venv/bin/python sbom2repo.py path/to/sbom.json --no-network
```

Verify inferred release links:

```bash
.venv/bin/python sbom2repo.py path/to/sbom.json --verify-release-links
```

Large Maven SBOMs can be slow because every component may require Maven POM
fetches, parent POM fetches, repository URL validation, and fallback metadata
checks for stale SCM URLs. Use `--repo-only` when release/tag URLs are not
needed. Use `--fast` when you want quick first-party metadata results without
repository validation, deps.dev, or fallback scraping. In fast mode, the default
timeout is `3.0` seconds instead of `10.0`. For finer control, use
`--no-validate-repositories`, `--no-deps-dev-fallback`, and
`--no-scraper-fallback` individually.

The bulk resolver switches require a `purl2repo` version that supports them. If
you see an error saying the installed `purl2repo` does not support the requested
bulk resolver settings, upgrade to `purl2repo>=2.0.2` or install the local
updated checkout with:

```bash
.venv/bin/python -m pip install -e ../purl2repo
```

## Output

For each SBOM component with a `purl`, the tool reports:

- component name
- PURL
- package name and version
- repository URL
- repository kind and type
- release URL, when available
- confidence
- whether the repository URL validated
- repository validation status from `purl2repo`
- whether fallback metadata or scraping was used
- metadata sources used by `purl2repo`
- warnings or per-component errors

Example:

```text
Package: requests
PURL: pkg:pypi/requests@2.31.0
Repository: https://github.com/psf/requests
Kind: source_code
Type: github
Version: 2.31.0
Release URL: not found
Confidence: high
Validated: yes
Validation status: validated
Fallback: no
Metadata sources: pypi-json
```

At the end of human-readable output, `sbom2repo` prints a summary with totals,
validated repository count, fallback-derived count, confidence distribution, and
elapsed runtime.

## Quality guidance

`sbom2repo` reports `purl2repo` evidence instead of hiding uncertain results.
For investigation work, low-confidence fallback results can still be useful. For
automation, prefer:

```bash
.venv/bin/python sbom2repo.py path/to/sbom.json \
  --repo-only \
  --min-confidence medium \
  --require-validated \
  --json --pretty
```

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -e ../purl2repo
.venv/bin/python -m pip install pytest
.venv/bin/python -m pytest
```
