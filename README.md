# sbom2repo

`sbom2repo` reads Package URLs (PURLs) from a CycloneDX JSON SBOM and resolves
them to repositories with `purl2repo`.

It is intentionally small: SBOM parsing stays limited to CycloneDX `components`,
and repository resolution is delegated to `purl2repo` 2.x.

## Install

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

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
.venv/bin/python -m pip install pytest
.venv/bin/python -m pytest
```
