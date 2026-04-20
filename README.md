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

## Output

For each SBOM component with a `purl`, the tool reports:

- component name
- PURL
- package name and version
- repository URL
- repository kind and type
- release URL, when available
- confidence
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
```

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install pytest
.venv/bin/python -m pytest
```
