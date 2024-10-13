# sbom2repo

sbom2repo is a tool designed to map package URLs (purls) from a Software Bill of Materials (SBOM) to their corresponding source repositories and release information. This can be useful for tracing dependencies, identifying vulnerabilities, and verifying software authenticity in the supply chain.

It implements the purl2repo library and is intended to be a minimal implementation designed for testing the library but can be used to process entire SBOM files and produce a list of vcs repo URIs. 

## Features
- Parses SBOMs containing purls (e.g., pkg:pypi/requests@2.25.1).
- Retrieves source repository and release information.
- Supports multiple ecosystems like PyPI, Maven, and more.
- Supports JSON formatted SBOM only

## Usage

```bash
    python3 sbom2repo.py <sbom path>
```

Example results:

Package: django  
Repository: https://github.com/django/django  
Version: 1.4  
Release URL: https://github.com/django/django/releases/tag/1.4  