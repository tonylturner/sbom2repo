"""Resolve package URLs from CycloneDX SBOMs with purl2repo."""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from purl2repo import Resolver
from purl2repo.errors import Purl2RepoError
from purl2repo.models import ResolutionResult

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SbomRepositoryResult:
    component_name: str | None
    purl: str
    package_name: str | None
    version: str | None
    repository_url: str | None
    repository_kind: str | None
    repository_type: str | None
    release_url: str | None
    release_kind: str | None
    confidence: str
    evidence: list[str]
    warnings: list[str]
    error: str | None = None


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def load_cyclonedx_sbom(file_path: str | Path) -> dict[str, Any]:
    path = Path(file_path)
    logger.debug("Opening SBOM file: %s", path)
    with path.open("r", encoding="utf-8") as file:
        sbom_data = json.load(file)
    logger.debug("Successfully loaded SBOM data from: %s", path)
    if not isinstance(sbom_data, dict):
        raise ValueError("Expected a JSON object at the SBOM root")
    return sbom_data


def resolve_sbom(
    sbom_data: dict[str, Any],
    resolver: Resolver,
) -> list[SbomRepositoryResult]:
    components = sbom_data.get("components")
    if not isinstance(components, list):
        logger.debug("No components list found in the SBOM")
        return []

    logger.debug("Found %s components to process", len(components))
    results: list[SbomRepositoryResult] = []
    for component in components:
        if not isinstance(component, dict):
            logger.debug("Skipping non-object component: %r", component)
            continue
        purl = component.get("purl")
        if not isinstance(purl, str) or not purl:
            logger.debug("No purl found for component: %r", component.get("name"))
            continue

        component_name = _string_or_none(component.get("name"))
        logger.debug("Processing purl: %s", purl)
        try:
            resolution = resolver.resolve(purl)
        except (Purl2RepoError, ValueError) as exc:
            logger.error("Error processing purl %s: %s", purl, exc)
            results.append(
                SbomRepositoryResult(
                    component_name=component_name,
                    purl=purl,
                    package_name=None,
                    version=None,
                    repository_url=None,
                    repository_kind=None,
                    repository_type=None,
                    release_url=None,
                    release_kind=None,
                    confidence="none",
                    evidence=[],
                    warnings=[],
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            continue

        logger.debug("Result for %s: %s", purl, resolution)
        results.append(_result_from_resolution(component_name, resolution))
    return results


def print_human(results: list[SbomRepositoryResult]) -> None:
    if not results:
        print("No purls found in the SBOM.")
        return

    for result in results:
        print(f"Package: {result.component_name or result.package_name or 'unknown'}")
        print(f"PURL: {result.purl}")
        if result.error:
            print(f"Error: {result.error}")
        else:
            print(f"Repository: {result.repository_url or 'not found'}")
            print(f"Kind: {result.repository_kind or 'unknown'}")
            print(f"Type: {result.repository_type or 'unknown'}")
            print(f"Version: {result.version or 'not specified'}")
            print(f"Release URL: {result.release_url or 'not found'}")
            print(f"Confidence: {result.confidence}")
            if result.warnings:
                print("Warnings:")
                for warning in result.warnings:
                    print(f"- {warning}")
        print()


def results_to_json(
    results: list[SbomRepositoryResult],
    *,
    pretty: bool,
) -> str:
    return json.dumps(
        [asdict(result) for result in results],
        indent=2 if pretty else None,
        sort_keys=pretty,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Resolve CycloneDX SBOM purls to repositories and release links."
    )
    parser.add_argument("sbom_file_path", help="Path to the CycloneDX SBOM JSON file")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument(
        "--pretty", action="store_true", help="Pretty-print JSON output"
    )
    parser.add_argument(
        "--strict", action="store_true", help="Use purl2repo strict mode"
    )
    parser.add_argument(
        "--no-network", action="store_true", help="Disable network access"
    )
    parser.add_argument(
        "--verify-release-links",
        action="store_true",
        help="Verify inferred version-specific release links",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="HTTP timeout in seconds"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.verbose)

    sbom_data = load_cyclonedx_sbom(args.sbom_file_path)
    with Resolver(
        timeout=args.timeout,
        strict=args.strict,
        no_network=args.no_network,
        verify_release_links=args.verify_release_links,
    ) as resolver:
        results = resolve_sbom(sbom_data, resolver)

    if args.json:
        print(results_to_json(results, pretty=args.pretty))
    else:
        print_human(results)
    return 0


def _result_from_resolution(
    component_name: str | None,
    resolution: ResolutionResult,
) -> SbomRepositoryResult:
    release = resolution.release_link
    return SbomRepositoryResult(
        component_name=component_name,
        purl=resolution.purl.raw,
        package_name=resolution.purl.name,
        version=resolution.purl.version,
        repository_url=resolution.repository_url,
        repository_kind=resolution.repository_kind,
        repository_type=resolution.repository_type,
        release_url=release.url if release else None,
        release_kind=release.kind if release else None,
        confidence=resolution.confidence,
        evidence=resolution.evidence,
        warnings=resolution.warnings,
    )


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


if __name__ == "__main__":
    raise SystemExit(main())
