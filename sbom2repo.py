"""Resolve package URLs from CycloneDX SBOMs with purl2repo."""

from __future__ import annotations

import argparse
import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from purl2repo import Resolver
from purl2repo.errors import Purl2RepoError
from purl2repo.models import ResolutionResult

logger = logging.getLogger(__name__)

CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


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
    validated_repository: bool
    used_fallback: bool
    metadata_sources: list[str]
    evidence: list[str]
    warnings: list[str]
    error: str | None = None


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger.setLevel(logging.DEBUG if verbose else logging.WARNING)
    noisy_level = logging.INFO if verbose else logging.WARNING
    logging.getLogger("httpx").setLevel(noisy_level)
    logging.getLogger("httpcore").setLevel(noisy_level)


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
    *,
    repo_only: bool = False,
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
            resolution = (
                resolver.resolve_repository(purl)
                if repo_only
                else resolver.resolve(purl)
            )
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
                    validated_repository=False,
                    used_fallback=False,
                    metadata_sources=[],
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
            print(f"Validated: {'yes' if result.validated_repository else 'no'}")
            print(f"Fallback: {'yes' if result.used_fallback else 'no'}")
            if result.metadata_sources:
                print(f"Metadata sources: {', '.join(result.metadata_sources)}")
            if result.warnings:
                print("Warnings:")
                for warning in result.warnings:
                    print(f"- {warning}")
        print()


def print_summary(
    results: list[SbomRepositoryResult], *, elapsed_seconds: float
) -> None:
    total = len(results)
    resolved = sum(1 for result in results if result.repository_url)
    validated = sum(1 for result in results if result.validated_repository)
    errors = sum(1 for result in results if result.error)
    fallback = sum(1 for result in results if result.used_fallback)
    confidence_counts = {
        confidence: sum(1 for result in results if result.confidence == confidence)
        for confidence in ("high", "medium", "low", "none")
    }

    print("Summary:")
    print(f"- Components with purls: {total}")
    print(f"- Resolved repositories: {resolved}")
    print(f"- Validated repositories: {validated}")
    print(f"- Fallback-derived results: {fallback}")
    print(f"- Errors: {errors}")
    print(
        "- Confidence: "
        f"high={confidence_counts['high']}, "
        f"medium={confidence_counts['medium']}, "
        f"low={confidence_counts['low']}, "
        f"none={confidence_counts['none']}"
    )
    print(f"- Elapsed: {elapsed_seconds:.2f}s")


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
        "--repo-only",
        action="store_true",
        help="Resolve repositories only and skip release-link derivation",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help=(
            "Fast inventory mode: repository-only, skip repository validation, "
            "deps.dev fallback, and scraper fallback"
        ),
    )
    parser.add_argument(
        "--no-validate-repositories",
        dest="validate_repositories",
        action="store_false",
        default=True,
        help="Skip purl2repo repository URL validation checks",
    )
    parser.add_argument(
        "--no-deps-dev-fallback",
        dest="deps_dev_fallback",
        action="store_false",
        default=True,
        help="Skip purl2repo deps.dev third-party fallback lookups",
    )
    parser.add_argument(
        "--no-scraper-fallback",
        dest="scraper_fallback",
        action="store_false",
        default=True,
        help="Skip purl2repo bounded HTML fallback scraping",
    )
    parser.add_argument(
        "--min-confidence",
        choices=("none", "low", "medium", "high"),
        default="none",
        help="Only print non-error results at or above this confidence",
    )
    parser.add_argument(
        "--require-validated",
        action="store_true",
        help="Only print non-error results whose repository URL was validated",
    )
    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Do not print the human-readable run summary",
    )
    parser.add_argument("--timeout", type=float, help="HTTP timeout in seconds")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    validate_repositories = args.validate_repositories and not args.fast
    use_deps_dev_fallback = args.deps_dev_fallback and not args.fast
    use_scraper_fallback = args.scraper_fallback and not args.fast
    if args.require_validated and (
        args.fast or args.no_network or not validate_repositories
    ):
        parser.error(
            "--require-validated requires repository validation; it cannot be "
            "combined with --fast, --no-network, or --no-validate-repositories"
        )
    configure_logging(args.verbose)

    sbom_data = load_cyclonedx_sbom(args.sbom_file_path)
    timeout = args.timeout if args.timeout is not None else (3.0 if args.fast else 10.0)
    started = time.monotonic()
    with Resolver(
        timeout=timeout,
        strict=args.strict,
        no_network=args.no_network,
        verify_release_links=args.verify_release_links,
        validate_repositories=validate_repositories,
        use_deps_dev_fallback=use_deps_dev_fallback,
        use_scraper_fallback=use_scraper_fallback,
    ) as resolver:
        results = resolve_sbom(
            sbom_data, resolver, repo_only=args.repo_only or args.fast
        )
    elapsed_seconds = time.monotonic() - started
    filtered_results = filter_results(
        results,
        min_confidence=args.min_confidence,
        require_validated=args.require_validated,
    )

    if args.json:
        print(results_to_json(filtered_results, pretty=args.pretty))
    else:
        print_human(filtered_results)
        if not args.no_summary:
            print_summary(results, elapsed_seconds=elapsed_seconds)
    return 0


def filter_results(
    results: list[SbomRepositoryResult],
    *,
    min_confidence: str,
    require_validated: bool,
) -> list[SbomRepositoryResult]:
    min_rank = CONFIDENCE_RANK[min_confidence]
    filtered: list[SbomRepositoryResult] = []
    for result in results:
        if result.error:
            filtered.append(result)
            continue
        if CONFIDENCE_RANK.get(result.confidence, 0) < min_rank:
            continue
        if require_validated and not result.validated_repository:
            continue
        filtered.append(result)
    return filtered


def _result_from_resolution(
    component_name: str | None,
    resolution: ResolutionResult,
) -> SbomRepositoryResult:
    release = resolution.release_link
    validated_repository = bool(
        resolution.repository_url
        and f"Validated repository URL: {resolution.repository_url}"
        in resolution.evidence
    )
    fallback_text = " ".join(
        [*resolution.evidence, *resolution.warnings, *resolution.metadata_sources]
    ).lower()
    used_fallback = "fallback scraping" in fallback_text or "deps.dev" in fallback_text
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
        validated_repository=validated_repository,
        used_fallback=used_fallback,
        metadata_sources=resolution.metadata_sources,
        evidence=resolution.evidence,
        warnings=resolution.warnings,
    )


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


if __name__ == "__main__":
    raise SystemExit(main())
