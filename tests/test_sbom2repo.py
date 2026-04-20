from __future__ import annotations

import json

from purl2repo.errors import InvalidPurlError
from purl2repo.models import ParsedPurl, ReleaseLink, ResolutionResult

from sbom2repo import filter_results, load_cyclonedx_sbom, resolve_sbom, results_to_json


class FakeResolver:
    def resolve(self, purl: str) -> ResolutionResult:
        return self._resolve(purl)

    def resolve_repository(self, purl: str) -> ResolutionResult:
        return self._resolve(purl)

    def _resolve(self, purl: str) -> ResolutionResult:
        if purl == "bad":
            raise InvalidPurlError("invalid")
        parsed = ParsedPurl(
            raw=purl,
            type="github",
            namespace="package-url",
            name="purl-spec",
            version="1.0.0",
            qualifiers={},
            subpath=None,
        )
        release = ReleaseLink(
            url="https://github.com/package-url/purl-spec/releases/tag/1.0.0",
            kind="release",
            version="1.0.0",
            source="github",
        )
        return ResolutionResult(
            purl=parsed,
            repository_url="https://github.com/package-url/purl-spec",
            repository_type="github",
            repository_kind="source_code",
            repository_candidates=[],
            canonical_repository=None,
            release_link=release,
            version_reference=release,
            confidence="high",
            evidence=[
                "resolved",
                "Validated repository URL: https://github.com/package-url/purl-spec",
            ],
            warnings=[],
            metadata_sources=["github-direct"],
        )


def test_load_cyclonedx_sbom(tmp_path):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps({"components": []}), encoding="utf-8")

    assert load_cyclonedx_sbom(path) == {"components": []}


def test_resolve_sbom_maps_purl2repo_result():
    results = resolve_sbom(
        {
            "components": [
                {"name": "PURL Spec", "purl": "pkg:github/package-url/purl-spec@1.0.0"},
                {"name": "No PURL"},
            ]
        },
        FakeResolver(),
    )

    assert len(results) == 1
    assert results[0].component_name == "PURL Spec"
    assert results[0].package_name == "purl-spec"
    assert results[0].repository_url == "https://github.com/package-url/purl-spec"
    assert results[0].repository_kind == "source_code"
    assert (
        results[0].release_url
        == "https://github.com/package-url/purl-spec/releases/tag/1.0.0"
    )
    assert results[0].confidence == "high"
    assert results[0].validated_repository is True
    assert results[0].used_fallback is False
    assert results[0].metadata_sources == ["github-direct"]


def test_resolve_sbom_records_errors_per_component():
    results = resolve_sbom(
        {"components": [{"name": "Broken", "purl": "bad"}]}, FakeResolver()
    )

    assert results[0].component_name == "Broken"
    assert results[0].repository_url is None
    assert results[0].confidence == "none"
    assert results[0].error == "InvalidPurlError: invalid"


def test_resolve_sbom_can_run_repository_only():
    results = resolve_sbom(
        {
            "components": [
                {"name": "PURL Spec", "purl": "pkg:github/package-url/purl-spec@1.0.0"}
            ]
        },
        FakeResolver(),
        repo_only=True,
    )

    assert results[0].repository_url == "https://github.com/package-url/purl-spec"


def test_filter_results_keeps_errors_and_applies_quality_filters():
    results = resolve_sbom(
        {
            "components": [
                {"name": "PURL Spec", "purl": "pkg:github/package-url/purl-spec@1.0.0"},
                {"name": "Broken", "purl": "bad"},
            ]
        },
        FakeResolver(),
    )

    filtered = filter_results(results, min_confidence="high", require_validated=True)

    assert [result.component_name for result in filtered] == ["PURL Spec", "Broken"]


def test_results_to_json():
    results = resolve_sbom(
        {
            "components": [
                {"name": "PURL Spec", "purl": "pkg:github/package-url/purl-spec@1.0.0"}
            ]
        },
        FakeResolver(),
    )

    payload = json.loads(results_to_json(results, pretty=True))

    assert payload[0]["repository_url"] == "https://github.com/package-url/purl-spec"
