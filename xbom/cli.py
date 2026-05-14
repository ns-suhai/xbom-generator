"""CLI entry point for xBOM generator."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click

from xbom import __version__
from xbom.assembler import to_json
from xbom.models.bom_types import SafeLevel
from xbom.scanner import scan_directory, scan_package
from xbom.unpacker import DEFAULT_MAX_EXTRACT_BYTES

# ANSI color codes for terminal output
_COLORS = {
    SafeLevel.EXCELLENT: "green",
    SafeLevel.GOOD: "cyan",
    SafeLevel.MODERATE: "yellow",
    SafeLevel.NEEDS_WORK: "bright_red",
    SafeLevel.CRITICAL: "red",
}


def _parse_size(value: str) -> int:
    """Parse a human-readable size string (e.g., '1GB', '500MB')."""
    value = value.strip().upper()
    multipliers = {"KB": 1024, "MB": 1024**2, "GB": 1024**3}
    for suffix, mult in multipliers.items():
        if value.endswith(suffix):
            return int(float(value[:-len(suffix)]) * mult)
    return int(value)


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """xBOM Generator - Extended Bill of Materials from binary analysis."""
    pass


@main.command()
@click.argument("package_path", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["json", "html", "both"]),
              default="json", help="Output format.")
@click.option("--output-dir", type=click.Path(), default="./xbom-output",
              help="Output directory.")
@click.option("--enrich", is_flag=True, help="Enable Netskope telemetry enrichment.")
@click.option("--validate-secrets", is_flag=True,
              help="Enable live secret validation (requires network).")
@click.option("--max-extract-size", default="1GB",
              help="Max extraction size (e.g., '1GB', '500MB').")
@click.option("--skip-analyzers", default="",
              help="Comma-separated analyzer names to skip.")
@click.option("--verbose", is_flag=True, help="Enable verbose logging.")
def scan(
    package_path: str,
    output_format: str,
    output_dir: str,
    enrich: bool,
    validate_secrets: bool,
    max_extract_size: str,
    skip_analyzers: str,
    verbose: bool,
) -> None:
    """Scan a package file or directory and generate xBOM report.

    PACKAGE_PATH can be a binary package (zip, tar.gz, jar, etc.) or a directory.
    When a directory is provided, it is scanned directly without unpacking.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    pkg = Path(package_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    max_bytes = _parse_size(max_extract_size)
    skip = set(s.strip() for s in skip_analyzers.split(",") if s.strip())

    is_directory = pkg.is_dir()
    click.echo(f"Scanning {pkg.name}{'/' if is_directory else ''}...")
    if not is_directory:
        click.echo("  Unpacking... ", nl=False)

    try:
        if is_directory:
            result = scan_directory(
                directory=pkg,
                skip_analyzers=skip,
                enrich=enrich,
            )
        else:
            result = scan_package(
                package_path=pkg,
                max_extract_bytes=max_bytes,
                skip_analyzers=skip,
                enrich=enrich,
            )
    except Exception as exc:
        click.secho(f"\nError: {exc}", fg="red", err=True)
        sys.exit(1)

    if not is_directory:
        click.echo("done.")

    # Determine output name: prefer skill name, fall back to directory/file name
    output_name = pkg.stem
    if output_name == "input" and result.skill_entries:
        # Docker mount uses /input — use skill name instead
        output_name = result.skill_entries[0].name
    elif is_directory and result.skill_entries:
        # For directory scans, prefer skill name over directory name
        output_name = result.skill_entries[0].name

    # Print summary
    color = _COLORS.get(result.safe_level, "white")
    click.echo()
    click.secho(
        f"  SAFE {result.safe_level.value} - {result.safe_level.label} "
        f"(score: {result.risk_score:.2f})",
        fg=color, bold=True,
    )
    click.echo()
    click.echo(f"  SBOM:    {len(result.sbom_entries)} components")
    click.echo(f"  SaaSBOM: {len(result.saasbom_entries)} services")
    click.echo(f"  ML-BOM:  {len(result.mlbom_entries)} models")
    click.echo(f"  CBOM:    {len(result.cbom_entries)} crypto assets")
    click.echo(f"  Secrets: {len(result.secrets_entries)} findings")
    if result.skill_entries:
        clean = sum(1 for e in result.skill_entries if e.metadata.get("finding_count", 0) == 0)
        flagged = len(result.skill_entries) - clean
        parts = []
        if clean:
            parts.append(f"{clean} clean")
        if flagged:
            severities = [e.metadata.get("max_severity", "") for e in result.skill_entries if e.metadata.get("finding_count", 0) > 0]
            max_sev = max(severities, key=lambda s: {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(s or "", 0), default="")
            parts.append(f"{flagged} {max_sev}")
        click.echo(f"  Skills:  {len(result.skill_entries)} files ({', '.join(parts)})")
    click.echo(f"  Duration: {result.scan_duration_ms}ms")

    if result.warnings:
        click.echo()
        for w in result.warnings:
            click.secho(f"  Warning: {w}", fg="yellow")

    if result.errors:
        click.echo()
        for e in result.errors:
            click.secho(f"  Error: {e}", fg="red")

    # Write outputs
    if output_format in ("json", "both"):
        json_path = out / f"xbom-{output_name}.json"
        json_path.write_text(to_json(result))
        click.echo(f"\n  CycloneDX JSON: {json_path}")

    if output_format in ("html", "both"):
        try:
            from xbom.report.html_generator import generate_html_report
            html_path = out / f"xbom-{output_name}.html"
            html_path.write_text(generate_html_report(result))
            click.echo(f"  HTML Report:    {html_path}")
        except ImportError:
            click.secho("  HTML report generator not available", fg="yellow")

    click.echo()


if __name__ == "__main__":
    main()
