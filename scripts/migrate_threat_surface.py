#!/usr/bin/env python3
"""Migrate threat surface vocab from deprecated domains/platforms/targets into threat.surface."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString

DOMAIN_MAP: dict[str, str | None] = {
    "Embedded": "Embedded",
    "Enterprise": None,
    "Industrial": "Industrial",
    "IoT": "Industrial IoT::IoT Gateways",
    "Mobile": "Mobile",
    "Networking": None,
    "OSINT": "Attack Surface Management",
    "Private Cloud": None,
    "Public Cloud": None,
    "SaaS": None,
}

PLATFORM_MAP: dict[str, str | None] = {
    "AD FS": "Active Directory::Federation Services",
    "AWS": "AWS",
    "AWS EC2": "AWS::Compute::EC2",
    "AWS ECS": "AWS::Compute::ECS",
    "AWS EKS": "AWS::Compute::EKS",
    "AWS Fargate": "AWS::Compute::Fargate",
    "AWS IAM": "AWS::Security::IAM",
    "AWS Lambda": "AWS::Compute::Lambda",
    "AWS VPC": "AWS::Networking::VPC",
    "Active Directory": "Active Directory",
    "Android": "Mobile::Android",
    "Apache HTTP Server": "Web Servers::Apache HTTP",
    "Azure": "Azure",
    "Azure AD": "Azure::Security::Entra ID",
    "Azure AKS": "Azure::Compute::Kubernetes Service",
    "Bitbucket": "Atlassian::Bitbucket",
    "Blob Storage": "Azure::Storage::Blob Storage",
    "Confluence": "Atlassian::Confluence",
    "Docker Engine": "Container Runtime::Docker",
    "Exchange": "Microsoft::Exchange",
    "Github": "Code Repositories::GitHub",
    "Gitlab": "Code Repositories::GitLab",
    "Google Workspace": "Google Workspace",
    "IBM Cloud Kubernetes": "IBM Cloud",
    "JIRA": "Atlassian::Jira",
    "Kubernetes": "Orchestration::Kubernetes",
    "Linux": "Linux",
    "Microsoft SharePoint": "Microsoft::SharePoint",
    "Microsoft Teams": "Microsoft::Teams",
    "MySQL": "Database Management::MySQL",
    "NGINX": "Web Servers::NGINX",
    "Network Router": "Routers",
    "OVHcloud": None,
    "Office 365": "Microsoft::Microsoft 365",
    "Oracle Container Engine": "OCI::Container Engine",
    "Outlook Web Access": "Microsoft::Outlook",
    "Placeholder": None,
    "Postgress": "Database Management::PostgreSQL",
    "PowerShell": "Windows",
    "Sysdig Backend": None,
    "VMWare": "Virtualisation::VMware ESXi",
    "VMware Tanzu": "Orchestration::Kubernetes",
    "Windows": "Windows",
    "iOS": "Mobile::iOS",
    "macOS": "macOS",
}

TARGET_MAP: dict[str, str | None] = {
    "API Endpoints": "Application Layer::HTTP",
    "Auth token": "OAuth / OIDC",
    "CI/CD Pipelines": "Development::CI/CD",
    "Call center": "Customer Support",
    "Cloud Portal": "Azure",
    "Cloud Storage Accounts": "AWS::Storage",
    "Code Repositories": "Code Repositories",
    "Compute Cluster": "Orchestration::Kubernetes",
    "Control Server": "Remote Access",
    "Critical Documents": "File Sharing",
    "Customer": "Customer Support",
    "DNS": "Domain Name System::DNS",
    "Data Historian": "Industrial",
    "Desktop": "Windows::Desktop",
    "Developer": "Development",
    "Development Pipelines": "Development::CI/CD",
    "Directory": "Active Directory",
    "Disk drive": "AWS::Storage::EBS",
    "Documents": "File Sharing",
    "Email Platform": "Email",
    "End-user": "Windows::Desktop",
    "Engineering Workstation": "Windows::Desktop",
    "Executive": "Windows::Desktop",
    "Firewall": "Firewalls",
    "Firmware": "Embedded",
    "Former employee": None,
    "Function-as-a-Service": "Serverless",
    "Helpdesk": "Customer Support",
    "IDS": "Network Security::IDS",
    "IaaS": "AWS::Compute::EC2",
    "Identity Services": "Entra ID",
    "Input/Output Server": "Windows::Server",
    "Key Store": "Azure::Security::Key Vault",
    "LAN": "Data Link Layer::VLAN",
    "Laptop": "Windows::Desktop",
    "Manager": None,
    "Media": None,
    "Microservices": "Orchestration::Kubernetes",
    "Mobile phone": "Mobile",
    "Network Equipment": "Switches",
    "NoSQL Database": "Database Management::MongoDB",
    "Other": None,
    "Partner": None,
    "Peripheral": "Printers::Multi-Function Peripherals",
    "Personal Information": None,
    "Production Database": "Database Management",
    "Production Software": "Microsoft",
    "Public-Facing Servers": "Web Servers",
    "Relational Database": "Database Management::PostgreSQL",
    "Remote access": "Remote Access",
    "Router or switch": "Routers",
    "SAML-Joined Applications": "Security::SAML",
    "Server Authentication": "Kerberos",
    "Server Backup": "AWS::Storage",
    "Server Logs": "Log Management",
    "Serverless": "Serverless",
    "Software Containers": "Container Runtime::Docker",
    "Software Development Tools": "Development",
    "System admin": "Microsoft::System Center",
    "Tablet": "Mobile::iPadOS",
    "VPN Client": "VPN",
    "Virtual Machines": "Azure::Compute::Virtual Machines",
    "Virtual Machines Host": "Virtualisation::VMware ESXi",
    "Web Application Servers": "Web Servers",
    "Windows API": "Application Layer::WMI",
    "Workstations": "Windows::Desktop",
}

SURFACE_ALIAS_MAP: dict[str, str] = {
    "OS::Windows::Desktop": "Windows::Desktop",
    "OS::Windows": "Windows",
    "OS::macOS": "macOS",
    "OS::Linux": "Linux",
    "Application::Development::Package Management::npm": "Development::Package Management::npm",
    "Application::Development::Package Management::PyPI": "Development::Package Management::PyPI",
    "Application::Development::CI/CD::GitHub Actions": "Development::CI/CD::GitHub Actions",
    "Application::Development::CI/CD": "Development::CI/CD",
}

MANUAL_TERRAIN_SURFACES: dict[str, list[str]] = {
    "client-controlled-session-state-authentication-bypass.yaml": [
        "Web Servers",
        "Application Layer::HTTP",
        "OAuth / OIDC",
    ],
    "late-access-control-enforcement-via-redirect-body-leakage.yaml": [
        "Web Servers",
        "Application Layer::HTTP",
    ],
    "unauthorized-account-provisioning-via-exposed-registration-flow.yaml": [
        "Web Servers",
        "Application Layer::HTTP",
        "Entra ID",
    ],
}

LABEL_PATTERN = re.compile(r"^(Domains|Platforms|Targets|Surface):\s*(.+)$", re.MULTILINE)
SPLIT_PATTERN = re.compile(r",\s*")

_yaml = YAML()
_yaml.default_flow_style = False
_yaml.width = 4096
_yaml.indent(mapping=2, sequence=4, offset=2)


def _load_surface_vocab(path: Path) -> set[str]:
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    return {str(entry["name"]) for entry in raw.get("keys", []) if entry.get("name")}


def _wrap_literal(value: Any) -> Any:
    if isinstance(value, str) and "\n" in value:
        return LiteralScalarString(value.rstrip("\n"))
    if isinstance(value, dict):
        return {key: _wrap_literal(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_wrap_literal(item) for item in value]
    return value


def _dump_yaml(path: Path, data: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        _yaml.dump(_wrap_literal(data), handle)


def _normalize_surface(value: str) -> str:
    cleaned = value.strip()
    if cleaned in SURFACE_ALIAS_MAP:
        return SURFACE_ALIAS_MAP[cleaned]
    for prefix in ("Application::", "OS::"):
        if cleaned.startswith(prefix):
            stripped = cleaned.removeprefix(prefix)
            if stripped in SURFACE_ALIAS_MAP:
                return SURFACE_ALIAS_MAP[stripped]
            return stripped
    return cleaned


def _parse_label_lines(terrain: str) -> tuple[str, dict[str, list[str]]]:
    labels: dict[str, list[str]] = {}
    first_label = None
    for match in LABEL_PATTERN.finditer(terrain):
        if first_label is None:
            first_label = match.start()
        label = match.group(1)
        values = [part.strip() for part in SPLIT_PATTERN.split(match.group(2).strip()) if part.strip()]
        labels[label] = values
    narrative = terrain[:first_label].strip() if first_label is not None else terrain.strip()
    return narrative, labels


def _map_values(values: list[str], mapping: dict[str, str | None]) -> list[str]:
    mapped: list[str] = []
    for value in values:
        target = mapping.get(value)
        if target:
            mapped.append(target)
    return mapped


def _surface_values_from_labels(labels: dict[str, list[str]]) -> list[str]:
    surfaces: list[str] = []
    for label, mapping in (
        ("Domains", DOMAIN_MAP),
        ("Platforms", PLATFORM_MAP),
        ("Targets", TARGET_MAP),
        ("Surface", {}),
    ):
        if label == "Surface":
            surfaces.extend(_normalize_surface(item) for item in labels.get("Surface", []))
            continue
        surfaces.extend(_map_values(labels.get(label, []), mapping))
    deduped: list[str] = []
    seen: set[str] = set()
    for item in surfaces:
        normalized = _normalize_surface(item)
        if normalized not in seen:
            deduped.append(normalized)
            seen.add(normalized)
    return deduped


def _reorder_threat_block(threat: dict[str, Any]) -> dict[str, Any]:
    """Place surface immediately after terrain; preserve all other key order."""
    keys = list(threat.keys())
    if "terrain" not in keys:
        return threat

    terrain_idx = keys.index("terrain")
    before = keys[:terrain_idx]
    after = [key for key in keys[terrain_idx + 1 :] if key != "surface"]

    ordered_keys = [*before, "terrain"]
    if "surface" in threat:
        ordered_keys.append("surface")
    ordered_keys.extend(after)
    return {key: threat[key] for key in ordered_keys}


def reorder_threat(data: dict[str, Any]) -> dict[str, Any]:
    threat = data.get("threat")
    if isinstance(threat, dict):
        data["threat"] = _reorder_threat_block(threat)
    return data


def migrate_threat(data: dict[str, Any], *, allowed: set[str], source_name: str = "") -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    threat = data.get("threat")
    if not isinstance(threat, dict):
        return data, issues

    for deprecated in ("domains", "platforms", "targets"):
        if deprecated in threat:
            issues.append(f"removed deprecated threat.{deprecated}")

    terrain_raw = threat.get("terrain")
    existing_surface = threat.get("surface")

    if isinstance(terrain_raw, list):
        # Recover from a prior bad migration that stored surface vocab in terrain.
        surfaces = [str(item).strip() for item in terrain_raw if str(item).strip()]
        narrative = ""
        issues.append("recovered surface values from terrain list — restore terrain narrative from source")
    elif isinstance(existing_surface, list) and existing_surface:
        surfaces = [str(item).strip() for item in existing_surface if str(item).strip()]
        terrain_text = str(terrain_raw or "")
        narrative, labels = _parse_label_lines(terrain_text)
        if any(key in labels for key in ("Domains", "Platforms", "Targets", "Surface")):
            label_surfaces = _surface_values_from_labels(labels)
            if label_surfaces:
                surfaces = label_surfaces
    else:
        terrain_text = str(terrain_raw or "")
        narrative, labels = _parse_label_lines(terrain_text)
        if any(key in labels for key in ("Domains", "Platforms", "Targets")):
            surfaces = _surface_values_from_labels(labels)
        elif labels.get("Surface"):
            surfaces = _surface_values_from_labels(labels)
        elif terrain_text.strip() and not LABEL_PATTERN.search(terrain_text):
            manual = MANUAL_TERRAIN_SURFACES.get(source_name, [])
            if manual:
                surfaces = manual
            else:
                issues.append("terrain narrative without surface labels — manual review")
                surfaces = []
        else:
            surfaces = _surface_values_from_labels(labels)

    invalid = [value for value in surfaces if value not in allowed]
    if invalid:
        issues.append(f"invalid surface values: {', '.join(invalid)}")
    if not surfaces:
        issues.append("no surface values resolved")
    if not narrative.strip():
        issues.append("empty terrain narrative")

    threat["terrain"] = narrative
    threat["surface"] = surfaces
    for deprecated in ("domains", "platforms", "targets"):
        threat.pop(deprecated, None)
    data["threat"] = _reorder_threat_block(threat)
    return data, issues


def reorder_tree(threats_dir: Path, *, dry_run: bool = False) -> int:
    count = 0
    for path in sorted(threats_dir.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        reordered = reorder_threat(data)
        if not dry_run:
            _dump_yaml(path, reordered)
        count += 1
    return count


def migrate_tree(
    threats_dir: Path,
    *,
    surface_vocab: Path,
    dry_run: bool = False,
) -> dict[str, int]:
    allowed = _load_surface_vocab(surface_vocab)
    counts = {"migrated": 0, "issues": 0}
    issue_rows: list[str] = []

    for path in sorted(threats_dir.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        migrated, issues = migrate_threat(data, allowed=allowed, source_name=path.name)
        if issues:
            counts["issues"] += 1
            issue_rows.append(f"{path.name}: {'; '.join(issues)}")
        if not dry_run:
            _dump_yaml(path, migrated)
        counts["migrated"] += 1

    if issue_rows:
        print("Migration issues:", file=sys.stderr)
        for row in issue_rows:
            print(f"  - {row}", file=sys.stderr)
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--threats-dir",
        type=Path,
        default=Path("objects/threats"),
        help="Threat YAML directory",
    )
    parser.add_argument(
        "--surface-vocab",
        type=Path,
        default=Path("../opentide/src/opentide/data/vocabulary/surface.vocab.toml"),
        help="surface.vocab.toml for validation",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--reorder-only",
        action="store_true",
        help="Only reorder threat block keys (surface after terrain); do not migrate",
    )
    args = parser.parse_args()

    threats_dir = args.threats_dir.resolve()
    surface_vocab = args.surface_vocab.resolve()
    if not threats_dir.is_dir():
        raise SystemExit(f"Threats directory not found: {threats_dir}")
    if args.reorder_only:
        count = reorder_tree(threats_dir, dry_run=args.dry_run)
        print(f"Reordered {count} threats")
        return
    if not surface_vocab.is_file():
        raise SystemExit(f"Surface vocabulary not found: {surface_vocab}")

    counts = migrate_tree(threats_dir, surface_vocab=surface_vocab, dry_run=args.dry_run)
    print(f"Migrated {counts['migrated']} threats ({counts['issues']} with issues)")


if __name__ == "__main__":
    main()
