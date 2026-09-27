#!/usr/bin/env python3
"""Build validated Shadowrocket rule sets from surge-rules/release.

Uses only the Python standard library. The 12 original categories and file
names are retained. Every .txt output contains typed Shadowrocket RULE-SET
entries, including those at the root of the release branch.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import NamedTuple


UPSTREAM_REPOSITORY = "Loyalsoldier/surge-rules"
DEFAULT_REPOSITORY = "kofttlcc/shadowrocket-rules"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULE_NAMES = (
    "private", "reject", "icloud", "apple", "google", "proxy", "direct",
    "gfw", "greatfire", "tld-not-cn", "telegramcidr", "cncidr",
)
CIDR_NAMES = frozenset({"telegramcidr", "cncidr"})
LAN_NETWORKS = (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)


class ValidationError(ValueError):
    """An input cannot safely be published as a Shadowrocket rule set."""


class ConvertedRules(NamedTuple):
    content: bytes
    input_rule_count: int
    output_rule_count: int


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def domain_name(value: str) -> str:
    """Validate a DNS name, including IDNA and underscore service labels.

    Wildcards, leading dots, URLs, ports, IP addresses, empty labels and
    whitespace are not valid domain operands in the accepted source syntax.
    """
    if not value or value != value.strip() or any(c.isspace() for c in value):
        raise ValidationError("empty domain or whitespace in domain")
    try:
        normalized = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValidationError("invalid IDNA domain") from exc
    if len(normalized) > 253:
        raise ValidationError("domain exceeds 253 characters")
    for label in normalized.split("."):
        if not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label):
            raise ValidationError(f"invalid DNS label: {label!r}")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        raise ValidationError("IP address supplied as a domain")
    return normalized


def active_lines(data: bytes, source_name: str):
    try:
        content = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{source_name}: input is not UTF-8") from exc
    for number, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "<" in line or ">" in line or "\x00" in line:
            raise ValidationError(f"{source_name}:{number}: HTML or invalid control data")
        yield number, line


def convert_rules(data: bytes, name: str) -> ConvertedRules:
    """Validate a category, normalize syntax, and deduplicate in source order.

    IPv6 uses Shadowrocket's IP-CIDR spelling. Optional no-resolve flags are
    preserved exactly in meaning; the converter never adds or removes them.
    """
    if name not in RULE_NAMES:
        raise ValidationError(f"unsupported rule category: {name!r}")
    output: list[str] = []
    seen: set[str] = set()
    input_count = 0
    for number, line in active_lines(data, name):
        input_count += 1
        try:
            fields = [field.strip() for field in line.split(",")]
            rule_type = fields[0]
            if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
                if name in CIDR_NAMES:
                    raise ValidationError("domain entry in a CIDR-only list")
                if len(fields) != 2:
                    raise ValidationError("domain rules require exactly two fields")
                result = f"{rule_type},{domain_name(fields[1])}"
            elif rule_type in {"IP-CIDR", "IP-CIDR6"}:
                if name not in CIDR_NAMES:
                    raise ValidationError("CIDR entry in a domain-only list")
                if len(fields) not in {2, 3} or (
                    len(fields) == 3 and fields[2] != "no-resolve"
                ):
                    raise ValidationError("CIDR rules accept only an optional no-resolve flag")
                if "/" not in fields[1]:
                    raise ValidationError("CIDR prefix length is required")
                try:
                    network = ipaddress.ip_network(fields[1], strict=True)
                except ValueError as exc:
                    raise ValidationError(f"invalid CIDR: {fields[1]!r}") from exc
                if rule_type == "IP-CIDR6" and network.version != 6:
                    raise ValidationError("IP-CIDR6 requires an IPv6 network")
                flag = ",no-resolve" if len(fields) == 3 else ""
                result = f"IP-CIDR,{network}{flag}"
            else:
                raise ValidationError(f"unsupported rule type: {rule_type!r}")
        except ValidationError as exc:
            raise ValidationError(f"{name}:{number}: {exc}") from exc
        if result not in seen:
            seen.add(result)
            output.append(result)
    if not output:
        raise ValidationError(f"{name}: required rule list is empty")
    return ConvertedRules(("\n".join(output) + "\n").encode(), input_count, len(output))


def configuration(repository: str, *, blacklist: bool = False) -> bytes:
    base = f"https://raw.githubusercontent.com/{repository}/release/ruleset"
    lines = [
        "# Shadowrocket for iOS — generated configuration",
        "# PROXY uses your existing selected node; this file contains no node credentials.",
        "# Select configuration routing mode in Shadowrocket.",
        "# Upstream blacklist policy: unmatched traffic is DIRECT." if blacklist else
        "# Upstream whitelist policy: unmatched traffic uses PROXY.",
        "", "[General]", "dns-server = system", "ipv6 = true",
        "prefer-ipv6 = false", "private-ip-answer = true", "", "[Rule]",
        f"RULE-SET,{base}/private.txt,DIRECT",
        f"RULE-SET,{base}/reject.txt,REJECT",
    ]
    if blacklist:
        lines.extend([
            f"RULE-SET,{base}/tld-not-cn.txt,PROXY",
            f"RULE-SET,{base}/gfw.txt,PROXY",
            f"RULE-SET,{base}/telegramcidr.txt,PROXY",
        ])
    else:
        lines.extend([
            f"RULE-SET,{base}/icloud.txt,DIRECT",
            f"RULE-SET,{base}/apple.txt,DIRECT",
            "# google.txt retains upstream DIRECT policy; upstream advises caution with this list.",
            f"RULE-SET,{base}/google.txt,DIRECT",
            f"RULE-SET,{base}/proxy.txt,PROXY",
            f"RULE-SET,{base}/direct.txt,DIRECT",
            f"RULE-SET,{base}/telegramcidr.txt,PROXY",
            f"RULE-SET,{base}/cncidr.txt,DIRECT",
        ])
    lines.append("# Literal LAN ranges use no-resolve to avoid triggering DNS for this check.")
    lines.extend(f"IP-CIDR,{network},DIRECT,no-resolve" for network in LAN_NETWORKS)
    lines.extend(["FINAL,DIRECT" if blacklist else "FINAL,PROXY", ""])
    return "\n".join(lines).encode("utf-8")


def build(
    source_dir: Path,
    output_dir: Path,
    upstream_sha: str,
    repository: str = DEFAULT_REPOSITORY,
) -> dict:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", upstream_sha):
        raise ValidationError("--upstream-sha must be a full 40-character Git SHA")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository):
        raise ValidationError("--repository must be owner/repository")
    upstream_sha = upstream_sha.lower()
    if source_dir.resolve() == output_dir.resolve():
        raise ValidationError("source and output directories must differ")
    artifacts: dict[str, bytes] = {}
    records: dict[str, dict] = {}
    for name in RULE_NAMES:
        relative_input = f"ruleset/{name}.txt"
        path = source_dir / relative_input
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ValidationError(f"cannot read required input {path}: {exc}") from exc
        converted = convert_rules(data, name)
        output_paths = (f"{name}.txt", relative_input)
        for relative in output_paths:
            artifacts[relative] = converted.content
        records[name] = {
            "input": relative_input,
            "input_sha256": sha256(data),
            "input_rule_count": converted.input_rule_count,
            "output_rule_count": converted.output_rule_count,
            "duplicates_removed": converted.input_rule_count - converted.output_rule_count,
            "outputs": {
                relative: {"sha256": sha256(converted.content), "bytes": len(converted.content)}
                for relative in output_paths
            },
        }
    license_path = source_dir / "LICENSE"
    if not license_path.is_file():
        license_path = PROJECT_ROOT / "LICENSE"
    for name, path in (("LICENSE", license_path), ("README.md", PROJECT_ROOT / "README.md")):
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise ValidationError(f"cannot read required {name}: {exc}") from exc
        if not content.strip():
            raise ValidationError(f"{name} is empty")
        artifacts[name] = content
    artifacts["shadowrocket.conf"] = configuration(repository)
    artifacts["shadowrocket-blacklist.conf"] = configuration(repository, blacklist=True)
    metadata = {
        "schema_version": 2,
        "upstream": {"repository": UPSTREAM_REPOSITORY, "branch": "release", "sha": upstream_sha},
        "repository": repository,
        "release_branch": "release",
        "rules": records,
        "artifacts": {
            name: {"sha256": sha256(content), "bytes": len(content)}
            for name, content in sorted(artifacts.items()) if not name.endswith(".txt")
        },
    }
    artifacts["metadata.json"] = (json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    # Validate and render every input before writing any release artifact.
    output_dir.mkdir(parents=True, exist_ok=True)
    for relative, content in artifacts.items():
        target = output_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return metadata


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--upstream-sha", required=True)
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    args = parser.parse_args(argv)
    try:
        metadata = build(args.source_dir, args.output_dir, args.upstream_sha, args.repository)
    except (ValidationError, OSError) as exc:
        print(f"Shadowrocket build failed: {exc}", file=sys.stderr)
        return 1
    count = sum(record["output_rule_count"] for record in metadata["rules"].values())
    print(f"Built {len(metadata['rules'])} rule categories ({count:,} rules; root and ruleset copies) in {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
