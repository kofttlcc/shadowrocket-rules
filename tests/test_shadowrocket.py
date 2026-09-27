"""Regression checks for category completeness, source integrity and routing."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_shadowrocket.py"
SPEC = importlib.util.spec_from_file_location("build_shadowrocket", SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
EXPECTED_CATEGORIES = {
    "private", "reject", "icloud", "apple", "google", "proxy", "direct",
    "gfw", "greatfire", "tld-not-cn", "telegramcidr", "cncidr",
}


class RuleValidationTests(unittest.TestCase):
    def test_domain_identity_order_deduplication_and_idna(self):
        data = b"# header\nDOMAIN,Example.com\nDOMAIN-SUFFIX,example.com\nDOMAIN,example.com\n"
        result = builder.convert_rules(data, "proxy")
        self.assertEqual(result.content, b"DOMAIN,example.com\nDOMAIN-SUFFIX,example.com\n")
        self.assertEqual((result.input_rule_count, result.output_rule_count), (3, 2))
        self.assertEqual(builder.domain_name("例子.測試"), "xn--fsqu00a.xn--g6w251d")

    def test_ipv6_conversion_preserves_source_dns_flags(self):
        raw = b"IP-CIDR,1.0.0.0/24\nIP-CIDR6,2400:3200::/32\nIP-CIDR6,2401::/16,no-resolve\n"
        expected = b"IP-CIDR,1.0.0.0/24\nIP-CIDR,2400:3200::/32\nIP-CIDR,2401::/16,no-resolve\n"
        for category in ("cncidr", "telegramcidr"):
            with self.subTest(category=category):
                self.assertEqual(builder.convert_rules(raw, category).content, expected)

    def test_cidr_normalization_deduplicates_only_equivalent_rules(self):
        raw = b"IP-CIDR6,2400:0320::/32\nIP-CIDR,2400:320:0:0::/32\nIP-CIDR,2400:320::/32,no-resolve\n"
        result = builder.convert_rules(raw, "telegramcidr")
        self.assertEqual(result.content, b"IP-CIDR,2400:320::/32\nIP-CIDR,2400:320::/32,no-resolve\n")
        self.assertEqual((result.input_rule_count, result.output_rule_count), (3, 2))

    def test_rejects_invalid_data_instead_of_silently_skipping(self):
        cases = [
            (b"", "proxy"), (b"# only comments\n", "proxy"),
            (b"<!DOCTYPE html>\n<html>502</html>", "proxy"),
            (b"DOMAIN-SUFFIX,valid.com\nURL-REGEX,.*", "proxy"),
            (b"DOMAIN-SUFFIX,example.com,PROXY", "proxy"),
            (b"DOMAIN-SUFFIX,.example.com", "proxy"),
            (b"DOMAIN,https://example.com", "proxy"),
            (b"DOMAIN,example.com/path", "proxy"),
            (b"DOMAIN,*.example.com", "proxy"),
            (b"DOMAIN,example..com", "proxy"),
            (b"DOMAIN,-example.com", "proxy"),
            (b"DOMAIN,127.0.0.1", "proxy"),
            (b"DOMAIN,ex ample.com", "proxy"),
            (b"DOMAIN,example.com\x00", "proxy"),
            (b"\xff", "proxy"),
            (b"IP-CIDR,10.0.0.1/8", "cncidr"),
            (b"IP-CIDR,10.0.0.0/33", "cncidr"),
            (b"IP-CIDR,10.0.0.1", "cncidr"),
            (b"IP-CIDR6,10.0.0.0/8", "cncidr"),
            (b"IP-CIDR,10.0.0.0/8,DIRECT", "cncidr"),
            (b"IP-CIDR,10.0.0.0/8,no-resolve,extra", "cncidr"),
            (b"DOMAIN,example.com", "cncidr"),
            (b"IP-CIDR,10.0.0.0/8", "proxy"),
            (b"DOMAIN,example.com", "unknown"),
        ]
        for data, name in cases:
            with self.subTest(data=data, name=name):
                with self.assertRaises(builder.ValidationError):
                    builder.convert_rules(data, name)


class BuildTests(unittest.TestCase):
    SHA = "0123456789abcdef0123456789abcdef01234567"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.output = self.root / "output"
        (self.source / "ruleset").mkdir(parents=True)
        for name in EXPECTED_CATEGORIES:
            content = "IP-CIDR,1.0.0.0/24\nIP-CIDR6,2400::/12\n" if name in {"cncidr", "telegramcidr"} else "DOMAIN-SUFFIX,example.com\n"
            (self.source / "ruleset" / f"{name}.txt").write_text(content)
        (self.source / "LICENSE").write_text("Fixture upstream license\n")

    def build(self, output=None):
        return builder.build(self.source, output or self.output, self.SHA)

    def test_complete_reproducible_outputs_and_source_hashes(self):
        metadata = self.build()
        second = self.root / "second"
        self.build(second)
        files = {path.relative_to(self.output).as_posix() for path in self.output.rglob("*") if path.is_file()}
        expected_rules = {f"{name}.txt" for name in EXPECTED_CATEGORIES} | {f"ruleset/{name}.txt" for name in EXPECTED_CATEGORIES}
        self.assertEqual(set(builder.RULE_NAMES), EXPECTED_CATEGORIES)
        self.assertEqual(set(metadata["rules"]), EXPECTED_CATEGORIES)
        self.assertEqual(files, expected_rules | {"LICENSE", "README.md", "shadowrocket.conf", "shadowrocket-blacklist.conf", "metadata.json"})
        for relative in files:
            self.assertEqual((self.output / relative).read_bytes(), (second / relative).read_bytes())
        self.assertEqual(json.loads((self.output / "metadata.json").read_text()), metadata)
        for name, record in metadata["rules"].items():
            self.assertEqual(record["input"], f"ruleset/{name}.txt")
            source_bytes = (self.source / record["input"]).read_bytes()
            self.assertEqual(record["input_sha256"], builder.sha256(source_bytes))
            self.assertEqual(record["input_rule_count"], len(source_bytes.splitlines()))
            self.assertEqual(set(record["outputs"]), {f"{name}.txt", f"ruleset/{name}.txt"})
            root_bytes = (self.output / f"{name}.txt").read_bytes()
            self.assertEqual(root_bytes, (self.output / f"ruleset/{name}.txt").read_bytes())
            self.assertEqual(record["output_rule_count"], len(root_bytes.splitlines()))
            self.assertEqual(record["duplicates_removed"], 0)
            for relative, output_record in record["outputs"].items():
                output_bytes = (self.output / relative).read_bytes()
                self.assertEqual(output_record, {"sha256": builder.sha256(output_bytes), "bytes": len(output_bytes)})
                self.assertTrue(all(line.startswith((b"DOMAIN,", b"DOMAIN-SUFFIX,", b"IP-CIDR,")) for line in output_bytes.splitlines()))
                self.assertNotIn(b"IP-CIDR6", output_bytes)
        for relative, record in metadata["artifacts"].items():
            data = (self.output / relative).read_bytes()
            self.assertEqual(record, {"sha256": builder.sha256(data), "bytes": len(data)})
        self.assertEqual((self.output / "LICENSE").read_bytes(), (self.source / "LICENSE").read_bytes())
        self.assertEqual((self.output / "README.md").read_bytes(), (builder.PROJECT_ROOT / "README.md").read_bytes())
        self.assertEqual(metadata["upstream"]["sha"], self.SHA)
        self.assertEqual(metadata["repository"], "kofttlcc/shadowrocket-rules")
        self.assertEqual(metadata["release_branch"], "release")

    def test_missing_or_late_invalid_input_leaves_output_unwritten(self):
        (self.source / "ruleset" / "cncidr.txt").write_text("<html>upstream error</html>")
        with self.assertRaises(builder.ValidationError):
            self.build()
        self.assertFalse(self.output.exists())
        (self.source / "ruleset" / "cncidr.txt").unlink()
        with self.assertRaises(builder.ValidationError):
            self.build()
        self.assertFalse(self.output.exists())

    def test_missing_readme_leaves_output_unwritten(self):
        with patch.object(builder, "PROJECT_ROOT", self.root):
            with self.assertRaises(builder.ValidationError):
                self.build()
        self.assertFalse(self.output.exists())

    def test_rejects_partial_sha_repository_injection_and_source_overwrite(self):
        for sha, repository in [("0123456", "owner/repo"), (self.SHA, "owner/repo\nFINAL,DIRECT")]:
            with self.subTest(sha=sha, repository=repository):
                with self.assertRaises(builder.ValidationError):
                    builder.build(self.source, self.output, sha, repository)
        with self.assertRaises(builder.ValidationError):
            builder.build(self.source, self.source, self.SHA)
        self.assertFalse(self.output.exists())

    def test_config_routing_preserves_both_upstream_policies(self):
        self.build()
        expected_policies = {
            "shadowrocket.conf": ([
                ("private", "DIRECT"), ("reject", "REJECT"), ("icloud", "DIRECT"),
                ("apple", "DIRECT"), ("google", "DIRECT"), ("proxy", "PROXY"),
                ("direct", "DIRECT"), ("telegramcidr", "PROXY"), ("cncidr", "DIRECT"),
            ], "FINAL,PROXY"),
            "shadowrocket-blacklist.conf": ([
                ("private", "DIRECT"), ("reject", "REJECT"), ("tld-not-cn", "PROXY"),
                ("gfw", "PROXY"), ("telegramcidr", "PROXY"),
            ], "FINAL,DIRECT"),
        }
        base = "https://raw.githubusercontent.com/kofttlcc/shadowrocket-rules/release/ruleset"
        for filename, (policies, final_rule) in expected_policies.items():
            with self.subTest(filename=filename):
                config = (self.output / filename).read_text()
                general, rule_section = config.split("[Rule]\n", 1)
                self.assertIn("dns-server = system", general)
                self.assertIn("ipv6 = true", general)
                self.assertIn("prefer-ipv6 = false", general)
                self.assertIn("private-ip-answer = true", general)
                rules = [line for line in rule_section.splitlines() if line and not line.startswith("#")]
                remote_rules = [line for line in rules if line.startswith("RULE-SET,")]
                self.assertEqual(remote_rules, [f"RULE-SET,{base}/{name}.txt,{policy}" for name, policy in policies])
                self.assertEqual(rules[:len(remote_rules)], remote_rules)
                self.assertEqual(rules[-1], final_rule)
                self.assertIn("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", rules)
                self.assertIn("IP-CIDR,fc00::/7,DIRECT,no-resolve", rules)
                for unsupported in ["[Proxy]", "[Proxy Group]", "PROCESS-NAME", "force-remote-dns", "dns-failed", "IP-CIDR6", "SYSTEM", "LAN,", "custom-direct", "shadowrocket-release", "kofttlcc/surge-rules"]:
                    self.assertNotIn(unsupported, config)
        self.assertIn("upstream advises caution", (self.output / "shadowrocket.conf").read_text())


if __name__ == "__main__":
    unittest.main()
