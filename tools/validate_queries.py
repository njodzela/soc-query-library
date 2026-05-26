#!/usr/bin/env python3
"""
validate_queries.py — SOC Query Library Validator
===================================================
Checks that:
  1. All 16 categories exist across all 5 SIEM platforms (file coverage)
  2. No query file is empty
  3. Each file contains a valid header block (Title, MITRE, Severity, Author)
  4. Platform-specific syntax markers are present (basic sanity check)

Usage:
  python3 tools/validate_queries.py               # Run from repo root
  python3 tools/validate_queries.py --verbose     # Show all checks
  python3 tools/validate_queries.py --fix-report  # Output a markdown gap report
"""

import os
import sys
import argparse
from pathlib import Path

# ─── Config ────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent

PLATFORMS = {
    "splunk":        {"ext": ".spl",   "comment": "`",   "syntax_markers": ["index=", "search ", "| stats", "| eval", "| where"]},
    "sentinel":      {"ext": ".kql",   "comment": "//",  "syntax_markers": ["| where", "| summarize", "| project", "| extend", "SigninLogs", "SecurityEvent", "DeviceProcessEvents"]},
    "qradar":        {"ext": ".aql",   "comment": "--",  "syntax_markers": ["SELECT", "FROM", "WHERE", "GROUP BY", "LAST "]},
    "google-secops": {"ext": ".yaral", "comment": "/*",  "syntax_markers": ["rule ", "condition:", "events:", "$e."]},
    "defender":      {"ext": ".kql",   "comment": "//",  "syntax_markers": ["| where", "| summarize", "| project", "DeviceProcessEvents", "DeviceNetworkEvents", "EmailEvents"]},
}

CATEGORIES = [
    "anomalous-process-execution",
    "brute-force-detection",
    "command-and-control",
    "credential-access",
    "data-exfiltration",
    "defense-evasion",
    "email-spoofing",
    "forwarding-rule-abuse",
    "impossible-travel",
    "lateral-movement",
    "persistence-mechanisms",
    "phishing-indicators",
    "privilege-escalation",
    "reconnaissance",
    "routine-threat-hunting",
    "spam-bot-detection",
]

REQUIRED_HEADER_FIELDS = ["Title", "MITRE", "Severity", "Author"]

# ─── Validator ─────────────────────────────────────────────────────────────────

class QueryValidator:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.errors = []
        self.warnings = []
        self.passed = 0
        self.total = 0

    def log(self, msg):
        if self.verbose:
            print(msg)

    def error(self, msg):
        self.errors.append(msg)
        print(f"  ❌ {msg}")

    def warn(self, msg):
        self.warnings.append(msg)
        print(f"  ⚠️  {msg}")

    def ok(self, msg):
        self.passed += 1
        self.log(f"  ✅ {msg}")

    def check_file_coverage(self):
        """Check that every category exists in every platform."""
        print("\n📂 Checking file coverage (16 categories × 5 platforms)...")
        missing = []
        for platform, config in PLATFORMS.items():
            ext = config["ext"]
            for category in CATEGORIES:
                self.total += 1
                filepath = REPO_ROOT / platform / f"{category}{ext}"
                if not filepath.exists():
                    self.error(f"MISSING: {platform}/{category}{ext}")
                    missing.append((platform, category))
                else:
                    self.ok(f"EXISTS:  {platform}/{category}{ext}")
        if not missing:
            print(f"  ✅ All 80 files present (16 categories × 5 platforms)")
        else:
            print(f"  ❌ {len(missing)} file(s) missing")
        return missing

    def check_file_not_empty(self, filepath: Path) -> bool:
        """Check that file has content beyond whitespace."""
        content = filepath.read_text(encoding="utf-8", errors="ignore").strip()
        if len(content) < 50:
            self.error(f"EMPTY/TOO SHORT: {filepath.relative_to(REPO_ROOT)} ({len(content)} chars)")
            return False
        return True

    def check_header_fields(self, filepath: Path, content: str) -> bool:
        """Check that required header fields exist in the file."""
        missing_fields = []
        for field in REQUIRED_HEADER_FIELDS:
            if field not in content:
                missing_fields.append(field)
        if missing_fields:
            self.warn(f"MISSING HEADER FIELDS {missing_fields}: {filepath.relative_to(REPO_ROOT)}")
            return False
        return True

    def check_syntax_markers(self, filepath: Path, content: str, platform: str) -> bool:
        """Check that at least one platform-specific syntax marker is present."""
        markers = PLATFORMS[platform]["syntax_markers"]
        found = any(marker.lower() in content.lower() for marker in markers)
        if not found:
            self.warn(f"NO SYNTAX MARKERS found (expected one of {markers}): {filepath.relative_to(REPO_ROOT)}")
            return False
        return True

    def check_all_files(self):
        """Run content checks on every query file."""
        print("\n📝 Checking file content (headers, syntax, non-empty)...")
        for platform, config in PLATFORMS.items():
            ext = config["ext"]
            platform_dir = REPO_ROOT / platform
            if not platform_dir.exists():
                self.error(f"PLATFORM DIRECTORY MISSING: {platform}/")
                continue
            for category in CATEGORIES:
                filepath = platform_dir / f"{category}{ext}"
                if not filepath.exists():
                    continue  # Already reported in coverage check
                self.total += 1
                content = filepath.read_text(encoding="utf-8", errors="ignore")

                empty_ok = self.check_file_not_empty(filepath)
                if not empty_ok:
                    continue

                header_ok = self.check_header_fields(filepath, content)
                syntax_ok = self.check_syntax_markers(filepath, content, platform)

                if empty_ok and header_ok and syntax_ok:
                    self.passed += 1
                    self.log(f"  ✅ {platform}/{category}{ext}")

    def generate_gap_report(self, missing: list) -> str:
        """Generate a markdown gap report for missing files."""
        if not missing:
            return "# ✅ No Gaps Found\n\nAll 80 query files are present across all 5 platforms."

        lines = ["# ⚠️ SOC Query Library — Gap Report\n"]
        lines.append(f"**{len(missing)} file(s) missing**\n")
        lines.append("| Platform | Category | Expected File |")
        lines.append("|----------|----------|---------------|")
        for platform, category in missing:
            ext = PLATFORMS[platform]["ext"]
            lines.append(f"| {platform} | {category} | `{platform}/{category}{ext}` |")
        lines.append("\n> Run `python3 tools/validate_queries.py` after adding missing files.")
        return "\n".join(lines)

    def run(self, fix_report=False):
        print("=" * 60)
        print("  SOC Query Library — Validation Report")
        print("=" * 60)

        missing = self.check_file_coverage()
        self.check_all_files()

        print("\n" + "=" * 60)
        print(f"  Results: {self.passed} passed · {len(self.warnings)} warnings · {len(self.errors)} errors")
        print("=" * 60)

        if fix_report and missing:
            report_path = REPO_ROOT / "docs" / "GAP-REPORT.md"
            report_path.write_text(self.generate_gap_report(missing), encoding="utf-8")
            print(f"\n📄 Gap report written to: {report_path.relative_to(REPO_ROOT)}")

        if self.errors:
            print("\n❌ Validation FAILED — fix errors above before pushing.")
            return False
        elif self.warnings:
            print("\n⚠️  Validation passed with warnings — review above.")
            return True
        else:
            print("\n✅ All checks passed. Library is clean.")
            return True


# ─── Entry Point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Validate SOC Query Library file coverage and basic syntax."
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all check results (not just failures)")
    parser.add_argument("--fix-report", action="store_true", help="Write a markdown gap report to docs/GAP-REPORT.md")
    args = parser.parse_args()

    validator = QueryValidator(verbose=args.verbose)
    success = validator.run(fix_report=args.fix_report)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
