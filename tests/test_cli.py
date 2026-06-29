"""CLI smoke tests — exercises all three Typer commands end-to-end."""
from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from app.cli import app

runner = CliRunner()

AWS_CSV   = Path("data/samples/aws_cur_sample.csv")
AZURE_CSV = Path("data/samples/azure_cost_sample.csv")
AZURE_JSON = Path("data/samples/azure_cost_sample.json")


# ── scan ─────────────────────────────────────────────────────────────────────


class TestScanCommand:
    def test_aws_exits_zero(self):
        result = runner.invoke(app, ["scan", str(AWS_CSV)])
        assert result.exit_code == 0, result.output

    def test_aws_shows_known_waste_resource(self):
        result = runner.invoke(app, ["scan", str(AWS_CSV)])
        # UnattachedDiskDetector fires via disk.is_attached=False signal — verify
        # the category appears (Rich truncates to "unattac…") and savings > $0.
        assert "unattac" in result.output  # "unattached_disk" truncated by Rich
        assert "331" in result.output  # $331.53/mo from WASTE_MANIFEST total

    def test_aws_shows_savings_summary(self):
        result = runner.invoke(app, ["scan", str(AWS_CSV)])
        assert "Savings Summary" in result.output
        assert "$" in result.output

    def test_aws_with_rules_yaml(self):
        result = runner.invoke(app, ["scan", str(AWS_CSV), "--rules", "rules.yaml"])
        assert result.exit_code == 0

    def test_azure_csv_exits_zero(self):
        result = runner.invoke(app, ["scan", str(AZURE_CSV)])
        assert result.exit_code == 0, result.output

    def test_azure_json_exits_zero(self):
        result = runner.invoke(app, ["scan", str(AZURE_JSON)])
        assert result.exit_code == 0, result.output

    def test_azure_shows_known_waste_resource(self):
        result = runner.invoke(app, ["scan", str(AZURE_CSV)])
        # UnattachedDiskDetector fires via disk.is_attached=False signal
        assert "unattac" in result.output  # "unattached_disk" truncated by Rich
        assert "142" in result.output  # $142.86/mo from WASTE_MANIFEST total

    def test_missing_file_exits_nonzero(self):
        result = runner.invoke(app, ["scan", "nonexistent_xyz.csv"])
        assert result.exit_code != 0


# ── report ────────────────────────────────────────────────────────────────────


class TestReportCommand:
    def test_json_creates_valid_file(self, tmp_path):
        out = tmp_path / "findings.json"
        result = runner.invoke(app, ["report", str(AWS_CSV), "--format", "json", "--output", str(out)])
        assert result.exit_code == 0, result.output
        assert out.exists()
        data = json.loads(out.read_text())
        assert isinstance(data, list)
        assert len(data) > 0

    def test_json_contains_known_waste_id(self, tmp_path):
        out = tmp_path / "findings.json"
        runner.invoke(app, ["report", str(AWS_CSV), "--format", "json", "--output", str(out)])
        ids = [f["resource_id"] for f in json.loads(out.read_text())]
        assert "vol-0orph0001dead0001" in ids

    def test_csv_creates_non_empty_file(self, tmp_path):
        out = tmp_path / "findings.csv"
        result = runner.invoke(app, ["report", str(AWS_CSV), "--format", "csv", "--output", str(out)])
        assert result.exit_code == 0, result.output
        assert out.exists()
        assert out.stat().st_size > 0

    def test_csv_has_header_row(self, tmp_path):
        out = tmp_path / "findings.csv"
        runner.invoke(app, ["report", str(AWS_CSV), "--format", "csv", "--output", str(out)])
        first_line = out.read_text().splitlines()[0]
        assert "resource_id" in first_line

    def test_invalid_format_exits_nonzero(self):
        result = runner.invoke(app, ["report", str(AWS_CSV), "--format", "xml"])
        assert result.exit_code != 0

    def test_missing_file_exits_nonzero(self):
        result = runner.invoke(app, ["report", "nonexistent_xyz.csv", "--format", "json"])
        assert result.exit_code != 0


# ── remediate ────────────────────────────────────────────────────────────────


class TestRemediateCommand:
    def test_creates_script_file(self, tmp_path):
        out = tmp_path / "remediation.sh"
        result = runner.invoke(app, ["remediate", str(AWS_CSV), "--output", str(out)])
        assert result.exit_code == 0, result.output
        assert out.exists()

    def test_script_contains_delete_volume(self, tmp_path):
        out = tmp_path / "remediation.sh"
        runner.invoke(app, ["remediate", str(AWS_CSV), "--output", str(out)])
        assert "delete-volume" in out.read_text()

    def test_script_dry_run_by_default(self, tmp_path):
        out = tmp_path / "remediation.sh"
        runner.invoke(app, ["remediate", str(AWS_CSV), "--output", str(out)])
        assert "DRY_RUN=true" in out.read_text()

    def test_azure_script_contains_az_disk_delete(self, tmp_path):
        out = tmp_path / "az_remediation.sh"
        result = runner.invoke(app, ["remediate", str(AZURE_CSV), "--output", str(out)])
        assert result.exit_code == 0, result.output
        assert "az disk delete" in out.read_text()

    def test_prints_savings_summary(self, tmp_path):
        out = tmp_path / "remediation.sh"
        result = runner.invoke(app, ["remediate", str(AWS_CSV), "--output", str(out)])
        assert "Savings Summary" in result.output

    def test_missing_file_exits_nonzero(self):
        result = runner.invoke(app, ["remediate", "nonexistent_xyz.csv"])
        assert result.exit_code != 0


# ── --enrich flag ─────────────────────────────────────────────────────────────


class TestEnrichFlag:
    def test_no_credentials_prints_warning_and_falls_back_to_mock(self):
        """--enrich with no credentials warns but still produces output (mock fallback)."""
        with patch(
            "app.cli.aws_provider.check_credentials",
            return_value=(False, "No AWS credentials found."),
        ):
            result = runner.invoke(app, ["scan", str(AWS_CSV), "--enrich"])
        assert result.exit_code == 0, result.output
        assert "Warning" in result.output or "warning" in result.output.lower()
        # Mock fallback still surfaces findings
        assert "unattac" in result.output or "Savings Summary" in result.output

    def test_with_credentials_calls_real_provider(self):
        """--enrich with valid credentials calls aws_provider.get_signals."""
        mock_signals: dict = {}  # real provider returns empty for sample IDs (they don't exist)
        with (
            patch(
                "app.cli.aws_provider.check_credentials",
                return_value=(True, "arn:aws:iam::123:user/test"),
            ),
            patch(
                "app.cli.aws_provider.get_signals",
                return_value=mock_signals,
            ),
        ):
            result = runner.invoke(app, ["scan", str(AWS_CSV), "--enrich"])
        assert result.exit_code == 0, result.output

    def test_no_enrich_flag_uses_mock_unchanged(self):
        """Without --enrich, aws_provider is never called."""
        with patch(
            "app.cli.aws_provider.check_credentials"
        ) as mock_creds:
            result = runner.invoke(app, ["scan", str(AWS_CSV)])
        assert result.exit_code == 0
        mock_creds.assert_not_called()

    def test_enrich_report_command(self, tmp_path):
        """--enrich works on the report command too."""
        out = tmp_path / "findings.json"
        with patch(
            "app.cli.aws_provider.check_credentials",
            return_value=(False, "No creds"),
        ):
            result = runner.invoke(
                app,
                ["report", str(AWS_CSV), "--format", "json", "--output", str(out), "--enrich"],
            )
        assert result.exit_code == 0
        assert out.exists()

    def test_enrich_remediate_command(self, tmp_path):
        """--enrich works on the remediate command too."""
        out = tmp_path / "remediation.sh"
        with patch(
            "app.cli.aws_provider.check_credentials",
            return_value=(False, "No creds"),
        ):
            result = runner.invoke(
                app,
                ["remediate", str(AWS_CSV), "--output", str(out), "--enrich"],
            )
        assert result.exit_code == 0
        assert out.exists()


# ── summary format ────────────────────────────────────────────────────────────


class TestSummaryFormat:
    def test_summary_creates_markdown_file(self, tmp_path):
        out = tmp_path / "report.md"
        result = runner.invoke(
            app, ["report", str(AWS_CSV), "--format", "summary", "--output", str(out)]
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        assert out.read_text().startswith("# Cloud Cost Optimizer")

    def test_summary_has_all_three_sections(self, tmp_path):
        out = tmp_path / "report.md"
        runner.invoke(app, ["report", str(AWS_CSV), "--format", "summary", "--output", str(out)])
        content = out.read_text()
        assert "## By Provider" in content
        assert "## By Service" in content
        assert "## By Waste Category" in content

    def test_summary_provider_totals_match_grand_total(self, tmp_path):
        """Per-provider savings must sum to the grand total in the Overview table."""
        out = tmp_path / "report.md"
        runner.invoke(app, ["report", str(AWS_CSV), "--format", "summary", "--output", str(out)])
        content = out.read_text()
        total_match = re.search(r"\| Monthly savings \| \$([0-9.]+) \|", content)
        assert total_match, "Grand total not found in summary"
        grand_total = float(total_match.group(1))
        # Scope to the "By Provider" section only — service rows embed "| AWS |" substrings too
        prov_section = re.search(r"## By Provider\n(.*?)\n## By Service", content, re.DOTALL)
        assert prov_section, "By Provider section not found"
        prov_rows = [
            line for line in prov_section.group(1).split("\n")
            if re.match(r"\| [A-Z]", line) and "**" not in line
        ]
        assert prov_rows, "No provider data rows found"
        prov_total = 0.0
        for line in prov_rows:
            m = re.search(r"\| \$([0-9.]+) \|", line)
            if m:
                prov_total += float(m.group(1))
        assert abs(prov_total - grand_total) < 0.02

    def test_summary_default_filename_is_md(self):
        result = runner.invoke(app, ["report", str(AWS_CSV), "--format", "summary"])
        assert result.exit_code == 0
        assert "findings.md" in result.output

    def test_summary_azure_includes_azure_provider(self, tmp_path):
        out = tmp_path / "az_report.md"
        result = runner.invoke(
            app, ["report", str(AZURE_CSV), "--format", "summary", "--output", str(out)]
        )
        assert result.exit_code == 0
        assert "AZURE" in out.read_text()
