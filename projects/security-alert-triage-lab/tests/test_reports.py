"""Verify real file-to-report execution and durable failure records."""

import base64
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from triage.analyze import main, run_analysis
from triage.parser import DATA_DIRECTORY
from triage.reporting import markdown_report


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)

    def run_case(self, scenario="suspicious", **kwargs):
        return run_analysis(scenario=scenario, output_directory=self.output, **kwargs)

    def test_both_scenarios_run_end_to_end_and_retain_exact_sources(self):
        before = {str(p): p.read_bytes() for p in DATA_DIRECTORY.glob('*/*.json')}
        for scenario, priority in (("suspicious", "ELEVATED"), ("authorized", "ROUTINE")):
            with self.subTest(scenario=scenario):
                directory, report = self.run_case(scenario)
                self.assertEqual(report["runStatus"], "COMPLETED")
                self.assertEqual(report["analysis"]["cases"][0]["priority"], priority)
                self.assertEqual(json.loads((directory / "report.json").read_text()), report)
                for source in report["sources"]:
                    body = base64.b64decode(source["rawBodyBase64"], validate=True)
                    self.assertEqual(hashlib.sha256(body).hexdigest(), source["sha256"])
                    self.assertEqual(json.loads(body), source["parsedInput"])
                text = (directory / "report.md").read_text()
                self.assertIn(priority, text)
                self.assertIn("report.json#/analysis/cases/0", text)
                self.assertIn("UNCONFIRMED", text)
        self.assertEqual(before, {str(p): p.read_bytes() for p in DATA_DIRECTORY.glob('*/*.json')})

    def test_run_ids_and_directories_do_not_collide(self):
        directory, first = self.run_case()
        other, second = self.run_case()
        self.assertNotEqual(directory, other)
        self.assertNotEqual(first["runId"], second["runId"])

    def test_missing_input_saves_failed_report_without_personal_path(self):
        directory, report = self.run_case(events_path=self.output / 'missing.json', context_path=self.output / 'context.json')
        self.assertEqual(report["runStatus"], "FAILED")
        self.assertIsNone(report["analysis"])
        self.assertIn("not completed", (directory / "report.md").read_text())
        self.assertNotIn(str(self.output), (directory / "report.json").read_text())

    def test_invalid_context_preserves_source_and_does_not_produce_clean_results(self):
        bad = self.output / "bad.json"
        bad.write_text('{"datasetId": "bad", "fictional": true, "schemaVersion": "1.0"}')
        directory, report = self.run_case(events_path=DATA_DIRECTORY / 'suspicious/events.json', context_path=bad)
        self.assertEqual(report["runStatus"], "FAILED")
        self.assertEqual(len(report["sources"]), 2)
        self.assertIn("rawBodyBase64", report["sources"][1])
        self.assertTrue((directory / "report.md").exists())

    def test_invalid_json_and_duplicate_keys_are_retained_as_failed_inputs(self):
        bad = self.output / "bad.json"
        for body in (b"invalid JSON", b'{"events": [], "events": []}', b'{"x": NaN}', b'\xff'):
            bad.write_bytes(body)
            _, report = self.run_case(events_path=bad, context_path=DATA_DIRECTORY / 'suspicious/context.json')
            with self.subTest(body=body):
                self.assertEqual(report["runStatus"], "FAILED")
                self.assertEqual(base64.b64decode(report["sources"][0]["rawBodyBase64"]), body)

    def test_markdown_escapes_untrusted_html_and_link_syntax(self):
        _, report = self.run_case()
        report["analystLabel"] = '<script>alert(1)</script> [click](https://example.com)'
        text = markdown_report(report)
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertNotIn("[click]", text)

    def test_markdown_write_failure_updates_retained_json_status(self):
        with patch("triage.analyze.save_markdown", side_effect=OSError("Disk full")):
            with self.assertRaises(OSError):
                self.run_case()
        saved = json.loads(next(self.output.glob('*/report.json')).read_text())
        self.assertEqual(saved["runStatus"], "FAILED")
        self.assertIn("Markdown", saved["error"])

    def test_cli_success_and_failure_exit_codes(self):
        with patch("sys.argv", ['analyze', '--scenario', 'authorized', '--output-dir', str(self.output)]):
            output = io.StringIO()
            with redirect_stdout(output):
                main()
            self.assertIn("ROUTINE:", output.getvalue())
        with patch("sys.argv", ['analyze', '--events', 'missing.json', '--context', 'missing-context.json', '--output-dir', str(self.output)]):
            with patch("sys.stderr", new_callable=io.StringIO):
                with redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        main()
                    self.assertEqual(raised.exception.code, 1)

    def test_empty_candidates_do_not_render_an_all_clear_claim(self):
        events = json.loads((DATA_DIRECTORY / 'suspicious/events.json').read_text())
        events["events"] = []
        file = self.output / 'empty.json'
        file.write_text(json.dumps(events))
        directory, report = self.run_case(events_path=file, context_path=DATA_DIRECTORY / 'suspicious/context.json')
        self.assertEqual(report["runStatus"], "COMPLETED")
        self.assertIn("not an all-clear", (directory / 'report.md').read_text())

    def test_custom_inputs_must_be_supplied_as_a_pair(self):
        with self.assertRaises(ValueError):
            self.run_case(events_path='events.json')


if __name__ == "__main__":
    unittest.main()
