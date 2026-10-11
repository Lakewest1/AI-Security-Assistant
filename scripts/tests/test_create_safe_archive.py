import contextlib
import importlib.util
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "create-safe-archive.py"
SPEC = importlib.util.spec_from_file_location("create_safe_archive", SCRIPT)
archive_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive_tool)


class SafeArchivePolicyTests(unittest.TestCase):
    def test_allowed_source_templates_and_false_positive_names(self):
        allowed = (
            "server/agent/BuildStatus.js",
            "server/tools/cache-control.js",
            "docs/build-process.md",
            "client/.env.example",
            "server/.env.example",
            "scripts/tests/test_create_safe_archive.py",
        )
        for name in allowed:
            with self.subTest(name=name):
                self.assertIsNone(archive_tool.prohibited_member_rule(name))

    def test_prohibited_directories_and_generated_files(self):
        prohibited = (
            ("node_modules/pkg/index.js", "generated-or-local-directory"),
            ("client/dist/assets/app.js", "generated-or-local-directory"),
            ("server/coverage/report.json", "generated-or-local-directory"),
            ("server/.cache/result.bin", "generated-or-local-directory"),
            ("server/logs/app.log", "generated-or-local-directory"),
            ("server/output.tmp", "generated-or-temporary-file"),
            ("client/.env.local", "environment-or-repository-metadata"),
            ("client/config.local.json", "local-only-configuration"),
            ("client/run.log.1", "generated-or-temporary-file"),
            (".env", "environment-or-repository-metadata"),
            (".git/config", "generated-or-local-directory"),
            ("keys/server.pem", "private-key-file"),
        )
        for name, expected_rule in prohibited:
            with self.subTest(name=name):
                self.assertEqual(archive_tool.prohibited_member_rule(name), expected_rule)

    def test_separator_variants_and_unsafe_path_forms_are_rejected(self):
        rejected = (
            "node_modules\\pkg\\secret.txt",
            "..\\outside.txt",
            "../outside.txt",
            "/etc/passwd",
            "C:/Windows/system.ini",
            "\\\\server\\share\\file.txt",
            "safe//nested.txt",
            "safe/./nested.txt",
            "safe/file.txt:stream",
        )
        for name in rejected:
            with self.subTest(name=name):
                with self.assertRaises(archive_tool.ArchivePolicyError):
                    archive_tool._safe_relative_name(name)

    def test_finished_zip_is_independently_scanned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "synthetic.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("docs/readme.md", "synthetic safe text")
                archive.writestr("client/.env.example", "API_KEY=your_example_placeholder")
            self.assertEqual(archive_tool.validate_zip(archive_path), 2)

    def test_finished_zip_rejects_prohibited_members_and_backslash_paths(self):
        for member in (
            "node_modules/pkg/a.js",
            "../outside.txt",
            "/absolute.txt",
            "C:/Windows/system.ini",
            "private\\credentials.txt",
        ):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as temp_dir:
                archive_path = Path(temp_dir) / "synthetic.zip"
                if "\\" in member:
                    # zipfile normalizes Windows separators while writing, so
                    # patch a same-length synthetic ZIP name to model an
                    # externally supplied noncanonical member.
                    with zipfile.ZipFile(archive_path, "w") as archive:
                        archive.writestr("private/credentials.txt", "synthetic")
                    raw_zip = archive_path.read_bytes()
                    archive_path.write_bytes(raw_zip.replace(b"private/credentials.txt", b"private\\credentials.txt"))
                else:
                    with zipfile.ZipFile(archive_path, "w") as archive:
                        archive.writestr(member, "synthetic")
                with self.assertRaises(archive_tool.ArchivePolicyError):
                    archive_tool.validate_zip(archive_path)

    def test_secret_scan_reports_only_path_and_rule_not_value(self):
        # Compose the synthetic marker so the test source itself has no token.
        marker = "A" + "KIA" + "1234567890ABCDEF"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "source"
            root.mkdir()
            (root / "synthetic.txt").write_text(marker, encoding="utf-8")
            output = Path(temp_dir) / "archive.zip"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = archive_tool.main(["--output", str(output)], root=root)
            combined = stdout.getvalue() + stderr.getvalue()
            self.assertEqual(code, 1)
            self.assertFalse(output.exists())
            self.assertIn("path=synthetic.txt", combined)
            self.assertIn("rule=aws-access-key-id", combined)
            self.assertNotIn(marker, combined)
            self.assertNotIn("created", stdout.getvalue().lower())

    def test_configuration_assignment_scan_does_not_report_value(self):
        synthetic_value = "synthetic" + "credential" + "value123"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "source"
            root.mkdir()
            (root / "settings.example").write_text(
                '{"SERVICE_API_KEY": "' + synthetic_value + '"}', encoding="utf-8"
            )
            output = Path(temp_dir) / "archive.zip"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = archive_tool.main(["--output", str(output)], root=root)
            self.assertEqual(code, 1)
            self.assertFalse(output.exists())
            self.assertIn("rule=credential-assignment", stderr.getvalue())
            self.assertNotIn(synthetic_value, stderr.getvalue())

    def test_check_only_scans_without_creating_archive(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "source"
            root.mkdir()
            (root / "hello.txt").write_text("synthetic content", encoding="utf-8")
            output = Path(temp_dir) / "archive.zip"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = archive_tool.main(["--output", str(output), "--check-only"], root=root)
            self.assertEqual(code, 0)
            self.assertFalse(output.exists())
            self.assertIn("no archive created", stdout.getvalue())

    def test_output_inside_source_tree_fails_without_success_message(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "source"
            root.mkdir()
            (root / "hello.txt").write_text("synthetic content", encoding="utf-8")
            output = root / "out.zip"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = archive_tool.main(["--output", str(output)], root=root)
            self.assertEqual(code, 1)
            self.assertFalse(output.exists())
            self.assertIn("output-inside-source", stderr.getvalue())
            self.assertEqual(stdout.getvalue(), "")

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "source"
            root.mkdir()
            (root / "hello.txt").write_text("synthetic content", encoding="utf-8")
            output = Path(temp_dir) / "archive.zip"
            output.write_bytes(b"keep existing")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = archive_tool.main(["--output", str(output)], root=root)
            self.assertEqual(code, 1)
            self.assertEqual(output.read_bytes(), b"keep existing")
            self.assertIn("output-exists", stderr.getvalue())

    def test_validation_failure_does_not_publish_and_cleans_temporary_zip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "source"
            root.mkdir()
            (root / "hello.txt").write_text("synthetic content", encoding="utf-8")
            output = Path(temp_dir) / "archive.zip"
            stderr = io.StringIO()
            with mock.patch.object(
                archive_tool,
                "validate_zip",
                side_effect=archive_tool.ArchivePolicyError("synthetic rejection", path="hello.txt", rule="test-rule"),
            ), contextlib.redirect_stderr(stderr):
                code = archive_tool.main(["--output", str(output)], root=root)
            self.assertEqual(code, 1)
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(temp_dir).glob(".safe-archive-*.tmp")), [])
            self.assertNotIn("created", stderr.getvalue().lower())

    def test_success_publishes_only_validated_archive(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "source"
            root.mkdir()
            (root / "hello.txt").write_text("synthetic content", encoding="utf-8")
            output = Path(temp_dir) / "archive.zip"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = archive_tool.main(["--output", str(output)], root=root)
            self.assertEqual(code, 0)
            self.assertIn("Validated archive created", stdout.getvalue())
            self.assertEqual(archive_tool.validate_zip(output), 1)
            self.assertEqual(list(Path(temp_dir).glob(".safe-archive-*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
