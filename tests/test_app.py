import tempfile
import tomllib
import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest

import app


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class UploadedFileStub:
    def __init__(self, name, content, reported_size=None):
        self.name = name
        self._content = content
        self.size = len(content) if reported_size is None else reported_size

    def getvalue(self):
        return self._content


class ThemeConfigurationRegressionTests(unittest.TestCase):
    def test_streamlit_theme_is_locked_to_the_docuguard_dark_palette(self):
        config_path = PROJECT_ROOT / ".streamlit" / "config.toml"
        with config_path.open("rb") as config_file:
            theme = tomllib.load(config_file)["theme"]

        self.assertEqual(theme["base"], "dark")
        self.assertEqual(theme["backgroundColor"], "#0B1016")
        self.assertEqual(theme["secondaryBackgroundColor"], "#111821")
        self.assertEqual(theme["textColor"], "#E6EDF3")
        self.assertTrue(theme["showWidgetBorder"])


class SanitizationRegressionTests(unittest.TestCase):
    def test_mixed_content_uses_stable_placeholders_and_restores(self):
        source = (
            "owner=alice@example.com\n"
            "backup=alice@example.com\n"
            "host=192.168.1.25\n"
            'password = "correct horse"\n'
            "api_key = 'token-123'\n"
        )

        sanitized, counts, mapping = app.sanitize_text(source)

        self.assertEqual(
            counts,
            {
                "Email": 1,
                "IPv4": 1,
                "Password": 1,
                "API Key / Token": 1,
            },
        )
        self.assertEqual(sanitized.count("[EMAIL_1]"), 2)
        self.assertNotIn("alice@example.com", sanitized)
        self.assertNotIn("correct horse", sanitized)
        self.assertNotIn("token-123", sanitized)
        self.assertEqual(app.restore_text(sanitized, mapping), source)

    def test_json_credentials_are_sanitized_without_double_counting(self):
        source = (
            '{"email":"ops@example.com","password":"secret",'
            '"secret_key":"abc","ip":"10.0.0.8"}'
        )

        sanitized, counts, _ = app.sanitize_text(source)

        self.assertEqual(counts["Email"], 1)
        self.assertEqual(counts["IPv4"], 1)
        self.assertEqual(counts["Password"], 1)
        self.assertEqual(counts["API Key / Token"], 1)
        self.assertIn('"password":"[PASSWORD_1]"', sanitized)
        self.assertIn('"secret_key":"[API_KEY_1]"', sanitized)

    def test_invalid_ipv4_is_not_detected(self):
        sanitized, counts, mapping = app.sanitize_text("host=999.1.2.3")

        self.assertEqual(sanitized, "host=999.1.2.3")
        self.assertEqual(counts["IPv4"], 0)
        self.assertEqual(mapping, {})

    def test_risk_levels_follow_the_explainable_rules(self):
        empty = {category: 0 for category in app.sanitize_text("")[1]}

        self.assertEqual(app.privacy_risk_level(empty)[0], "LOW")

        medium = dict(empty, Email=1)
        self.assertEqual(app.privacy_risk_level(medium)[0], "MEDIUM")

        high_password = dict(empty, Password=1)
        self.assertEqual(app.privacy_risk_level(high_password)[0], "HIGH")

        high_token = dict(empty)
        high_token["API Key / Token"] = 1
        self.assertEqual(app.privacy_risk_level(high_token)[0], "HIGH")

    def test_upload_validation_and_download_metadata(self):
        text, error = app.read_uploaded_file(
            UploadedFileStub("config.json", b"\xef\xbb\xbf{\"ok\": true}")
        )
        self.assertEqual(text, '{"ok": true}')
        self.assertIsNone(error)

        _, error = app.read_uploaded_file(
            UploadedFileStub("config.exe", b"not executable")
        )
        self.assertIn("Unsupported file type", error)

        _, error = app.read_uploaded_file(
            UploadedFileStub("large.txt", b"small", reported_size=2 * 1024 * 1024 + 1)
        )
        self.assertIn("larger than 2 MB", error)

        self.assertEqual(
            app.sanitized_filename_for("../unsafe report.JSON"),
            "sanitized_unsafe_report.json",
        )
        self.assertEqual(app.mime_type_for("result.json"), "application/json")
        self.assertEqual(app.mime_type_for("result.py"), "text/x-python")


class StreamlitWorkflowRegressionTests(unittest.TestCase):
    def new_app(self):
        app_test = AppTest.from_file(
            str(PROJECT_ROOT / "app.py"), default_timeout=10
        ).run()
        self.assertFalse(app_test.exception)
        return app_test

    def test_manual_sanitize_report_download_and_restore(self):
        app_test = self.new_app()
        source = 'contact=person@example.com\npassword="keep-private"'

        app_test.text_area(key="source_text").set_value(source).run()
        app_test.button(key="primary_sanitize").click().run()

        self.assertFalse(app_test.exception)
        metrics = {metric.label: metric.value for metric in app_test.metric}
        self.assertEqual(metrics["Total sensitive entities detected"], "2")
        self.assertEqual(metrics["Email"], "1")
        self.assertEqual(metrics["IPv4"], "0")
        self.assertEqual(metrics["Password"], "1")
        self.assertEqual(metrics["API Key / Token"], "0")
        self.assertEqual(metrics["Session Mapping"], "Session only")
        self.assertEqual(metrics["External AI/API Requests"], "0")
        self.assertTrue(
            any(
                markdown.value
                == "**At least one Password or API Key / Token / Secret was detected.**"
                for markdown in app_test.markdown
            )
        )
        self.assertEqual(
            app_test.session_state["sanitized_output"],
            'contact=[EMAIL_1]\npassword="[PASSWORD_1]"',
        )
        self.assertEqual(len(app_test.download_button), 1)

        app_test.text_area[1].set_value("Notify [EMAIL_1].").run()
        app_test.button(key="restore_original_values").click().run()

        self.assertFalse(app_test.exception)
        self.assertEqual(app_test.code[-1].value, "Notify person@example.com.")

    def test_hosted_safe_copy_keeps_local_monitoring_clearly_scoped(self):
        app_test = self.new_app()

        markdown_values = [element.value for element in app_test.markdown]
        caption_values = [element.value for element in app_test.caption]
        info_values = [element.value for element in app_test.info]

        self.assertFalse(
            any("Processing:** LOCAL" in value for value in markdown_values)
        )
        self.assertTrue(
            any(
                "External AI/API Requests:** 0" in value
                for value in markdown_values
            )
        )
        self.assertEqual(
            app_test.text_input(key="monitored_path_input").label,
            "Local / self-hosted file path",
        )
        self.assertTrue(
            any(
                "hosted demo cannot access files on your computer" in value
                and "Browser uploads are snapshots" in value
                for value in info_values
            )
        )
        self.assertTrue(
            any(
                "Browser uploads are sent to this Streamlit app" in value
                and "does not forward them to an external AI/API" in value
                for value in caption_values
            )
        )

    def test_low_and_medium_reports(self):
        app_test = self.new_app()
        app_test.text_area(key="source_text").set_value("nothing sensitive").run()
        app_test.button(key="primary_sanitize").click().run()
        self.assertTrue(
            any(
                markdown.value
                == "**No supported sensitive entities were detected.**"
                for markdown in app_test.markdown
            )
        )

        app_test.text_area(key="source_text").set_value("host=10.0.0.2").run()
        app_test.button(key="primary_sanitize").click().run()
        self.assertTrue(
            any(
                markdown.value
                == "**Email or IPv4 data was detected, with no credential category detected.**"
                for markdown in app_test.markdown
            )
        )

    def test_freshness_guard_reprocesses_changed_file_and_mapping(self):
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as temp_directory:
            monitored_file = Path(temp_directory) / "watched.json"
            monitored_file.write_text(
                '{"email":"first@example.com"}', encoding="utf-8"
            )
            app_test = self.new_app()

            app_test.text_input(key="monitored_path_input").set_value(
                str(monitored_file)
            ).run()
            app_test.button(key="load_monitored_file").click().run()

            self.assertFalse(app_test.exception)
            self.assertEqual(app_test.session_state["freshness_status"], "FRESH")
            self.assertIn(
                "first@example.com",
                app_test.session_state["placeholder_mapping"].values(),
            )

            monitored_file.write_text(
                '{"password":"new-secret"}', encoding="utf-8"
            )
            app_test.button(key="check_monitored_file").click().run()

            self.assertFalse(app_test.exception)
            self.assertEqual(app_test.session_state["freshness_status"], "FRESH")
            self.assertEqual(
                app_test.session_state["sanitized_output"],
                '{"password":"[PASSWORD_1]"}',
            )
            self.assertNotIn(
                "first@example.com",
                app_test.session_state["placeholder_mapping"].values(),
            )
            self.assertIn(
                "new-secret",
                app_test.session_state["placeholder_mapping"].values(),
            )
            self.assertEqual(
                app_test.session_state["detection_counts"]["Password"], 1
            )

            app_test.button(key="prepare_monitored_download").click().run()
            self.assertFalse(app_test.exception)
            self.assertTrue(app_test.session_state["monitored_download_ready"])
            self.assertEqual(len(app_test.download_button), 1)


if __name__ == "__main__":
    unittest.main()
