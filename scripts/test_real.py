"""Real SMTP launcher: dotenv stays data, secrets stay out of diagnostics."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import real


class RealSMTPTest(unittest.TestCase):
    def env_file(self, content):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name) / ".env"
        path.write_text(content)
        return path

    def smtp(self, extra=""):
        return self.env_file("""AIRLANCE_AUTH_SMTP_ADDR=smtp.example.test:587
AIRLANCE_AUTH_SMTP_USERNAME=user
AIRLANCE_AUTH_SMTP_PASSWORD='p $HOME $(touch /tmp/should-not-exist) `command` # secret'
AIRLANCE_AUTH_MAIL_FROM=no-reply@example.test
""" + extra)

    def test_password_is_literal_and_dotenv_cannot_replace_path_or_home(self):
        path = self.smtp("PATH=bad\nHOME=bad\nAIRLANCE_AUTH_MAIL_FROM_NAME=My app # comment\n")
        env = real.real_environment(path, {"PATH": "original", "HOME": "original"})
        self.assertEqual(env["PATH"], "original")
        self.assertEqual(env["HOME"], "original")
        self.assertEqual(env["AIRLANCE_AUTH_SMTP_PASSWORD"], 'p $HOME $(touch /tmp/should-not-exist) `command` # secret')
        self.assertEqual(env["AIRLANCE_AUTH_MAIL_FROM_NAME"], "My app")
        self.assertEqual(env["AIRLANCE_AUTH_SMTP_TLS"], "starttls")

    def test_empty_values_and_export_assignments(self):
        path = self.smtp('export AIRLANCE_AUTH_SMTP_TLS="tls" # comment with "quotes"\nAIRLANCE_AUTH_KEYRING_FILE=\n')
        env = real.real_environment(path, {})
        self.assertEqual(env["AIRLANCE_AUTH_SMTP_TLS"], "tls")
        self.assertEqual(env["AIRLANCE_AUTH_KEYRING_FILE"], "")

    def test_missing_credentials_and_plaintext_delivery_are_refused(self):
        for extra, message in [("AIRLANCE_AUTH_SMTP_PASSWORD=\n", "AIRLANCE_AUTH_SMTP_PASSWORD"), ("AIRLANCE_AUTH_SMTP_TLS=none\n", "AIRLANCE_AUTH_SMTP_TLS")]:
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(ValueError, message):
                    real.real_environment(self.smtp(extra), {})

    def test_diagnostics_do_not_echo_malformed_secret_lines(self):
        for content in ["secret-password-without-assignment", "AIRLANCE_AUTH_SMTP_PASSWORD='secret-password"]:
            with self.subTest(content=content):
                try:
                    real.load_env(self.env_file(content))
                except ValueError as err:
                    self.assertNotIn("secret-password", str(err))
                else:
                    self.fail("malformed env was accepted")

    def test_check_does_not_start_services_or_print_credentials(self):
        path = self.smtp()
        output = io.StringIO()
        with patch("sys.argv", ["real.py", "--env-file", str(path), "--check"]), patch("real.os.environ", {}), patch("real.os.execve") as execute, contextlib.redirect_stdout(output):
            real.main()
        execute.assert_not_called()
        self.assertNotIn("secret", output.getvalue())
        self.assertNotIn("smtp.example.test", output.getvalue())

    def test_launcher_passes_real_smtp_to_tunnel_without_shell_evaluation(self):
        path = self.smtp()
        with patch("sys.argv", ["real.py", "--env-file", str(path)]), patch("real.os.environ", {}), patch("real.os.execve") as execute:
            real.main()
        target, args, env = execute.call_args.args
        self.assertEqual(target, str(real.ROOT / "scripts" / "tunnel.sh"))
        self.assertEqual(args, ["tunnel.sh", "--real-smtp"])
        self.assertEqual(env["AIRLANCE_AUTH_SMTP_ADDR"], "smtp.example.test:587")
        self.assertNotIn(env["AIRLANCE_AUTH_SMTP_PASSWORD"], " ".join(args))
