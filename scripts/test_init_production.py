"""Tests of scripts/init_production.sh: what it writes, who can read it, what it refuses and what it prints."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "init_production.sh"


class InitProductionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "prod"
        self.compose_env = Path(self.tmp.name) / "compose.env"

    def run_script(self, *extra_env, directory=None):
        env = dict(os.environ, AIRLANCE_AUTH_COMPOSE_ENV=str(self.compose_env))
        env.update(dict(item.split("=", 1) for item in extra_env))
        return subprocess.run([str(SCRIPT), str(directory or self.dir)], env=env, capture_output=True, text=True, timeout=60)

    def mode(self, path):
        return stat.S_IMODE(path.stat().st_mode)

    def test_makes_every_file_private_and_names_the_domain(self):
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        for path in (self.dir, self.dir / "keys"):
            self.assertEqual(self.mode(path), 0o700, path)
        for name in ("postgres_password", "postgres_app_password", "airlance_auth.env", "airlance_auth_migrate.env", "cloudflared.env", "keys/otp-a", "keys/sign-a.pem", "keys/keyring.json"):
            self.assertEqual(self.mode(self.dir / name), 0o600, name)
        env = (self.dir / "airlance_auth.env").read_text()
        self.assertIn("AIRLANCE_AUTH_WEBAUTHN_RP_ID=auth.airlance.org\n", env)
        self.assertIn("AIRLANCE_AUTH_WEBAUTHN_ORIGINS=https://auth.airlance.org\n", env)
        self.assertIn("AIRLANCE_AUTH_JWT_ISSUER=https://auth.airlance.org\n", env)

    def test_the_keyring_names_the_files_it_made_by_absolute_path(self):
        self.run_script()
        ring = json.loads((self.dir / "keys" / "keyring.json").read_text())
        self.assertEqual(ring["format_version"], 1)
        for purpose, kid in (("otp_hmac", "otp-a"), ("jwt_signing", "sign-a")):
            group = ring[purpose]
            self.assertEqual(group["active_kid"], kid)
            path = Path(group["keys"][kid]["key_file"])
            self.assertTrue(path.is_absolute() and path.is_file(), path)
            self.assertEqual(path.parent, self.dir / "keys")
        self.assertIn("BEGIN PRIVATE KEY", (self.dir / "keys" / "sign-a.pem").read_text())

    def test_the_service_and_the_migration_use_different_roles_with_their_own_passwords(self):
        self.run_script()
        owner = (self.dir / "postgres_password").read_text()
        app = (self.dir / "postgres_app_password").read_text()
        self.assertRegex(owner, r"^[0-9a-f]{48}$")
        self.assertRegex(app, r"^[0-9a-f]{48}$")
        self.assertNotEqual(owner, app)
        env = (self.dir / "airlance_auth.env").read_text()
        self.assertIn(f"AIRLANCE_AUTH_DATABASE_URL=postgres://airlance_auth_app:{app}@postgres:5432/airlance_auth?sslmode=disable", env)
        self.assertNotIn(owner, env, "the service must not hold the owner's password")
        migrate = (self.dir / "airlance_auth_migrate.env").read_text()
        self.assertIn(f"AIRLANCE_AUTH_DATABASE_URL=postgres://airlance_auth:{owner}@postgres:5432/airlance_auth?sslmode=disable", migrate)
        self.assertNotIn(app, migrate)

    def test_prints_no_secret(self):
        done = self.run_script()
        output = done.stdout + done.stderr
        self.assertNotIn((self.dir / "postgres_password").read_text(), output)
        self.assertNotIn((self.dir / "postgres_app_password").read_text(), output)
        self.assertNotIn((self.dir / "keys" / "otp-a").read_text().strip(), output)
        self.assertNotIn("PRIVATE", output)

    def test_refuses_an_initialized_directory_and_changes_nothing(self):
        self.run_script()
        before = {p: p.read_bytes() for p in self.dir.rglob("*") if p.is_file()}
        done = self.run_script()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("refusing", done.stderr)
        self.assertEqual(before, {p: p.read_bytes() for p in self.dir.rglob("*") if p.is_file()})

    def test_two_directories_get_different_secrets(self):
        self.run_script()
        other = Path(self.tmp.name) / "other"
        self.assertEqual(self.run_script(directory=other).returncode, 0)
        for name in ("postgres_password", "postgres_app_password", "keys/otp-a", "keys/sign-a.pem"):
            self.assertNotEqual((self.dir / name).read_bytes(), (other / name).read_bytes(), name)

    def test_the_compose_variables_name_the_directory_and_the_reader_and_survive_a_second_run(self):
        self.run_script()
        text = self.compose_env.read_text()
        self.assertIn(f"AIRLANCE_AUTH_SECRETS_DIR={self.dir}\n", text)
        self.assertIn(f"AIRLANCE_AUTH_UID={os.getuid()}\n", text)
        self.assertIn(f"AIRLANCE_AUTH_GID={os.getgid()}\n", text)
        self.assertIn("AIRLANCE_AUTH_DOMAIN=auth.airlance.org\n", text)
        self.assertIn("COMPOSE_PROFILES=caddy\n", text)
        self.assertEqual(self.mode(self.compose_env), 0o600)
        self.compose_env.write_text("AIRLANCE_AUTH_SECRETS_DIR=/somewhere/else\n")
        other = Path(self.tmp.name) / "other"
        done = self.run_script(directory=other)
        self.assertEqual(done.returncode, 0)
        self.assertEqual(self.compose_env.read_text(), "AIRLANCE_AUTH_SECRETS_DIR=/somewhere/else\n", "an existing file must not be overwritten")
        self.assertIn("exists", done.stdout)

    def test_the_compose_variables_can_be_left_out(self):
        done = self.run_script("AIRLANCE_AUTH_COMPOSE_ENV=none")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse(self.compose_env.exists())
        self.assertFalse(Path("none").exists())

    def test_the_openid_provider_is_off_unless_asked_for(self):
        self.run_script()
        env = (self.dir / "airlance_auth.env").read_text()
        self.assertIn("# AIRLANCE_AUTH_OIDC_ISSUER=https://auth.airlance.org\n", env)
        self.assertNotRegex(env, r"(?m)^AIRLANCE_AUTH_OIDC_ISSUER=")
        ring = json.loads((self.dir / "keys" / "keyring.json").read_text())
        self.assertNotIn("oidc_signing", ring)
        self.assertFalse((self.dir / "keys" / "oidc-a.pem").exists())

    def test_asking_for_the_openid_provider_makes_an_rsa_key_and_sets_the_issuer(self):
        done = self.run_script("AIRLANCE_AUTH_OIDC=1")
        self.assertEqual(done.returncode, 0, done.stderr)
        env = (self.dir / "airlance_auth.env").read_text()
        self.assertIn("\nAIRLANCE_AUTH_OIDC_ISSUER=https://auth.airlance.org\n", env)
        ring = json.loads((self.dir / "keys" / "keyring.json").read_text())
        group = ring["oidc_signing"]
        self.assertEqual(group["active_kid"], "oidc-a")
        key = Path(group["keys"]["oidc-a"]["key_file"])
        self.assertEqual(key, self.dir / "keys" / "oidc-a.pem")
        self.assertEqual(self.mode(key), 0o600)
        text = subprocess.run(["openssl", "rsa", "-in", str(key), "-noout", "-text"], capture_output=True, text=True).stdout
        self.assertIn("Private-Key: (3072 bit", text)
        self.assertNotIn("PRIVATE", done.stdout + done.stderr)
        # The issuer is the domain's origin, which the passkeys already allow.
        self.assertIn("AIRLANCE_AUTH_WEBAUTHN_ORIGINS=https://auth.airlance.org\n", env)

    def test_the_openid_switch_takes_only_0_or_1(self):
        done = self.run_script("AIRLANCE_AUTH_OIDC=yes")
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse((self.dir / "airlance_auth.env").exists())

    def test_the_domain_and_audience_can_be_changed(self):
        self.run_script("AIRLANCE_AUTH_DOMAIN=id.example.test", "AIRLANCE_AUTH_AUDIENCE=other")
        env = (self.dir / "airlance_auth.env").read_text()
        self.assertIn("AIRLANCE_AUTH_WEBAUTHN_RP_ID=id.example.test\n", env)
        self.assertIn("AIRLANCE_AUTH_JWT_AUDIENCE=other\n", env)

    def test_the_key_files_can_be_named_for_the_place_they_will_be_mounted(self):
        # Kubernetes mounts the keys at a path of its own, not at the directory this script made.
        self.run_script("AIRLANCE_AUTH_KEYS_PATH=/etc/airlance-auth/keys")
        ring = json.loads((self.dir / "keys" / "keyring.json").read_text())
        self.assertEqual(ring["otp_hmac"]["keys"]["otp-a"]["key_file"], "/etc/airlance-auth/keys/otp-a")
        self.assertEqual(ring["jwt_signing"]["keys"]["sign-a"]["key_file"], "/etc/airlance-auth/keys/sign-a.pem")
        self.assertIn("AIRLANCE_AUTH_KEYRING_FILE=/etc/airlance-auth/keys/keyring.json\n", (self.dir / "airlance_auth.env").read_text())
        self.assertTrue((self.dir / "keys" / "otp-a").is_file(), "the files are still made in the directory")

    def test_the_smtp_and_the_tunnel_token_are_left_for_the_operator(self):
        self.run_script()
        env = (self.dir / "airlance_auth.env").read_text()
        for key in ("AIRLANCE_AUTH_SMTP_ADDR", "AIRLANCE_AUTH_SMTP_USERNAME", "AIRLANCE_AUTH_SMTP_PASSWORD"):
            self.assertRegex(env, rf"(?m)^{key}=$")
        self.assertIn("AIRLANCE_AUTH_SMTP_TLS=starttls\n", env)
        self.assertRegex((self.dir / "cloudflared.env").read_text(), r"(?m)^TUNNEL_TOKEN=$")

    def test_a_relative_directory_is_made_where_the_caller_stands(self):
        with tempfile.TemporaryDirectory() as cwd:
            env = dict(os.environ, AIRLANCE_AUTH_COMPOSE_ENV=str(self.compose_env))
            done = subprocess.run([str(SCRIPT), "rel"], env=env, cwd=cwd, capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertTrue((Path(cwd) / "rel" / "airlance_auth.env").is_file())
            ring = json.loads((Path(cwd) / "rel" / "keys" / "keyring.json").read_text())
            self.assertTrue(Path(ring["otp_hmac"]["keys"]["otp-a"]["key_file"]).is_absolute())

    def test_the_stack_file_is_valid_compose_in_every_profile_when_docker_is_there(self):
        self.run_script()
        env = dict(os.environ, AIRLANCE_AUTH_SECRETS_DIR=str(self.dir), AIRLANCE_AUTH_UID="1000", AIRLANCE_AUTH_GID="1000",
                   AIRLANCE_AUTH_DOMAIN="auth.example.test")
        env.pop("COMPOSE_PROFILES", None)
        for profiles in ([], ["caddy"], ["tunnel"], ["monitoring"], ["caddy", "monitoring"]):
            args = ["docker", "compose", "-f", str(ROOT / "deploy/compose.prod.yaml")]
            for profile in profiles:
                args += ["--profile", profile]
            try:
                done = subprocess.run(args + ["config", "-q"], env=env, capture_output=True, text=True, timeout=60)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self.skipTest("docker is not available")
            if "Cannot connect" in done.stderr or "docker daemon" in done.stderr.lower():
                self.skipTest("the docker daemon is not running")
            self.assertEqual(done.returncode, 0, f"profiles {profiles}: {done.stderr}")


if __name__ == "__main__":
    unittest.main()
