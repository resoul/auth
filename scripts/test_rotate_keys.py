"""Tests of scripts/rotate_keys.py: every refusal, and that a rotation leaves a keyring that still loads."""
import base64
from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

import rotate_keys as rk


class FakeDatabase:
    def __init__(self):
        self.waiting = {}
        self.expired = []
        self.known = set()

    def waiting_flows(self, kid):
        return self.waiting.get(kid, 0)

    def expire_flows(self, kid):
        self.expired.append(kid)
        return self.waiting.pop(kid, 0)

    def run(self, sql, kid):
        return ["1" if kid in self.known else "0"]


class RotateKeysTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        root = Path(self.dir.name)
        (root / "otp-a").write_text(base64.b64encode(os.urandom(32)).decode() + "\n")
        key = rk.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256")
        (root / "sign-a.pem").write_bytes(key)
        self.ring = root / "keyring.json"
        self.ring.write_text(json.dumps({
            "format_version": 1,
            "otp_hmac": {"active_kid": "otp-a", "keys": {"otp-a": {"key_file": str(root / "otp-a")}}},
            "jwt_signing": {"active_kid": "sign-a", "keys": {"sign-a": {"key_file": str(root / "sign-a.pem")}}},
        }))
        self.db = FakeDatabase()
        self.history = rk.History(self.ring)

    def run_cli(self, *argv, database=True):
        args = rk.build_parser().parse_args(["--keyring", str(self.ring), *argv])
        out, err = io.StringIO(), io.StringIO()
        ring = rk.read_ring(self.ring)
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rk.COMMANDS[args.command](args, ring, self.history, self.db if database else None)
            return True, out.getvalue()
        except rk.Refusal as refusal:
            return False, str(refusal)

    def load(self):
        return json.loads(self.ring.read_text())

    def kids(self, purpose):
        return set(self.load()[rk.PURPOSES[purpose]]["keys"])

    def age(self, purpose, kid, event, by):
        """Make an event older, as if time had passed."""
        lines = [json.loads(line) for line in self.history.path.read_text().splitlines()]
        for line in lines:
            if (line["purpose"], line["kid"], line["event"]) == (purpose, kid, event):
                line["at"] = (rk.datetime.fromisoformat(line["at"]) - by).isoformat()
        self.history.path.write_text("".join(json.dumps(line) + "\n" for line in lines))

    def test_add_makes_a_private_inactive_key_with_a_fresh_kid(self):
        for purpose, active in (("otp", "otp-a"), ("jwt", "sign-a")):
            ok, _ = self.run_cli("add", purpose)
            self.assertTrue(ok)
            group = self.load()[rk.PURPOSES[purpose]]
            self.assertEqual(group["active_kid"], active)
            (kid,) = set(group["keys"]) - {active}
            path = Path(group["keys"][kid]["key_file"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertTrue(path.parent == Path(self.dir.name))
            self.assertIn(kid, self.history.used(purpose))
        otp_file = Path(self.dir.name) / sorted(self.kids("otp") - {"otp-a"})[0]
        self.assertEqual(len(base64.b64decode(otp_file.read_text().strip(), validate=True)), 32)

    def test_a_kid_is_never_given_out_twice_even_after_it_was_retired(self):
        ok, _ = self.run_cli("add", "otp")
        (kid,) = self.kids("otp") - {"otp-a"}
        ok, _ = self.run_cli("retire", "otp", kid)
        self.assertTrue(ok)
        self.assertNotIn(kid, self.kids("otp"))
        ok, _ = self.run_cli("add", "otp")
        (again,) = self.kids("otp") - {"otp-a"}
        self.assertNotEqual(again, kid)
        # A kid that old flows still carry is skipped too.
        self.db.known.add(f"otp-{rk.now().strftime('%Y%m%d')}-3")
        ok, _ = self.run_cli("add", "otp")
        self.assertNotIn(f"otp-{rk.now().strftime('%Y%m%d')}-3", self.kids("otp"))

    def test_the_previous_keyring_is_kept_and_the_files_stay_private(self):
        before = self.ring.read_bytes()
        self.run_cli("add", "otp")
        self.assertEqual(self.ring.with_name("keyring.json.prev").read_bytes(), before)
        for path in (self.ring, self.ring.with_name("keyring.json.prev"), self.history.path):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)

    def test_otp_rotation_in_the_runbook_order(self):
        self.run_cli("add", "otp")
        (new,) = self.kids("otp") - {"otp-a"}
        ok, _ = self.run_cli("activate", "otp", new)
        self.assertTrue(ok)
        self.assertEqual(self.load()["otp_hmac"]["active_kid"], new)
        # Open flows still wait for the old key: it stays until they end.
        self.db.waiting["otp-a"] = 2
        ok, message = self.run_cli("retire", "otp", "otp-a")
        self.assertFalse(ok)
        self.assertIn("2 flows still wait", message)
        self.assertIn("otp-a", self.kids("otp"))
        self.db.waiting["otp-a"] = 0
        ok, _ = self.run_cli("retire", "otp", "otp-a")
        self.assertTrue(ok)
        self.assertEqual(self.kids("otp"), {new})

    def test_the_active_key_cannot_be_retired_or_stripped(self):
        self.assertFalse(self.run_cli("retire", "otp", "otp-a")[0])
        self.assertFalse(self.run_cli("retire", "jwt", "sign-a")[0])
        self.assertFalse(self.run_cli("public-only", "sign-a")[0])
        self.assertFalse(self.run_cli("activate", "jwt", "sign-a")[0])

    def test_a_jwt_key_signs_only_after_verifiers_could_see_it(self):
        self.run_cli("add", "jwt")
        (new,) = self.kids("jwt") - {"sign-a"}
        ok, message = self.run_cli("activate", "jwt", new)
        self.assertFalse(ok)
        self.assertIn("wait", message)
        self.assertEqual(self.load()["jwt_signing"]["active_kid"], "sign-a")
        self.age("jwt", new, "added", timedelta(minutes=11))
        ok, _ = self.run_cli("activate", "jwt", new)
        self.assertTrue(ok)
        self.assertEqual(self.load()["jwt_signing"]["active_kid"], new)

    def test_a_public_only_key_cannot_sign(self):
        self.run_cli("add", "jwt")
        (new,) = self.kids("jwt") - {"sign-a"}
        self.run_cli("activate", "jwt", new, "--assume-published")
        self.assertTrue(self.run_cli("public-only", "sign-a")[0])
        path = Path(self.load()["jwt_signing"]["keys"]["sign-a"]["key_file"])
        self.assertIn("BEGIN PUBLIC KEY", path.read_text())
        self.assertNotIn("PRIVATE", path.read_text())
        # Going back to it is refused: there is nothing to sign with.
        ok, message = self.run_cli("activate", "jwt", "sign-a", "--assume-published")
        self.assertFalse(ok)
        self.assertIn("private", message)

    def test_an_old_jwt_key_waits_for_its_tokens_to_expire(self):
        self.run_cli("add", "jwt")
        (new,) = self.kids("jwt") - {"sign-a"}
        self.run_cli("activate", "jwt", new, "--assume-published")
        ok, message = self.run_cli("retire", "jwt", "sign-a", "--access-ttl", "5m")
        self.assertFalse(ok)
        self.assertIn("can still be valid", message)
        self.age("jwt", "sign-a", "deactivated", timedelta(minutes=5))
        ok, message = self.run_cli("retire", "jwt", "sign-a", "--access-ttl", "5m")
        self.assertFalse(ok, "the skew must be waited out too")
        self.age("jwt", "sign-a", "deactivated", timedelta(minutes=2))
        self.assertTrue(self.run_cli("retire", "jwt", "sign-a", "--access-ttl", "5m")[0])
        self.assertEqual(self.kids("jwt"), {new})

    def test_a_key_the_script_did_not_deactivate_needs_the_operator_to_vouch(self):
        raw = json.loads(self.ring.read_text())
        path = Path(raw["jwt_signing"]["keys"]["sign-a"]["key_file"])
        other = path.with_name("sign-b.pem")
        other.write_bytes(rk.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"))
        raw["jwt_signing"]["keys"]["sign-b"] = {"key_file": str(other)}
        raw["jwt_signing"]["active_kid"] = "sign-b"
        self.ring.write_text(json.dumps(raw))
        ok, message = self.run_cli("retire", "jwt", "sign-a")
        self.assertFalse(ok)
        self.assertIn("--assume-elapsed", message)
        self.assertTrue(self.run_cli("retire", "jwt", "sign-a", "--assume-elapsed")[0])

    def test_a_compromised_key_goes_at_once_with_its_file_and_its_open_flows(self):
        self.run_cli("add", "otp")
        (new,) = self.kids("otp") - {"otp-a"}
        self.run_cli("activate", "otp", new)
        self.db.waiting["otp-a"] = 3
        old_file = Path(self.load()["otp_hmac"]["keys"]["otp-a"]["key_file"])
        ok, out = self.run_cli("retire", "otp", "otp-a", "--compromised")
        self.assertTrue(ok)
        self.assertEqual(self.db.expired, ["otp-a"])
        self.assertIn("closed 3 open flows", out)
        self.assertFalse(old_file.exists())

        self.run_cli("add", "jwt")
        (fresh,) = self.kids("jwt") - {"sign-a"}
        self.run_cli("activate", "jwt", fresh, "--assume-published")
        leaked = Path(self.load()["jwt_signing"]["keys"]["sign-a"]["key_file"])
        self.assertTrue(self.run_cli("retire", "jwt", "sign-a", "--compromised")[0], "no waiting for a key that leaked")
        self.assertFalse(leaked.exists())
        self.assertEqual(self.kids("jwt"), {fresh})

    def test_otp_retirement_needs_the_database(self):
        self.run_cli("add", "otp")
        (new,) = self.kids("otp") - {"otp-a"}
        self.run_cli("activate", "otp", new)
        ok, message = self.run_cli("retire", "otp", "otp-a", database=False)
        self.assertFalse(ok)
        self.assertIn("database", message)

    def test_unknown_kids_and_a_wrong_key_file_are_refused(self):
        self.assertFalse(self.run_cli("activate", "otp", "nope")[0])
        self.assertFalse(self.run_cli("retire", "jwt", "nope")[0])
        self.run_cli("add", "otp")
        (new,) = self.kids("otp") - {"otp-a"}
        Path(self.load()["otp_hmac"]["keys"][new]["key_file"]).write_text("not base64 !!")
        self.assertFalse(self.run_cli("activate", "otp", new)[0])
        with self.assertRaises(SystemExit):
            rk.build_parser().parse_args(["activate", "otp", "../etc/passwd"])

    def test_a_broken_keyring_file_is_refused_not_repaired(self):
        self.ring.write_text('{"format_version": 1, "format_version": 1}')
        with self.assertRaises(rk.Refusal):
            rk.read_ring(self.ring)
        self.ring.write_text(json.dumps({"format_version": 2}))
        with self.assertRaises(rk.Refusal):
            rk.read_ring(self.ring)

    def test_nothing_secret_is_printed(self):
        raw = Path(self.load()["otp_hmac"]["keys"]["otp-a"]["key_file"]).read_text().strip()
        ok, out = self.run_cli("status", database=False)
        self.assertTrue(ok)
        self.assertNotIn(raw, out)
        self.assertNotIn("PRIVATE", out)
        for command in (("add", "otp"), ("add", "jwt")):
            self.assertNotIn("PRIVATE", self.run_cli(*command)[1])

    def test_relative_references_stay_relative(self):
        raw = json.loads(self.ring.read_text())
        raw["otp_hmac"]["keys"]["otp-a"]["key_file"] = os.path.relpath(raw["otp_hmac"]["keys"]["otp-a"]["key_file"], rk.ROOT)
        self.ring.write_text(json.dumps(raw))
        self.run_cli("add", "otp")
        (new,) = self.kids("otp") - {"otp-a"}
        reference = self.load()["otp_hmac"]["keys"][new]["key_file"]
        self.assertFalse(Path(reference).is_absolute())
        self.assertTrue((rk.ROOT / reference).is_file())



class RotateOIDCKeysTest(RotateKeysTest):
    """The OpenID Provider's RS256 keys rotate like the ES256 ones, and a keyring without them is left alone."""

    def setUp(self):
        super().setUp()
        root = Path(self.dir.name)
        (root / "oidc-a.pem").write_bytes(rk.openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"))
        ring = self.load()
        ring["oidc_signing"] = {"active_kid": "oidc-a", "keys": {"oidc-a": {"key_file": str(root / "oidc-a.pem")}}}
        self.ring.write_text(json.dumps(ring))

    def test_add_makes_a_private_rsa_key_that_is_not_active(self):
        ok, _ = self.run_cli("add", "oidc")
        self.assertTrue(ok)
        group = self.load()["oidc_signing"]
        self.assertEqual(group["active_kid"], "oidc-a")
        (kid,) = set(group["keys"]) - {"oidc-a"}
        path = Path(group["keys"][kid]["key_file"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertTrue(path.name.endswith(".pem") and kid.startswith("oidc-"))
        text = rk.openssl("rsa", "-in", str(path), "-noout", "-text").decode()
        self.assertIn("Private-Key: (3072 bit", text)

    def test_the_provider_rotates_in_the_runbook_order(self):
        self.run_cli("add", "oidc")
        (new,) = self.kids("oidc") - {"oidc-a"}
        ok, message = self.run_cli("activate", "oidc", new)
        self.assertFalse(ok)  # verifiers may not have seen the key set yet
        self.assertIn("wait", message)
        self.age("oidc", new, "added", rk.duration("11m"))
        ok, _ = self.run_cli("activate", "oidc", new)
        self.assertTrue(ok)
        self.assertEqual(self.load()["oidc_signing"]["active_kid"], new)

        ok, message = self.run_cli("retire", "oidc", "oidc-a")
        self.assertFalse(ok)
        self.assertIn("wait", message)
        self.age("oidc", "oidc-a", "deactivated", rk.duration("2h"))
        ok, _ = self.run_cli("public-only", "--purpose", "oidc", "oidc-a")
        self.assertTrue(ok)
        self.assertNotIn("PRIVATE", Path(self.load()["oidc_signing"]["keys"]["oidc-a"]["key_file"]).read_text())
        ok, _ = self.run_cli("retire", "oidc", "oidc-a")
        self.assertTrue(ok)
        self.assertEqual(self.kids("oidc"), {new})

    def test_status_names_every_purpose_in_use(self):
        ok, out = self.run_cli("status")
        self.assertTrue(ok)
        for line in ("otp: active otp-a", "jwt: active sign-a", "oidc: active oidc-a"):
            self.assertIn(line, out)

    def test_a_keyring_without_the_provider_refuses_its_purpose_and_still_rotates_the_rest(self):
        ring = self.load()
        del ring["oidc_signing"]
        self.ring.write_text(json.dumps(ring))
        ok, message = self.run_cli("add", "oidc")
        self.assertFalse(ok)
        self.assertIn("oidc_signing", message)
        ok, out = self.run_cli("status")
        self.assertTrue(ok)
        self.assertNotIn("oidc", out)
        ok, _ = self.run_cli("add", "jwt")
        self.assertTrue(ok)

    def test_an_unknown_group_is_still_refused(self):
        ring = self.load()
        ring["extra_signing"] = ring["jwt_signing"]
        self.ring.write_text(json.dumps(ring))
        with self.assertRaises(rk.Refusal):
            rk.read_ring(self.ring)


    def test_a_keyring_that_names_pod_paths_is_rotated_with_keys_dir(self):
        # The Kubernetes secret mounts the keys at /etc/airlance-auth/keys; here they are in a local copy.
        root = Path(self.dir.name)
        ring = self.load()
        ring["otp_hmac"]["keys"]["otp-a"]["key_file"] = "/etc/airlance-auth/keys/otp-a"
        ring["jwt_signing"]["keys"]["sign-a"]["key_file"] = "/etc/airlance-auth/keys/sign-a.pem"
        self.ring.write_text(json.dumps(ring))
        self.addCleanup(setattr, rk, "KEYS_DIR", None)
        rk.KEYS_DIR = root

        ok, out = self.run_cli("add", "jwt")
        self.assertTrue(ok, out)
        (kid,) = self.kids("jwt") - {"sign-a"}
        self.assertEqual(self.load()["jwt_signing"]["keys"][kid]["key_file"], f"/etc/airlance-auth/keys/{kid}.pem")
        self.assertIn("BEGIN PRIVATE KEY", (root / f"{kid}.pem").read_text())
        self.assertTrue(self.run_cli("status")[0])


if __name__ == "__main__":
    unittest.main()


class DirectDatabaseTest(unittest.TestCase):
    """Without Docker the script reaches PostgreSQL by psql, the password in the environment and not in the arguments."""

    def command(self, url):
        old = os.environ.get("AIRLANCE_AUTH_PSQL_URL")
        try:
            if url is None:
                os.environ.pop("AIRLANCE_AUTH_PSQL_URL", None)
            else:
                os.environ["AIRLANCE_AUTH_PSQL_URL"] = url
            return rk.Compose("airlance_auth", "e2e_x").command("otp-a")
        finally:
            if old is None:
                os.environ.pop("AIRLANCE_AUTH_PSQL_URL", None)
            else:
                os.environ["AIRLANCE_AUTH_PSQL_URL"] = old

    def test_the_url_is_split_into_the_environment(self):
        argv, env = self.command("postgres://ci_user:p%40ss@db.internal:6543/ci_db?sslmode=disable")
        self.assertEqual(argv[0], "psql")
        self.assertNotIn("docker", argv)
        self.assertNotIn("p@ss", " ".join(argv))
        self.assertEqual((env["PGHOST"], env["PGPORT"], env["PGUSER"], env["PGDATABASE"]), ("db.internal", "6543", "ci_user", "ci_db"))
        self.assertEqual((env["PGPASSWORD"], env["PGSSLMODE"]), ("p@ss", "disable"))

    def test_without_the_url_it_goes_through_compose(self):
        argv, env = self.command(None)
        self.assertEqual(argv[:2], ["docker", "compose"])
        self.assertIsNone(env)
