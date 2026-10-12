"""Backup guards: retain historical keys; refuse corruption and destructive targets."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import backup


class BackupTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)

    def bundle(self):
        path = self.root / "bundle"
        path.mkdir()
        (path / "keys").mkdir()
        ring = {"format_version": 1}
        for purpose in ("otp_hmac", "jwt_signing"):
            ring[purpose] = {"active_kid": "new", "keys": {
                "new": {"key_file": "keys/0000"}, "old": {"key_file": "keys/0001"}}}
        (path / "keys/0000").write_bytes(b"active material")
        (path / "keys/0001").write_bytes(b"historical material")
        (path / "keyring.json").write_text(json.dumps(ring))
        (path / "database.dump").write_bytes(b"dump")
        manifest = {"format_version": 1, "source_database": "airlance_auth", "table_counts": {"users": 2},
                    "sha256": {name: backup.digest(path / name) for name in
                               ("database.dump", "keyring.json", "keys/0000", "keys/0001")}}
        (path / "manifest.json").write_text(json.dumps(manifest))
        return path

    def test_all_historical_keys_and_kids_survive_portable_copy(self):
        bundle = self.bundle()
        ring = json.loads((bundle / "keyring.json").read_text())
        for purpose in ("otp_hmac", "jwt_signing"):
            for entry in ring[purpose]["keys"].values():
                entry["key_file"] = str(bundle / entry["key_file"])
        (bundle / "source.json").write_text(json.dumps(ring))
        material = backup.keyring_files(bundle / "source.json")
        portable = json.loads(material["keyring.json"])
        for purpose in ("otp_hmac", "jwt_signing"):
            self.assertEqual(set(portable[purpose]["keys"]), {"new", "old"})
            ref = portable[purpose]["keys"]["old"]["key_file"]
            self.assertEqual(material[ref], b"historical material")
        self.assertNotIn(str(self.root), material["keyring.json"].decode())

    def test_corruption_missing_key_and_symlinks_refused_before_database_creation(self):
        for action in ("corrupt", "missing", "symlink"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as folder:
                self.root = Path(folder)
                bundle = self.bundle()
                key = bundle / "keys/0001"
                if action == "corrupt":
                    key.write_bytes(b"wrong")
                else:
                    key.unlink()
                    if action == "symlink":
                        key.symlink_to(bundle / "keys/0000")
                with patch("backup.run") as command, self.assertRaises(ValueError):
                    backup.restore(bundle, "copy", self.root / "restored")
                command.assert_not_called()

    def test_path_traversal_and_absolute_key_reference_refused(self):
        bundle = self.bundle()
        manifest = json.loads((bundle / "manifest.json").read_text())
        manifest["sha256"]["../outside"] = "bad"
        (bundle / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "unsafe"):
            backup.validate(bundle)
        del manifest["sha256"]["../outside"]
        ring = json.loads((bundle / "keyring.json").read_text())
        ring["otp_hmac"]["keys"]["old"]["key_file"] = "/outside"
        (bundle / "keyring.json").write_text(json.dumps(ring))
        manifest["sha256"]["keyring.json"] = backup.digest(bundle / "keyring.json")
        (bundle / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "outside"):
            backup.validate(bundle)

    def test_source_and_system_databases_refused_without_commands(self):
        bundle = self.bundle()
        for target in ("airlance_auth", "postgres", "template0", "template1", "bad; DROP DATABASE airlance_auth"):
            with self.subTest(target=target), patch("backup.run") as command, self.assertRaises(ValueError):
                backup.restore(bundle, target, self.root / "restored")
            command.assert_not_called()

    def test_existing_database_is_never_dropped_on_createdb_failure(self):
        bundle = self.bundle()
        with patch("backup.run", side_effect=ValueError("createdb failed")) as command, self.assertRaises(ValueError):
            backup.restore(bundle, "existing", self.root / "restored")
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[0][0], "createdb")
        self.assertFalse((self.root / "restored").exists())

    def test_existing_key_destination_is_not_overwritten(self):
        bundle = self.bundle()
        target = self.root / "restored"
        target.mkdir()
        (target / "keep").write_text("keep")
        with patch("backup.run") as command, self.assertRaises(FileExistsError):
            backup.restore(bundle, "copy", target)
        command.assert_not_called()
        self.assertEqual((target / "keep").read_text(), "keep")

    def test_failed_restore_drops_only_database_created_by_this_attempt(self):
        bundle = self.bundle()
        with patch("backup.run", side_effect=[None, ValueError("pg_restore failed"), None]) as command, self.assertRaises(ValueError):
            backup.restore(bundle, "new_copy", self.root / "restored")
        self.assertEqual([call.args[0][0] for call in command.call_args_list], ["createdb", "pg_restore", "dropdb"])
        self.assertEqual(command.call_args.args[0][-1], "new_copy")

    def test_success_restores_exact_material_and_private_permissions(self):
        bundle = self.bundle()
        destination = self.root / "restored"
        with patch("backup.run"), patch("backup.counts", return_value={"users": 2}):
            backup.restore(bundle, "copy", destination)
        restored = json.loads((destination / "keyring.json").read_text())
        self.assertEqual(restored["otp_hmac"]["keys"]["old"]["key_file"], str(destination / "keys/0001"))
        self.assertEqual((destination / "keys/0001").read_bytes(), b"historical material")
        self.assertEqual((destination / "keyring.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
