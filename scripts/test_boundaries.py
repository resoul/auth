"""Check that depguard rules in .golangci.yml reject forbidden imports."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINT = shutil.which("golangci-lint")

CASES = {
    "domain imports adapter": (
        "internal/domain/identity/bad.go",
        'package identity\n\nimport _ "airlance.org/auth/internal/config"\n',
    ),
    "domain imports third party": (
        "internal/domain/identity/bad.go",
        'package identity\n\nimport _ "github.com/spf13/cobra"\n',
    ),
    "application imports transport": (
        "internal/application/probe/bad.go",
        'package probe\n\nimport _ "airlance.org/auth/internal/transport/http"\n',
    ),
    # A package nothing else imports, so the probe cannot form an import cycle.
    "adapter imports bootstrap": (
        "internal/adapter/probe/bad.go",
        'package probe\n\nimport _ "airlance.org/auth/internal/bootstrap"\n',
    ),
    "adapter imports use case": (
        "internal/adapter/probe/bad.go",
        'package probe\n\nimport _ "airlance.org/auth/internal/application/emailauth"\n',
    ),
    "transport imports adapter": (
        "internal/transport/http/bad.go",
        'package http\n\nimport _ "airlance.org/auth/internal/adapter/clock"\n',
    ),
    "production imports testutil": (
        "internal/bootstrap/bad.go",
        'package bootstrap\n\nimport _ "airlance.org/auth/internal/testutil"\n',
    ),
    "production imports memory adapter": (
        "internal/bootstrap/bad.go",
        'package bootstrap\n\nimport _ "airlance.org/auth/internal/adapter/memory"\n',
    ),
    "cmd imports adapter": (
        "cmd/airlance-auth/bad.go",
        'package main\n\nimport _ "airlance.org/auth/internal/adapter/clock"\n',
    ),
}

SUPPORT = {
    "internal/testutil/testutil.go": "package testutil\n",
    "internal/adapter/memory/memory.go": "package memory\n",
    "internal/adapter/clock/clock.go": "package clock\n",
    "internal/application/emailauth/emailauth.go": "package emailauth\n",
    "internal/transport/http/http.go": "package http\n",
}


@unittest.skipUnless(LINT, "golangci-lint is not installed")
class BoundariesTest(unittest.TestCase):
    def copy_module(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        work = Path(tmp.name)
        for name in ("go.mod", "go.sum", ".golangci.yml", "cmd", "internal", "migrations"):
            source = ROOT / name
            if source.is_dir():
                shutil.copytree(source, work / name)
            else:
                shutil.copy2(source, work / name)
        for name, content in SUPPORT.items():
            path = work / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return work

    def lint(self, work):
        return subprocess.run([LINT, "run", "./..."], cwd=work, capture_output=True, text=True)

    def test_clean_copy_passes(self):
        result = self.lint(self.copy_module())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_forbidden_imports_fail(self):
        for name, (path, source) in CASES.items():
            with self.subTest(name):
                work = self.copy_module()
                target = work / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
                result = self.lint(work)
                self.assertNotEqual(result.returncode, 0, f"{name}: lint passed")
                self.assertIn("depguard", result.stdout, result.stdout)

    def test_test_files_may_import_testutil(self):
        work = self.copy_module()
        target = work / "internal/domain/identity/zz_boundary_test.go"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('package identity_test\n\nimport _ "airlance.org/auth/internal/testutil"\n', encoding="utf-8")
        result = self.lint(work)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
