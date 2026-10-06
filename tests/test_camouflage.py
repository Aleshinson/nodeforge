"""Offline regression tests: real files and Bash, stub only Docker/HTTPS."""
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
SUSPECT = '''<!doctype html><title>Page_a1b2c3d4</title>
<meta content="0123456789abcdef0123456789abcdef" name="session-id">
<!-- 0123456789abcdef --><body class="style-aabbccdd">Old template</body>'''
CLEAN = '<!doctype html><title>Field notes</title><h1>My field notes</h1>'


class CamouflageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=REPO)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.site = self.base / "public"
        self.source = self.base / "my site"
        self.backups = self.base / "backups"
        for folder in (self.site, self.source, self.backups):
            folder.mkdir()
        (self.site / "index.html").write_text(SUSPECT, encoding="utf-8")
        (self.site / "old.css").write_text("old fingerprint", encoding="utf-8")
        (self.site / ".well-known").mkdir()
        (self.site / ".well-known" / "token").write_text("acme", encoding="utf-8")
        (self.source / "index.html").write_text(CLEAN, encoding="utf-8")
        (self.source / "assets").mkdir()
        (self.source / "assets" / "site.css").write_text("h1 {color: green}")

    def bash(self, script, *args):
        # On Windows Git Bash has Python as `python`, but python3 is an OS alias.
        shim = 'python3() { python "$@"; };' if os.name == "nt" else ""
        result = subprocess.run(
            [BASH, "-c", shim + 'source ./setup; ' + script, "test",
             *(a.relative_to(REPO).as_posix() if isinstance(a, Path) else str(a) for a in args)],
            cwd=REPO, capture_output=True, encoding="utf-8", errors="replace",
        )
        return result

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def site_helpers(self):
        code = (REPO / "setup").read_text(encoding="utf-8").split("_site_tool() {", 1)[1]
        code = code.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        tree = ast.parse(code)
        # Load the embedded Python helpers without executing the CLI dispatcher.
        tree.body = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef))]
        namespace = {}
        exec(compile(tree, "site-helper", "exec"), namespace)
        return namespace

    def test_nested_host_bind_mount_is_rejected_even_on_same_device(self):
        helpers = self.site_helpers()
        self.assertIn("reject_nested_mounts", helpers)
        mountpoint = (self.site / "shared assets").as_posix().replace(" ", r"\040")
        table = self.base / "mountinfo"
        table.write_text(f"123 45 8:1 /shared {mountpoint} rw - ext4 /dev/sda1 rw\n")
        with self.assertRaises(ValueError):
            helpers["reject_nested_mounts"](self.site.resolve(), table)
        self.assertEqual((self.site / "index.html").read_text(), SUSPECT)

    @unittest.skipUnless(os.name == "posix" and getattr(os, "geteuid", lambda: -1)() == 0,
                         "requires Linux root to verify real uid/gid preservation")
    def test_rollback_preserves_old_file_ownership(self):
        page = self.site / "index.html"
        os.chown(page, 1234, 1235)
        page.chmod(0o640)
        result = self.install(CLEAN, "503")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTPS_PROBED", result.stderr)
        self.assertEqual((page.stat().st_uid, page.stat().st_gid), (1234, 1235))
        self.assertEqual(page.stat().st_mode & 0o777, 0o640)

    def install(self, body=None, code="200", curl_rc=0):
        response = self.base / "response.html"
        response.write_text(CLEAN if body is None else body, encoding="utf-8")
        return self.bash('''
curl() {
  local output
  while [ "$#" -gt 0 ]; do
    case "$1" in -o) output="$2"; shift;; esac
    shift
  done
  cp "$RESPONSE" "$output"
  echo HTTPS_PROBED >&2
  printf '%s' "$HTTP_CODE"
  return "$CURL_RC"
}
RESPONSE="$4" HTTP_CODE="$5" CURL_RC="$6"
_site_install "$1" "$2" example.org "$3"
''', self.source, self.site, self.backups, response, code, curl_rc)

    def test_audit_detects_template_even_with_valid_https(self):
        conf = self.base / "nginx.conf"
        conf.write_text("server_name example.org;\n")
        result = self.bash('''
curl() {
  local output
  while [ "$#" -gt 0 ]; do
    case "$1" in -o) output="$2"; shift;; esac
    shift
  done
  cp "$BODY" "$output"; printf 200
}
_a_ok() { echo "OK:$*"; }
_a_fail() { echo "FAIL:$*"; }
_a_warn() { echo "WARN:$*"; }
_a_hint() { :; }
_a_fix() { echo "FIX:$*"; }
BODY="$2"
_audit_camouflage "$1"
''', conf, self.site / "index.html")
        self.assert_ok(result)
        self.assertIn("block_camouflage", result.stdout)
        self.assertIn("Page_", result.stdout)

    def test_scanner_detects_markers_across_nested_files(self):
        (self.source / "assets" / "old.html").write_text(SUSPECT)
        result = self.bash('_site_tool scan "$1"', self.source)
        self.assert_ok(result)
        self.assertIn("Page_", result.stdout)
        self.assertIn("session-id", result.stdout)
        self.assertIn("hex", result.stdout)

    def test_scanner_detects_randomized_css_even_after_title_edit(self):
        (self.source / "assets" / "site.css").write_text("/* 0123456789abcdef */\n.ui-aabbccdd { display: block; }")
        result = self.bash('_site_tool scan "$1"', self.source)
        self.assert_ok(result)
        self.assertIn("CSS random class", result.stdout)

    def test_audit_does_not_claim_success_for_partial_http_response(self):
        conf = self.base / "nginx.conf"
        conf.write_text("server_name example.org;\n")
        result = self.bash('''
curl() { printf 200; return 28; }
_a_ok() { echo AUDIT_SUCCESS; }
_a_warn() { echo AUDIT_INCOMPLETE; }
_audit_camouflage "$1"
''', conf)
        self.assert_ok(result)
        self.assertNotIn("AUDIT_SUCCESS", result.stdout)
        self.assertIn("AUDIT_INCOMPLETE", result.stdout)

    def test_clean_site_has_no_known_markers(self):
        result = self.bash('_site_tool scan "$1"', self.source)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_menu_dispatches_h(self):
        result = self.bash('''
print_menu() { :; }
block_camouflage() { echo SITE_MENU; }
menu <<< $'h\\n\\n0'
''')
        self.assert_ok(result)
        self.assertIn("SITE_MENU", result.stdout)

    def test_install_replaces_all_old_assets_and_keeps_acme_and_backup(self):
        inode = self.site.stat().st_ino
        self.assert_ok(self.install())
        self.assertEqual(self.site.stat().st_ino, inode, "Docker bind-mount inode must not change")
        self.assertEqual((self.site / "index.html").read_text(), CLEAN)
        self.assertFalse((self.site / "old.css").exists())
        self.assertTrue((self.site / "assets" / "site.css").is_file())
        self.assertEqual((self.site / ".well-known" / "token").read_text(), "acme")
        originals = list(self.backups.glob("site-*/old/index.html"))
        self.assertEqual(len(originals), 1)
        self.assertEqual(originals[0].read_text(), SUSPECT)

    def test_bad_http_wrong_site_and_tls_failure_restore_old_files(self):
        for body, code, rc in [(CLEAN, "503", 0), (SUSPECT, "200", 0), (CLEAN, "000", 60)]:
            with self.subTest(code=code, rc=rc):
                result = self.install(body, code, rc)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("HTTPS_PROBED", result.stderr, result.stdout + result.stderr)
                self.assertEqual((self.site / "index.html").read_text(), SUSPECT)
                self.assertTrue((self.site / "old.css").is_file())
                self.assertFalse((self.site / "assets").exists())

    def test_refuses_template_or_private_files_without_touching_site(self):
        for name, content in [("nested.html", SUSPECT), (".env", "SECRET=x")]:
            with self.subTest(name=name):
                path = self.source / name
                path.write_text(content)
                result = self.install()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.site / "index.html").read_text(), SUSPECT)
                path.unlink()

    def test_refuses_overlapping_source(self):
        result = self.bash('_site_install "$1" "$1" example.org "$2"', self.site, self.backups)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.site / "index.html").read_text(), SUSPECT)

    def test_partial_copy_failure_rolls_back(self):
        result = self.bash('''
eval "$(declare -f _site_tool | sed '1s/_site_tool/_real_site_tool/')"
_site_tool() {
  if [ "$1" = replace ] && [[ "$2" = */new ]]; then
    cp "$2/index.html" "$3/index.html"
    return 2
  fi
  _real_site_tool "$@"
}
_site_install "$1" "$2" example.org "$3"
''', self.source, self.site, self.backups)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.site / "index.html").read_text(), SUSPECT)
        self.assertEqual(len(list(self.backups.glob("site-*/old/index.html"))), 1)

    def test_context_resolves_real_mount_and_rejects_nested_mount(self):
        conf = self.base / "nginx.conf"
        conf.write_text('''server {
  server_name example.org;
  listen unix:/dev/shm/nginx.sock ssl proxy_protocol;
  root /var/www/html;
  index index.html;
}
server { server_name _; return 444; }
''')
        mounts = [
            {"Type": "bind", "Source": str(conf), "Destination": "/etc/nginx/conf.d/default.conf"},
            {"Type": "bind", "Source": str(self.site), "Destination": "/var/www/html"},
        ]
        inspect = self.base / "inspect.json"
        inspect.write_text(json.dumps([{"Mounts": mounts}]))
        result = self.bash('_site_tool context "$1"', inspect)
        self.assert_ok(result)
        self.assertEqual(result.stdout.splitlines(), ["example.org", str(self.site.resolve())])
        # Exercise the real menu function under run_block's errexit mode: a
        # clean scan returns 1 and must not accidentally abort the menu.
        (self.site / "index.html").write_text(CLEAN)
        result = self.bash('''
require_node() { NODE_DIR=/opt/remnanode; }
docker() {
  case "$1" in
    ps) printf 'nginx-id nginx:1.30\\n';;
    inspect) cat "$INSPECT";;
    *) return 99;;
  esac
}
ask() { printf -v "$1" '%s' 0; }
INSPECT="$1"
set -e
block_camouflage
echo SCAN_COMPLETED
''', inspect)
        self.assert_ok(result)
        self.assertIn("SCAN_COMPLETED", result.stdout)
        mounts.append({"Type": "bind", "Source": str(self.source), "Destination": "/var/www/html/assets"})
        inspect.write_text(json.dumps([{"Mounts": mounts}]))
        self.assertNotEqual(self.bash('_site_tool context "$1"', inspect).returncode, 0)


if __name__ == "__main__":
    unittest.main()
