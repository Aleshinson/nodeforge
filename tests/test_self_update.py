"""Exercise the updater with real Bash/exec/files; replace only HTTP download."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit


REPO = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
FRESH = '#!/usr/bin/env bash\nprintf "FRESH_MENU: seven templates\\n"\n'
OLD = '#!/usr/bin/env bash\nprintf "STALE_MENU: three templates\\n"\n'


@unittest.skipUnless(BASH, "requires Bash")
class SelfUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=REPO)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.destination = self.base / "setup.sh"
        self.destination.write_text(OLD, encoding="utf-8", newline="\n")

    def update(self, payload=FRESH, launched_from_pipe=False, url=None, curl_rc=0, cached=False):
        (self.base / "download.sh").write_text(payload, encoding="utf-8", newline="\n")
        (self.base / "cached.sh").write_text(OLD, encoding="utf-8", newline="\n")
        script = r'''
source ./setup
cd "$1" || exit 1
mkdir scratch
export TMPDIR="$PWD/scratch"
SELF="$PWD/setup.sh"
[ "$2" = pipe ] && SELF=/dev/fd/63
UPDATE_URL="$3"
CURL_RC="$4" CACHED="$5"
curl() {
  local output url revalidate=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -o) output="$2"; shift ;;
      -H|--header) [ "$2" = 'Cache-Control: no-cache' ] && revalidate=1; shift ;;
      https://*) url="$1" ;;
    esac
    shift
  done
  printf '%s\n' "$url" >> requests.txt
  if [ "$CURL_RC" != 0 ]; then return "$CURL_RC"; fi
  if [ "$CACHED" = 1 ] && { [ "$url" = "$UPDATE_URL" ] || [ "$revalidate" != 1 ]; }; then
    cp cached.sh "$output"
  else
    cp download.sh "$output"
  fi
}
self_update
rc=$?
printf 'RETURNED_TO_OLD_MENU\n'
exit "$rc"
'''
        return subprocess.run(
            [BASH, "-c", script, "test", self.base.relative_to(REPO).as_posix(),
             "pipe" if launched_from_pipe else "file",
             url or "https://raw.githubusercontent.com/Aleshinson/nodeforge/main/setup",
             str(curl_rc), "1" if cached else "0"],
            cwd=REPO, capture_output=True, encoding="utf-8", errors="replace", timeout=15,
            env={**os.environ, "NO_COLOR": "1"},
        )

    def assert_restarted(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("FRESH_MENU: seven templates", result.stdout)
        self.assertNotIn("RETURNED_TO_OLD_MENU", result.stdout)
        self.assertEqual(list((self.base / "scratch").iterdir()), [])

    def test_restarts_when_disk_already_matches_download_but_running_menu_is_old(self):
        self.destination.write_text(FRESH, encoding="utf-8", newline="\n")
        self.assert_restarted(self.update())

    def test_pipe_launch_restarts_existing_fresh_setup_in_working_directory(self):
        self.destination.write_text(FRESH, encoding="utf-8", newline="\n")
        self.assert_restarted(self.update(launched_from_pipe=True))

    def test_download_revalidates_cache_and_uses_fresh_url(self):
        self.assert_restarted(self.update(cached=True))

    def test_update_url_keeps_existing_query_parameters(self):
        url = "https://example.test/setup?channel=stable&arch=amd64"
        self.assert_restarted(self.update(url=url, cached=True))
        requested = urlsplit((self.base / "requests.txt").read_text().strip())
        self.assertEqual((requested.scheme, requested.netloc, requested.path),
                         ("https", "example.test", "/setup"))
        query = parse_qs(requested.query)
        self.assertEqual(query["channel"], ["stable"])
        self.assertEqual(query["arch"], ["amd64"])

    def test_changed_file_is_installed_and_restarted(self):
        self.assert_restarted(self.update())
        self.assertEqual(self.destination.read_text(encoding="utf-8"), FRESH)

    def test_pipe_launch_creates_setup_when_missing(self):
        self.destination.unlink()
        self.assert_restarted(self.update(launched_from_pipe=True))
        self.assertEqual(self.destination.read_text(encoding="utf-8"), FRESH)

    def test_download_failure_leaves_file_and_running_menu_intact(self):
        result = self.update(curl_rc=22)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RETURNED_TO_OLD_MENU", result.stdout)
        self.assertEqual(self.destination.read_text(encoding="utf-8"), OLD)
        self.assertEqual(list((self.base / "scratch").iterdir()), [])

    def test_invalid_shell_download_is_rejected_before_replacing_file(self):
        result = self.update(payload='#!/usr/bin/env bash\nprintf "unterminated\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RETURNED_TO_OLD_MENU", result.stdout)
        self.assertEqual(self.destination.read_text(encoding="utf-8"), OLD)
        self.assertEqual(list((self.base / "scratch").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
