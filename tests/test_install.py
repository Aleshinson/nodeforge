"""Full install (i), own node layout and the j firewall shortcut: real Bash, stubbed system."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
NL = chr(10)
# Windows: python3 is "python" and prints CRLF; flock is absent.
SHIM = ('python3() { python "$@" | tr -d "' + chr(92) + 'r"; }; flock() { :; };') if os.name == "nt" else ""
DOMAIN = "de.example.org"
CERT = "example.org"
SECRET = "eyJub2RlQ2VydFBlbSI6Ii0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLSJ9" + "=="

# Every install step is stubbed: it records its name; FAIL_<fn>=1 makes it fail once.
STEPS = '''
record() {
  echo "STEP:$1" >> "$LOG"
  local v="FAIL_$1"
  if [ -n "${!v:-}" ] && [ ! -e "$LOG.failed_$1" ]; then touch "$LOG.failed_$1"; return 1; fi
}
for f in block_ru_access block_ssh _install_ipv6_off block_optimize _install_protect block_netbird block_remnanode block_node_own block_rublock block_logs block_camouflage block_http_hardening block_beszel_agent block_audit _install_checks; do
  eval "$f() { record $f; }"
done
_reboot_pending() { [ -n "${REBOOT:-}" ] && [ ! -e "$LOG.rebooted" ]; }
reboot() { echo REBOOT >> "$LOG"; touch "$LOG.rebooted"; }
detect_ssh_port() { echo 22022; }
_public_ipv4() { echo 192.0.2.10; }
'''


def put(path, text):
    """Write LF-only: Bash reads these files, and write_text on Windows would add CR."""
    path.write_bytes(text.encode("utf-8"))


AFTER_GATE = ["block_ssh", "_install_ipv6_off", "block_optimize", "_install_protect", "block_netbird"]
AFTER_NODE = ["block_rublock", "block_logs", "block_camouflage", "block_http_hardening",
              "block_beszel_agent", "block_audit", "_install_checks"]


class BashCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=REPO)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def bash(self, script, *args, stdin=""):
        # Answers go through a file as bytes: a text-mode pipe on Windows turns LF into CRLF.
        answers = self.base / "stdin.txt"
        put(answers, stdin)
        return subprocess.run(
            [shutil.which("bash"), "-c", SHIM + f'exec < "{answers.relative_to(REPO).as_posix()}"; '
             + "source ./setup; " + script, "test",
             *(a.relative_to(REPO).as_posix() if isinstance(a, Path) else str(a) for a in args)],
            cwd=REPO, capture_output=True, encoding="utf-8", errors="replace", timeout=60,
        )

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class FullInstallTests(BashCase):
    def setUp(self):
        super().setUp()
        self.state = self.base / "nodeforge" / "install.state"
        self.log = self.base / "steps.log"

    def install(self, answers, **flags):
        script = 'NF_INSTALL_STATE="$1"; LOG="$2"; ' + "".join(f"{k}=1; " for k in flags) + STEPS + "block_install"
        result = self.bash(script, self.state, self.log, stdin=NL.join(answers) + NL)
        self.assert_ok(result)
        return result

    def steps(self):
        if not self.log.exists():
            return []
        return [line[5:] for line in self.log.read_text().splitlines() if line.startswith("STEP:")]

    def test_declined_after_ru_check_runs_nothing_else(self):
        self.install(["n"])
        self.assertEqual(self.steps(), ["block_ru_access"])
        self.assertFalse(self.state.exists())

    def test_own_variant_runs_every_step_in_order(self):
        self.install(["y", "2"])
        self.assertEqual(self.steps(), ["block_ru_access", *AFTER_GATE, "block_node_own", *AFTER_NODE])
        self.assertFalse(self.state.exists())

    def test_egames_variant_uses_item_5(self):
        self.install(["y", "1"])
        self.assertIn("block_remnanode", self.steps())
        self.assertNotIn("block_node_own", self.steps())

    def test_reboot_saves_next_step_and_variant_then_resumes_there(self):
        result = self.install(["y", "1", "y"], REBOOT=1)
        self.assertEqual(self.steps(), ["block_ru_access", "block_ssh", "_install_ipv6_off", "block_optimize"])
        self.assertIn("REBOOT", self.log.read_text())
        self.assertEqual(self.state.read_text().split(), ["3", "egames"])
        self.assertIn("«i»", result.stdout)

        done = len(self.steps())
        self.install(["y"], REBOOT=1)
        # No second RU check, no variant question: straight from protect, with item 5.
        self.assertEqual(self.steps()[done:], ["_install_protect", "block_netbird", "block_remnanode", *AFTER_NODE])
        self.assertFalse(self.state.exists())

    def test_failed_step_can_be_retried(self):
        self.install(["y", "2", "r"], FAIL_block_netbird=1)
        self.assertEqual(self.steps().count("block_netbird"), 2)
        self.assertEqual(self.steps()[-1], "_install_checks")

    def test_failed_step_can_be_skipped(self):
        self.install(["y", "2", "s"], FAIL_block_netbird=1)
        self.assertEqual(self.steps().count("block_netbird"), 1)
        self.assertEqual(self.steps()[-1], "_install_checks")

    def test_stop_keeps_the_failed_step_for_next_time(self):
        self.install(["y", "2", "0"], FAIL_block_netbird=1)
        self.assertEqual(self.steps()[-1], "block_netbird")
        self.assertEqual(self.state.read_text().split(), ["4", "own"])

    def test_declined_resume_can_start_over(self):
        self.state.parent.mkdir(parents=True)
        put(self.state, "6 egames" + NL)
        self.install(["n", "y", "y", "2"])
        self.assertEqual(self.steps(), ["block_ru_access", *AFTER_GATE, "block_node_own", *AFTER_NODE])

    def test_unknown_saved_step_starts_from_the_ru_check(self):
        self.state.parent.mkdir(parents=True)
        put(self.state, "zz own" + NL)
        result = self.install(["n"])
        self.assertIn("из прошлой установки", result.stderr)
        self.assertEqual(self.steps(), ["block_ru_access"])

    def test_run_block_returns_step_status(self):
        result = self.bash("ok_fn() { :; }; bad_fn() { return 3; }; "
                           "run_block ok ok_fn; echo RC=$?; run_block bad bad_fn; echo RC=$?")
        self.assertIn("RC=0", result.stdout)
        self.assertIn("RC=3", result.stdout)

    def test_menu_dispatches_full_install(self):
        result = self.bash("print_menu() { :; }; block_install() { echo FULL_INSTALL; }; menu",
                           stdin="i" + NL + NL + "0" + NL)
        self.assert_ok(result)
        self.assertIn("FULL_INSTALL", result.stdout)

    def test_ssh_over_ipv6_detection(self):
        script = 'LINE="$1"; detect_ssh_port() { echo 22022; }; ss() { echo "$LINE"; }; _ssh_over_ipv6'
        self.assertEqual(self.bash(script, "0 0 [2001:db8::2]:22022 [2001:db8::5]:51000").returncode, 0)
        self.assertNotEqual(self.bash(script, "0 0 192.0.2.2:22022 198.51.100.8:51000").returncode, 0)
        self.assertNotEqual(self.bash(script, "0 0 [::ffff:192.0.2.2]:22022 [::ffff:198.51.100.8]:51000").returncode, 0)


class ChecksTests(BashCase):
    STUBS = ('ensure_check_dependencies() { :; }; wget() { echo "echo RAN"; }; curl() { echo "echo RAN"; }; '
             'sysbench() { echo SYSBENCH; }; ')

    def test_install_runs_checks_1_2_3_4_6(self):
        result = self.bash(self.STUBS + "_install_checks")
        self.assert_ok(result)
        for name in ("IP region", "CensorCheck geoblock", "CensorCheck DPI", "IP.Check.Place", "Russian iPerf3"):
            self.assertIn(name, result.stdout)
        for name in ("IPQuality", "YABS", "bench.sh", "sysbench CPU"):
            self.assertNotIn(name, result.stdout)
        self.assertEqual(result.stdout.count("RAN"), 5)

    def test_checks_submenu_still_runs_by_number(self):
        result = self.bash(self.STUBS + "print_checks_menu() { :; }; submenu_checks",
                           stdin="1 9" + NL + NL + "0" + NL)
        self.assert_ok(result)
        self.assertIn("IP region", result.stdout)
        self.assertIn("SYSBENCH", result.stdout)


class HttpPortTests(BashCase):
    def open_port(self, chain):
        registry = self.base / "firewall.env"
        put(registry, 'EXTRA_TCP="8443"' + NL)
        result = self.bash('''
FW_ENV="$1" CHAIN="$2"
fw_init() { :; }
nft() { if [ "$2" = table ]; then return 0; fi; printf '%s' "$CHAIN"; }
apply_firewall() { echo APPLY; }
_node_http_open_port
''', registry, chain)
        self.assert_ok(result)
        self.assertIn('EXTRA_TCP="80,8443"', registry.read_text())
        return result

    def test_open_port_80_does_not_rebuild_firewall(self):
        chain = NL.join(["        tcp dport 443 ct state new accept", "        tcp dport 80 ct state new accept"])
        self.assertNotIn("APPLY", self.open_port(chain).stdout)

    def test_missing_port_80_still_rebuilds_firewall(self):
        chain = NL.join(["        tcp dport 8080 ct state new accept", "        tcp dport 80 ct state new meter cc4_80"])
        self.assertIn("APPLY", self.open_port(chain).stdout)


class OwnNodeTests(BashCase):
    def stack(self):
        node = self.base / "remnanode"
        site = self.base / "html"
        node.mkdir()
        site.mkdir()
        result = self.bash('_node_compose_yml "$2" "$3" > "$1/docker-compose.yml"; '
                           '_node_nginx_text "$4" "$2" > "$1/nginx.conf"', node, CERT, SECRET, DOMAIN)
        self.assert_ok(result)
        inspect = self.base / "inspect.json"
        inspect.write_text(json.dumps([{"HostConfig": {"NetworkMode": "host"}, "Mounts": [
            {"Type": "bind", "Source": str(node / "nginx.conf"), "Destination": "/etc/nginx/conf.d/default.conf"},
            {"Type": "bind", "Source": str(site), "Destination": "/var/www/html"}]}]))
        return node, inspect

    def test_compose_is_found_by_the_node_helpers(self):
        node, _ = self.stack()
        compose = node / "docker-compose.yml"
        text = compose.read_text()
        self.assertIn("- SECRET_KEY=" + SECRET, text)
        self.assertIn("- NODE_PORT=2222", text)
        self.assertIn(f"/etc/letsencrypt/live/{CERT}/privkey.pem:/etc/nginx/ssl/{CERT}/privkey.pem:ro", text)
        result = self.bash('f="$1"; echo "SVC=$(_compose_node_service "$f")"; '
                           'echo "NAME=$(_compose_service_key "$f" remnanode container_name)"', compose)
        self.assertIn("SVC=remnanode", result.stdout)
        self.assertIn("NAME=remnanode", result.stdout)

    def test_ru_block_volume_lands_in_the_node_service(self):
        node, _ = self.stack()
        result = self.bash('D="$1"; require_node() { NODE_DIR="$D"; NODE_SERVICE=remnanode; }; '
                           'compose_add_volume "/opt/remnanode/xray-assets:/usr/local/share/xray"', node)
        self.assert_ok(result)
        text = (node / "docker-compose.yml").read_text()
        node_part = text[text.index("  remnanode:"):]
        self.assertIn("      - /opt/remnanode/xray-assets:/usr/local/share/xray", node_part)
        self.assertEqual(text.count("xray-assets"), 1)

    def test_nginx_config_is_understood_by_items_h_and_j(self):
        _, inspect = self.stack()
        candidate = self.base / "candidate.conf"
        j = self.bash('_node_http_tool prepare "$1" "$2"', inspect, candidate)
        self.assert_ok(j)
        self.assertIn(DOMAIN, j.stdout)
        self.assertIn("return 301 https://" + DOMAIN, candidate.read_text())
        h = self.bash('_site_tool context "$1"', inspect)
        self.assert_ok(h)
        self.assertEqual(h.stdout.splitlines()[0], DOMAIN)

    def test_secret_key_is_taken_from_any_panel_form(self):
        forms = [SECRET, "SECRET_KEY=" + SECRET, '      - SECRET_KEY="' + SECRET + '"', "'" + SECRET + "'"]
        for form in forms:
            with self.subTest(form=form):
                result = self.bash('_node_ask_secret K; echo "KEY=$K"', stdin=form + NL)
                self.assert_ok(result)
                self.assertIn("KEY=" + SECRET, result.stdout)
        result = self.bash('_node_ask_secret K; echo "KEY=$K"', stdin="short" + NL + SECRET + NL)
        self.assertIn("KEY=" + SECRET, result.stdout)
        self.assertIn("Не похоже", result.stderr)

    def test_cloudflare_token_is_checked_against_the_new_domain(self):
        ini = self.base / "secrets" / "cloudflare.ini"
        script = '''
INI="$1" DOMAINS="$2"
_cf_api() {
  case "$1" in
    user/tokens/verify) echo '{"result":{"status":"active"}}';;
    *) echo '{"result":[{"name":"example.org"}]}';;
  esac
}
_cf_token_set "$INI" "$DOMAINS"
'''
        result = self.bash(script, ini, CERT, stdin="tok123" + NL)
        self.assert_ok(result)
        self.assertEqual(ini.read_text().strip(), "dns_cloudflare_api_token = tok123")

        ini.unlink()
        result = self.bash(script, ini, "other.net", stdin="tok123" + NL + "n" + NL)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("other.net", result.stderr)
        self.assertFalse(ini.exists())


if __name__ == "__main__":
    unittest.main()
