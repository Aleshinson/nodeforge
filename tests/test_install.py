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
CR = chr(92) + "r"
# Windows: python3 is "python"; it and openssl print CRLF; flock is absent.
SHIM = ('python3() { python "$@" | tr -d "' + CR + '"; }; '
        'openssl() { command openssl "$@" | tr -d "' + CR + '"; }; flock() { :; };') if os.name == "nt" else ""
DOMAIN = "de.example.org"
CERT = "example.org"
SECRET = "eyJub2RlQ2VydFBlbSI6Ii0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLSJ9" + "=="

STEP_FNS = ("block_ru_access _install_ssh _install_ipv6_off block_optimize _install_protect _install_netbird "
            "_remnanode_egames block_node_own block_rublock block_logs _install_node_check _install_site "
            "block_http_hardening _install_beszel _install_audit")
ASK_FNS = ("_install_ask_ssh _install_ask_ipv6 _install_ask_protect _install_ask_netbird _install_ask_site "
           "_install_ask_beszel _install_ask_audit")

# Every step and question is stubbed: it records its name; FAIL_<fn>=1 makes a step fail once.
# The node question keeps the real variant choice; netbird carries an awkward answer through the file.
STEPS = '''
record() {
  echo "STEP:$1" >> "$LOG"
  local v="FAIL_$1"
  if [ -n "${!v:-}" ] && [ ! -e "$LOG.failed_$1" ]; then touch "$LOG.failed_$1"; return 1; fi
}
ask_record() { echo "ASK:$1" >> "$LOG"; }
for f in ''' + STEP_FNS + '''; do eval "$f() { record $f; }"; done
for f in ''' + ASK_FNS + '''; do eval "$f() { ask_record $f; }"; done
_install_ask_netbird() { ask_record _install_ask_netbird; NF_IN_NETBIRD_KEY='nb key "q" $x'; }
_install_netbird() { echo "KEY:$NF_IN_NETBIRD_KEY" >> "$LOG"; record _install_netbird; }
_install_ask_node() { ask_record _install_ask_node; if [ -z "$NF_INSTALL_NODE" ]; then _install_ask_variant; fi; }
_install_summary() { :; }
require_node() { :; }
_reboot_pending() { [ -n "${REBOOT:-}" ] && [ ! -e "$LOG.rebooted" ]; }
reboot() { echo REBOOT >> "$LOG"; touch "$LOG.rebooted"; }
detect_ssh_port() { echo 22022; }
_public_ipv4() { echo 192.0.2.10; }
'''


def put(path, text):
    """Write LF-only: Bash reads these files, and write_text on Windows would add CR."""
    path.write_bytes(text.encode("utf-8"))


def values(stdout):
    """NAME=value lines printed by a test script."""
    return dict(line.split("=", 1) for line in stdout.splitlines() if "=" in line)


AFTER_GATE = ["_install_ssh", "_install_ipv6_off", "block_optimize", "_install_protect", "_install_netbird"]
AFTER_NODE = ["block_rublock", "block_logs", "_install_node_check", "_install_site", "block_http_hardening",
              "_install_beszel", "_install_audit"]
ALL_ASKS = ["_install_ask_ssh", "_install_ask_ipv6", "_install_ask_protect", "_install_ask_netbird",
            "_install_ask_node", "_install_ask_site", "_install_ask_beszel", "_install_ask_audit"]


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
        self.answers = self.base / "nodeforge" / "install.answers"
        self.log = self.base / "steps.log"

    def install(self, answers, **flags):
        script = ('NF_INSTALL_STATE="$1"; NF_INSTALL_ANSWERS="$2"; LOG="$3"; '
                  + "".join(f"{k}=1; " for k in flags) + STEPS + "block_install")
        result = self.bash(script, self.state, self.answers, self.log, stdin=NL.join(answers) + NL)
        self.assert_ok(result)
        return result

    def lines(self, prefix):
        if not self.log.exists():
            return []
        return [line[len(prefix):] for line in self.log.read_text().splitlines() if line.startswith(prefix)]

    def steps(self):
        return self.lines("STEP:")

    def asks(self):
        return self.lines("ASK:")

    def test_declined_after_ru_check_runs_nothing_else(self):
        self.install(["n"])
        self.assertEqual(self.steps(), ["block_ru_access"])
        self.assertEqual(self.asks(), [])
        self.assertFalse(self.state.exists())

    def test_all_questions_come_first_then_steps_run_in_order(self):
        # y — continue after the RU check, 2 — own node, y — the summary is right.
        self.install(["y", "2", "y"])
        log = self.log.read_text().splitlines()
        first = log.index("STEP:_install_ssh")
        self.assertEqual([line for line in log[:first] if line.startswith("ASK:")], ["ASK:" + a for a in ALL_ASKS])
        self.assertFalse([line for line in log[first:] if line.startswith("ASK:")])
        self.assertEqual(self.steps(), ["block_ru_access", *AFTER_GATE, "block_node_own", *AFTER_NODE])
        self.assertNotIn("REBOOT", log)
        self.assertFalse(self.state.exists())
        self.assertFalse(self.answers.exists())

    def test_node_is_checked_only_after_ru_lists_and_logs(self):
        self.install(["y", "2", "y"])
        steps = self.steps()
        node = steps.index("block_node_own")
        self.assertEqual(steps[node:node + 5],
                         ["block_node_own", "block_rublock", "block_logs", "_install_node_check", "_install_site"])

    def test_egames_variant_uses_item_5(self):
        self.install(["y", "1", "y"])
        self.assertIn("_remnanode_egames", self.steps())
        self.assertNotIn("block_node_own", self.steps())

    def test_declined_summary_changes_nothing(self):
        result = self.install(["y", "2", "n"])
        self.assertEqual(self.steps(), ["block_ru_access"])
        self.assertFalse(self.state.exists())
        self.assertFalse(self.answers.exists())
        self.assertIn("ответы не сохранены", result.stderr)

    def test_reboot_comes_last_after_every_step(self):
        # The new kernel is pending right after optimize, yet nothing stops there.
        result = self.install(["y", "1", "y", "y"], REBOOT=1)
        log = self.log.read_text().splitlines()
        self.assertEqual(self.steps(), ["block_ru_access", *AFTER_GATE, "_remnanode_egames", *AFTER_NODE])
        self.assertEqual(log[-1], "REBOOT")
        self.assertEqual(log.count("REBOOT"), 1)
        self.assertEqual(self.lines("KEY:"), ['nb key "q" $x'])
        self.assertFalse(self.state.exists())
        self.assertFalse(self.answers.exists())
        self.assertIn("ssh -p 22022", result.stderr + result.stdout)

    def test_declined_reboot_still_finishes_the_install(self):
        result = self.install(["y", "2", "y", "n"], REBOOT=1)
        self.assertNotIn("REBOOT", self.log.read_text())
        self.assertEqual(self.steps()[-1], "_install_audit")
        self.assertFalse(self.state.exists())
        self.assertFalse(self.answers.exists())
        self.assertIn("Перезагрузи сам", result.stdout + result.stderr)

    def test_failed_step_can_be_retried(self):
        self.install(["y", "2", "y", "r"], FAIL__install_netbird=1)
        self.assertEqual(self.steps().count("_install_netbird"), 2)
        self.assertEqual(self.steps()[-1], "_install_audit")

    def test_failed_step_can_be_skipped(self):
        self.install(["y", "2", "y", "s"], FAIL__install_netbird=1)
        self.assertEqual(self.steps().count("_install_netbird"), 1)
        self.assertEqual(self.steps()[-1], "_install_audit")

    def test_stop_keeps_the_failed_step_and_answers_for_next_time(self):
        self.install(["y", "2", "y", "0"], FAIL__install_netbird=1)
        self.assertEqual(self.steps()[-1], "_install_netbird")
        self.assertEqual(self.state.read_text().split(), ["4", "own"])
        self.assertTrue(self.answers.exists())

    def test_declined_resume_can_start_over(self):
        self.state.parent.mkdir(parents=True)
        put(self.state, "6 egames" + NL)
        put(self.answers, "NF_IN_ASKED=1" + NL)
        self.install(["n", "y", "y", "2", "y"])
        self.assertEqual(self.asks(), ALL_ASKS)
        self.assertEqual(self.steps(), ["block_ru_access", *AFTER_GATE, "block_node_own", *AFTER_NODE])

    def test_resume_without_saved_answers_asks_only_the_remaining_steps(self):
        # State from the version before the questionnaire: step 6, no answers file.
        self.state.parent.mkdir(parents=True)
        put(self.state, "6 own" + NL)
        self.install(["y", "y"])
        self.assertEqual(self.asks(), ["_install_ask_site", "_install_ask_beszel", "_install_ask_audit"])
        self.assertEqual(self.steps(), AFTER_NODE)

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


class QuestionnaireTests(BashCase):
    """The real questions of «i»: everything is asked up front and nothing changes before «начинаем»."""

    STUBS = '''
FW_ENV="$1"; NF_INSTALL_ANSWERS="$2"; NF_CF_INI="$3"
fw_init() { :; }
_ipv6_on() { return 1; }
require_node() { return 1; }
ss() { :; }
_public_ipv4() { echo 192.0.2.10; }
_cdn_resolve() { echo 192.0.2.10; }
_node_cert_ready() { return 1; }
_cf_api() {
  case "$1" in
    user/tokens/verify) echo '{"result":{"status":"active"}}';;
    *) echo '{"result":[{"name":"example.org"}]}';;
  esac
}
'''
    SHOW = '''
unset "${!NF_IN_@}"; _install_load
for v in "${!NF_IN_@}"; do echo "$v=${!v}"; done
echo "VARIANT=$NF_INSTALL_NODE"
salt="$(cut -d'$' -f3 <<<"$NF_IN_SSH_HASH")"
if [ "$(openssl passwd -6 -salt "$salt" "$PW")" = "$NF_IN_SSH_HASH" ]; then echo HASH=ok; fi
'''

    def test_all_answers_are_collected_before_anything_changes(self):
        registry = self.base / "firewall.env"
        answers = self.base / "install.answers"
        ini = self.base / "cloudflare.ini"
        put(registry, 'ENABLE_BLOCKLISTS="1"' + NL + 'PANEL_IPS=""' + NL)
        password = "Correct-Horse-9"
        stdin = [
            "22022", "alex", password, password, "",     # 1: SSH, no key
            "", "", "", "198.51.100.7", "", "n", "n",     # 3: firewall
            "nb-setup-key",                               # 4: netbird
            "2", DOMAIN, SECRET, "tok123",                # 5: own node, new Cloudflare token
            "2",                                          # h: Palette API
            "ssh-ed25519 AAAAbeszel", "", "", "", "y",    # 11: Beszel with auto-update
            "",                                           # a: default — fix what needs no downtime
            "y",                                          # summary
        ]
        script = (self.STUBS + 'PW="$4"; NF_INSTALL_NODE=""; _install_questions 0; echo "RC=$?"' + NL + self.SHOW)
        result = self.bash(script, registry, answers, ini, password, stdin=NL.join(stdin) + NL)
        self.assert_ok(result)
        got = values(result.stdout)
        self.assertEqual(got["RC"], "0", result.stderr)
        expected = {
            "NF_IN_SSH_PORT": "22022", "NF_IN_SSH_USER": "alex", "NF_IN_SSH_KEY": "", "NF_IN_IPV6": "yes",
            "NF_IN_FW_NODE_PORT": "2222", "NF_IN_FW_TCP": "443", "NF_IN_FW_UDP": "443",
            "NF_IN_FW_PANEL": "198.51.100.7", "NF_IN_FW_BLOCKLISTS": "", "NF_IN_FW_TOR": "0",
            "NF_IN_NETBIRD_KEY": "nb-setup-key", "NF_IN_NODE_DOMAIN": DOMAIN, "NF_IN_NODE_SECRET": SECRET,
            "NF_IN_CF_TOKEN": "tok123", "NF_IN_SITE": "palette", "NF_IN_BESZEL_KEY": "ssh-ed25519 AAAAbeszel",
            "NF_IN_BESZEL_PORT": "45876", "NF_IN_BESZEL_AUTO": "true", "NF_IN_AUDIT": "safe",
            "NF_IN_ASKED": "1 ipv6 3 4 5 h 11 a", "VARIANT": "own",
        }
        for name, value in expected.items():
            with self.subTest(name=name):
                self.assertEqual(got.get(name), value)
        self.assertEqual(got.get("HASH"), "ok")
        self.assertNotIn(password, answers.read_text())
        # Answers are only answers: the registry and the Cloudflare ini are written by the steps.
        self.assertNotIn("198.51.100.7", registry.read_text())
        self.assertFalse(ini.exists())
        for shown in ("Palette API", DOMAIN, "выпущу example.org", "198.51.100.7", "блоклисты: да"):
            self.assertIn(shown, result.stdout)

    def test_ipv6_is_asked_only_when_the_session_comes_over_it(self):
        script = '''
ARG="$1"
_ipv6_on() { return 0; }; _fix_disable_ipv6() { echo DISABLED; }
_ssh_over_ipv6() { [ "$ARG" = v6 ]; }
_install_ask_ipv6; echo "ANSWER=$NF_IN_IPV6"
_install_ipv6_off
'''
        kept = self.bash(script, "v6", stdin="n" + NL)
        self.assertEqual(values(kept.stdout)["ANSWER"], "no")
        self.assertNotIn("DISABLED", kept.stdout)
        off = self.bash(script, "v4")
        self.assertEqual(values(off.stdout)["ANSWER"], "yes")
        self.assertIn("DISABLED", off.stdout)

    def test_ssh_is_not_touched_without_a_password_hash(self):
        result = self.bash('set_sshd_option() { echo TOUCHED; }; fw_set() { echo TOUCHED; }; '
                           '_ssh_apply 22022 alex "" ""; echo "RC=$?"')
        self.assertIn("RC=1", result.stdout)
        self.assertNotIn("TOUCHED", result.stdout)


class InstallStepTests(BashCase):
    """Install steps take the saved answers and ask nothing."""

    def test_protect_answers_reach_the_registry_only_at_step_3(self):
        registry = self.base / "firewall.env"
        put(registry, 'ENABLE_BLOCKLISTS="1"' + NL + 'EXTRA_TCP=""' + NL)
        script = '''
FW_ENV="$1"
fw_init() { :; }; ss() { :; }; detect_ssh_port() { echo 22022; }
apply_firewall() { echo APPLY; }
_protect_ask
echo "BEFORE=$(grep -c 198.51.100.7 "$FW_ENV")"
_install_protect
'''
        # Defaults for ports, panel IP, empty whitelist, «no» to blocklists, «yes» to Tor.
        result = self.bash(script, registry, stdin=NL.join(["", "", "", "198.51.100.7", "", "n", "y"]) + NL)
        self.assert_ok(result)
        self.assertEqual(values(result.stdout)["BEFORE"], "0")
        self.assertIn("APPLY", result.stdout)
        text = registry.read_text()
        for line in ('NODE_PORT="2222"', 'TCP_PORTS="443"', 'UDP_PORTS="443"', 'PANEL_IPS="198.51.100.7"',
                     'ENABLE_BLOCKLISTS="1"', 'BLOCK_TOR="1"', 'SSH_PORT="22022"', 'EXTRA_TCP="80"'):
            self.assertIn(line, text)

    def test_beszel_gets_auto_update_from_the_answers(self):
        registry = self.base / "firewall.env"
        put(registry, "")
        script = '''
FW_ENV="$1"
fw_init() { :; }; panel_only_apply() { :; }; systemctl() { return 1; }
curl() {
  cat > "$4" <<'EOF'
#!/bin/sh
echo "ARGS:$*"
EOF
}
NF_IN_BESZEL_KEY="$2"; NF_IN_BESZEL_PORT=45876; NF_IN_BESZEL_TOKEN=""; NF_IN_BESZEL_URL=""; NF_IN_BESZEL_AUTO=false
_install_beszel
NF_IN_BESZEL_KEY=""
_install_beszel
'''
        result = self.bash(script, registry, "ssh-ed25519 AAAA")
        self.assert_ok(result)
        self.assertEqual(result.stdout.count("ARGS:"), 1)
        self.assertIn("ARGS:-k ssh-ed25519 AAAA -p 45876 --auto-update false", result.stdout)
        self.assertIn('PANEL_PORTS="45876"', registry.read_text())
        self.assertIn("не ставлю", result.stdout)

    def audit(self, mode):
        script = '''
NF_IN_AUDIT="$1"
_audit_run() {
  AUD_FIX_DESC=("без простоя" "с обрывом"); AUD_FIX_COST=(0 1); AUD_FIX_FN=(fix_a fix_b)
  AUD_FIX_ARG=("" ""); AUD_FIX_STATE=("" "")
}
fix_a() { echo FIXED_A; }; fix_b() { echo FIXED_B; }
_install_audit
'''
        result = self.bash(script, mode)
        self.assert_ok(result)
        return result.stdout

    def test_audit_fixes_only_what_needs_no_downtime(self):
        out = self.audit("safe")
        self.assertIn("FIXED_A", out)
        self.assertNotIn("FIXED_B", out)

    def test_audit_report_fixes_nothing(self):
        out = self.audit("report")
        self.assertNotIn("FIXED_A", out)
        self.assertNotIn("FIXED_B", out)
        self.assertIn("пунктом «a»", out)

    def test_audit_in_the_install_leaves_the_reboot_for_the_end(self):
        script = ('_reboot_pending_pkgs() { echo linux-image-6.8.0-90-generic; }; '
                  '_audit_run() { _audit_reboot; }; NF_IN_AUDIT=menu; _install_audit; echo ---; '
                  'AUD_FIX_FN=(); _audit_reboot; echo "FIXES=${AUD_FIX_FN[*]}"')
        result = self.bash(script)
        self.assert_ok(result)
        inside, outside = result.stdout.split("---")
        self.assertIn("Чинить скриптом нечего", inside)
        self.assertIn("в конце установки", result.stderr)
        self.assertIn("FIXES=_fix_reboot", outside)

    def test_site_variant_is_picked_by_number(self):
        for answer, variant in (("2", "palette"), ("9" + NL + "3", "calendar"), ("0", ""), ("", "")):
            with self.subTest(answer=answer):
                result = self.bash('_site_variant_ask V; echo "V=$V"', stdin=answer + NL)
                self.assertEqual(values(result.stdout)["V"], variant)
        result = self.bash('_site_variant_ask V; echo "V=$V"')
        self.assertEqual(values(result.stdout)["V"], "")
        self.assertIn("Calendar API", result.stdout)

    def test_site_step_installs_the_chosen_variant_without_a_menu(self):
        site = self.base / "html"
        site.mkdir()
        put(site / "index.html", "<html><body>hi</body></html>")
        result = self.bash('_site_auto_fix() { echo "DEPLOY:$5:$6"; }; '
                           '_site_choose "$1" example.org "$2" nginx-id palette', site, self.base / "bak")
        self.assert_ok(result)
        self.assertIn("DEPLOY:palette:1", result.stdout)
        self.assertNotIn("Вариант сайта", result.stdout)
        result = self.bash('block_camouflage() { echo "SITE:$1"; }; NF_IN_SITE=paper; _install_site; '
                           'NF_IN_SITE=""; _install_site')
        self.assertIn("SITE:paper", result.stdout)
        self.assertEqual(result.stdout.count("SITE:"), 1)


class ChecksTests(BashCase):
    STUBS = ('ensure_check_dependencies() { :; }; wget() { echo "echo RAN"; }; curl() { echo "echo RAN"; }; '
             'sysbench() { echo SYSBENCH; }; ')

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

    def own(self, script, *args):
        stubs = '''
NF_NODE_DIR="$1"
fw_load() { :; }; ss() { :; }; _docker_install() { :; }; _cert_hook_ensure() { :; }
_node_cert() { printf -v "$1" '%s' example.org; echo "CERT:$2:$3"; }
_node_write_stack() { echo "STACK:$1:$2"; }
docker() { echo "DOCKER:$*"; }
_node_check() { echo WAITED; }
sleep() { echo SLEPT; }
'''
        return self.bash(stubs + script, self.base, *args)

    def test_own_node_does_not_wait_for_xray(self):
        result = self.own('require_node() { return 1; }; '
                          '( set -eo pipefail; block_node_own "$2" "$3" tok123 ); echo "RC=$?"', DOMAIN, SECRET)
        self.assertIn("RC=0", result.stdout)
        self.assertIn(f"CERT:{DOMAIN}:tok123", result.stdout)
        self.assertIn(f"STACK:{DOMAIN}:{CERT}", result.stdout)
        self.assertIn("DOCKER:compose up -d", result.stdout)
        self.assertNotIn("WAITED", result.stdout)
        self.assertNotIn("SLEPT", result.stdout)

    def test_installed_own_node_is_left_alone(self):
        result = self.own('require_node() { NODE_DIR=/opt/remnanode; NODE_CONTAINER=remnanode; }; '
                          '( set -eo pipefail; block_node_own "" "" ); echo "RC=$?"')
        self.assertIn("RC=0", result.stdout)
        self.assertNotIn("DOCKER:", result.stdout)
        self.assertNotIn("WAITED", result.stdout)

    def test_own_node_without_answers_fails(self):
        result = self.own('require_node() { return 1; }; ( set -eo pipefail; block_node_own "" "" ); echo "RC=$?"')
        self.assertIn("RC=1", result.stdout)
        self.assertNotIn("DOCKER:", result.stdout)

    def test_node_check_step_takes_the_domain_from_nginx(self):
        node, _ = self.stack()
        result = self.bash('D="$1"; require_node() { NODE_DIR="$D"; NODE_SERVICE=remnanode; NODE_CONTAINER=remnanode; }; '
                           '_node_check() { echo "CHECK:$1"; }; _install_node_check', node)
        self.assert_ok(result)
        self.assertIn("CHECK:" + DOMAIN, result.stdout)

    def test_cloudflare_token_from_the_answers_goes_to_the_ini(self):
        ini = self.base / "secrets" / "cloudflare.ini"
        script = '''
NF_CF_INI="$1"
_node_cert_ready() { return 1; }; wait_for_apt() { :; }; apt-get() { :; }; systemctl() { :; }
certbot() { echo "CERTBOT:$*"; }
_node_cert C "$2" "$3"; echo "RC=$? NAME=$C"
'''
        result = self.bash(script, ini, DOMAIN, "tok123")
        self.assertIn("RC=0 NAME=" + CERT, result.stdout)
        self.assertIn(f"--cert-name {CERT} -d {CERT} -d *.{CERT}", result.stdout)
        self.assertEqual(ini.read_text().strip(), "dns_cloudflare_api_token = tok123")

        ini.unlink()
        result = self.bash(script, ini, DOMAIN, "")
        self.assertIn("RC=1", result.stdout)
        self.assertNotIn("CERTBOT", result.stdout)

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
