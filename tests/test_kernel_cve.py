"""Kernel hole CVE-2026-98432 (item z): which kernels are fixed, the shield, the order of steps."""
import unittest

from test_install import BashCase, NL


# The system is stubbed: every command that changes something leaves a line in $LOG.
STUBS = r'''
uname() { echo "$RUNNING"; }
_cve_kernel_state() { if [ "$1" = "${FIXED_REL:-}" ]; then echo fixed; else echo "${STATE:-vulnerable}"; fi; }
_cve_newest_kernel() { echo "${NEWEST:-$RUNNING}"; }
_cve_kernel_pkgs() { echo "${PKGS:-}"; }
_cve_mptcp_listeners() { echo -n "${LISTENERS:-}"; }
_cve_pid_container() { echo "${OWNER:-}"; }
_apt_need() { echo "100 200"; }
_sysupd_fits() { [ -z "${NO_SPACE:-}" ]; }
_sysupd_apt() { echo "apt $*" >> "$LOG"; }
_sysctl_persist() { echo "sysctl $1=$2" >> "$LOG"; }
_cve_mptcp_off() { _sysctl_persist net.mptcp.enabled 0; }
apt-get() { echo "apt-get $*" >> "$LOG"; }
systemctl() { echo "systemctl $*" >> "$LOG"; }
docker() { echo "docker $*" >> "$LOG"; }
nft() {
  case "$1" in
    list) [ -e "$FILTER" ] ;;
    delete) rm -f "$FILTER"; echo "nft delete" >> "$LOG" ;;
  esac
}
'''

APT_PLAN = """Inst linux-firmware-amd-graphics [20240318.git3b128b60-0ubuntu3.3] (20240318.git3b128b60-0ubuntu3.4 Ubuntu:24.04/noble-updates [all])
Inst linux-modules-6.8.0-149-generic (6.8.0-149.149 Ubuntu:24.04/noble-updates [amd64])
Inst linux-image-6.8.0-149-generic (6.8.0-149.149 Ubuntu:24.04/noble-updates [amd64])
Inst linux-image-generic [6.8.0-147.147] (6.8.0-149.149 Ubuntu:24.04/noble-updates [amd64])
Inst linux-headers-generic [6.8.0-147.147] (6.8.0-149.149 Ubuntu:24.04/noble-updates [amd64])
Inst linux-tools-common [6.8.0-147.147] (6.8.0-149.149 Ubuntu:24.04/noble-updates [all])
Inst curl [8.5.0-2ubuntu10.6] (8.5.0-2ubuntu10.7 Ubuntu:24.04/noble-updates [amd64])
"""


class VerdictTests(BashCase):
    CASES = [
        # Ubuntu keeps its own numbering: only the build counts.
        ("6.8.0-147-generic", "ubuntu", "", "vulnerable"),
        ("6.8.0-149-generic", "ubuntu", "", "fixed"),
        ("6.8.0-150-generic", "ubuntu", "", "fixed"),
        ("5.15.0-202-generic", "ubuntu", "", "vulnerable"),
        ("5.15.0-203-generic", "ubuntu", "", "fixed"),
        ("7.0.0-43-generic", "ubuntu", "", "fixed"),
        ("6.8.0-1068-aws", "ubuntu", "", "vulnerable"),
        ("6.8.0-1069-aws", "ubuntu", "", "fixed"),
        ("5.15.0-1111-kvm", "ubuntu", "", "vulnerable"),
        ("6.8.0-1050-oracle", "ubuntu", "", "unknown"),
        # Debian: the package version is the stable branch, the kernel name is not.
        ("6.1.0-41-amd64", "debian", "6.1.176-1", "vulnerable"),
        ("6.1.0-44-amd64", "debian", "6.1.190-1", "fixed"),
        ("6.12.107+deb13-amd64", "debian", "6.12.107-1", "vulnerable"),
        ("6.12.115+deb13-amd64", "debian", "6.12.115-2", "fixed"),
        ("6.12.113+deb12-amd64", "debian", "6.12.113-1~deb12u1", "fixed"),
        ("6.1.0-41-amd64", "debian", "", "unknown"),
        # XanMod follows stable whatever the distribution is.
        ("6.12.112-x64v3-xanmod1", "ubuntu", "", "vulnerable"),
        ("6.12.113-x64v3-xanmod1", "debian", "", "fixed"),
        ("6.18.55-x64v3-xanmod1", "ubuntu", "", "vulnerable"),
        ("6.18.56-x64v3-xanmod1", "ubuntu", "", "fixed"),
        ("7.1.9-x64v3-xanmod1", "ubuntu", "", "vulnerable"),
        ("7.2.10-x64v3-xanmod1", "ubuntu", "", "fixed"),
        ("7.3.1-x64v3-xanmod1", "ubuntu", "", "fixed"),
        ("7.3-x64v3-xanmod1", "ubuntu", "", "fixed"),
        ("6.8.12-4-pve", "debian", "", "unknown"),
        ("6.8.12-4-pve", "ubuntu", "", "unknown"),
    ]

    def test_every_kernel_gets_its_verdict(self):
        script = "".join(f'_cve_verdict "{rel}" "{os_id}" "{pkg}"; ' for rel, os_id, pkg, _ in self.CASES)
        result = self.bash(script)
        self.assert_ok(result)
        got = result.stdout.split()
        self.assertEqual(len(got), len(self.CASES), result.stdout + result.stderr)
        for case, verdict in zip(self.CASES, got):
            self.assertEqual(verdict, case[3], case)


class Base(BashCase):
    def setUp(self):
        super().setUp()
        self.calls = self.base / "calls.log"
        self.filter = self.base / "filter.up"

    def script(self, body, env):
        env = {"RUNNING": "6.8.0-147-generic", **env}
        head = "".join(f'{k}="{v}"; ' for k, v in env.items())
        return ('LOG="$PWD/$1"; FILTER="$PWD/$2"; CVE_NFT="$PWD/$3/cve.nft"; CVE_UNIT_FILE="$PWD/$3/cve.service"; '
                + head + STUBS + body)

    def run_item(self, answers=(), **env):
        script = self.script('run_block "Дыра в ядре" block_kernel_cve', env)
        return self.bash(script, self.calls, self.filter, self.base, stdin=NL.join(answers) + NL)

    def log(self):
        return self.calls.read_text(encoding="utf-8").splitlines() if self.calls.exists() else []

    def has(self, text):
        return any(text in line for line in self.log())


class ItemTests(Base):
    PENDING = {"NEWEST": "6.8.0-149-generic", "FIXED_REL": "6.8.0-149-generic"}

    def run_item(self, answers=(), **env):
        # A real `nft -f` is absent here: restarting the unit is what brings the table up.
        body = ('systemctl() { echo "systemctl $*" >> "$LOG"; '
                'if [ "$1" = restart ] && [ -z "${FILTER_FAILS:-}" ]; then : > "$FILTER"; fi; }\n'
                'command() { if [ "$1" = -v ] && [ "$2" = nft ]; then return 0; fi; builtin command "$@"; }\n'
                'run_block "Дыра в ядре" block_kernel_cve')
        return self.bash(self.script(body, env), self.calls, self.filter, self.base, stdin=NL.join(answers) + NL)

    def test_fixed_kernel_changes_nothing(self):
        result = self.run_item(FIXED_REL="6.8.0-147-generic")
        self.assert_ok(result)
        self.assertEqual(self.log(), [])
        self.assertFalse((self.base / "cve.nft").exists())

    def test_fixed_kernel_offers_to_lift_the_filter(self):
        self.filter.touch()
        result = self.run_item(["y"], FIXED_REL="6.8.0-147-generic")
        self.assert_ok(result)
        self.assertFalse(self.filter.exists())
        self.assertTrue(self.has("disable --now"))

    def test_shield_goes_up_before_the_kernel_and_reboot_comes_last(self):
        result = self.run_item(["y", "y"], PKGS="linux-image-generic", **self.PENDING)
        self.assert_ok(result)
        log = self.log()
        restart = next(i for i, l in enumerate(log) if l.startswith("systemctl restart"))
        mptcp = log.index("sysctl net.mptcp.enabled=0")
        update = next(i for i, l in enumerate(log) if l.startswith("apt-get -q update"))
        install = next(i for i, l in enumerate(log) if "install linux-image-generic" in l)
        self.assertLess(restart, update)
        self.assertLess(mptcp, update)
        self.assertLess(update, install)
        self.assertEqual(log[-1], "systemctl reboot")

    def test_no_reboot_without_a_yes(self):
        result = self.run_item(["y", "n"], PKGS="linux-image-generic", **self.PENDING)
        self.assert_ok(result)
        self.assertTrue(self.has("install linux-image-generic"))
        self.assertFalse(self.has("systemctl reboot"))
        self.assertIn("Перезагрузку отложил", result.stderr + result.stdout)

    def test_refused_install_keeps_the_shield(self):
        result = self.run_item(["n"], PKGS="linux-image-generic")
        self.assert_ok(result)
        self.assertFalse(self.has(" install "))
        self.assertTrue(self.filter.exists())

    def test_kernel_installed_earlier_only_needs_the_reboot(self):
        result = self.run_item(["y"], **self.PENDING)
        self.assert_ok(result)
        self.assertEqual(self.log()[-1], "systemctl reboot")

    def test_newer_kernel_without_the_fix_is_no_reason_to_reboot(self):
        result = self.run_item(NEWEST="6.8.0-148-generic")
        self.assert_ok(result)
        self.assertFalse(self.has("systemctl reboot"))
        self.assertIn("пока не нашёл", result.stderr + result.stdout)

    def test_no_room_stops_before_apt_install_but_keeps_the_shield(self):
        result = self.run_item(PKGS="linux-image-generic", NO_SPACE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.has(" install "))
        self.assertTrue(self.filter.exists())

    def test_filter_that_did_not_load_is_an_error(self):
        result = self.run_item(FILTER_FAILS="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.has("apt-get -q update"))

    def test_unknown_kernel_still_gets_the_shield(self):
        result = self.run_item(RUNNING="6.8.12-4-pve", STATE="unknown")
        self.assert_ok(result)
        self.assertIn("Не знаю эту сборку", result.stderr + result.stdout)
        self.assertTrue(self.filter.exists())

    def test_filter_covers_prerouting_and_outlives_nftables_service(self):
        self.assert_ok(self.run_item())
        rules = (self.base / "cve.nft").read_text(encoding="utf-8")
        unit = (self.base / "cve.service").read_text(encoding="utf-8")
        self.assertIn("hook prerouting priority -300", rules)
        self.assertIn("meta l4proto tcp ip hdrlength > 5 counter drop", rules)
        self.assertIn("delete table ip nodeforge_cve98432", rules)
        self.assertIn("After=nftables.service", unit)
        self.assertIn("Before=network-pre.target", unit)

    def test_host_network_container_is_restarted_only_on_a_yes(self):
        rows = "host rw-core *:443 1234" + NL
        self.assert_ok(self.run_item(["y"], LISTENERS=rows, OWNER="remnanode"))
        self.assertTrue(self.has("docker restart remnanode"))

    def test_no_restart_without_a_yes(self):
        rows = "host rw-core *:443 1234" + NL
        self.assert_ok(self.run_item(["n"], LISTENERS=rows, OWNER="remnanode"))
        self.assertFalse(self.has("docker restart"))

    def test_container_with_own_network_is_not_restarted(self):
        result = self.run_item(LISTENERS="docker vpnado_nginx 0.0.0.0:443" + NL)
        self.assert_ok(result)
        self.assertFalse(self.has("docker restart"))
        self.assertIn("в своей сети", result.stderr + result.stdout)

    def test_pending_kernel_leaves_listeners_alone(self):
        rows = "host rw-core *:443 1234" + NL
        self.assert_ok(self.run_item(["n"], LISTENERS=rows, OWNER="remnanode", **self.PENDING))
        self.assertFalse(self.has("docker restart"))


class ParsingTests(BashCase):
    def test_only_installed_kernel_packages_are_upgraded(self):
        plan = self.base / "plan.txt"
        plan.write_bytes(APT_PLAN.encode())
        result = self.bash('f="$1"; apt-get() { cat "$f"; }; _cve_kernel_pkgs', plan)
        self.assert_ok(result)
        self.assertEqual(result.stdout.split(), ["linux-image-generic", "linux-headers-generic"])

    def test_listeners_of_the_host(self):
        line = 'LISTEN 0 4096 *:443 *:* users:(("rw-core",pid=4242,fd=9))'
        result = self.bash(f"ss() {{ echo '{line}'; }}; command() {{ return 1; }}; _cve_mptcp_listeners")
        self.assert_ok(result)
        self.assertEqual(result.stdout.split(), ["host", "rw-core", "*:443", "4242"])


class AuditTests(Base):
    def audit(self, **env):
        body = ('AUD_WARN=0; AUD_FAIL=0; AUD_FIX_DESC=(); AUD_FIX_COST=(); AUD_FIX_FN=(); AUD_FIX_ARG=(); AUD_FIX_STATE=();'
                '_audit_kernel_cve; echo "FAIL=$AUD_FAIL WARN=$AUD_WARN FIXES=${AUD_FIX_FN[*]:-}"')
        result = self.bash(self.script(body, env), self.calls, self.filter, self.base)
        self.assert_ok(result)
        return result.stdout.strip().splitlines()[-1]

    def test_unprotected_kernel_is_a_failure_with_a_fix(self):
        self.assertEqual(self.audit(), "FAIL=1 WARN=0 FIXES=_cve_shield_on")

    def test_kernel_on_offer_adds_the_upgrade(self):
        self.assertEqual(self.audit(PKGS="linux-image-generic"),
                         "FAIL=1 WARN=0 FIXES=_cve_shield_on _cve_kernel_upgrade")

    def test_shield_alone_is_a_warning(self):
        self.filter.touch()
        self.assertEqual(self.audit(), "FAIL=0 WARN=1 FIXES=")

    def test_fixed_kernel_with_the_filter_offers_to_lift_it(self):
        self.filter.touch()
        self.assertEqual(self.audit(FIXED_REL="6.8.0-147-generic"), "FAIL=0 WARN=0 FIXES=_cve_filter_off")


if __name__ == "__main__":
    unittest.main()
