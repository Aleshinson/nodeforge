"""Kernel hole CVE-2026-98432 (item z): which kernels are fixed, the shield, the order of steps."""
import unittest

from test_install import BashCase, NL


# The system is stubbed: every command that changes something leaves a line in $LOG.
STUBS = r'''
uname() { echo "$RUNNING"; }
_cve_os() { echo "${DISTRO:-ubuntu}"; }
_cve_candidate() { echo "${CAND:-}"; }
_cve_kernel_holds() { echo "${HOLDS:-}"; }
_cve_add_updates_repo() { echo "add-repo" >> "$LOG"; : > "$CVE_UPDATES_LIST"; CAND="${CAND_AFTER:-$CAND}"; }
apt-mark() { echo "apt-mark $*" >> "$LOG"; }
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
apt-get() {
  echo "apt-get $*" >> "$LOG"
  if [ -n "${REPO_BREAKS:-}" ] && [ -e "$CVE_UPDATES_LIST" ]; then return 100; fi
  case "${4:-}" in
    *sourcelist=*)
      if grep -qE "${DEAD_REPO:-^$}" "${4#*=}"; then echo "E: The repository does not have a Release file."; return 100; fi
      if [ -n "${REPO_SILENT_FAIL:-}" ]; then echo "Err:1 https://deb.xanmod.org noble InRelease"; echo "W: Failed to fetch noble/InRelease  Could not connect"; fi ;;
    *) if [ -n "${FOREIGN_BROKEN:-}" ]; then echo "E: The repository 'http://foreign.example' does not have a Release file."; return 100; fi ;;
  esac
}
apt-cache() { :; }
dpkg-query() { printf '%s' "${DPKG:-}"; }
_cve_boot_problem() { echo -n "${BOOT_PROBLEM:-}"; }
_cve_xanmod_suite() { echo "${SUITE:-noble}"; }
_cve_xanmod_key() { echo "xanmod-key" >> "$LOG"; [ -z "${NO_KEY:-}" ]; }
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
        self.sources = self.base / "sources"
        self.sources.mkdir()

    def script(self, body, env):
        env = {"RUNNING": "6.8.0-147-generic", **env}
        head = "".join(f'{k}="{v}"; ' for k, v in env.items())
        return ('LOG="$PWD/$1"; FILTER="$PWD/$2"; CVE_NFT="$PWD/$3/cve.nft"; CVE_UNIT_FILE="$PWD/$3/cve.service"; CVE_UPDATES_LIST="$PWD/$3/updates.list"; CVE_APT_SOURCES="$PWD/$3/sources"; '
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
    # The kernel appears only once the install has run: see run_item.
    PENDING_AFTER_INSTALL = {"FIXED_REL": "6.8.0-149-generic", "INSTALLS": "6.8.0-149-generic"}

    def run_item(self, answers=(), **env):
        # A real `nft -f` is absent here: restarting the unit is what brings the table up.
        body = ('systemctl() { echo "systemctl $*" >> "$LOG"; '
                'if [ "$1" = restart ] && [ -z "${FILTER_FAILS:-}" ]; then : > "$FILTER"; fi; }\n'
                'command() { if [ "$1" = -v ] && [ "$2" = nft ]; then return 0; fi; builtin command "$@"; }\n'
                '_sysupd_apt() { echo "apt $*" >> "$LOG"; [ -z "${INSTALLS:-}" ] || NEWEST="$INSTALLS"; }\n'
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
        self.assertIn("Дыра НЕ закрыта", result.stderr + result.stdout)

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

    def test_hoster_image_without_the_meta_package_still_gets_the_kernel(self):
        # apt has nothing to upgrade, the fixed kernel is only reachable through the meta package.
        result = self.run_item(["y", "y"], CAND="6.8.0-149.149", **self.PENDING_AFTER_INSTALL)
        self.assert_ok(result)
        self.assertTrue(self.has("install linux-image-generic"))
        self.assertFalse(self.has("add-repo"))

    def test_repository_without_the_fix_is_opened_on_a_yes(self):
        result = self.run_item(["y", "y", "n"], CAND="6.8.0-147.147", CAND_AFTER="6.8.0-149.149",
                               **self.PENDING_AFTER_INSTALL)
        self.assert_ok(result)
        log = self.log()
        self.assertLess(log.index("add-repo"), next(i for i, l in enumerate(log) if "install linux-image-generic" in l))

    def test_repository_that_breaks_apt_is_taken_back(self):
        result = self.run_item(["y"], CAND="6.8.0-147.147", REPO_BREAKS="1")
        self.assert_ok(result)
        self.assertTrue(self.has("add-repo"))
        self.assertFalse((self.base / "updates.list").exists())
        self.assertIn("вернул как было", result.stderr + result.stdout)

    def test_repository_stays_closed_without_a_yes(self):
        result = self.run_item(["n"], CAND="6.8.0-147.147")
        self.assert_ok(result)
        self.assertFalse(self.has("add-repo"))
        self.assertFalse(self.has(" install "))
        self.assertIn("Дыра НЕ закрыта", result.stderr + result.stdout)
        self.assertIn("6.8.0-147.147", result.stderr + result.stdout)

    def test_stale_kernel_is_not_installed_instead_of_the_fixed_one(self):
        # Without the fix anywhere the upgrade may still be offered, but the meta package is not forced.
        result = self.run_item(["n", "n"], CAND="6.8.0-147.147", PKGS="linux-image-generic")
        self.assert_ok(result)
        self.assertFalse(self.has(" install "))

    def test_held_kernel_is_released_only_on_a_yes(self):
        self.assert_ok(self.run_item(["y"], HOLDS="linux-image-generic"))
        self.assertTrue(self.has("apt-mark unhold linux-image-generic"))

    def test_held_kernel_stays_held_without_a_yes(self):
        self.assert_ok(self.run_item(["n"], HOLDS="linux-image-generic"))
        self.assertFalse(self.has("apt-mark"))

    def test_debian_is_not_sent_to_the_ubuntu_repository(self):
        result = self.run_item(RUNNING="6.1.0-41-amd64", DISTRO="debian", CAND="6.1.176-1")
        self.assert_ok(result)
        self.assertFalse(self.has("add-repo"))

    def test_debian_without_the_meta_package_gets_it(self):
        result = self.run_item(["n"], RUNNING="6.1.0-41-amd64", DISTRO="debian", CAND="6.1.190-1",
                               PKGS="", NEWEST="6.1.0-41-amd64")
        self.assert_ok(result)
        self.assertIn("linux-image-amd64", result.stderr + result.stdout)

    def test_open_hole_is_never_called_done(self):
        result = self.bash(self.script('_menu_kernel_cve', {"NEWEST": "6.8.0-147-generic"}),
                           self.calls, self.filter, self.base)
        out = result.stdout + result.stderr
        self.assertIn("Дыра НЕ закрыта", out)
        self.assertNotIn("готово", out)

    def test_many_ports_of_one_container_make_one_line(self):
        rows = NL.join(["docker certwarden *:4050", "docker certwarden *:4060", "docker beszel *:8090"]) + NL
        result = self.run_item(LISTENERS=rows)
        self.assert_ok(result)
        self.assertEqual((result.stdout + result.stderr).count("certwarden"), 1)

    XANMOD = {"RUNNING": "6.19.11-x64v3-xanmod1", "CAND": "7.3.3-xanmod1-0", "DPKG": "ii  linux-xanmod-x64v3" + NL,
              "FIXED_REL": "7.3.3-x64v3-xanmod1", "INSTALLS": "7.3.3-x64v3-xanmod1"}
    XANMOD_LINE = "deb [signed-by=/k.gpg] https://deb.xanmod.org noble main" + NL

    def xanmod_list(self, text=None, name="xanmod-release.list"):
        path = self.sources / name
        if text is not None:
            path.write_bytes(text.encode())
        return path

    def test_foreign_broken_source_does_not_hide_the_xanmod_kernel(self):
        self.xanmod_list(self.XANMOD_LINE)
        result = self.run_item(["y", "n"], FOREIGN_BROKEN="1", **self.XANMOD)
        self.assert_ok(result)
        out = result.stdout + result.stderr
        self.assertIn("foreign.example", out)
        self.assertTrue(self.has("install linux-xanmod-x64v3"))
        self.assertFalse(self.has("xanmod-key"))
        self.assertEqual(self.xanmod_list().read_text(encoding="utf-8"), self.XANMOD_LINE)

    def test_lost_xanmod_repository_is_connected_on_a_yes(self):
        result = self.run_item(["y", "y", "n"], **self.XANMOD)
        self.assert_ok(result)
        self.assertEqual(self.xanmod_list().read_bytes().decode(),
                         "deb [signed-by=/etc/apt/keyrings/xanmod-archive-keyring.gpg] https://deb.xanmod.org noble main" + NL)
        self.assertTrue(self.has("install linux-xanmod-x64v3"))

    def test_commented_out_source_counts_as_lost(self):
        self.xanmod_list("# deb https://deb.xanmod.org noble main # disabled on upgrade" + NL)
        result = self.run_item(["y", "y", "n"], **self.XANMOD)
        self.assert_ok(result)
        self.assertTrue(self.has("xanmod-key"))
        self.assertTrue(self.xanmod_list().read_text(encoding="utf-8").startswith("deb [signed-by="))

    def test_stale_xanmod_address_is_replaced(self):
        self.xanmod_list("deb http://deb.xanmod.org releases main" + NL, "xanmod-kernel.list")
        result = self.run_item(["y", "y", "n"], DEAD_REPO="releases", **self.XANMOD)
        self.assert_ok(result)
        self.assertIn(" noble main", self.xanmod_list(name="xanmod-kernel.list").read_text(encoding="utf-8"))
        self.assertIn("does not have a Release file", result.stdout + result.stderr)
        self.assertFalse(self.xanmod_list().exists())

    def test_old_system_falls_back_to_the_suite_that_exists(self):
        result = self.run_item(["y", "y", "n"], DEAD_REPO=" noble ", **self.XANMOD)
        self.assert_ok(result)
        self.assertIn(" bookworm main", self.xanmod_list().read_text(encoding="utf-8"))

    def test_repository_that_does_not_answer_is_put_back(self):
        old = "deb http://deb.xanmod.org releases main" + NL
        self.xanmod_list(old)
        env = {**self.XANMOD, "CAND": "6.19.11-xanmod1-0"}
        result = self.run_item(["y"], DEAD_REPO=".", **env)
        self.assert_ok(result)
        out = result.stdout + result.stderr
        self.assertEqual(self.xanmod_list().read_bytes().decode(), old)
        self.assertIn("вернул как было", out)
        self.assertIn("does not have a Release file", out)
        self.assertIn("Дыра НЕ закрыта", out)
        self.assertFalse(self.has(" install "))

    def test_new_source_that_does_not_answer_is_removed(self):
        result = self.run_item(["y"], RUNNING="6.19.11-x64v3-xanmod1", DEAD_REPO=".")
        self.assert_ok(result)
        self.assertFalse(self.xanmod_list().exists())

    def test_silent_network_failure_is_a_failure(self):
        # apt update exits 0 when the server is out of reach.
        self.xanmod_list(self.XANMOD_LINE)
        result = self.run_item(["n"], RUNNING="6.19.11-x64v3-xanmod1", REPO_SILENT_FAIL="1")
        self.assert_ok(result)
        self.assertIn("Could not connect", result.stdout + result.stderr)

    def test_xanmod_repository_stays_closed_without_a_yes(self):
        result = self.run_item(["n"], RUNNING="6.19.11-x64v3-xanmod1")
        self.assert_ok(result)
        self.assertFalse(self.xanmod_list().exists())
        self.assertFalse(self.has("xanmod-key"))

    def test_no_key_no_source(self):
        result = self.run_item(["y"], RUNNING="6.19.11-x64v3-xanmod1", NO_KEY="1")
        self.assert_ok(result)
        self.assertFalse(self.xanmod_list().exists())
        self.assertIn("ключ XanMod", result.stdout + result.stderr)

    def test_older_branch_is_not_installed_over_a_newer_kernel(self):
        # bookworm carries only the LTS: GRUB would keep booting 6.19 anyway.
        self.xanmod_list(self.XANMOD_LINE)
        env = {**self.XANMOD, "CAND": "6.18.62-xanmod1-0"}
        result = self.run_item(["y", "y"], **env)
        self.assert_ok(result)
        out = result.stdout + result.stderr
        self.assertFalse(self.has(" install "))
        self.assertIn("младше запущенного", out)
        self.assertIn("Дыра НЕ закрыта", out)

    def test_xanmod_system_is_not_sent_to_the_ubuntu_repository(self):
        self.xanmod_list(self.XANMOD_LINE)
        result = self.run_item(RUNNING="6.19.11-x64v3-xanmod1", CAND="6.19.11-xanmod1-0")
        self.assert_ok(result)
        self.assertFalse(self.has("add-repo"))

    def test_broken_source_elsewhere_keeps_the_ubuntu_repository(self):
        result = self.run_item(["y", "y", "n"], CAND="6.8.0-147.147", CAND_AFTER="6.8.0-149.149", FOREIGN_BROKEN="1",
                               **self.PENDING_AFTER_INSTALL)
        self.assert_ok(result)
        self.assertTrue((self.base / "updates.list").exists())
        self.assertTrue(self.has("install linux-image-generic"))

    def test_kernel_that_cannot_boot_gets_no_reboot(self):
        result = self.run_item(BOOT_PROBLEM="нет initrd", **self.PENDING)
        self.assert_ok(result)
        self.assertFalse(self.has("systemctl reboot"))
        self.assertIn("Не перезагружай", result.stdout + result.stderr)

    def test_held_xanmod_kernel_is_offered_too(self):
        result = self.bash('apt-mark() { printf "linux-xanmod-x64v3' + chr(92) + 'ncurl' + chr(92) + 'n"; }; _cve_kernel_holds')
        self.assert_ok(result)
        self.assertEqual(result.stdout.strip(), "linux-xanmod-x64v3")

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

    def test_docker_dns_on_loopback_is_not_a_listener(self):
        line = 'LISTEN 0 4096 127.0.0.11:39897 0.0.0.0:* users:(("dockerd",pid=7,fd=9))'
        result = self.bash(f"ss() {{ echo '{line}'; }}; command() {{ return 1; }}; _cve_mptcp_listeners")
        self.assert_ok(result)
        self.assertEqual(result.stdout.strip(), "")

    def test_meta_package_of_each_build(self):
        cases = {"6.8.0-146-generic": "linux-image-generic", "6.8.0-1069-aws": "linux-image-aws",
                 "6.1.0-41-amd64": "linux-image-amd64", "6.12.107+deb13-amd64": "linux-image-amd64",
                 "6.1.0-41-cloud-amd64": "linux-image-cloud-amd64", "6.12.107+deb13-cloud-amd64": "linux-image-cloud-amd64"}
        result = self.bash("".join(f'_cve_meta_pkg "{rel}"; ' for rel in cases))
        self.assert_ok(result)
        self.assertEqual(result.stdout.split(), list(cases.values()))

    def xanmod_meta(self, rel, known, installed=""):
        script = (f"""dpkg-query() {{ printf '%s' '{installed}'; }}; """
                  f"""_cve_candidate() {{ case " {known} " in *" $1 "*) echo 7.3.3-xanmod1-0 ;; *) echo "(none)" ;; esac; }}; """
                  f"""_cve_meta_pkg {rel}""")
        result = self.bash(script)
        self.assert_ok(result)
        return result.stdout.strip()

    def test_xanmod_meta_package(self):
        self.assertEqual(self.xanmod_meta("6.19.11-x64v3-xanmod1", "linux-xanmod-x64v3"), "linux-xanmod-x64v3")
        self.assertEqual(self.xanmod_meta("6.19.11-x64v2-xanmod1", "linux-xanmod-x64v2"), "linux-xanmod-x64v2")
        # x64v4 is gone from the repository, and an unmarked old build runs on anything.
        self.assertEqual(self.xanmod_meta("6.12.8-x64v4-xanmod1", "linux-xanmod-x64v3"), "linux-xanmod-x64v3")
        self.assertEqual(self.xanmod_meta("6.1.0-xanmod1", "linux-xanmod-x64v2"), "linux-xanmod-x64v2")
        # bookworm carries only the LTS, x64v1 too.
        self.assertEqual(self.xanmod_meta("6.18.50-x64v1-xanmod1", "linux-xanmod-lts-x64v1"), "linux-xanmod-lts-x64v1")
        self.assertEqual(self.xanmod_meta("6.18.50-x64v3-xanmod1", "linux-xanmod-lts-x64v3 linux-xanmod-x64v3",
                                          "ii  linux-xanmod-lts-x64v3"), "linux-xanmod-lts-x64v3")
        # A package that was removed and left its configuration is not installed.
        self.assertEqual(self.xanmod_meta("6.19.11-x64v3-xanmod1", "linux-xanmod-x64v3 linux-xanmod-rt-x64v3",
                                          "rc  linux-xanmod-rt-x64v3"), "linux-xanmod-x64v3")
        self.assertEqual(self.xanmod_meta("6.19.11-x64v3-xanmod1", "nothing"), "")

    def test_xanmod_key_is_taken_only_with_the_exact_fingerprint(self):
        good = "D38D7D1DA1349567ADED882D86F7D09EE734E623"
        sub = "fpr:::::::::D991C5BE3B4D859D61B169E89E8A277150F7E1DD:"
        for keys, taken in ([[good], True], [["AAAA"], False], [[good, "AAAA"], False], [[], False]):
            with self.subTest(keys=keys):
                listing = "".join("pub:-:4096:::::::::" + NL + f"fpr:::::::::{k}:" + NL + sub + NL for k in keys)
                data = self.base / "listing.txt"
                data.write_bytes(listing.encode())
                ring = self.base / "ring" / "k.gpg"
                ring.unlink(missing_ok=True)
                script = ('curl() { :; }; '
                          'gpg() { case "$2" in --show-keys) cat "$LISTING" ;; *) echo key > "$CVE_XANMOD_KEYRING" ;; esac; }; '
                          'LISTING="$PWD/$1"; CVE_XANMOD_KEYRING="$PWD/$2"; '
                          '_cve_xanmod_key; echo "rc=$?"')
                result = self.bash(script, data, ring)
                self.assertEqual(result.stdout.strip(), "rc=0" if taken else "rc=1", result.stderr)
                self.assertEqual(ring.exists(), taken)

    def test_update_of_one_source_reports_the_reason(self):
        body = ("""apt-get() { printf 'Hit:1 x' ; echo; echo 'Err:2 https://deb.xanmod.org noble InRelease'; """
                """echo 'W: Failed to fetch https://deb.xanmod.org/dists/noble/InRelease  Could not connect'; """
                """echo 'W: Some index files failed to download.'; }; apt-cache() { :; }; """
                """_cve_update_list /x.list; echo "rc=$?" """)
        result = self.bash(body)
        self.assertEqual(result.stdout.splitlines(),
                         ["    W: Failed to fetch https://deb.xanmod.org/dists/noble/InRelease  Could not connect", "rc=1"])

    def test_source_that_breaks_apt_as_a_whole_is_a_failure(self):
        # A Signed-By clash passes a scoped update but stops every other apt call.
        result = self.bash("""apt-get() { :; }; apt-cache() { return 100; }; _cve_update_list /x.list; echo "rc=$?" """)
        self.assertEqual(result.stdout.strip(), "rc=1")

    def test_boot_problems(self):
        self.assertIn("initrd", self.bash("_cve_boot_problem 7.3.3-x64v3-xanmod1").stdout)

    def test_candidate_versions(self):
        cases = [("6.8.0-149.149", "ubuntu", "generic", "fixed"), ("6.8.0.149.149", "ubuntu", "generic", "fixed"),
                 ("6.8.0-147.147", "ubuntu", "generic", "vulnerable"), ("(none)", "ubuntu", "generic", "unknown"),
                 ("6.12.115-2", "debian", "amd64", "fixed"), ("6.1.176-1", "debian", "amd64", "vulnerable"),
                 ("(none)", "debian", "amd64", "unknown"), ("7.3.3-xanmod1-0", "ubuntu", "", "fixed"),
                 ("6.18.62-xanmod1-0", "debian", "", "fixed"), ("6.19.11-xanmod1-0", "ubuntu", "", "vulnerable")]
        result = self.bash("".join(f'_cve_candidate_state "{v}" "{o}" "{f}"; ' for v, o, f, _ in cases))
        self.assert_ok(result)
        self.assertEqual(result.stdout.split(), [c[3] for c in cases])


class AuditTests(Base):
    def audit(self, **env):
        body = ('AUD_WARN=0; AUD_FAIL=0; AUD_FIX_DESC=(); AUD_FIX_COST=(); AUD_FIX_FN=(); AUD_FIX_ARG=(); AUD_FIX_STATE=();'
                '_audit_kernel_cve; echo "FAIL=$AUD_FAIL WARN=$AUD_WARN FIXES=${AUD_FIX_FN[*]:-}"')
        result = self.bash(self.script(body, env), self.calls, self.filter, self.base)
        self.assert_ok(result)
        return result.stdout.strip().splitlines()[-1]

    def test_unprotected_kernel_is_a_failure_with_a_fix(self):
        self.assertEqual(self.audit(), "FAIL=1 WARN=0 FIXES=_cve_shield_on _cve_kernel_upgrade")

    def test_shield_alone_is_a_warning(self):
        self.filter.touch()
        self.assertEqual(self.audit(), "FAIL=0 WARN=1 FIXES=_cve_kernel_upgrade")

    def test_fixed_kernel_with_the_filter_offers_to_lift_it(self):
        self.filter.touch()
        self.assertEqual(self.audit(FIXED_REL="6.8.0-147-generic"), "FAIL=0 WARN=0 FIXES=_cve_filter_off")


if __name__ == "__main__":
    unittest.main()
